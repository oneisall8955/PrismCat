package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestValidateArchiveKeyPrefix(t *testing.T) {
	valid := []string{
		"backups/prismcat",
		"backups/prismcat/${yyyy}",
		"backups/${yyyy}/${MM}-${dd}",
		"backups/${yyyy}/${yyyy}-${MM}-${dd}",
	}
	for _, prefix := range valid {
		if err := ValidateArchiveKeyPrefix(prefix); err != nil {
			t.Errorf("%q: %v", prefix, err)
		}
	}
	invalid := []string{"", "/backups", "backups/", "backups//x", "backups/../x", "backups/${month}", "backups/bad}"}
	for _, prefix := range invalid {
		if err := ValidateArchiveKeyPrefix(prefix); err == nil {
			t.Errorf("%q unexpectedly valid", prefix)
		}
	}
}

func TestValidateArchiveConfigDoesNotSilentlyNormalizeInvalidValues(t *testing.T) {
	base := ArchiveConfig{
		KeyPrefix: "backups/prismcat", ScheduleTime: "02:00", Timezone: "Asia/Shanghai",
		ZstdLevel: 10, LocalRetentionHours: 24, ImportRetentionHours: 24,
	}
	tests := []ArchiveConfig{
		func() ArchiveConfig { v := base; v.KeyPrefix = ""; return v }(),
		func() ArchiveConfig { v := base; v.ScheduleTime = "25:00"; return v }(),
		func() ArchiveConfig { v := base; v.Timezone = "Not/A-Timezone"; return v }(),
		func() ArchiveConfig { v := base; v.ZstdLevel = 20; return v }(),
		func() ArchiveConfig { v := base; v.LocalRetentionHours = 0; return v }(),
	}
	for _, cfg := range tests {
		if err := ValidateArchiveConfig(cfg); err == nil {
			t.Errorf("invalid archive config unexpectedly accepted: %#v", cfg)
		}
	}
}

func TestResolveArchiveKeyPrefix(t *testing.T) {
	day := time.Date(2026, 8, 17, 0, 0, 0, 0, time.UTC)
	got := ResolveArchiveKeyPrefix("backups/${yyyy}/${MM}-${dd}", day)
	if got != "backups/2026/08-17" {
		t.Fatalf("resolved = %q", got)
	}
}

func TestSavePreservesArchiveAlongsideIdentityAuditConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	cfg := &Config{
		configPath: path,
		Archive: ArchiveConfig{
			Enabled: true, S3: ArchiveS3Config{Endpoint: "https://s3.example.com", Bucket: "audit-backups"},
			KeyPrefix: "backups/prismcat", ScheduleTime: "02:00", Timezone: "Asia/Shanghai",
			ZstdLevel: 10, LocalRetentionHours: 24, ImportRetentionHours: 24,
		},
		IdentityResolution: IdentityResolutionGlobalConfig{Enabled: true},
	}
	if err := cfg.Save(); err != nil {
		t.Fatalf("save config: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read saved config: %v", err)
	}
	saved := string(data)
	if !strings.Contains(saved, "archive:") || !strings.Contains(saved, "bucket: audit-backups") ||
		!strings.Contains(saved, "identity_resolution:") || !strings.Contains(saved, "enabled: true") {
		t.Fatalf("saved config omitted archive or identity audit settings:\n%s", saved)
	}
}
