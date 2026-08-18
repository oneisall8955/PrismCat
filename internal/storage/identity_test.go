package storage

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestSQLiteIdentityAssignmentIsImmutableAndScoped(t *testing.T) {
	repo := mustNewSQLiteRepoForTest(t)
	defer repo.Close()

	now := time.Now().UTC()
	entries := []*RequestLog{
		{ID: "one", CreatedAt: now, Upstream: "alpha", UpstreamTarget: "primary", Method: "POST", Path: "/v1", APIKeyFingerprint: "fp-one"},
		{ID: "two", CreatedAt: now.Add(time.Millisecond), Upstream: "beta", UpstreamTarget: "primary", Method: "POST", Path: "/v1", APIKeyFingerprint: "fp-two"},
		{ID: "three", CreatedAt: now.Add(2 * time.Millisecond), Upstream: "alpha", UpstreamTarget: "backup", Method: "POST", Path: "/v1", APIKeyFingerprint: "fp-three"},
		{ID: "legacy", CreatedAt: now.Add(3 * time.Millisecond), Upstream: "alpha", Method: "POST", Path: "/v1"},
	}
	for _, entry := range entries {
		if err := repo.SaveLog(entry); err != nil {
			t.Fatalf("SaveLog(%s): %v", entry.ID, err)
		}
	}

	pending, err := repo.ListPendingIdentityLogs("alpha", "primary", "directory-v1", 0, "", 10)
	if err != nil || len(pending) != 1 || pending[0].ID != "one" {
		t.Fatalf("pending logs = %#v, err = %v", pending, err)
	}
	if err := repo.MarkLogsIdentityResolutionVersion([]string{"one"}, "directory-v1"); err != nil {
		t.Fatalf("mark identity resolution version: %v", err)
	}
	pending, err = repo.ListPendingIdentityLogs("alpha", "primary", "directory-v1", 0, "", 10)
	if err != nil || len(pending) != 0 {
		t.Fatalf("same directory version pending logs = %#v, err = %v", pending, err)
	}
	pending, err = repo.ListPendingIdentityLogs("alpha", "primary", "directory-v2", 0, "", 10)
	if err != nil || len(pending) != 1 || pending[0].ID != "one" {
		t.Fatalf("changed directory version pending logs = %#v, err = %v", pending, err)
	}
	if updated, err := repo.SetLogIdentityIfEmpty("one", "123"); err != nil || !updated {
		t.Fatalf("first identity assignment updated=%v err=%v", updated, err)
	}
	if updated, err := repo.SetLogIdentityIfEmpty("one", "456"); err != nil || updated {
		t.Fatalf("second identity assignment updated=%v err=%v", updated, err)
	}
	for _, id := range []string{"two", "three"} {
		if _, err := repo.SetLogIdentityIfEmpty(id, "123"); err != nil {
			t.Fatalf("assign %s: %v", id, err)
		}
	}

	upsert := *entries[0]
	upsert.UpstreamIdentityID = ""
	upsert.StatusCode = 200
	if err := repo.SaveLog(&upsert); err != nil {
		t.Fatalf("upsert log: %v", err)
	}
	got, err := repo.GetLog("one")
	if err != nil || got.UpstreamIdentityID != "123" {
		t.Fatalf("identity after upsert = %q, err = %v", got.UpstreamIdentityID, err)
	}

	logs, total, err := repo.ListLogs(LogFilter{
		IdentityID: "123", IdentityUpstream: "alpha", IdentityTarget: "primary", Limit: 10,
	})
	if err != nil || total != 1 || len(logs) != 1 || logs[0].ID != "one" {
		t.Fatalf("scoped identity filter logs=%#v total=%d err=%v", logs, total, err)
	}

	encoded, err := json.Marshal(entries[0])
	if err != nil {
		t.Fatalf("marshal log: %v", err)
	}
	if strings.Contains(string(encoded), "fp-one") || strings.Contains(string(encoded), "api_key_fingerprint") {
		t.Fatalf("public JSON leaked fingerprint: %s", encoded)
	}

	var exported []*RequestLog
	err = repo.ExportLogs(context.Background(), LogFilter{
		IdentityID: "123", IdentityUpstream: "alpha", IdentityTarget: "primary",
	}, func(entry *RequestLog) error {
		exported = append(exported, entry)
		return nil
	})
	if err != nil || len(exported) != 1 || exported[0].UpstreamIdentityID != "123" {
		t.Fatalf("identity export logs=%#v err=%v", exported, err)
	}
	exportJSON, _ := json.Marshal(exported[0])
	if strings.Contains(string(exportJSON), "api_key_fingerprint") || !strings.Contains(string(exportJSON), `"upstream_identity_id":"123"`) {
		t.Fatalf("identity export JSON = %s", exportJSON)
	}
}
