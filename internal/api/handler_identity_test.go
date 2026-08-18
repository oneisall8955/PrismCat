package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/paopaoandlingyia/PrismCat/internal/config"
	"github.com/paopaoandlingyia/PrismCat/internal/storage"
	"github.com/paopaoandlingyia/PrismCat/internal/upstreamidentity"
)

func TestIdentityConfigAPISecretsAndMergeSemantics(t *testing.T) {
	current := &config.IdentityResolutionConfig{
		Provider: config.IdentityProviderSub2API, AdminBaseURL: "https://example.com/api/v1",
		AdminAPIKey: "existing-admin-secret", SyncIntervalSeconds: 300,
	}
	public := identityForAPI(current)
	encoded, err := json.Marshal(public)
	if err != nil {
		t.Fatalf("marshal public identity config: %v", err)
	}
	if strings.Contains(string(encoded), current.AdminAPIKey) || !public.AdminAPIKeyConfigured {
		t.Fatalf("public identity config leaked key or omitted configured flag: %s", encoded)
	}

	kept := identityFromAPI(&identityResolutionAPI{
		Provider: config.IdentityProviderSub2API, AdminBaseURL: current.AdminBaseURL, SyncIntervalSeconds: 600,
	}, current)
	if kept.AdminAPIKey != current.AdminAPIKey || kept.SyncIntervalSeconds != 600 {
		t.Fatalf("blank-key merge = %#v", kept)
	}
	cleared := identityFromAPI(&identityResolutionAPI{
		Provider: config.IdentityProviderSub2API, ClearAdminAPIKey: true, SyncIntervalSeconds: 300,
	}, current)
	if cleared.AdminAPIKey != "" {
		t.Fatalf("explicit clear retained admin key: %#v", cleared)
	}
	if disabled := identityFromAPI(&identityResolutionAPI{}, current); disabled != nil {
		t.Fatalf("blank provider should disable identity resolution: %#v", disabled)
	}
}

func TestParseLogFilterIncludesIdentityScope(t *testing.T) {
	filter := parseLogFilter(url.Values{
		"identity_id":       {"123"},
		"identity_upstream": {"alpha"},
		"identity_target":   {"backup"},
	}, false)
	if filter.IdentityID != "123" || filter.IdentityUpstream != "alpha" || filter.IdentityTarget != "backup" {
		t.Fatalf("identity filter = %#v", filter)
	}
}

func TestIdentityDirectoryRequiresUpstreamAndNormalizesPagination(t *testing.T) {
	h := &Handler{cfg: &config.Config{IdentityResolution: config.IdentityResolutionGlobalConfig{Enabled: true}}}
	missing := httptest.NewRecorder()
	h.handleUpstreamIdentities(missing, httptest.NewRequest(http.MethodGet, "/api/upstream-identities?limit=10", nil))
	if missing.Code != http.StatusBadRequest {
		t.Fatalf("missing upstream status=%d body=%s", missing.Code, missing.Body.String())
	}

	recorder := httptest.NewRecorder()
	h.handleUpstreamIdentities(recorder, httptest.NewRequest(http.MethodGet, "/api/upstream-identities?upstream=audit&offset=-9&limit=1000", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("identity list status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var response struct {
		Total  int `json:"total"`
		Offset int `json:"offset"`
		Limit  int `json:"limit"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response.Total != 0 || response.Offset != 0 || response.Limit != 100 {
		t.Fatalf("pagination metadata=%#v", response)
	}
}

func TestIdentityIDFilterRequiresUpstreamForListAndExport(t *testing.T) {
	h := &Handler{cfg: &config.Config{IdentityResolution: config.IdentityResolutionGlobalConfig{Enabled: true}}}
	for _, endpoint := range []struct {
		name string
		call func(http.ResponseWriter, *http.Request)
		url  string
	}{
		{name: "list", call: h.handleLogs, url: "/api/logs?identity_id=42"},
		{name: "export", call: h.handleLogsExport, url: "/api/logs/export?identity_id=42"},
	} {
		t.Run(endpoint.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			endpoint.call(recorder, httptest.NewRequest(http.MethodGet, endpoint.url, nil))
			if recorder.Code != http.StatusBadRequest {
				t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
			}
		})
	}
}

func TestIdentityAuditSwitchPersistsAndDisablesIdentityAPIs(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")
	content := "identity_resolution:\n  enabled: true\nstorage:\n  database: \"" + filepath.ToSlash(filepath.Join(dir, "logs.db")) + "\"\n  blob_dir: \"" + filepath.ToSlash(filepath.Join(dir, "blobs")) + "\"\n"
	if err := os.WriteFile(configPath, []byte(content), 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	h := &Handler{cfg: cfg}

	update := httptest.NewRecorder()
	h.handleConfig(update, httptest.NewRequest(http.MethodPut, "/api/config", strings.NewReader(`{"identity_resolution":{"enabled":false}}`)))
	if update.Code != http.StatusOK {
		t.Fatalf("disable audit status=%d body=%s", update.Code, update.Body.String())
	}
	if cfg.IdentityAuditEnabled() {
		t.Fatal("audit remained enabled after config update")
	}
	reloaded, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("reload config: %v", err)
	}
	if reloaded.IdentityAuditEnabled() {
		t.Fatal("disabled audit switch was not persisted")
	}

	for _, endpoint := range []struct {
		name string
		call func(http.ResponseWriter, *http.Request)
		req  *http.Request
	}{
		{name: "directory", call: h.handleUpstreamIdentities, req: httptest.NewRequest(http.MethodGet, "/api/upstream-identities?upstream=audit", nil)},
		{name: "sync", call: h.handleUpstreamIdentitySync, req: httptest.NewRequest(http.MethodPost, "/api/upstreams/identity-sync", strings.NewReader(`{"upstream":"audit"}`))},
		{name: "filter", call: h.handleLogs, req: httptest.NewRequest(http.MethodGet, "/api/logs?identity_id=1&identity_upstream=audit", nil)},
	} {
		t.Run(endpoint.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			endpoint.call(recorder, endpoint.req)
			if recorder.Code != http.StatusConflict {
				t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
			}
		})
	}
}

func TestHandleUpstreamsNeverReturnsAdminKey(t *testing.T) {
	h := &Handler{cfg: &config.Config{Upstreams: map[string]config.UpstreamConfig{
		"audit": {
			Target: "https://example.com", Timeout: 120, OutboundProxy: "direct",
			IdentityResolution: &config.IdentityResolutionConfig{
				Provider: config.IdentityProviderSub2API, AdminAPIKey: "never-return-this", SyncIntervalSeconds: 300,
			},
		},
	}}}
	req := httptest.NewRequest(http.MethodGet, "/api/upstreams", nil)
	recorder := httptest.NewRecorder()
	h.handleUpstreams(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	body := recorder.Body.String()
	if strings.Contains(body, "never-return-this") || strings.Contains(body, "admin_api_key\"") {
		t.Fatalf("upstream API leaked admin key: %s", body)
	}
	if !strings.Contains(body, `"admin_api_key_configured":true`) {
		t.Fatalf("upstream API omitted configured flag: %s", body)
	}
}

func TestIdentityJSONLExportOmitsFingerprint(t *testing.T) {
	repo, err := storage.NewSQLiteRepository(filepath.Join(t.TempDir(), "identity-export.db"))
	if err != nil {
		t.Fatalf("open sqlite repository: %v", err)
	}
	defer repo.Close()
	if err := repo.SaveLog(&storage.RequestLog{
		ID: "identity-log", CreatedAt: time.Now().UTC(), Upstream: "audit", UpstreamTarget: "primary",
		UpstreamIdentityID: "77", APIKeyFingerprint: "internal-hmac-fingerprint", Method: http.MethodPost, Path: "/v1/chat/completions",
	}); err != nil {
		t.Fatalf("save identity log: %v", err)
	}

	h := &Handler{cfg: &config.Config{IdentityResolution: config.IdentityResolutionGlobalConfig{Enabled: true}}, repo: repo}
	req := httptest.NewRequest(http.MethodGet, "/api/logs/export?identity_id=77&identity_upstream=audit&identity_target=primary", nil)
	recorder := httptest.NewRecorder()
	h.handleLogsExport(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Fatalf("export status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	body := recorder.Body.String()
	if !strings.Contains(body, `"upstream_identity_id":"77"`) || !strings.HasSuffix(body, "\n") {
		t.Fatalf("export omitted identity or was not JSONL: %s", body)
	}
	if strings.Contains(body, "internal-hmac-fingerprint") || strings.Contains(body, "api_key_fingerprint") {
		t.Fatalf("export leaked internal fingerprint: %s", body)
	}
}

func TestDisabledIdentityAuditHidesStoredIdentityFromLogResponses(t *testing.T) {
	repo, err := storage.NewSQLiteRepository(filepath.Join(t.TempDir(), "identity-disabled.db"))
	if err != nil {
		t.Fatalf("open sqlite repository: %v", err)
	}
	defer repo.Close()
	if err := repo.SaveLog(&storage.RequestLog{
		ID: "identity-log", TraceID: "identity-trace", CreatedAt: time.Now().UTC(), Upstream: "audit",
		UpstreamIdentityID: "77", Method: http.MethodPost, Path: "/v1/chat/completions",
	}); err != nil {
		t.Fatalf("save identity log: %v", err)
	}

	h := &Handler{cfg: &config.Config{}, repo: repo}
	for _, endpoint := range []struct {
		name string
		call func(http.ResponseWriter, *http.Request)
		url  string
	}{
		{name: "list", call: h.handleLogs, url: "/api/logs"},
		{name: "detail", call: h.handleLogDetail, url: "/api/logs/identity-log"},
		{name: "trace", call: h.handleTraceDetail, url: "/api/traces/identity-trace"},
		{name: "export", call: h.handleLogsExport, url: "/api/logs/export"},
	} {
		t.Run(endpoint.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			endpoint.call(recorder, httptest.NewRequest(http.MethodGet, endpoint.url, nil))
			if recorder.Code != http.StatusOK {
				t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
			}
			if strings.Contains(recorder.Body.String(), "upstream_identity_id") || strings.Contains(recorder.Body.String(), `"77"`) {
				t.Fatalf("disabled audit leaked stored identity: %s", recorder.Body.String())
			}
		})
	}
}

func TestPendingIdentityResolutionEndpointQueuesBackgroundWork(t *testing.T) {
	admin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"items":[],"page":1,"page_size":1000,"pages":1,"total":0}}`))
	}))
	defer admin.Close()
	repo, err := storage.NewSQLiteRepository(filepath.Join(t.TempDir(), "identity-resolution.db"))
	if err != nil {
		t.Fatalf("open sqlite repository: %v", err)
	}
	defer repo.Close()
	cfg := &config.Config{
		IdentityResolution: config.IdentityResolutionGlobalConfig{FingerprintSecret: "MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE"},
		Upstreams: map[string]config.UpstreamConfig{
			"audit": {Target: admin.URL, IdentityResolution: &config.IdentityResolutionConfig{Provider: config.IdentityProviderSub2API, AdminBaseURL: admin.URL, AdminAPIKey: "admin", SyncIntervalSeconds: 300}},
		},
	}
	manager := upstreamidentity.New(cfg, repo)
	defer manager.Close()
	if _, err := manager.SyncNow(context.Background(), upstreamidentity.SourceKey{Upstream: "audit"}); err != nil {
		t.Fatalf("sync identity directory: %v", err)
	}
	h := &Handler{cfg: cfg, repo: repo, identity: manager}
	req := httptest.NewRequest(http.MethodPost, "/api/upstream-identities/resolve-pending", strings.NewReader(`{"upstream":"audit"}`))
	recorder := httptest.NewRecorder()
	h.handlePendingIdentityResolution(recorder, req)

	if recorder.Code != http.StatusAccepted {
		t.Fatalf("resolution status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), `"resolution_queued":true`) {
		t.Fatalf("resolution response did not report queued work: %s", recorder.Body.String())
	}
}
