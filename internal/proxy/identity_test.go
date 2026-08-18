package proxy

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/paopaoandlingyia/PrismCat/internal/config"
	"github.com/paopaoandlingyia/PrismCat/internal/upstreamidentity"
)

func TestSanitizeIdentityQuery(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want []string
		not  []string
	}{
		{name: "normal", raw: "key=gemini-secret&api_key=other-secret&model=x", want: []string{"key=%2A%2A%2A", "api_key=%2A%2A%2A", "model=x"}, not: []string{"gemini-secret", "other-secret"}},
		{name: "case insensitive", raw: "KEY=secret", want: []string{"KEY=%2A%2A%2A"}, not: []string{"secret"}},
		{name: "malformed escape", raw: "key=raw-secret&bad=%zz", want: []string{"key=***", "bad=%zz"}, not: []string{"raw-secret"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sanitizeIdentityQuery(tt.raw, true)
			for _, value := range tt.want {
				if !strings.Contains(got, value) {
					t.Fatalf("sanitizeIdentityQuery(%q) = %q, missing %q", tt.raw, got, value)
				}
			}
			for _, value := range tt.not {
				if strings.Contains(got, value) {
					t.Fatalf("sanitizeIdentityQuery(%q) leaked %q in %q", tt.raw, value, got)
				}
			}
		})
	}

	target, _ := url.Parse("https://example.com/v1beta/models?key=url-secret&safe=yes")
	got := sanitizeIdentityURL(target, true)
	if strings.Contains(got, "url-secret") || !strings.Contains(got, "safe=yes") {
		t.Fatalf("sanitizeIdentityURL = %q", got)
	}
}

func TestProxyFingerprintsFinalOverriddenCredentialAndRedactsLogs(t *testing.T) {
	const originalKey = "original-client-secret"
	const finalKey = "final-upstream-secret"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer "+finalKey {
			t.Errorf("upstream Authorization = %q", got)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	secret := []byte("01234567890123456789012345678901")
	cfg := &config.Config{
		Server:             config.ServerConfig{ProxyDomains: []string{"localhost"}},
		IdentityResolution: config.IdentityResolutionGlobalConfig{FingerprintSecret: base64.RawURLEncoding.EncodeToString(secret)},
		Upstreams: map[string]config.UpstreamConfig{
			"audit": {Target: upstream.URL, OutboundProxy: "direct", IdentityResolution: &config.IdentityResolutionConfig{Provider: config.IdentityProviderSub2API, AdminAPIKey: "admin", SyncIntervalSeconds: 300}},
		},
		Overrides: config.RequestOverridesConfig{
			Enabled: true,
			Upstreams: map[string]config.RequestOverrideUpstreamBinding{
				"audit": {Enabled: true, RuleNames: []string{"final credential"}},
			},
			Rules: []config.RequestOverrideRule{{
				Name: "final credential", Enabled: true,
				Match:   config.RequestOverrideMatch{Methods: []string{http.MethodGet}},
				Headers: []config.RequestOverrideHeader{{Op: "set", Name: "Authorization", Value: "Bearer " + finalKey}},
			}},
		},
	}
	repo := newProxyTestRepo()
	handler := New(cfg, repo, nil, nil)
	req := httptest.NewRequest(http.MethodGet, "http://audit.localhost/v1/chat/completions?api_key=query-secret&safe=yes", nil)
	req.Header.Set("Authorization", "Bearer "+originalKey)
	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("proxy status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	repo.mu.Lock()
	if len(repo.logs) == 0 {
		repo.mu.Unlock()
		t.Fatal("proxy saved no logs")
	}
	entry := repo.logs[len(repo.logs)-1].Clone()
	repo.mu.Unlock()

	if got, want := entry.APIKeyFingerprint, upstreamidentity.Fingerprint(secret, finalKey); got != want {
		t.Fatalf("final fingerprint = %q, want %q", got, want)
	}
	if entry.APIKeyFingerprint == upstreamidentity.Fingerprint(secret, originalKey) {
		t.Fatal("fingerprint used original client credential")
	}
	serialized := entry.TargetURL + "\n" + entry.Query
	for _, leaked := range []string{originalKey, finalKey, "query-secret"} {
		if strings.Contains(serialized, leaked) {
			t.Fatalf("logged URL/query leaked %q: %s", leaked, serialized)
		}
	}
	for _, values := range entry.RequestHeaders {
		for _, value := range values {
			if strings.Contains(value, originalKey) || strings.Contains(value, finalKey) {
				t.Fatalf("logged headers leaked credential: %#v", entry.RequestHeaders)
			}
		}
	}
}

func TestProxyFingerprintsGeminiKeyFromFinalTargetURL(t *testing.T) {
	const targetKey = "target-url-secret"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("key"); got != targetKey {
			t.Errorf("upstream query key = %q", got)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	secret := []byte("01234567890123456789012345678901")
	cfg := &config.Config{
		Server:             config.ServerConfig{ProxyDomains: []string{"localhost"}},
		IdentityResolution: config.IdentityResolutionGlobalConfig{FingerprintSecret: base64.RawURLEncoding.EncodeToString(secret)},
		Upstreams: map[string]config.UpstreamConfig{
			"gemini": {
				Target: upstream.URL + "?key=" + targetKey, OutboundProxy: "direct",
				IdentityResolution: &config.IdentityResolutionConfig{Provider: config.IdentityProviderSub2API, AdminAPIKey: "admin", SyncIntervalSeconds: 300},
			},
		},
	}
	repo := newProxyTestRepo()
	handler := New(cfg, repo, nil, nil)
	req := httptest.NewRequest(http.MethodGet, "http://gemini.localhost/v1beta/models/gemini-pro:generateContent", nil)
	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("proxy status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	repo.mu.Lock()
	if len(repo.logs) == 0 {
		repo.mu.Unlock()
		t.Fatal("proxy saved no logs")
	}
	entry := repo.logs[len(repo.logs)-1].Clone()
	repo.mu.Unlock()

	if got, want := entry.APIKeyFingerprint, upstreamidentity.Fingerprint(secret, targetKey); got != want {
		t.Fatalf("final fingerprint = %q, want %q", got, want)
	}
	if strings.Contains(entry.TargetURL, targetKey) || !strings.Contains(entry.TargetURL, "key=%2A%2A%2A") {
		t.Fatalf("logged target URL did not redact key: %q", entry.TargetURL)
	}
}

func TestProxyDoesNotFingerprintWhenIdentityAuditIsDisabled(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	cfg := &config.Config{
		Server: config.ServerConfig{ProxyDomains: []string{"localhost"}},
		IdentityResolution: config.IdentityResolutionGlobalConfig{
			FingerprintSecret: base64.RawURLEncoding.EncodeToString([]byte("01234567890123456789012345678901")),
		},
		Upstreams: map[string]config.UpstreamConfig{
			"audit": {Target: upstream.URL, OutboundProxy: "direct", IdentityResolution: &config.IdentityResolutionConfig{Provider: config.IdentityProviderSub2API}},
		},
	}
	cfg.SetIdentityAuditEnabled(false)
	repo := newProxyTestRepo()
	handler := New(cfg, repo, nil, nil)
	req := httptest.NewRequest(http.MethodGet, "http://audit.localhost/v1/chat/completions", nil)
	req.Header.Set("Authorization", "Bearer client-secret")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("proxy status = %d", recorder.Code)
	}
	repo.mu.Lock()
	entry := repo.logs[len(repo.logs)-1].Clone()
	repo.mu.Unlock()
	if entry.APIKeyFingerprint != "" || entry.IdentityResolutionReady {
		t.Fatalf("disabled audit captured identity state: %#v", entry)
	}
}
