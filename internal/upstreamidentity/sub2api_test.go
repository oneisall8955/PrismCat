package upstreamidentity

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/paopaoandlingyia/PrismCat/internal/config"
	"github.com/paopaoandlingyia/PrismCat/internal/outbound"
	"github.com/paopaoandlingyia/PrismCat/internal/storage"
)

func TestExtractSub2APIKeyPriority(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		headers http.Header
		query   url.Values
		want    string
	}{
		{name: "normal bearer", path: "/v1/chat/completions", headers: http.Header{"Authorization": {"Bearer bearer-key"}, "X-Api-Key": {"anthropic-key"}, "X-Goog-Api-Key": {"google-key"}}, want: "bearer-key"},
		{name: "normal x api key", path: "/v1/messages", headers: http.Header{"X-Api-Key": {"anthropic-key"}}, want: "anthropic-key"},
		{name: "normal google fallback", path: "/models", headers: http.Header{"X-Goog-Api-Key": {"google-key"}}, want: "google-key"},
		{name: "gemini google first", path: "/v1beta/models/gemini:generateContent", headers: http.Header{"Authorization": {"Bearer bearer-key"}, "X-Goog-Api-Key": {"google-key"}}, want: "google-key"},
		{name: "gemini query", path: "/v1beta/models/gemini:generateContent", query: url.Values{"key": {"query-key"}}, want: "query-key"},
		{name: "query not allowed elsewhere", path: "/v1/chat/completions", query: url.Values{"key": {"query-key"}}, want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ExtractSub2APIKey(tt.path, tt.headers, tt.query); got != tt.want {
				t.Fatalf("ExtractSub2APIKey() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestSub2APIProviderSyncPaginatesAuthenticatesAndBoundsConcurrency(t *testing.T) {
	const adminKey = "admin-secret"
	var active atomic.Int32
	var maxActive atomic.Int32
	var badAuth atomic.Bool
	var userPages atomic.Int32
	var keyRequests atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("x-api-key") != adminKey {
			badAuth.Store(true)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/api/v1/admin/users" {
			userPages.Add(1)
			page, _ := strconv.Atoi(r.URL.Query().Get("page"))
			start := 1
			if page == 2 {
				start = 4
			}
			users := make([]sub2APIUser, 0, 3)
			for id := start; id < start+3; id++ {
				users = append(users, sub2APIUser{ID: int64(id), Username: "user-" + strconv.Itoa(id), Email: "user@example.com"})
			}
			_ = json.NewEncoder(w).Encode(sub2APIEnvelope[sub2APIPage[sub2APIUser]]{Data: sub2APIPage[sub2APIUser]{Items: users, Page: page, PageSize: 3, Pages: 2, Total: 6}})
			return
		}
		if strings.HasPrefix(r.URL.Path, "/api/v1/admin/users/") && strings.HasSuffix(r.URL.Path, "/api-keys") {
			keyRequests.Add(1)
			current := active.Add(1)
			for {
				observed := maxActive.Load()
				if current <= observed || maxActive.CompareAndSwap(observed, current) {
					break
				}
			}
			defer active.Add(-1)
			time.Sleep(20 * time.Millisecond)
			parts := strings.Split(r.URL.Path, "/")
			userID, _ := strconv.ParseInt(parts[len(parts)-2], 10, 64)
			_ = json.NewEncoder(w).Encode(sub2APIEnvelope[sub2APIPage[sub2APIKey]]{Data: sub2APIPage[sub2APIKey]{Items: []sub2APIKey{{ID: userID, UserID: userID, Key: "key-" + strconv.FormatInt(userID, 10)}}, Page: 1, PageSize: 1000, Pages: 1, Total: 1}})
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	clients := outbound.NewClientCache(10, 4)
	defer clients.CloseIdleConnections()
	provider := NewSub2APIProvider(clients)
	secret := []byte("01234567890123456789012345678901")
	result, err := provider.Sync(context.Background(), SourceConfig{
		AdminBaseURL: server.URL + "/api/v1", AdminAPIKey: adminKey, OutboundProxy: "direct",
	}, secret)
	if err != nil {
		t.Fatalf("Sync returned error: %v", err)
	}
	if badAuth.Load() || userPages.Load() != 2 || keyRequests.Load() != 6 {
		t.Fatalf("auth/pages/keys = %v/%d/%d", badAuth.Load(), userPages.Load(), keyRequests.Load())
	}
	if maxActive.Load() < 2 || maxActive.Load() > 4 {
		t.Fatalf("max key-request concurrency = %d, want 2..4", maxActive.Load())
	}
	if len(result.Identities) != 6 || result.KeyCount != 6 {
		t.Fatalf("sync counts identities=%d keys=%d", len(result.Identities), result.KeyCount)
	}
	if got := result.Fingerprints[Fingerprint(secret, "key-4")]; got != "4" {
		t.Fatalf("fingerprint key-4 maps to %q, want 4", got)
	}
}

func TestSub2APIProviderTestConnectionOnlyListsOneUserPage(t *testing.T) {
	const adminKey = "admin-secret"
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Header.Get("x-api-key") != adminKey {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if r.URL.Path != "/api/v1/admin/users" || r.URL.Query().Get("page_size") != "1" {
			http.Error(w, "unexpected test request", http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(sub2APIEnvelope[sub2APIPage[sub2APIUser]]{Data: sub2APIPage[sub2APIUser]{Total: 53, Page: 1, PageSize: 1, Pages: 53}})
	}))
	defer server.Close()

	clients := outbound.NewClientCache(2, 2)
	defer clients.CloseIdleConnections()
	provider := NewSub2APIProvider(clients)
	users, err := provider.TestConnection(context.Background(), SourceConfig{
		AdminBaseURL: server.URL + "/api/v1", AdminAPIKey: adminKey, OutboundProxy: "direct",
	})
	if err != nil || users != 53 || requests.Load() != 1 {
		t.Fatalf("TestConnection users=%d requests=%d err=%v", users, requests.Load(), err)
	}
}

type identityTestRepo struct {
	mu       sync.Mutex
	pending  []storage.PendingIdentityLog
	assigned map[string]string
	checked  map[string]string
}

func (r *identityTestRepo) identity(logID string) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.assigned[logID]
}

func (r *identityTestRepo) SetLogIdentityIfEmpty(logID, identityID string) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.assigned == nil {
		r.assigned = make(map[string]string)
	}
	if r.assigned[logID] != "" {
		return false, nil
	}
	r.assigned[logID] = identityID
	return true, nil
}

func (r *identityTestRepo) ListPendingIdentityLogs(upstream, target, directoryVersion string, afterMS int64, afterID string, limit int) ([]storage.PendingIdentityLog, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []storage.PendingIdentityLog
	for _, item := range r.pending {
		if item.Upstream == upstream && item.UpstreamTarget == target && r.assigned[item.ID] == "" &&
			(directoryVersion == "" || r.checked[item.ID] != directoryVersion) &&
			(item.CreatedAtMS > afterMS || item.CreatedAtMS == afterMS && item.ID > afterID) {
			out = append(out, item)
		}
	}
	return out, nil
}

func (r *identityTestRepo) MarkLogsIdentityResolutionVersion(logIDs []string, directoryVersion string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.checked == nil {
		r.checked = make(map[string]string)
	}
	for _, logID := range logIDs {
		if r.assigned[logID] == "" {
			r.checked[logID] = directoryVersion
		}
	}
	return nil
}

type sequenceProvider struct {
	mu     sync.Mutex
	calls  int
	result SyncResult
}

func (p *sequenceProvider) TestConnection(context.Context, SourceConfig) (int64, error) {
	return int64(len(p.result.Identities)), nil
}

func (p *sequenceProvider) Sync(context.Context, SourceConfig, []byte) (SyncResult, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls++
	if p.calls > 1 {
		return SyncResult{}, errors.New("temporary upstream failure")
	}
	return p.result, nil
}

type changingProvider struct {
	mu      sync.Mutex
	calls   int
	results []SyncResult
}

func (p *changingProvider) TestConnection(context.Context, SourceConfig) (int64, error) {
	return 0, nil
}

func (p *changingProvider) Sync(context.Context, SourceConfig, []byte) (SyncResult, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	result := p.results[len(p.results)-1]
	if p.calls < len(p.results) {
		result = p.results[p.calls]
	}
	p.calls++
	return result, nil
}

func (p *changingProvider) callCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.calls
}

func identityManagerTestConfig(secret []byte) *config.Config {
	return &config.Config{
		IdentityResolution: config.IdentityResolutionGlobalConfig{FingerprintSecret: base64.RawURLEncoding.EncodeToString(secret)},
		Upstreams: map[string]config.UpstreamConfig{
			"audit": {
				Target: "https://sub2api.example.com", OutboundProxy: "direct",
				IdentityResolution: &config.IdentityResolutionConfig{
					Provider: config.IdentityProviderSub2API, AdminAPIKey: "admin", SyncIntervalSeconds: 300,
				},
			},
		},
	}
}

func TestAfterSaveSkipsEmptyCredentialsAndCoalescesUnknownRefresh(t *testing.T) {
	secret := []byte("01234567890123456789012345678901")
	manager := New(identityManagerTestConfig(secret), &identityTestRepo{})
	defer manager.Close()
	if err := manager.ReconcileConfig(); err != nil {
		t.Fatalf("ReconcileConfig returned error: %v", err)
	}

	for i := 0; i < 10000; i++ {
		manager.AfterSave(&storage.RequestLog{
			ID: "empty-" + strconv.Itoa(i), Upstream: "audit", IdentityResolutionReady: true,
		})
	}
	if got := len(manager.queue); got != 0 {
		t.Fatalf("empty credentials queued %d resolution items, want 0", got)
	}

	for i := 0; i < 10000; i++ {
		manager.AfterSave(&storage.RequestLog{
			ID: "invalid-" + strconv.Itoa(i), Upstream: "audit", IdentityResolutionReady: true,
			APIKeyFingerprint: Fingerprint(secret, "invalid-key-"+strconv.Itoa(i)),
		})
	}
	if got := len(manager.queue); got != 1 {
		t.Fatalf("unknown credentials queued %d refresh items, want 1", got)
	}
	state := manager.source(SourceKey{Upstream: "audit"})
	state.mu.RLock()
	pending := state.unknownRefreshPending
	state.mu.RUnlock()
	if !pending {
		t.Fatal("unknown refresh was not marked pending")
	}
}

func TestIdentityAuditSwitchClearsSourcesAndStopsQueueing(t *testing.T) {
	secret := []byte("01234567890123456789012345678901")
	cfg := identityManagerTestConfig(secret)
	manager := New(cfg, &identityTestRepo{})
	defer manager.Close()
	if err := manager.ReconcileConfig(); err != nil {
		t.Fatalf("ReconcileConfig returned error: %v", err)
	}
	if got := len(manager.sourceKeys()); got != 1 {
		t.Fatalf("configured sources=%d, want 1", got)
	}

	cfg.SetIdentityAuditEnabled(false)
	if err := manager.ReloadConfig(); err != nil {
		t.Fatalf("ReloadConfig returned error: %v", err)
	}
	if got := len(manager.sourceKeys()); got != 0 {
		t.Fatalf("sources after disabling audit=%d, want 0", got)
	}

	manager.AfterSave(&storage.RequestLog{
		ID: "disabled", Upstream: "audit", IdentityResolutionReady: true,
		APIKeyFingerprint: Fingerprint(secret, "user-key"),
	})
	if got := len(manager.queue); got != 0 {
		t.Fatalf("disabled audit queued %d resolution items, want 0", got)
	}
}

func TestFreshDirectoryNegativeCachesHighFrequencyUnknownCredentials(t *testing.T) {
	secret := []byte("01234567890123456789012345678901")
	provider := &changingProvider{results: []SyncResult{{Fingerprints: map[string]string{}, Identities: map[string]Identity{}}}}
	manager := New(identityManagerTestConfig(secret), &identityTestRepo{})
	manager.providers[config.IdentityProviderSub2API] = provider
	defer manager.Close()
	if _, err := manager.SyncNow(context.Background(), SourceKey{Upstream: "audit"}); err != nil {
		t.Fatalf("SyncNow returned error: %v", err)
	}

	for i := 0; i < 20000; i++ {
		manager.AfterSave(&storage.RequestLog{
			ID: "invalid-" + strconv.Itoa(i), Upstream: "audit", IdentityResolutionReady: true,
			APIKeyFingerprint: Fingerprint(secret, "random-invalid-key-"+strconv.Itoa(i)),
		})
	}
	if got := len(manager.queue); got != 0 {
		t.Fatalf("fresh directory queued %d unknown refresh items, want 0", got)
	}
	if got := provider.callCount(); got != 1 {
		t.Fatalf("provider sync calls = %d, want 1", got)
	}
	state := manager.source(SourceKey{Upstream: "audit"})
	state.mu.RLock()
	negativeCount := len(state.negativeFingerprints)
	state.mu.RUnlock()
	if negativeCount != maxNegativeFingerprintsPerSource {
		t.Fatalf("negative cache size = %d, want bounded size %d", negativeCount, maxNegativeFingerprintsPerSource)
	}
}

func TestSuccessfulSyncClearsNegativeCacheAndRecognizesNewKey(t *testing.T) {
	secret := []byte("01234567890123456789012345678901")
	fingerprint := Fingerprint(secret, "new-user-key")
	provider := &changingProvider{results: []SyncResult{
		{Fingerprints: map[string]string{}, Identities: map[string]Identity{}},
		{Fingerprints: map[string]string{fingerprint: "42"}, Identities: map[string]Identity{"42": {ID: "42", Label: "alice"}}, KeyCount: 1},
	}}
	manager := New(identityManagerTestConfig(secret), &identityTestRepo{})
	manager.providers[config.IdentityProviderSub2API] = provider
	defer manager.Close()
	key := SourceKey{Upstream: "audit"}
	if _, err := manager.SyncNow(context.Background(), key); err != nil {
		t.Fatalf("first SyncNow returned error: %v", err)
	}
	entry := &storage.RequestLog{ID: "new-key-log", Upstream: "audit", IdentityResolutionReady: true, APIKeyFingerprint: fingerprint}
	manager.AfterSave(entry)
	state := manager.source(key)
	state.mu.RLock()
	_, negative := state.negativeFingerprints[fingerprint]
	state.mu.RUnlock()
	if !negative || len(manager.queue) != 0 {
		t.Fatalf("unknown key negative=%v queue=%d, want true/0", negative, len(manager.queue))
	}

	if _, err := manager.SyncNow(context.Background(), key); err != nil {
		t.Fatalf("second SyncNow returned error: %v", err)
	}
	manager.AfterSave(entry)
	state.mu.RLock()
	negativeCount := len(state.negativeFingerprints)
	state.mu.RUnlock()
	if negativeCount != 0 || len(manager.queue) != 1 {
		t.Fatalf("after refresh negative cache=%d queue=%d, want 0/1", negativeCount, len(manager.queue))
	}
}

func TestListIdentitiesScopesSearchesSortsAndPaginates(t *testing.T) {
	manager := New(&config.Config{}, &identityTestRepo{})
	defer manager.Close()
	manager.sources = map[SourceKey]*sourceState{
		{Upstream: "audit", Target: "backup"}: {
			cfg: SourceConfig{Key: SourceKey{Upstream: "audit", Target: "backup"}, Provider: config.IdentityProviderSub2API},
			identities: map[string]Identity{
				"same-1": {ID: "same-1", Username: "carol", Email: "carol@example.com", Label: "carol"},
				"3":      {ID: "3", Username: "aaron", Email: "aaron@example.com", Label: "aaron"},
			},
		},
		{Upstream: "audit", Target: "primary"}: {
			cfg: SourceConfig{Key: SourceKey{Upstream: "audit", Target: "primary"}, Provider: config.IdentityProviderSub2API},
			identities: map[string]Identity{
				"same-1": {ID: "same-1", Username: "alice", Email: "alice@example.com", Label: "alice"},
				"2":      {ID: "2", Username: "bob", Email: "bob@example.com", Label: "bob"},
			},
		},
	}

	items, total, sources := manager.ListIdentities("audit", "", "", 1, 2)
	if total != 4 || len(items) != 2 || len(sources) != 2 {
		t.Fatalf("page items=%#v total=%d sources=%#v", items, total, sources)
	}
	if items[0]["username"] != "carol" || items[1]["username"] != "alice" {
		t.Fatalf("stable page order=%#v", items)
	}

	items, total, _ = manager.ListIdentities("audit", "", "same-1", 0, 10)
	if total != 2 || len(items) != 2 || items[0]["target"] == items[1]["target"] {
		t.Fatalf("duplicate IDs across targets items=%#v total=%d", items, total)
	}
	items, total, _ = manager.ListIdentities("audit", "primary", "BOB@EXAMPLE", 0, 10)
	if total != 1 || len(items) != 1 || items[0]["id"] != "2" {
		t.Fatalf("target/search items=%#v total=%d", items, total)
	}

	primary := manager.sources[SourceKey{Upstream: "audit", Target: "primary"}]
	for i := 0; i < 105; i++ {
		id := fmt.Sprintf("bulk-%03d", i)
		primary.identities[id] = Identity{ID: id, Username: id, Label: id}
	}
	items, total, _ = manager.ListIdentities("audit", "primary", "bulk-", 0, 500)
	if total != 105 || len(items) != 100 {
		t.Fatalf("capped page length=%d total=%d", len(items), total)
	}
}

func TestPendingUnmatchedLogsAreScannedOncePerDirectoryVersion(t *testing.T) {
	secret := []byte("01234567890123456789012345678901")
	repo := &identityTestRepo{pending: []storage.PendingIdentityLog{{
		ID: "invalid-log", Upstream: "audit", Fingerprint: Fingerprint(secret, "invalid-key"), CreatedAtMS: 1,
	}}}
	manager := New(identityManagerTestConfig(secret), repo)
	defer manager.Close()
	if err := manager.ReconcileConfig(); err != nil {
		t.Fatalf("ReconcileConfig returned error: %v", err)
	}
	key := SourceKey{Upstream: "audit"}
	firstDirectory := map[string]string{}
	version := fingerprintDirectoryVersion(firstDirectory)
	if scanned, resolved, unmatched, err := manager.retryPending(key, version, firstDirectory); err != nil || scanned != 1 || resolved != 0 || unmatched != 1 {
		t.Fatalf("first retry scanned/resolved/unmatched=%d/%d/%d err=%v", scanned, resolved, unmatched, err)
	}
	if scanned, resolved, unmatched, err := manager.retryPending(key, version, firstDirectory); err != nil || scanned != 0 || resolved != 0 || unmatched != 0 {
		t.Fatalf("same-version retry scanned/resolved/unmatched=%d/%d/%d err=%v", scanned, resolved, unmatched, err)
	}
	changedDirectory := map[string]string{Fingerprint(secret, "another-key"): "9"}
	if scanned, resolved, unmatched, err := manager.retryPending(key, fingerprintDirectoryVersion(changedDirectory), changedDirectory); err != nil || scanned != 1 || resolved != 0 || unmatched != 1 {
		t.Fatalf("changed-version retry scanned/resolved/unmatched=%d/%d/%d err=%v", scanned, resolved, unmatched, err)
	}
}

func TestManagerRetriesPendingAndRetainsCacheAfterFailure(t *testing.T) {
	secret := []byte("01234567890123456789012345678901")
	fingerprint := Fingerprint(secret, "user-key")
	cfg := &config.Config{
		IdentityResolution: config.IdentityResolutionGlobalConfig{FingerprintSecret: base64.RawURLEncoding.EncodeToString(secret)},
		Upstreams: map[string]config.UpstreamConfig{
			"audit": {Target: "https://sub2api.example.com", OutboundProxy: "direct", IdentityResolution: &config.IdentityResolutionConfig{Provider: config.IdentityProviderSub2API, AdminAPIKey: "admin", SyncIntervalSeconds: 300}},
		},
	}
	repo := &identityTestRepo{pending: []storage.PendingIdentityLog{{ID: "pending-log", Upstream: "audit", Fingerprint: fingerprint, CreatedAtMS: 1}}}
	provider := &sequenceProvider{result: SyncResult{
		Fingerprints: map[string]string{fingerprint: "42"},
		Identities:   map[string]Identity{"42": {ID: "42", Username: "alice", Label: "alice"}},
		KeyCount:     1,
	}}
	manager := New(cfg, repo)
	manager.providers[config.IdentityProviderSub2API] = provider
	if err := manager.Start(); err != nil {
		t.Fatalf("Start returned error: %v", err)
	}
	defer manager.Close()

	waitForIdentityTestCondition(t, func() bool { return repo.identity("pending-log") == "42" })
	if got := repo.identity("pending-log"); got != "42" {
		t.Fatalf("pending log assigned identity %q, want 42", got)
	}
	if label := manager.Label("audit", "", "42"); label != "alice" {
		t.Fatalf("label after successful sync = %q", label)
	}

	status, err := manager.SyncNow(context.Background(), SourceKey{Upstream: "audit"})
	if err == nil || !strings.Contains(status.LastError, "temporary upstream failure") {
		t.Fatalf("second sync status=%#v err=%v", status, err)
	}
	if label := manager.Label("audit", "", "42"); label != "alice" {
		t.Fatalf("failed sync replaced cache, label = %q", label)
	}
}

type blockingIdentityRepo struct {
	identityTestRepo
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func (r *blockingIdentityRepo) ListPendingIdentityLogs(upstream, target, directoryVersion string, afterMS int64, afterID string, limit int) ([]storage.PendingIdentityLog, error) {
	r.once.Do(func() { close(r.started) })
	<-r.release
	return r.identityTestRepo.ListPendingIdentityLogs(upstream, target, directoryVersion, afterMS, afterID, limit)
}

func TestSyncReturnsBeforePendingLogResolutionCompletes(t *testing.T) {
	secret := []byte("01234567890123456789012345678901")
	fingerprint := Fingerprint(secret, "user-key")
	cfg := &config.Config{
		IdentityResolution: config.IdentityResolutionGlobalConfig{FingerprintSecret: base64.RawURLEncoding.EncodeToString(secret)},
		Upstreams: map[string]config.UpstreamConfig{
			"audit": {Target: "https://sub2api.example.com", OutboundProxy: "direct", IdentityResolution: &config.IdentityResolutionConfig{Provider: config.IdentityProviderSub2API, AdminAPIKey: "admin", SyncIntervalSeconds: 300}},
		},
	}
	repo := &blockingIdentityRepo{
		identityTestRepo: identityTestRepo{pending: []storage.PendingIdentityLog{{ID: "pending-log", Upstream: "audit", Fingerprint: fingerprint, CreatedAtMS: 1}}},
		started:          make(chan struct{}),
		release:          make(chan struct{}),
	}
	provider := &sequenceProvider{result: SyncResult{
		Fingerprints: map[string]string{fingerprint: "42"},
		Identities:   map[string]Identity{"42": {ID: "42", Label: "alice"}},
		KeyCount:     1,
	}}
	manager := New(cfg, repo)
	manager.providers[config.IdentityProviderSub2API] = provider
	manager.wg.Add(1)
	go manager.backfillLoop()
	defer manager.Close()
	released := false
	defer func() {
		if !released {
			close(repo.release)
		}
	}()

	started := time.Now()
	status, err := manager.SyncNow(context.Background(), SourceKey{Upstream: "audit"})
	if err != nil {
		t.Fatalf("SyncNow returned error: %v", err)
	}
	if elapsed := time.Since(started); elapsed > 250*time.Millisecond {
		t.Fatalf("SyncNow waited for pending resolution: %s", elapsed)
	}
	if !status.ResolutionQueued {
		t.Fatalf("sync status did not report queued resolution: %#v", status)
	}
	select {
	case <-repo.started:
	case <-time.After(time.Second):
		t.Fatal("pending resolution did not start")
	}
	second, err := manager.EnqueuePendingResolution(SourceKey{Upstream: "audit"})
	if err != nil || !second.ResolvingLogs {
		t.Fatalf("duplicate enqueue status=%#v err=%v", second, err)
	}
	close(repo.release)
	released = true
	waitForIdentityTestCondition(t, func() bool { return repo.identity("pending-log") == "42" })
	_, _, statuses := manager.ListIdentities("audit", "", "", 0, 10)
	if len(statuses) != 1 || statuses[0].ResolvedLogs != 1 || statuses[0].PendingLogsScanned != 1 || statuses[0].ResolvingLogs {
		t.Fatalf("completed resolution status = %#v", statuses)
	}
}

func TestSub2APIEndToEndAssociatesPersistedLog(t *testing.T) {
	const userKey = "persisted-user-key"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/admin/users":
			_ = json.NewEncoder(w).Encode(sub2APIEnvelope[sub2APIPage[sub2APIUser]]{Data: sub2APIPage[sub2APIUser]{Items: []sub2APIUser{{ID: 77, Username: "auditor"}}, Page: 1, Pages: 1, Total: 1}})
		case "/api/v1/admin/users/77/api-keys":
			_ = json.NewEncoder(w).Encode(sub2APIEnvelope[sub2APIPage[sub2APIKey]]{Data: sub2APIPage[sub2APIKey]{Items: []sub2APIKey{{ID: 1, UserID: 77, Key: userKey}}, Page: 1, Pages: 1, Total: 1}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	secret := []byte("01234567890123456789012345678901")
	repo, err := storage.NewSQLiteRepository(filepath.Join(t.TempDir(), "identity.db"))
	if err != nil {
		t.Fatalf("open sqlite repository: %v", err)
	}
	defer repo.Close()
	if err := repo.SaveLog(&storage.RequestLog{
		ID: "request-1", CreatedAt: time.Now().UTC(), Upstream: "audit", UpstreamTarget: "primary", Method: "POST", Path: "/v1/chat/completions",
		APIKeyFingerprint: Fingerprint(secret, userKey),
	}); err != nil {
		t.Fatalf("save pending log: %v", err)
	}
	cfg := &config.Config{
		IdentityResolution: config.IdentityResolutionGlobalConfig{FingerprintSecret: base64.RawURLEncoding.EncodeToString(secret)},
		Upstreams: map[string]config.UpstreamConfig{
			"audit": {
				ActiveTarget: "primary",
				Targets: map[string]config.UpstreamTargetConfig{
					"primary": {URL: server.URL, OutboundProxy: "direct", IdentityResolution: &config.IdentityResolutionConfig{Provider: config.IdentityProviderSub2API, AdminBaseURL: server.URL + "/api/v1", AdminAPIKey: "admin", SyncIntervalSeconds: 300}},
				},
			},
		},
	}
	manager := New(cfg, repo)
	if err := manager.Start(); err != nil {
		t.Fatalf("start identity manager: %v", err)
	}
	defer manager.Close()
	waitForIdentityTestCondition(t, func() bool {
		entry, getErr := repo.GetLog("request-1")
		return getErr == nil && entry.UpstreamIdentityID == "77"
	})

	entry, err := repo.GetLog("request-1")
	if err != nil || entry.UpstreamIdentityID != "77" {
		t.Fatalf("associated log identity = %q, err = %v", entry.UpstreamIdentityID, err)
	}
	filter := storage.LogFilter{IdentityID: "77", IdentityUpstream: "audit", IdentityTarget: "primary", Limit: 10}
	logs, total, err := repo.ListLogs(filter)
	if err != nil || total != 1 || len(logs) != 1 || logs[0].ID != "request-1" {
		t.Fatalf("identity-filtered logs=%#v total=%d err=%v", logs, total, err)
	}
	var exported []*storage.RequestLog
	if err := repo.ExportLogs(context.Background(), filter, func(entry *storage.RequestLog) error {
		exported = append(exported, entry)
		return nil
	}); err != nil || len(exported) != 1 {
		t.Fatalf("identity export logs=%#v err=%v", exported, err)
	}
	exportJSON, err := json.Marshal(exported[0])
	if err != nil || strings.Contains(string(exportJSON), "api_key_fingerprint") || strings.Contains(string(exportJSON), Fingerprint(secret, userKey)) {
		t.Fatalf("identity export leaked fingerprint: %s, err=%v", exportJSON, err)
	}
}

func waitForIdentityTestCondition(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("timed out waiting for identity background work")
}
