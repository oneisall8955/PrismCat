package upstreamidentity

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/paopaoandlingyia/PrismCat/internal/config"
	"github.com/paopaoandlingyia/PrismCat/internal/outbound"
	"github.com/paopaoandlingyia/PrismCat/internal/storage"
)

type SourceKey struct {
	Upstream string
	Target   string
}

type SourceConfig struct {
	Key           SourceKey
	Provider      string
	AdminBaseURL  string
	AdminAPIKey   string
	SyncInterval  time.Duration
	OutboundProxy string
}

type Identity struct {
	ID       string `json:"id"`
	Username string `json:"username,omitempty"`
	Email    string `json:"email,omitempty"`
	Label    string `json:"label"`
}

type SourceStatus struct {
	Upstream           string     `json:"upstream"`
	Target             string     `json:"target,omitempty"`
	Provider           string     `json:"provider"`
	LastSync           *time.Time `json:"last_sync_at,omitempty"`
	LastError          string     `json:"last_error,omitempty"`
	Users              int        `json:"identity_count"`
	Keys               int        `json:"key_count"`
	Syncing            bool       `json:"syncing"`
	ResolutionQueued   bool       `json:"resolution_queued"`
	ResolvingLogs      bool       `json:"resolving_logs"`
	LastResolution     *time.Time `json:"last_resolution_at,omitempty"`
	ResolutionError    string     `json:"resolution_error,omitempty"`
	PendingLogsScanned int        `json:"pending_logs_scanned"`
	ResolvedLogs       int        `json:"resolved_logs"`
	UnmatchedLogs      int        `json:"unmatched_logs"`
}

type ConnectionTestResult struct {
	Upstream string `json:"upstream"`
	Target   string `json:"target,omitempty"`
	Provider string `json:"provider"`
	Users    int64  `json:"identity_count"`
}

type SyncResult struct {
	Fingerprints map[string]string
	Identities   map[string]Identity
	KeyCount     int
}

type Provider interface {
	TestConnection(context.Context, SourceConfig) (int64, error)
	Sync(context.Context, SourceConfig, []byte) (SyncResult, error)
}

const maxNegativeFingerprintsPerSource = 8192

type sourceState struct {
	mu                    sync.RWMutex
	cfg                   SourceConfig
	fingerprints          map[string]string
	identities            map[string]Identity
	lastSync              time.Time
	lastAttempt           time.Time
	lastError             string
	keyCount              int
	directoryVersion      string
	syncing               bool
	done                  chan struct{}
	negativeFingerprints  map[string]struct{}
	unknownRefreshPending bool
	resolutionQueued      bool
	resolvingLogs         bool
	lastResolution        time.Time
	resolutionError       string
	pendingLogsScanned    int
	resolvedLogs          int
	unmatchedLogs         int
}

type pendingItem struct {
	logID          string
	source         SourceKey
	fingerprint    string
	refreshUnknown bool
}

type Manager struct {
	cfg       *config.Config
	repo      storage.IdentityRepository
	clients   *outbound.ClientCache
	providers map[string]Provider

	mu            sync.RWMutex
	sources       map[SourceKey]*sourceState
	queue         chan pendingItem
	backfillQueue chan SourceKey
	reload        chan struct{}
	stop          chan struct{}
	wg            sync.WaitGroup
}

func New(cfg *config.Config, repo storage.IdentityRepository) *Manager {
	clients := outbound.NewClientCache(20, 10)
	return &Manager{
		cfg:           cfg,
		repo:          repo,
		clients:       clients,
		providers:     map[string]Provider{config.IdentityProviderSub2API: NewSub2APIProvider(clients)},
		sources:       make(map[SourceKey]*sourceState),
		queue:         make(chan pendingItem, 2048),
		backfillQueue: make(chan SourceKey, 256),
		reload:        make(chan struct{}, 1),
		stop:          make(chan struct{}),
	}
}

func Fingerprint(secret []byte, credential string) string {
	credential = strings.TrimSpace(credential)
	if len(secret) == 0 || credential == "" {
		return ""
	}
	h := hmac.New(sha256.New, secret)
	_, _ = h.Write([]byte(credential))
	return hex.EncodeToString(h.Sum(nil))
}

func fingerprintDirectoryVersion(fingerprints map[string]string) string {
	keys := make([]string, 0, len(fingerprints))
	for fingerprint := range fingerprints {
		keys = append(keys, fingerprint)
	}
	sort.Strings(keys)
	h := sha256.New()
	for _, fingerprint := range keys {
		_, _ = h.Write([]byte(fingerprint))
		_, _ = h.Write([]byte{0})
		_, _ = h.Write([]byte(fingerprints[fingerprint]))
		_, _ = h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

func (m *Manager) Start() error {
	if m == nil || m.repo == nil {
		return nil
	}
	if err := m.ReconcileConfig(); err != nil {
		return err
	}
	m.wg.Add(3)
	go m.queueLoop()
	go m.backfillLoop()
	go m.syncLoop()
	return nil
}

func (m *Manager) Close() {
	if m == nil {
		return
	}
	select {
	case <-m.stop:
		return
	default:
		close(m.stop)
	}
	m.wg.Wait()
	m.clients.CloseIdleConnections()
}

func (m *Manager) ReconcileConfig() error {
	if m == nil {
		return nil
	}
	if !m.cfg.IdentityAuditEnabled() {
		m.mu.Lock()
		m.sources = make(map[SourceKey]*sourceState)
		m.mu.Unlock()
		return nil
	}
	if err := m.cfg.EnsureIdentityFingerprintSecretInitialized(); err != nil {
		return err
	}
	next := make(map[SourceKey]SourceConfig)
	for upstreamName, upstream := range m.cfg.ListUpstreams() {
		if len(upstream.Targets) == 0 {
			if source, ok := buildSourceConfig(upstreamName, "", upstream.Target, upstream.OutboundProxy, upstream.IdentityResolution); ok {
				next[source.Key] = source
			}
			continue
		}
		for targetName, target := range upstream.Targets {
			if source, ok := buildSourceConfig(upstreamName, targetName, target.URL, target.OutboundProxy, target.IdentityResolution); ok {
				next[source.Key] = source
			}
		}
	}

	m.mu.Lock()
	updated := make(map[SourceKey]*sourceState, len(next))
	for key, sourceCfg := range next {
		state := m.sources[key]
		if state == nil {
			state = &sourceState{
				fingerprints:         map[string]string{},
				identities:           map[string]Identity{},
				negativeFingerprints: map[string]struct{}{},
			}
		}
		state.mu.Lock()
		if state.syncing && sourceConnectionChanged(state.cfg, sourceCfg) {
			replacement := &sourceState{
				cfg: sourceCfg, fingerprints: state.fingerprints, identities: state.identities,
				lastSync: state.lastSync, lastError: state.lastError, keyCount: state.keyCount, directoryVersion: state.directoryVersion,
				negativeFingerprints: state.negativeFingerprints,
				lastResolution:       state.lastResolution, resolutionError: state.resolutionError,
				pendingLogsScanned: state.pendingLogsScanned, resolvedLogs: state.resolvedLogs, unmatchedLogs: state.unmatchedLogs,
			}
			state.mu.Unlock()
			state = replacement
		} else {
			state.cfg = sourceCfg
			state.mu.Unlock()
		}
		updated[key] = state
	}
	m.sources = updated
	m.mu.Unlock()
	return nil
}

// ReloadConfig applies configuration immediately and asks the background sync
// loop to refresh all newly enabled or changed sources without blocking the
// settings request on upstream network calls.
func (m *Manager) ReloadConfig() error {
	if err := m.ReconcileConfig(); err != nil {
		return err
	}
	select {
	case m.reload <- struct{}{}:
	default:
	}
	return nil
}

func sourceConnectionChanged(left, right SourceConfig) bool {
	return left.Provider != right.Provider || left.AdminBaseURL != right.AdminBaseURL ||
		left.AdminAPIKey != right.AdminAPIKey || left.OutboundProxy != right.OutboundProxy
}

func buildSourceConfig(upstream, target, targetURL, outboundProxy string, identity *config.IdentityResolutionConfig) (SourceConfig, bool) {
	if identity == nil || strings.TrimSpace(identity.Provider) == "" {
		return SourceConfig{}, false
	}
	baseURL := strings.TrimRight(strings.TrimSpace(identity.AdminBaseURL), "/")
	if baseURL == "" {
		parsed, err := url.Parse(targetURL)
		if err != nil || parsed.Scheme == "" || parsed.Host == "" {
			return SourceConfig{}, false
		}
		baseURL = parsed.Scheme + "://" + parsed.Host + "/api/v1"
	}
	interval := time.Duration(identity.SyncIntervalSeconds) * time.Second
	if interval <= 0 {
		interval = time.Duration(config.DefaultIdentitySyncIntervalSeconds) * time.Second
	}
	return SourceConfig{
		Key:      SourceKey{Upstream: strings.ToLower(strings.TrimSpace(upstream)), Target: strings.ToLower(strings.TrimSpace(target))},
		Provider: strings.ToLower(strings.TrimSpace(identity.Provider)), AdminBaseURL: baseURL,
		AdminAPIKey: identity.AdminAPIKey, SyncInterval: interval, OutboundProxy: outboundProxy,
	}, true
}

func (m *Manager) AfterSave(entry *storage.RequestLog) {
	if m == nil || entry == nil || !entry.IdentityResolutionReady || entry.APIKeyFingerprint == "" || entry.UpstreamIdentityID != "" {
		return
	}
	item := pendingItem{logID: entry.ID, source: SourceKey{Upstream: entry.Upstream, Target: entry.UpstreamTarget}, fingerprint: entry.APIKeyFingerprint}
	state := m.source(item.source)
	if state == nil {
		return
	}

	state.mu.Lock()
	_, known := state.fingerprints[item.fingerprint]
	if !known {
		if _, negative := state.negativeFingerprints[item.fingerprint]; negative {
			state.mu.Unlock()
			return
		}
		if !state.lastSync.IsZero() && time.Since(state.lastSync) < state.cfg.SyncInterval {
			addNegativeFingerprintLocked(state, item.fingerprint)
			state.mu.Unlock()
			return
		}
		if state.unknownRefreshPending || state.syncing ||
			(!state.lastAttempt.IsZero() && time.Since(state.lastAttempt) < state.cfg.SyncInterval) {
			state.mu.Unlock()
			return
		}
		state.unknownRefreshPending = true
		item.refreshUnknown = true
	}
	state.mu.Unlock()

	select {
	case m.queue <- item:
	default:
		// The persisted fingerprint is retried by the periodic pending scan.
		if item.refreshUnknown {
			m.clearUnknownRefreshPending(item.source)
		}
	}
}

func (m *Manager) queueLoop() {
	defer m.wg.Done()
	for {
		select {
		case item := <-m.queue:
			if m.resolve(item) {
				if item.refreshUnknown {
					m.clearUnknownRefreshPending(item.source)
				}
				continue
			}
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			_, syncErr := m.syncSource(ctx, item.source, false)
			cancel()
			resolved := m.resolve(item)
			if syncErr == nil && !resolved {
				m.markNegativeIfDirectoryFresh(item.source, item.fingerprint)
			}
			if item.refreshUnknown {
				m.clearUnknownRefreshPending(item.source)
			}
		case <-m.stop:
			return
		}
	}
}

func (m *Manager) resolve(item pendingItem) bool {
	state := m.source(item.source)
	if state == nil {
		return false
	}
	state.mu.RLock()
	identityID := state.fingerprints[item.fingerprint]
	state.mu.RUnlock()
	if identityID == "" {
		return false
	}
	_, _ = m.repo.SetLogIdentityIfEmpty(item.logID, identityID)
	return true
}

func addNegativeFingerprintLocked(state *sourceState, fingerprint string) {
	if fingerprint == "" || len(state.negativeFingerprints) >= maxNegativeFingerprintsPerSource {
		return
	}
	state.negativeFingerprints[fingerprint] = struct{}{}
}

func (m *Manager) markNegativeIfDirectoryFresh(key SourceKey, fingerprint string) {
	state := m.source(key)
	if state == nil {
		return
	}
	state.mu.Lock()
	if !state.lastSync.IsZero() && time.Since(state.lastSync) < state.cfg.SyncInterval {
		addNegativeFingerprintLocked(state, fingerprint)
	}
	state.mu.Unlock()
}

func (m *Manager) clearUnknownRefreshPending(key SourceKey) {
	state := m.source(key)
	if state == nil {
		return
	}
	state.mu.Lock()
	state.unknownRefreshPending = false
	state.mu.Unlock()
}

func (m *Manager) syncLoop() {
	defer m.wg.Done()
	m.syncDueSources(true)
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			_ = m.ReconcileConfig()
			m.syncDueSources(false)
		case <-m.reload:
			m.syncDueSources(true)
		case <-m.stop:
			return
		}
	}
}

func (m *Manager) syncDueSources(all bool) {
	for _, key := range m.sourceKeys() {
		state := m.source(key)
		if state == nil {
			continue
		}
		state.mu.RLock()
		due := all || state.lastAttempt.IsZero() || time.Since(state.lastAttempt) >= state.cfg.SyncInterval
		state.mu.RUnlock()
		if !due {
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		_, _ = m.syncSource(ctx, key, false)
		cancel()
	}
}

func (m *Manager) SyncNow(ctx context.Context, key SourceKey) (SourceStatus, error) {
	if err := m.ReconcileConfig(); err != nil {
		return SourceStatus{}, err
	}
	return m.syncSource(ctx, key, true)
}

func (m *Manager) TestConnection(ctx context.Context, key SourceKey) (ConnectionTestResult, error) {
	if err := m.ReconcileConfig(); err != nil {
		return ConnectionTestResult{}, err
	}
	state := m.source(key)
	if state == nil {
		return ConnectionTestResult{}, fmt.Errorf("identity source not configured")
	}
	state.mu.RLock()
	sourceCfg := state.cfg
	state.mu.RUnlock()
	if strings.TrimSpace(sourceCfg.AdminAPIKey) == "" {
		return ConnectionTestResult{}, fmt.Errorf("Sub2API admin API key is not configured")
	}
	provider := m.providers[sourceCfg.Provider]
	if provider == nil {
		return ConnectionTestResult{}, fmt.Errorf("identity provider %q is unavailable", sourceCfg.Provider)
	}
	users, err := provider.TestConnection(ctx, sourceCfg)
	if err != nil {
		return ConnectionTestResult{}, err
	}
	return ConnectionTestResult{Upstream: sourceCfg.Key.Upstream, Target: sourceCfg.Key.Target, Provider: sourceCfg.Provider, Users: users}, nil
}

func (m *Manager) syncSource(ctx context.Context, key SourceKey, force bool) (SourceStatus, error) {
	state := m.source(key)
	if state == nil {
		return SourceStatus{}, fmt.Errorf("identity source not configured")
	}
	state.mu.Lock()
	if state.syncing {
		done := state.done
		state.mu.Unlock()
		select {
		case <-done:
			status := statusFromState(state)
			if status.LastError != "" {
				return status, fmt.Errorf("%s", status.LastError)
			}
			return status, nil
		case <-ctx.Done():
			return SourceStatus{}, ctx.Err()
		}
	}
	if !force && !state.lastAttempt.IsZero() && time.Since(state.lastAttempt) < 30*time.Second {
		status := statusFromStateLocked(state)
		state.mu.Unlock()
		return status, nil
	}
	state.syncing = true
	state.done = make(chan struct{})
	state.lastAttempt = time.Now().UTC()
	sourceCfg := state.cfg
	done := state.done
	state.mu.Unlock()

	secret, secretErr := m.cfg.IdentityFingerprintSecret()
	provider := m.providers[sourceCfg.Provider]
	var result SyncResult
	err := secretErr
	if err == nil && strings.TrimSpace(sourceCfg.AdminAPIKey) == "" {
		err = fmt.Errorf("Sub2API admin API key is not configured")
	}
	if err == nil && provider == nil {
		err = fmt.Errorf("identity provider %q is unavailable", sourceCfg.Provider)
	}
	if err == nil {
		result, err = provider.Sync(ctx, sourceCfg, secret)
	}

	now := time.Now().UTC()
	state.mu.Lock()
	if err == nil {
		state.fingerprints = result.Fingerprints
		state.identities = result.Identities
		state.negativeFingerprints = make(map[string]struct{})
		state.keyCount = result.KeyCount
		state.directoryVersion = fingerprintDirectoryVersion(result.Fingerprints)
		state.lastSync = now
		state.lastError = ""
	} else {
		state.lastError = err.Error()
	}
	state.syncing = false
	close(done)
	status := statusFromStateLocked(state)
	state.mu.Unlock()
	if err == nil {
		if queuedStatus, queueErr := m.enqueuePendingResolution(key, true); queueErr == nil {
			status = queuedStatus
		}
	}
	return status, err
}

func (m *Manager) EnqueuePendingResolution(key SourceKey) (SourceStatus, error) {
	return m.enqueuePendingResolution(key, false)
}

func (m *Manager) enqueuePendingResolution(key SourceKey, rerunIfActive bool) (SourceStatus, error) {
	state := m.source(key)
	if state == nil {
		return SourceStatus{}, fmt.Errorf("identity source not configured")
	}
	state.mu.Lock()
	if state.lastSync.IsZero() || state.directoryVersion == "" {
		state.mu.Unlock()
		return SourceStatus{}, fmt.Errorf("identity directory has not been synchronized")
	}
	if state.resolutionQueued {
		status := statusFromStateLocked(state)
		state.mu.Unlock()
		return status, nil
	}
	if state.resolvingLogs {
		if rerunIfActive {
			state.resolutionQueued = true
		}
		status := statusFromStateLocked(state)
		state.mu.Unlock()
		return status, nil
	}
	key = state.cfg.Key
	state.resolutionQueued = true
	status := statusFromStateLocked(state)
	state.mu.Unlock()

	select {
	case m.backfillQueue <- key:
		return status, nil
	case <-m.stop:
		state.mu.Lock()
		state.resolutionQueued = false
		state.mu.Unlock()
		return SourceStatus{}, fmt.Errorf("identity manager is stopping")
	default:
		state.mu.Lock()
		state.resolutionQueued = false
		state.mu.Unlock()
		return SourceStatus{}, fmt.Errorf("identity resolution queue is full")
	}
}

func (m *Manager) backfillLoop() {
	defer m.wg.Done()
	for {
		select {
		case key := <-m.backfillQueue:
			m.runPendingResolution(key)
		case <-m.stop:
			return
		}
	}
}

func (m *Manager) runPendingResolution(key SourceKey) {
	state := m.source(key)
	if state == nil {
		return
	}
	state.mu.Lock()
	state.resolutionQueued = false
	state.resolvingLogs = true
	state.resolutionError = ""
	state.pendingLogsScanned = 0
	state.resolvedLogs = 0
	state.unmatchedLogs = 0
	directoryVersion := state.directoryVersion
	fingerprints := state.fingerprints
	state.mu.Unlock()

	scanned, resolved, unmatched, err := m.retryPending(key, directoryVersion, fingerprints)
	state.mu.Lock()
	state.resolvingLogs = false
	state.lastResolution = time.Now().UTC()
	state.pendingLogsScanned = scanned
	state.resolvedLogs = resolved
	state.unmatchedLogs = unmatched
	if err != nil {
		state.resolutionError = err.Error()
	}
	rerun := state.resolutionQueued
	state.mu.Unlock()
	if rerun {
		select {
		case m.backfillQueue <- key:
		case <-m.stop:
		}
	}
}

func (m *Manager) retryPending(key SourceKey, directoryVersion string, fingerprints map[string]string) (int, int, int, error) {
	var scanned int
	var resolved int
	var unmatched int
	var afterMS int64
	var afterID string
	for {
		select {
		case <-m.stop:
			return scanned, resolved, unmatched, context.Canceled
		default:
		}
		items, err := m.repo.ListPendingIdentityLogs(key.Upstream, key.Target, directoryVersion, afterMS, afterID, 500)
		if err != nil {
			return scanned, resolved, unmatched, err
		}
		if len(items) == 0 {
			return scanned, resolved, unmatched, nil
		}
		unmatchedIDs := make([]string, 0, len(items))
		for _, item := range items {
			scanned++
			state := m.source(key)
			if state == nil {
				return scanned, resolved, unmatched, fmt.Errorf("identity source was removed")
			}
			identityID := fingerprints[item.Fingerprint]
			if identityID == "" {
				state.mu.Lock()
				addNegativeFingerprintLocked(state, item.Fingerprint)
				state.mu.Unlock()
				unmatchedIDs = append(unmatchedIDs, item.ID)
				unmatched++
			} else if updated, updateErr := m.repo.SetLogIdentityIfEmpty(item.ID, identityID); updateErr != nil {
				return scanned, resolved, unmatched, updateErr
			} else if updated {
				resolved++
			}
			afterMS, afterID = item.CreatedAtMS, item.ID
		}
		if err := m.repo.MarkLogsIdentityResolutionVersion(unmatchedIDs, directoryVersion); err != nil {
			return scanned, resolved, unmatched, err
		}
		if len(items) < 500 {
			return scanned, resolved, unmatched, nil
		}
	}
}

func (m *Manager) Label(upstream, target, identityID string) string {
	state := m.source(SourceKey{Upstream: upstream, Target: target})
	if state == nil {
		return ""
	}
	state.mu.RLock()
	identity := state.identities[identityID]
	state.mu.RUnlock()
	return identity.Label
}

func (m *Manager) EnrichLogs(logs []*storage.RequestLog) {
	for _, entry := range logs {
		if entry != nil && entry.UpstreamIdentityID != "" {
			entry.UpstreamIdentityLabel = m.Label(entry.Upstream, entry.UpstreamTarget, entry.UpstreamIdentityID)
		}
	}
}

func (m *Manager) ListIdentities(upstream, target, query string, offset, limit int) ([]map[string]string, int, []SourceStatus) {
	upstream = strings.ToLower(strings.TrimSpace(upstream))
	target = strings.ToLower(strings.TrimSpace(target))
	query = strings.ToLower(strings.TrimSpace(query))
	if offset < 0 {
		offset = 0
	}
	if limit <= 0 {
		limit = 10
	} else if limit > 100 {
		limit = 100
	}
	var items []map[string]string
	var statuses []SourceStatus
	for _, key := range m.sourceKeys() {
		if upstream != "" && key.Upstream != upstream || target != "" && key.Target != target {
			continue
		}
		state := m.source(key)
		state.mu.RLock()
		statuses = append(statuses, statusFromStateLocked(state))
		for _, identity := range state.identities {
			haystack := strings.ToLower(identity.ID + " " + identity.Username + " " + identity.Email)
			if query != "" && !strings.Contains(haystack, query) {
				continue
			}
			items = append(items, map[string]string{
				"upstream": key.Upstream, "target": key.Target, "id": identity.ID,
				"username": identity.Username, "email": identity.Email, "label": identity.Label,
			})
		}
		state.mu.RUnlock()
	}
	sort.Slice(items, func(i, j int) bool {
		left := strings.ToLower(items[i]["upstream"] + "\x00" + items[i]["target"] + "\x00" + items[i]["username"] + "\x00" + items[i]["email"] + "\x00" + items[i]["id"])
		right := strings.ToLower(items[j]["upstream"] + "\x00" + items[j]["target"] + "\x00" + items[j]["username"] + "\x00" + items[j]["email"] + "\x00" + items[j]["id"])
		return left < right
	})
	total := len(items)
	if offset >= total {
		return []map[string]string{}, total, statuses
	}
	end := offset + limit
	if end > total {
		end = total
	}
	return items[offset:end], total, statuses
}

func (m *Manager) source(key SourceKey) *sourceState {
	key.Upstream = strings.ToLower(strings.TrimSpace(key.Upstream))
	key.Target = strings.ToLower(strings.TrimSpace(key.Target))
	m.mu.RLock()
	state := m.sources[key]
	m.mu.RUnlock()
	return state
}

func (m *Manager) sourceKeys() []SourceKey {
	m.mu.RLock()
	keys := make([]SourceKey, 0, len(m.sources))
	for key := range m.sources {
		keys = append(keys, key)
	}
	m.mu.RUnlock()
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].Upstream == keys[j].Upstream {
			return keys[i].Target < keys[j].Target
		}
		return keys[i].Upstream < keys[j].Upstream
	})
	return keys
}

func statusFromState(state *sourceState) SourceStatus {
	state.mu.RLock()
	defer state.mu.RUnlock()
	return statusFromStateLocked(state)
}

func statusFromStateLocked(state *sourceState) SourceStatus {
	status := SourceStatus{
		Upstream: state.cfg.Key.Upstream, Target: state.cfg.Key.Target, Provider: state.cfg.Provider,
		LastError: state.lastError, Users: len(state.identities), Keys: state.keyCount, Syncing: state.syncing,
		ResolutionQueued: state.resolutionQueued, ResolvingLogs: state.resolvingLogs,
		ResolutionError: state.resolutionError, PendingLogsScanned: state.pendingLogsScanned,
		ResolvedLogs: state.resolvedLogs, UnmatchedLogs: state.unmatchedLogs,
	}
	if !state.lastSync.IsZero() {
		last := state.lastSync
		status.LastSync = &last
	}
	if !state.lastResolution.IsZero() {
		last := state.lastResolution
		status.LastResolution = &last
	}
	return status
}
