package api

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/paopaoandlingyia/PrismCat/internal/config"
	"github.com/paopaoandlingyia/PrismCat/internal/upstreamidentity"
)

type identityResolutionAPI struct {
	Provider              string `json:"provider"`
	AdminBaseURL          string `json:"admin_base_url,omitempty"`
	AdminAPIKey           string `json:"admin_api_key,omitempty"`
	AdminAPIKeyConfigured bool   `json:"admin_api_key_configured,omitempty"`
	ClearAdminAPIKey      bool   `json:"clear_admin_api_key,omitempty"`
	SyncIntervalSeconds   int    `json:"sync_interval_seconds,omitempty"`
}

type upstreamTargetAPI struct {
	URL                          string                                 `json:"url"`
	Timeout                      int                                    `json:"timeout,omitempty"`
	ResponseHeaderTimeout        int                                    `json:"response_header_timeout,omitempty"`
	ResponseBodyFirstByteTimeout int                                    `json:"response_body_first_byte_timeout,omitempty"`
	ResponseBodyIdleTimeout      int                                    `json:"response_body_idle_timeout,omitempty"`
	OutboundProxy                string                                 `json:"outbound_proxy,omitempty"`
	RequestOverrides             *config.RequestOverrideUpstreamBinding `json:"request_overrides,omitempty"`
	UsageExtraction              *config.UsageExtractionUpstreamBinding `json:"usage_extraction,omitempty"`
	IdentityResolution           *identityResolutionAPI                 `json:"identity_resolution,omitempty"`
}

func identityForAPI(in *config.IdentityResolutionConfig) *identityResolutionAPI {
	if in == nil {
		return nil
	}
	return &identityResolutionAPI{
		Provider: in.Provider, AdminBaseURL: in.AdminBaseURL,
		AdminAPIKeyConfigured: strings.TrimSpace(in.AdminAPIKey) != "",
		SyncIntervalSeconds:   in.SyncIntervalSeconds,
	}
}

func identityFromAPI(in *identityResolutionAPI, current *config.IdentityResolutionConfig) *config.IdentityResolutionConfig {
	if in == nil {
		if current == nil {
			return nil
		}
		copy := *current
		return &copy
	}
	if strings.TrimSpace(in.Provider) == "" {
		return nil
	}
	adminKey := strings.TrimSpace(in.AdminAPIKey)
	if adminKey == "" && !in.ClearAdminAPIKey && current != nil {
		adminKey = current.AdminAPIKey
	}
	return &config.IdentityResolutionConfig{
		Provider: in.Provider, AdminBaseURL: in.AdminBaseURL, AdminAPIKey: adminKey,
		SyncIntervalSeconds: in.SyncIntervalSeconds,
	}
}

func targetsForAPI(in map[string]config.UpstreamTargetConfig) map[string]upstreamTargetAPI {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]upstreamTargetAPI, len(in))
	for name, target := range in {
		out[name] = upstreamTargetAPI{
			URL: target.URL, Timeout: target.Timeout, ResponseHeaderTimeout: target.ResponseHeaderTimeout,
			ResponseBodyFirstByteTimeout: target.ResponseBodyFirstByteTimeout, ResponseBodyIdleTimeout: target.ResponseBodyIdleTimeout,
			OutboundProxy: target.OutboundProxy, RequestOverrides: target.RequestOverrides,
			UsageExtraction: target.UsageExtraction, IdentityResolution: identityForAPI(target.IdentityResolution),
		}
	}
	return out
}

func targetsFromAPI(in map[string]upstreamTargetAPI, current map[string]config.UpstreamTargetConfig) map[string]config.UpstreamTargetConfig {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]config.UpstreamTargetConfig, len(in))
	for name, target := range in {
		var currentIdentity *config.IdentityResolutionConfig
		if existing, ok := current[strings.ToLower(strings.TrimSpace(name))]; ok {
			currentIdentity = existing.IdentityResolution
		}
		out[name] = config.UpstreamTargetConfig{
			URL: target.URL, Timeout: target.Timeout, ResponseHeaderTimeout: target.ResponseHeaderTimeout,
			ResponseBodyFirstByteTimeout: target.ResponseBodyFirstByteTimeout, ResponseBodyIdleTimeout: target.ResponseBodyIdleTimeout,
			OutboundProxy: target.OutboundProxy, RequestOverrides: target.RequestOverrides,
			UsageExtraction: target.UsageExtraction, IdentityResolution: identityFromAPI(target.IdentityResolution, currentIdentity),
		}
	}
	return out
}

func (h *Handler) handleUpstreamIdentities(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.jsonError(w, "方法不允许", http.StatusMethodNotAllowed)
		return
	}
	if !h.cfg.IdentityAuditEnabled() {
		h.jsonError(w, "上游身份审计未启用", http.StatusConflict)
		return
	}
	query := r.URL.Query()
	upstream := strings.TrimSpace(query.Get("upstream"))
	if upstream == "" {
		h.jsonError(w, "upstream 参数不能为空", http.StatusBadRequest)
		return
	}
	offset := parseIdentityListInteger(query.Get("offset"), 0)
	limit := parseIdentityListInteger(query.Get("limit"), 10)
	if offset < 0 {
		offset = 0
	}
	if limit <= 0 {
		limit = 10
	} else if limit > 100 {
		limit = 100
	}
	if h.identity == nil {
		h.jsonResponse(w, map[string]interface{}{"items": []interface{}{}, "sources": []interface{}{}, "total": 0, "offset": offset, "limit": limit})
		return
	}
	items, total, sources := h.identity.ListIdentities(upstream, query.Get("target"), query.Get("q"), offset, limit)
	h.jsonResponse(w, map[string]interface{}{"items": items, "sources": sources, "total": total, "offset": offset, "limit": limit})
}

func parseIdentityListInteger(raw string, fallback int) int {
	if strings.TrimSpace(raw) == "" {
		return fallback
	}
	value, err := strconv.Atoi(raw)
	if err != nil {
		return fallback
	}
	return value
}

func (h *Handler) handleUpstreamIdentitySync(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.jsonError(w, "方法不允许", http.StatusMethodNotAllowed)
		return
	}
	if !h.cfg.IdentityAuditEnabled() {
		h.jsonError(w, "上游身份审计未启用", http.StatusConflict)
		return
	}
	if h.identity == nil {
		h.jsonError(w, "上游身份关联未启用", http.StatusServiceUnavailable)
		return
	}
	request, ok := decodeIdentitySourceRequest(w, r)
	if !ok {
		h.jsonError(w, "无效的请求体", http.StatusBadRequest)
		return
	}
	status, err := h.identity.SyncNow(r.Context(), request)
	if err != nil {
		h.jsonError(w, err.Error(), http.StatusBadGateway)
		return
	}
	h.jsonResponse(w, status)
}

func (h *Handler) handleUpstreamIdentityTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.jsonError(w, "方法不允许", http.StatusMethodNotAllowed)
		return
	}
	if !h.cfg.IdentityAuditEnabled() {
		h.jsonError(w, "上游身份审计未启用", http.StatusConflict)
		return
	}
	if h.identity == nil {
		h.jsonError(w, "上游身份关联未启用", http.StatusServiceUnavailable)
		return
	}
	request, ok := decodeIdentitySourceRequest(w, r)
	if !ok {
		h.jsonError(w, "无效的请求体", http.StatusBadRequest)
		return
	}
	result, err := h.identity.TestConnection(r.Context(), request)
	if err != nil {
		h.jsonError(w, err.Error(), http.StatusBadGateway)
		return
	}
	h.jsonResponse(w, result)
}

func (h *Handler) handlePendingIdentityResolution(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.jsonError(w, "方法不允许", http.StatusMethodNotAllowed)
		return
	}
	if !h.cfg.IdentityAuditEnabled() {
		h.jsonError(w, "上游身份审计未启用", http.StatusConflict)
		return
	}
	if h.identity == nil {
		h.jsonError(w, "上游身份关联未启用", http.StatusServiceUnavailable)
		return
	}
	request, ok := decodeIdentitySourceRequest(w, r)
	if !ok {
		h.jsonError(w, "无效的请求体", http.StatusBadRequest)
		return
	}
	status, err := h.identity.EnqueuePendingResolution(request)
	if err != nil {
		h.jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(status)
}

func decodeIdentitySourceRequest(w http.ResponseWriter, r *http.Request) (upstreamidentity.SourceKey, bool) {
	var request struct {
		Upstream string `json:"upstream"`
		Target   string `json:"target"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil || strings.TrimSpace(request.Upstream) == "" {
		return upstreamidentity.SourceKey{}, false
	}
	return upstreamidentity.SourceKey{Upstream: request.Upstream, Target: request.Target}, true
}
