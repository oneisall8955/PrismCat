package upstreamidentity

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/paopaoandlingyia/PrismCat/internal/outbound"
)

const sub2APIMaxResponseBytes = 16 << 20

type Sub2APIProvider struct {
	clients *outbound.ClientCache
}

func NewSub2APIProvider(clients *outbound.ClientCache) *Sub2APIProvider {
	return &Sub2APIProvider{clients: clients}
}

type sub2APIEnvelope[T any] struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    T      `json:"data"`
}

type sub2APIPage[T any] struct {
	Items    []T   `json:"items"`
	Total    int64 `json:"total"`
	Page     int   `json:"page"`
	PageSize int   `json:"page_size"`
	Pages    int   `json:"pages"`
}

type sub2APIUser struct {
	ID       int64  `json:"id"`
	Username string `json:"username"`
	Email    string `json:"email"`
}

type sub2APIKey struct {
	ID     int64  `json:"id"`
	UserID int64  `json:"user_id"`
	Key    string `json:"key"`
}

func (p *Sub2APIProvider) TestConnection(ctx context.Context, source SourceConfig) (int64, error) {
	page, err := p.listUsersPage(ctx, source, 1, 1)
	if err != nil {
		return 0, err
	}
	return page.Total, nil
}

func (p *Sub2APIProvider) Sync(ctx context.Context, source SourceConfig, secret []byte) (SyncResult, error) {
	users, err := p.listUsers(ctx, source)
	if err != nil {
		return SyncResult{}, err
	}
	result := SyncResult{Fingerprints: make(map[string]string), Identities: make(map[string]Identity)}
	for _, user := range users {
		id := strconv.FormatInt(user.ID, 10)
		label := strings.TrimSpace(user.Username)
		if label == "" {
			label = strings.TrimSpace(user.Email)
		}
		if label == "" {
			label = id
		}
		result.Identities[id] = Identity{ID: id, Username: user.Username, Email: user.Email, Label: label}
	}

	type userKeys struct {
		userID int64
		keys   []sub2APIKey
		err    error
	}
	jobs := make(chan sub2APIUser)
	results := make(chan userKeys, len(users))
	var wg sync.WaitGroup
	workers := 4
	if len(users) < workers {
		workers = len(users)
	}
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for user := range jobs {
				keys, keyErr := p.listUserKeys(ctx, source, user.ID)
				results <- userKeys{userID: user.ID, keys: keys, err: keyErr}
			}
		}()
	}
	go func() {
		defer close(results)
		for _, user := range users {
			select {
			case jobs <- user:
			case <-ctx.Done():
				close(jobs)
				wg.Wait()
				return
			}
		}
		close(jobs)
		wg.Wait()
	}()
	for batch := range results {
		if batch.err != nil {
			return SyncResult{}, fmt.Errorf("list API keys for user %d: %w", batch.userID, batch.err)
		}
		for _, key := range batch.keys {
			fingerprint := Fingerprint(secret, key.Key)
			if fingerprint == "" {
				continue
			}
			userID := key.UserID
			if userID == 0 {
				userID = batch.userID
			}
			result.Fingerprints[fingerprint] = strconv.FormatInt(userID, 10)
			result.KeyCount++
		}
	}
	return result, nil
}

func (p *Sub2APIProvider) listUsers(ctx context.Context, source SourceConfig) ([]sub2APIUser, error) {
	var all []sub2APIUser
	for page := 1; ; page++ {
		result, err := p.listUsersPage(ctx, source, page, 1000)
		if err != nil {
			return nil, err
		}
		all = append(all, result.Items...)
		if page >= result.Pages || len(result.Items) == 0 {
			return all, nil
		}
	}
}

func (p *Sub2APIProvider) listUsersPage(ctx context.Context, source SourceConfig, page, pageSize int) (sub2APIPage[sub2APIUser], error) {
	var envelope sub2APIEnvelope[sub2APIPage[sub2APIUser]]
	path := "/admin/users?page=" + strconv.Itoa(page) + "&page_size=" + strconv.Itoa(pageSize) + "&include_subscriptions=false"
	if err := p.getJSON(ctx, source, path, &envelope); err != nil {
		return sub2APIPage[sub2APIUser]{}, err
	}
	if envelope.Code != 0 {
		return sub2APIPage[sub2APIUser]{}, fmt.Errorf("Sub2API users API returned code %d: %s", envelope.Code, envelope.Message)
	}
	return envelope.Data, nil
}

func (p *Sub2APIProvider) listUserKeys(ctx context.Context, source SourceConfig, userID int64) ([]sub2APIKey, error) {
	var all []sub2APIKey
	for page := 1; ; page++ {
		var envelope sub2APIEnvelope[sub2APIPage[sub2APIKey]]
		path := "/admin/users/" + strconv.FormatInt(userID, 10) + "/api-keys?page=" + strconv.Itoa(page) + "&page_size=1000"
		if err := p.getJSON(ctx, source, path, &envelope); err != nil {
			return nil, err
		}
		if envelope.Code != 0 {
			return nil, fmt.Errorf("Sub2API API keys API returned code %d: %s", envelope.Code, envelope.Message)
		}
		all = append(all, envelope.Data.Items...)
		if page >= envelope.Data.Pages || len(envelope.Data.Items) == 0 {
			return all, nil
		}
	}
}

func (p *Sub2APIProvider) getJSON(ctx context.Context, source SourceConfig, path string, out any) error {
	base, err := url.Parse(strings.TrimRight(source.AdminBaseURL, "/"))
	if err != nil {
		return err
	}
	rel, err := url.Parse(path)
	if err != nil {
		return err
	}
	requestURL := base.ResolveReference(&url.URL{Path: strings.TrimRight(base.Path, "/") + rel.Path, RawQuery: rel.RawQuery})
	requestCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(requestCtx, http.MethodGet, requestURL.String(), nil)
	if err != nil {
		return err
	}
	req.Header.Set("x-api-key", source.AdminAPIKey)
	req.Header.Set("Accept", "application/json")
	client, err := p.clients.ClientWithResponseHeaderTimeout(source.OutboundProxy, 15*time.Second)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("Sub2API admin request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
		return fmt.Errorf("Sub2API admin request returned HTTP %d", resp.StatusCode)
	}
	limited := io.LimitReader(resp.Body, sub2APIMaxResponseBytes+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return err
	}
	if len(data) > sub2APIMaxResponseBytes {
		return fmt.Errorf("Sub2API admin response exceeds %d bytes", sub2APIMaxResponseBytes)
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("decode Sub2API admin response: %w", err)
	}
	return nil
}

// ExtractSub2APIKey follows Sub2API's authentication priority.
func ExtractSub2APIKey(path string, headers http.Header, query url.Values) string {
	if isGooglePath(path) {
		if value := strings.TrimSpace(headers.Get("x-goog-api-key")); value != "" {
			return value
		}
		if value := bearerKey(headers.Get("Authorization")); value != "" {
			return value
		}
		if value := strings.TrimSpace(headers.Get("x-api-key")); value != "" {
			return value
		}
		if strings.HasPrefix(path, "/v1beta") || strings.HasPrefix(path, "/antigravity/v1beta") {
			return strings.TrimSpace(query.Get("key"))
		}
		return ""
	}
	if value := bearerKey(headers.Get("Authorization")); value != "" {
		return value
	}
	if value := strings.TrimSpace(headers.Get("x-api-key")); value != "" {
		return value
	}
	return strings.TrimSpace(headers.Get("x-goog-api-key"))
}

func bearerKey(value string) string {
	parts := strings.SplitN(strings.TrimSpace(value), " ", 2)
	if len(parts) == 2 && strings.EqualFold(parts[0], "Bearer") {
		return strings.TrimSpace(parts[1])
	}
	return ""
}

func isGooglePath(path string) bool {
	return strings.HasPrefix(path, "/v1beta") || strings.HasPrefix(path, "/antigravity/") || strings.Contains(path, "generateContent")
}
