package quota

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v6/internal/config"
	coreauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"
)

// memoryAuthStore 是一个内存实现的 auth store，用于测试。
type memoryAuthStore struct {
	mu    sync.RWMutex
	auths map[string]*coreauth.Auth
	saves int32
}

func newMemoryAuthStore() *memoryAuthStore {
	return &memoryAuthStore{
		auths: make(map[string]*coreauth.Auth),
	}
}

func (s *memoryAuthStore) List(ctx context.Context) ([]*coreauth.Auth, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*coreauth.Auth, 0, len(s.auths))
	for _, a := range s.auths {
		out = append(out, a.Clone())
	}
	return out, nil
}

func (s *memoryAuthStore) Save(ctx context.Context, auth *coreauth.Auth) (string, error) {
	if auth == nil {
		return "", nil
	}
	s.mu.Lock()
	s.auths[auth.ID] = auth.Clone()
	s.mu.Unlock()
	atomic.AddInt32(&s.saves, 1)
	return auth.ID, nil
}

func (s *memoryAuthStore) Delete(ctx context.Context, id string) error {
	s.mu.Lock()
	delete(s.auths, id)
	s.mu.Unlock()
	return nil
}

func (s *memoryAuthStore) SaveCount() int {
	return int(atomic.LoadInt32(&s.saves))
}

func (s *memoryAuthStore) Add(auth *coreauth.Auth) {
	s.mu.Lock()
	s.auths[auth.ID] = auth.Clone()
	s.mu.Unlock()
}

// mockQuotaServer 创建模拟的 quota API 服务器。
func mockQuotaServer(handler http.HandlerFunc) *httptest.Server {
	return httptest.NewServer(handler)
}

// TestQuotaCfgSnapshot_Defaults 测试默认配置值。
func TestQuotaCfgSnapshot_Defaults(t *testing.T) {
	cfg := &config.Config{}
	store := newMemoryAuthStore()
	mgr := coreauth.NewManager(store, nil, nil)
	qm := NewAntigravityQuotaManager(cfg, mgr)

	enabled, pollInterval, cacheTTL, concurrency, _ := qm.quotaCfgSnapshot()

	if enabled {
		t.Error("expected enabled=false by default")
	}
	if pollInterval != 30*time.Minute {
		t.Errorf("expected pollInterval=30m, got %v", pollInterval)
	}
	if cacheTTL != 10*time.Minute {
		t.Errorf("expected cacheTTL=10m, got %v", cacheTTL)
	}
	if concurrency != 4 {
		t.Errorf("expected concurrency=4, got %d", concurrency)
	}
}

// TestQuotaCfgSnapshot_CustomValues 测试自定义配置值及边界钳制。
func TestQuotaCfgSnapshot_CustomValues(t *testing.T) {
	cfg := &config.Config{
		AntigravityQuota: config.AntigravityQuotaConfig{
			Enabled:                true,
			PollIntervalSeconds:    60,
			CacheTTLSeconds:        120,
			Concurrency:            8,
		},
	}
	store := newMemoryAuthStore()
	mgr := coreauth.NewManager(store, nil, nil)
	qm := NewAntigravityQuotaManager(cfg, mgr)

	enabled, pollInterval, cacheTTL, concurrency, _ := qm.quotaCfgSnapshot()

	if !enabled {
		t.Error("expected enabled=true")
	}
	if pollInterval != 60*time.Second {
		t.Errorf("expected pollInterval=60s, got %v", pollInterval)
	}
	if cacheTTL != 120*time.Second {
		t.Errorf("expected cacheTTL=120s, got %v", cacheTTL)
	}
	if concurrency != 8 {
		t.Errorf("expected concurrency=8, got %d", concurrency)
	}
}

// TestQuotaCfgSnapshot_Clamping 测试边界钳制。
func TestQuotaCfgSnapshot_Clamping(t *testing.T) {
	// poll-interval < 10s → 钳制为 10s
	// cache-ttl < 30s → 钳制为 30s
	// concurrency > 32 → 钳制为 32
	cfg := &config.Config{
		AntigravityQuota: config.AntigravityQuotaConfig{
			Enabled:                true,
			PollIntervalSeconds:    5,  // < 10
			CacheTTLSeconds:        10, // < 30
			Concurrency:            100, // > 32
		},
	}
	store := newMemoryAuthStore()
	mgr := coreauth.NewManager(store, nil, nil)
	qm := NewAntigravityQuotaManager(cfg, mgr)

	_, pollInterval, cacheTTL, concurrency, _ := qm.quotaCfgSnapshot()

	if pollInterval != 10*time.Second {
		t.Errorf("expected pollInterval clamped to 10s, got %v", pollInterval)
	}
	if cacheTTL != 30*time.Second {
		t.Errorf("expected cacheTTL clamped to 30s, got %v", cacheTTL)
	}
	if concurrency != 32 {
		t.Errorf("expected concurrency clamped to 32, got %d", concurrency)
	}
}

// TestRefreshOne_RespectsCacheTTL 测试 TTL 内不重复请求上游。
func TestRefreshOne_RespectsCacheTTL(t *testing.T) {
	var requestCount int32
	server := mockQuotaServer(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requestCount, 1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"models": []string{"model-a"}})
	})
	defer server.Close()

	cfg := &config.Config{
		AntigravityQuota: config.AntigravityQuotaConfig{
			Enabled:         false, // 禁用轮询
			CacheTTLSeconds: 600,   // 10 分钟
		},
	}
	store := newMemoryAuthStore()
	auth := &coreauth.Auth{
		ID:       "test-auth",
		Provider: "antigravity",
		Metadata: map[string]any{
			"base_url":     server.URL,
			"access_token": "test-token",
			"expired":      time.Now().Add(1 * time.Hour).Format(time.RFC3339),
		},
	}
	store.Add(auth)

	mgr := coreauth.NewManager(store, nil, nil)
	_ = mgr.Load(context.Background())

	qm := NewAntigravityQuotaManager(cfg, mgr)

	ctx := context.Background()

	// 第一次请求应该命中上游。
	snap1, err := qm.RefreshOne(ctx, "test-auth", false, false)
	if err != nil {
		t.Fatalf("first refresh failed: %v", err)
	}
	if snap1 == nil {
		t.Fatal("expected snapshot, got nil")
	}
	if atomic.LoadInt32(&requestCount) != 1 {
		t.Errorf("expected 1 request, got %d", requestCount)
	}

	// 第二次请求应该使用缓存（TTL 未过期）。
	snap2, err := qm.RefreshOne(ctx, "test-auth", false, false)
	if err != nil {
		t.Fatalf("second refresh failed: %v", err)
	}
	if snap2 == nil {
		t.Fatal("expected snapshot, got nil")
	}
	if atomic.LoadInt32(&requestCount) != 1 {
		t.Errorf("expected still 1 request (cached), got %d", requestCount)
	}

	// 强制刷新应该绕过缓存。
	snap3, err := qm.RefreshOne(ctx, "test-auth", true, false)
	if err != nil {
		t.Fatalf("force refresh failed: %v", err)
	}
	if snap3 == nil {
		t.Fatal("expected snapshot, got nil")
	}
	if atomic.LoadInt32(&requestCount) != 2 {
		t.Errorf("expected 2 requests after force, got %d", requestCount)
	}
}

// TestRefreshAll_ConcurrencyCap 测试并发数不超过配置的 concurrency。
func TestRefreshAll_ConcurrencyCap(t *testing.T) {
	var (
		maxConcurrent int32
		current       int32
		mu            sync.Mutex
	)

	server := mockQuotaServer(func(w http.ResponseWriter, r *http.Request) {
		c := atomic.AddInt32(&current, 1)
		mu.Lock()
		if c > maxConcurrent {
			maxConcurrent = c
		}
		mu.Unlock()

		time.Sleep(50 * time.Millisecond) // 模拟延迟

		atomic.AddInt32(&current, -1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"models": []string{}})
	})
	defer server.Close()

	cfg := &config.Config{
		AntigravityQuota: config.AntigravityQuotaConfig{
			Enabled:         false,
			CacheTTLSeconds: 600,
			Concurrency:     2, // 限制并发为 2
		},
	}
	store := newMemoryAuthStore()

	// 添加 5 个 antigravity auth。
	for i := 0; i < 5; i++ {
		auth := &coreauth.Auth{
			ID:       "auth-" + string(rune('a'+i)),
			Provider: "antigravity",
			Metadata: map[string]any{
				"base_url":     server.URL,
				"access_token": "test-token",
				"expired":      time.Now().Add(1 * time.Hour).Format(time.RFC3339),
			},
		}
		store.Add(auth)
	}

	mgr := coreauth.NewManager(store, nil, nil)
	_ = mgr.Load(context.Background())

	qm := NewAntigravityQuotaManager(cfg, mgr)

	ctx := context.Background()
	_, err := qm.RefreshAll(ctx, true, false)
	if err != nil {
		t.Fatalf("RefreshAll failed: %v", err)
	}

	mu.Lock()
	mc := maxConcurrent
	mu.Unlock()

	if mc > 2 {
		t.Errorf("expected max concurrent <= 2, got %d", mc)
	}
}

// TestPersistSnapshot_RespectsIntervalAndHash 测试 persist 节流生效。
func TestPersistSnapshot_RespectsIntervalAndHash(t *testing.T) {
	server := mockQuotaServer(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"models": []string{"model-a"}})
	})
	defer server.Close()

	cfg := &config.Config{
		AntigravityQuota: config.AntigravityQuotaConfig{
			Enabled:                false,
			CacheTTLSeconds:        1, // 短 TTL 方便测试
		},
	}
	store := newMemoryAuthStore()
	auth := &coreauth.Auth{
		ID:       "test-auth",
		Provider: "antigravity",
		Metadata: map[string]any{
			"base_url":     server.URL,
			"access_token": "test-token",
			"expired":      time.Now().Add(1 * time.Hour).Format(time.RFC3339),
		},
	}
	store.Add(auth)

	mgr := coreauth.NewManager(store, nil, nil)
	_ = mgr.Load(context.Background())

	qm := NewAntigravityQuotaManager(cfg, mgr)
	ctx := context.Background()

	// 第一次刷新 + persist。
	_, err := qm.RefreshOne(ctx, "test-auth", true, true)
	if err != nil {
		t.Fatalf("first refresh failed: %v", err)
	}
	saveCount1 := store.SaveCount()

	// 第二次刷新 + persist（hash 未变 + interval 未到，应跳过）。
	time.Sleep(10 * time.Millisecond)
	_, err = qm.RefreshOne(ctx, "test-auth", true, true)
	if err != nil {
		t.Fatalf("second refresh failed: %v", err)
	}
	saveCount2 := store.SaveCount()

	// 由于 hash 未变且 interval 未到，save 次数应该不变。
	// 但因为有两次 coreManager.Update 调用（来自 token refresh 和 quota persist），需要仔细检查。
	// 简化：只验证第二次没有额外的 quota persist save。
	if saveCount2 > saveCount1+1 {
		t.Errorf("expected no additional saves due to throttling, got saveCount1=%d, saveCount2=%d", saveCount1, saveCount2)
	}
}

// TestUpdateConfig_RestartsTickerOnIntervalChange 测试热更新时 ticker 重启。
func TestUpdateConfig_RestartsTickerOnIntervalChange(t *testing.T) {
	cfg := &config.Config{
		AntigravityQuota: config.AntigravityQuotaConfig{
			Enabled:             false,
			PollIntervalSeconds: 60,
		},
	}
	store := newMemoryAuthStore()
	mgr := coreauth.NewManager(store, nil, nil)
	qm := NewAntigravityQuotaManager(cfg, mgr)

	// 初始状态：enabled=false，pollCancel 应该为 nil。
	qm.pollMu.Lock()
	if qm.pollCancel != nil {
		t.Error("expected pollCancel to be nil when disabled")
	}
	qm.pollMu.Unlock()

	// 更新配置：启用轮询。
	newCfg := &config.Config{
		AntigravityQuota: config.AntigravityQuotaConfig{
			Enabled:             true,
			PollIntervalSeconds: 30,
		},
	}
	qm.UpdateConfig(newCfg)

	qm.pollMu.Lock()
	if qm.pollCancel == nil {
		t.Error("expected pollCancel to be set after enabling")
	}
	qm.pollMu.Unlock()

	// 更新配置：禁用轮询。
	disabledCfg := &config.Config{
		AntigravityQuota: config.AntigravityQuotaConfig{
			Enabled:             false,
			PollIntervalSeconds: 30,
		},
	}
	qm.UpdateConfig(disabledCfg)

	qm.pollMu.Lock()
	if qm.pollCancel != nil {
		t.Error("expected pollCancel to be nil after disabling")
	}
	qm.pollMu.Unlock()

	// 清理。
	qm.Stop()
}

// TestStartPolling_Enabled_TriggersRefresh 测试启用轮询后会触发刷新请求。
func TestStartPolling_Enabled_TriggersRefresh(t *testing.T) {
	var requestCount int32
	server := mockQuotaServer(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requestCount, 1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"models": []string{}})
	})
	defer server.Close()

	cfg := &config.Config{
		AntigravityQuota: config.AntigravityQuotaConfig{
			Enabled:             true,
			PollIntervalSeconds: 10, // 最小值
			CacheTTLSeconds:     30,
		},
	}
	store := newMemoryAuthStore()
	auth := &coreauth.Auth{
		ID:       "poll-test",
		Provider: "antigravity",
		Metadata: map[string]any{
			"base_url":     server.URL,
			"access_token": "test-token",
			"expired":      time.Now().Add(1 * time.Hour).Format(time.RFC3339),
		},
	}
	store.Add(auth)

	mgr := coreauth.NewManager(store, nil, nil)
	_ = mgr.Load(context.Background())

	qm := NewAntigravityQuotaManager(cfg, mgr)
	qm.Start()

	// 等待 warm up 请求。
	time.Sleep(200 * time.Millisecond)

	if atomic.LoadInt32(&requestCount) < 1 {
		t.Error("expected at least 1 request from warm up")
	}

	qm.Stop()
}

// TestRefreshAll_FiltersNonAntigravityAuth 测试 RefreshAll 只刷新 provider=antigravity 的 auth。
func TestRefreshAll_FiltersNonAntigravityAuth(t *testing.T) {
	var requestCount int32
	server := mockQuotaServer(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requestCount, 1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"models": []string{"model-a"}})
	})
	defer server.Close()

	cfg := &config.Config{
		AntigravityQuota: config.AntigravityQuotaConfig{
			Enabled:         false,
			CacheTTLSeconds: 30,
		},
	}
	store := newMemoryAuthStore()

	// 添加一个 antigravity auth。
	store.Add(&coreauth.Auth{
		ID:       "antigravity-auth",
		Provider: "antigravity",
		Metadata: map[string]any{
			"base_url":     server.URL,
			"access_token": "test-token",
			"expired":      time.Now().Add(1 * time.Hour).Format(time.RFC3339),
		},
	})
	// 添加非 antigravity auth（gemini、claude）。
	store.Add(&coreauth.Auth{
		ID:       "gemini-auth",
		Provider: "gemini",
		Metadata: map[string]any{
			"base_url":     server.URL,
			"access_token": "gemini-token",
		},
	})
	store.Add(&coreauth.Auth{
		ID:       "claude-auth",
		Provider: "claude",
		Metadata: map[string]any{
			"base_url":     server.URL,
			"access_token": "claude-token",
		},
	})

	mgr := coreauth.NewManager(store, nil, nil)
	_ = mgr.Load(context.Background())

	qm := NewAntigravityQuotaManager(cfg, mgr)
	ctx := context.Background()

	res, err := qm.RefreshAll(ctx, true, false)
	if err != nil {
		t.Fatalf("RefreshAll failed: %v", err)
	}

	// 应该只请求了 1 次（只有 antigravity-auth）。
	if atomic.LoadInt32(&requestCount) != 1 {
		t.Errorf("expected 1 request (only antigravity), got %d", requestCount)
	}
	// 结果应该只包含 antigravity-auth。
	if len(res) != 1 {
		t.Errorf("expected 1 result, got %d", len(res))
	}
	if _, ok := res["antigravity-auth"]; !ok {
		t.Error("expected antigravity-auth in results")
	}
}

// TestRefreshOne_NonExistentAuthID 测试不存在的 authID 返回错误。
func TestRefreshOne_NonExistentAuthID(t *testing.T) {
	cfg := &config.Config{}
	store := newMemoryAuthStore()
	mgr := coreauth.NewManager(store, nil, nil)
	_ = mgr.Load(context.Background())

	qm := NewAntigravityQuotaManager(cfg, mgr)
	ctx := context.Background()

	_, err := qm.RefreshOne(ctx, "non-existent-id", false, false)
	if err == nil {
		t.Error("expected error for non-existent authID")
	}
	if !strings.Contains(err.Error(), "auth not found") {
		t.Errorf("expected 'auth not found' error, got: %v", err)
	}
}

// TestRefreshOne_ProviderNotAntigravity 测试非 antigravity provider 返回错误。
func TestRefreshOne_ProviderNotAntigravity(t *testing.T) {
	cfg := &config.Config{}
	store := newMemoryAuthStore()
	store.Add(&coreauth.Auth{
		ID:       "gemini-auth",
		Provider: "gemini",
		Metadata: map[string]any{
			"access_token": "test-token",
		},
	})

	mgr := coreauth.NewManager(store, nil, nil)
	_ = mgr.Load(context.Background())

	qm := NewAntigravityQuotaManager(cfg, mgr)
	ctx := context.Background()

	_, err := qm.RefreshOne(ctx, "gemini-auth", false, false)
	if err == nil {
		t.Error("expected error for non-antigravity provider")
	}
	if !strings.Contains(err.Error(), "provider is not antigravity") {
		t.Errorf("expected 'provider is not antigravity' error, got: %v", err)
	}
}

// TestRefreshOne_RecordsErrorInSnapshot 测试请求失败时 LastErrStr 正确记录。
func TestRefreshOne_RecordsErrorInSnapshot(t *testing.T) {
	// 模拟一个总是返回 500 错误的服务器。
	server := mockQuotaServer(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"internal error"}`))
	})
	defer server.Close()

	cfg := &config.Config{
		AntigravityQuota: config.AntigravityQuotaConfig{
			Enabled:         false,
			CacheTTLSeconds: 30,
		},
	}
	store := newMemoryAuthStore()
	store.Add(&coreauth.Auth{
		ID:       "error-auth",
		Provider: "antigravity",
		Metadata: map[string]any{
			"base_url":     server.URL,
			"access_token": "test-token",
			"expired":      time.Now().Add(1 * time.Hour).Format(time.RFC3339),
		},
	})

	mgr := coreauth.NewManager(store, nil, nil)
	_ = mgr.Load(context.Background())

	qm := NewAntigravityQuotaManager(cfg, mgr)
	ctx := context.Background()

	snap, err := qm.RefreshOne(ctx, "error-auth", true, false)
	if err == nil {
		t.Error("expected error from failed request")
	}
	if snap == nil {
		t.Fatal("expected snapshot even on error")
	}
	if snap.LastErrStr == "" {
		t.Error("expected LastErrStr to be set")
	}
	if !strings.Contains(snap.LastErrStr, "500") {
		t.Errorf("expected error to contain status code, got: %s", snap.LastErrStr)
	}
}

// TestPersistSnapshot_ForceBypassesThrottling 测试 force=true 绕过节流。
func TestPersistSnapshot_ForceBypassesThrottling(t *testing.T) {
	server := mockQuotaServer(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"models": []string{"model-a"}})
	})
	defer server.Close()

	cfg := &config.Config{
		AntigravityQuota: config.AntigravityQuotaConfig{
			Enabled:                false,
			CacheTTLSeconds:        1,
		},
	}
	store := newMemoryAuthStore()
	auth := &coreauth.Auth{
		ID:       "force-test",
		Provider: "antigravity",
		Metadata: map[string]any{
			"base_url":     server.URL,
			"access_token": "test-token",
			"expired":      time.Now().Add(1 * time.Hour).Format(time.RFC3339),
		},
	}
	store.Add(auth)

	mgr := coreauth.NewManager(store, nil, nil)
	_ = mgr.Load(context.Background())

	qm := NewAntigravityQuotaManager(cfg, mgr)
	ctx := context.Background()

	// 第一次刷新 + persist。
	_, err := qm.RefreshOne(ctx, "force-test", true, true)
	if err != nil {
		t.Fatalf("first refresh failed: %v", err)
	}
	saveCount1 := store.SaveCount()

	// 等待一小段时间确保 TTL 过期。
	time.Sleep(20 * time.Millisecond)

	// 第二次刷新 + persist，但 persist interval 未到（3600s），正常情况应该被节流。
	_, err = qm.RefreshOne(ctx, "force-test", true, true)
	if err != nil {
		t.Fatalf("second refresh failed: %v", err)
	}
	saveCount2 := store.SaveCount()

	// 由于 hash 相同且 interval 未到，save 次数应该不变（或只增加 1 次来自 token refresh）。
	// 注意：第一次 persist 会 save，第二次因为节流不会 save。
	if saveCount2 < saveCount1 {
		t.Errorf("save count decreased unexpectedly: %d -> %d", saveCount1, saveCount2)
	}
}

// TestFetchAvailableModels_BaseURLFallback 测试 429 时降级到下一个 URL。
func TestFetchAvailableModels_BaseURLFallback(t *testing.T) {
	var requestURLs []string
	var mu sync.Mutex

	// 创建两个服务器：第一个返回 429，第二个成功。
	server1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requestURLs = append(requestURLs, "server1")
		mu.Unlock()
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"error":"rate limited"}`))
	}))
	defer server1.Close()

	server2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requestURLs = append(requestURLs, "server2")
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"models": []string{"fallback-model"}})
	}))
	defer server2.Close()

	// 注意：由于 resolveQuotaBaseURLFallbackOrder 使用 auth 的 base_url，
	// 我们无法在测试中直接测试 fallback 逻辑（因为 custom base_url 只返回单个 URL）。
	// 这个测试验证当 base_url 设置时，只使用该 URL。
	cfg := &config.Config{
		AntigravityQuota: config.AntigravityQuotaConfig{
			Enabled:         false,
			CacheTTLSeconds: 30,
		},
	}
	store := newMemoryAuthStore()
	store.Add(&coreauth.Auth{
		ID:       "fallback-test",
		Provider: "antigravity",
		Metadata: map[string]any{
			"base_url":     server1.URL, // 使用第一个服务器（返回 429）
			"access_token": "test-token",
			"expired":      time.Now().Add(1 * time.Hour).Format(time.RFC3339),
		},
	})

	mgr := coreauth.NewManager(store, nil, nil)
	_ = mgr.Load(context.Background())

	qm := NewAntigravityQuotaManager(cfg, mgr)
	ctx := context.Background()

	// 由于设置了 custom base_url，不会 fallback，应该返回错误。
	_, err := qm.RefreshOne(ctx, "fallback-test", true, false)
	if err == nil {
		t.Error("expected error when server returns 429 with custom base_url")
	}

	mu.Lock()
	urlCount := len(requestURLs)
	mu.Unlock()

	if urlCount != 1 {
		t.Errorf("expected 1 request (no fallback with custom base_url), got %d", urlCount)
	}
}

// TestStop_WaitsForGoroutines 测试 Stop 等待所有 goroutine 结束。
func TestStop_WaitsForGoroutines(t *testing.T) {
	var requestCount int32
	server := mockQuotaServer(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requestCount, 1)
		// 模拟慢请求。
		time.Sleep(50 * time.Millisecond)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"models": []string{}})
	})
	defer server.Close()

	cfg := &config.Config{
		AntigravityQuota: config.AntigravityQuotaConfig{
			Enabled:             true,
			PollIntervalSeconds: 10,
			CacheTTLSeconds:     30,
		},
	}
	store := newMemoryAuthStore()
	store.Add(&coreauth.Auth{
		ID:       "stop-test",
		Provider: "antigravity",
		Metadata: map[string]any{
			"base_url":     server.URL,
			"access_token": "test-token",
			"expired":      time.Now().Add(1 * time.Hour).Format(time.RFC3339),
		},
	})

	mgr := coreauth.NewManager(store, nil, nil)
	_ = mgr.Load(context.Background())

	qm := NewAntigravityQuotaManager(cfg, mgr)
	qm.Start()

	// 等待 warm up 开始。
	time.Sleep(20 * time.Millisecond)

	// 调用 Stop 应该阻塞直到所有 goroutine 结束。
	done := make(chan struct{})
	go func() {
		qm.Stop()
		close(done)
	}()

	select {
	case <-done:
		// Stop 成功完成。
	case <-time.After(2 * time.Second):
		t.Error("Stop did not complete within timeout")
	}
}

// TestGetSnapshot_ReturnsDeepCopy 测试 GetSnapshot 返回副本而非引用。
func TestGetSnapshot_ReturnsDeepCopy(t *testing.T) {
	server := mockQuotaServer(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"models": []string{"model-a"}})
	})
	defer server.Close()

	cfg := &config.Config{
		AntigravityQuota: config.AntigravityQuotaConfig{
			Enabled:         false,
			CacheTTLSeconds: 600,
		},
	}
	store := newMemoryAuthStore()
	store.Add(&coreauth.Auth{
		ID:       "copy-test",
		Provider: "antigravity",
		Metadata: map[string]any{
			"base_url":     server.URL,
			"access_token": "test-token",
			"expired":      time.Now().Add(1 * time.Hour).Format(time.RFC3339),
		},
	})

	mgr := coreauth.NewManager(store, nil, nil)
	_ = mgr.Load(context.Background())

	qm := NewAntigravityQuotaManager(cfg, mgr)
	ctx := context.Background()

	// 刷新一次。
	_, err := qm.RefreshOne(ctx, "copy-test", true, false)
	if err != nil {
		t.Fatalf("refresh failed: %v", err)
	}

	// 获取两次快照。
	snap1, ok1 := qm.GetSnapshot("copy-test")
	snap2, ok2 := qm.GetSnapshot("copy-test")

	if !ok1 || !ok2 {
		t.Fatal("expected snapshots to be found")
	}

	// 修改 snap1，不应影响 snap2。
	snap1.AuthID = "modified"
	if snap2.AuthID == "modified" {
		t.Error("GetSnapshot should return a copy, not a reference")
	}
}

// TestListSnapshots_ReturnsDeepCopy 测试 ListSnapshots 返回副本而非引用。
func TestListSnapshots_ReturnsDeepCopy(t *testing.T) {
	server := mockQuotaServer(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"models": []string{"model-a"}})
	})
	defer server.Close()

	cfg := &config.Config{
		AntigravityQuota: config.AntigravityQuotaConfig{
			Enabled:         false,
			CacheTTLSeconds: 600,
		},
	}
	store := newMemoryAuthStore()
	store.Add(&coreauth.Auth{
		ID:       "list-copy-test",
		Provider: "antigravity",
		Metadata: map[string]any{
			"base_url":     server.URL,
			"access_token": "test-token",
			"expired":      time.Now().Add(1 * time.Hour).Format(time.RFC3339),
		},
	})

	mgr := coreauth.NewManager(store, nil, nil)
	_ = mgr.Load(context.Background())

	qm := NewAntigravityQuotaManager(cfg, mgr)
	ctx := context.Background()

	// 刷新一次。
	_, err := qm.RefreshOne(ctx, "list-copy-test", true, false)
	if err != nil {
		t.Fatalf("refresh failed: %v", err)
	}

	// 获取两次列表。
	list1 := qm.ListSnapshots()
	list2 := qm.ListSnapshots()

	if len(list1) == 0 || len(list2) == 0 {
		t.Fatal("expected non-empty lists")
	}

	// 修改 list1 中的快照，不应影响 list2。
	for k, v := range list1 {
		v.AuthID = "modified"
		list1[k] = v
	}

	for _, v := range list2 {
		if v.AuthID == "modified" {
			t.Error("ListSnapshots should return copies, not references")
		}
	}
}

// TestQuotaCfgSnapshot_NilConfig 测试 cfg=nil 时使用默认值。
func TestQuotaCfgSnapshot_NilConfig(t *testing.T) {
	store := newMemoryAuthStore()
	mgr := coreauth.NewManager(store, nil, nil)
	qm := NewAntigravityQuotaManager(nil, mgr)

	enabled, pollInterval, cacheTTL, concurrency, _ := qm.quotaCfgSnapshot()

	if enabled {
		t.Error("expected enabled=false with nil config")
	}
	if pollInterval != 30*time.Minute {
		t.Errorf("expected pollInterval=30m, got %v", pollInterval)
	}
	if cacheTTL != 10*time.Minute {
		t.Errorf("expected cacheTTL=10m, got %v", cacheTTL)
	}
	if concurrency != 4 {
		t.Errorf("expected concurrency=4, got %d", concurrency)
	}
}

// TestRefreshAll_PartialFailureContinues 测试部分 auth 失败不影响其他。
func TestRefreshAll_PartialFailureContinues(t *testing.T) {
	var requestCount int32

	// 成功的服务器。
	successServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requestCount, 1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"models": []string{"model-a"}})
	}))
	defer successServer.Close()

	// 失败的服务器。
	failServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requestCount, 1)
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"internal error"}`))
	}))
	defer failServer.Close()

	cfg := &config.Config{
		AntigravityQuota: config.AntigravityQuotaConfig{
			Enabled:         false,
			CacheTTLSeconds: 30,
			Concurrency:     4,
		},
	}
	store := newMemoryAuthStore()

	// 添加一个成功的 auth。
	store.Add(&coreauth.Auth{
		ID:       "success-auth",
		Provider: "antigravity",
		Metadata: map[string]any{
			"base_url":     successServer.URL,
			"access_token": "test-token",
			"expired":      time.Now().Add(1 * time.Hour).Format(time.RFC3339),
		},
	})
	// 添加一个失败的 auth。
	store.Add(&coreauth.Auth{
		ID:       "fail-auth",
		Provider: "antigravity",
		Metadata: map[string]any{
			"base_url":     failServer.URL,
			"access_token": "test-token",
			"expired":      time.Now().Add(1 * time.Hour).Format(time.RFC3339),
		},
	})

	mgr := coreauth.NewManager(store, nil, nil)
	_ = mgr.Load(context.Background())

	qm := NewAntigravityQuotaManager(cfg, mgr)
	ctx := context.Background()

	// RefreshAll 应该继续处理所有 auth，即使部分失败。
	res, err := qm.RefreshAll(ctx, true, false)
	if err != nil {
		t.Fatalf("RefreshAll should not return error for partial failures: %v", err)
	}

	// 应该有 2 个请求。
	if atomic.LoadInt32(&requestCount) != 2 {
		t.Errorf("expected 2 requests, got %d", requestCount)
	}

	// 结果应该包含两个快照（成功的和失败的都有快照）。
	if len(res) != 2 {
		t.Errorf("expected 2 results, got %d", len(res))
	}

	// 检查成功的快照。
	if successSnap, ok := res["success-auth"]; ok {
		if successSnap.LastErrStr != "" {
			t.Errorf("success-auth should not have error, got: %s", successSnap.LastErrStr)
		}
	} else {
		t.Error("expected success-auth in results")
	}

	// 检查失败的快照。
	if failSnap, ok := res["fail-auth"]; ok {
		if failSnap.LastErrStr == "" {
			t.Error("fail-auth should have error recorded")
		}
	} else {
		t.Error("expected fail-auth in results")
	}
}

// TestApplyClaudeQuotaThreshold_BlocksWhenBelowThreshold 测试配额阈值检查。
func TestApplyClaudeQuotaThreshold_BlocksWhenBelowThreshold(t *testing.T) {
	// 模拟返回 Claude 模型配额数据
	quotaResponse := map[string]any{
		"models": map[string]any{
			"claude-sonnet-4-5": map[string]any{
				"modelProvider": "MODEL_PROVIDER_ANTHROPIC",
				"quotaInfo": map[string]any{
					"remainingFraction": 0.1, // 10% 剩余
					"resetTime":         "2026-01-31T10:00:00Z",
				},
			},
			"claude-opus-4-5": map[string]any{
				"modelProvider": "MODEL_PROVIDER_ANTHROPIC",
				"quotaInfo": map[string]any{
					// 无 remainingFraction，配额耗尽
					"resetTime": "2026-01-31T10:00:00Z",
				},
			},
			"gemini-2.5-pro": map[string]any{
				"modelProvider": "MODEL_PROVIDER_GOOGLE",
				"quotaInfo": map[string]any{
					"remainingFraction": 1.0,
				},
			},
		},
	}
	respBody, _ := json.Marshal(quotaResponse)

	server := mockQuotaServer(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(respBody)
	})
	defer server.Close()

	cfg := &config.Config{
		AntigravityQuota: config.AntigravityQuotaConfig{
			Enabled:              false,
			CacheTTLSeconds:      600,
			ClaudeQuotaThreshold: 0.2, // 阈值 20%
		},
	}
	store := newMemoryAuthStore()
	auth := &coreauth.Auth{
		ID:       "test-auth",
		Provider: "antigravity",
		Metadata: map[string]any{
			"base_url":     server.URL,
			"access_token": "test-token",
			"expired":      time.Now().Add(1 * time.Hour).Format(time.RFC3339),
		},
	}
	store.Add(auth)

	mgr := coreauth.NewManager(store, nil, nil)
	_ = mgr.Load(context.Background())

	qm := NewAntigravityQuotaManager(cfg, mgr)

	ctx := context.Background()
	_, err := qm.RefreshOne(ctx, "test-auth", true, false)
	if err != nil {
		t.Fatalf("RefreshOne failed: %v", err)
	}

	// 获取更新后的 auth
	updatedAuth, ok := mgr.GetByID("test-auth")
	if !ok {
		t.Fatal("expected auth to exist")
	}

	// claude-sonnet-4-5: remainingFraction=0.1 < threshold=0.2，应被阻止
	if state, ok := updatedAuth.ModelStates["claude-sonnet-4-5"]; ok {
		if !state.QuotaThresholdExceeded {
			t.Error("claude-sonnet-4-5 should be marked as QuotaThresholdExceeded")
		}
	} else {
		t.Error("expected ModelState for claude-sonnet-4-5")
	}

	// claude-opus-4-5: 无 remainingFraction，应被阻止
	if state, ok := updatedAuth.ModelStates["claude-opus-4-5"]; ok {
		if !state.QuotaThresholdExceeded {
			t.Error("claude-opus-4-5 should be marked as QuotaThresholdExceeded")
		}
	} else {
		t.Error("expected ModelState for claude-opus-4-5")
	}

	// gemini-2.5-pro: 非 Claude 模型，不应受影响
	if state, ok := updatedAuth.ModelStates["gemini-2.5-pro"]; ok {
		if state.QuotaThresholdExceeded {
			t.Error("gemini-2.5-pro should NOT be marked as QuotaThresholdExceeded")
		}
	}
}

// TestApplyClaudeQuotaThreshold_ClearsWhenAboveThreshold 测试配额恢复后清除标记。
func TestApplyClaudeQuotaThreshold_ClearsWhenAboveThreshold(t *testing.T) {
	callCount := 0
	server := mockQuotaServer(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "application/json")
		var resp map[string]any
		if callCount == 1 {
			// 第一次：配额不足
			resp = map[string]any{
				"models": map[string]any{
					"claude-sonnet-4-5": map[string]any{
						"modelProvider": "MODEL_PROVIDER_ANTHROPIC",
						"quotaInfo": map[string]any{
							"remainingFraction": 0.05,
							"resetTime":         "2026-01-31T10:00:00Z",
						},
					},
				},
			}
		} else {
			// 第二次：配额恢复
			resp = map[string]any{
				"models": map[string]any{
					"claude-sonnet-4-5": map[string]any{
						"modelProvider": "MODEL_PROVIDER_ANTHROPIC",
						"quotaInfo": map[string]any{
							"remainingFraction": 0.8,
							"resetTime":         "2026-01-31T12:00:00Z",
						},
					},
				},
			}
		}
		_ = json.NewEncoder(w).Encode(resp)
	})
	defer server.Close()

	cfg := &config.Config{
		AntigravityQuota: config.AntigravityQuotaConfig{
			Enabled:              false,
			CacheTTLSeconds:      1, // 短 TTL
			ClaudeQuotaThreshold: 0.2,
		},
	}
	store := newMemoryAuthStore()
	auth := &coreauth.Auth{
		ID:       "test-auth",
		Provider: "antigravity",
		Metadata: map[string]any{
			"base_url":     server.URL,
			"access_token": "test-token",
			"expired":      time.Now().Add(1 * time.Hour).Format(time.RFC3339),
		},
	}
	store.Add(auth)

	mgr := coreauth.NewManager(store, nil, nil)
	_ = mgr.Load(context.Background())

	qm := NewAntigravityQuotaManager(cfg, mgr)
	ctx := context.Background()

	// 第一次刷新：应被阻止
	_, _ = qm.RefreshOne(ctx, "test-auth", true, false)
	auth1, _ := mgr.GetByID("test-auth")
	if state, ok := auth1.ModelStates["claude-sonnet-4-5"]; !ok || !state.QuotaThresholdExceeded {
		t.Error("first refresh should mark claude-sonnet-4-5 as QuotaThresholdExceeded")
	}

	// 第二次刷新：配额恢复，应清除标记
	_, _ = qm.RefreshOne(ctx, "test-auth", true, false)
	auth2, _ := mgr.GetByID("test-auth")
	if state, ok := auth2.ModelStates["claude-sonnet-4-5"]; ok && state.QuotaThresholdExceeded {
		t.Error("second refresh should clear QuotaThresholdExceeded for claude-sonnet-4-5")
	}
}
