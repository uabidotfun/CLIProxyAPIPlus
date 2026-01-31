package quota

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/proxy"

	"github.com/router-for-me/CLIProxyAPI/v6/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/runtime/executor"
	coreauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"
	log "github.com/sirupsen/logrus"
)

// AntigravityQuotaSnapshot 表示一次从上游 fetchAvailableModels 获取到的快照。
//
// 为什么保存 Raw：
// - 上游响应字段较多且可能扩展；保存原始 JSON 能最大限度保持信息（尤其是 quotaInfo）。
// - 管理 API 直接返回 Raw，避免在 Go 侧重复建模导致字段丢失。
//
// 为什么额外保存 Parsed：
// - 便于后续在 Go 侧按需读取/比较（例如 hash、命中 baseURL、时间戳）。
// - Parsed 来自 Raw 的 json.Unmarshal，属于“缓存视图”，不作为单一事实来源。
//
// 注意：Parsed 的 map 内容只用于内部逻辑，不建议外部修改。
type AntigravityQuotaSnapshot struct {
	AuthID     string
	FetchedAt  time.Time
	BaseURL    string
	Raw        json.RawMessage
	Parsed     map[string]any
	RawSHA256  string
	ExpiresAt  time.Time
	PersistAt  time.Time
	LastErrStr string
}

// AntigravityQuotaManager 负责：
// - 遍历 antigravity auth 凭证
// - 调用 /v1internal:fetchAvailableModels 拉取 quotaInfo
// - 缓存快照，并可按策略写回 auth.Metadata 以持久化
type AntigravityQuotaManager struct {
	cfgMu       sync.RWMutex
	cfg         *config.Config
	coreManager *coreauth.Manager

	mu        sync.RWMutex
	snapshots map[string]*AntigravityQuotaSnapshot

	stopOnce sync.Once
	stopCh   chan struct{}
	wg       sync.WaitGroup

	// pollCancel 用于热更新时重启 ticker（与 stopCh 解耦）。
	pollMu     sync.Mutex
	pollCancel context.CancelFunc

	// persistMu 保护 lastPersistHash/lastPersistAt 的并发读写。
	persistMu sync.Mutex
	// 写回节流：记录最近一次写回的 hash，避免频繁写文件。
	lastPersistHash map[string]string
	lastPersistAt   map[string]time.Time
}

var (
	globalMu            sync.RWMutex
	globalQuotaManager  *AntigravityQuotaManager
)

// SetGlobalAntigravityQuotaManager 设置全局 quota manager。
// 用于 management handler 在不直接依赖 Service 的情况下访问。
func SetGlobalAntigravityQuotaManager(m *AntigravityQuotaManager) {
	globalMu.Lock()
	globalQuotaManager = m
	globalMu.Unlock()
}

// GetGlobalAntigravityQuotaManager 获取全局 quota manager。
func GetGlobalAntigravityQuotaManager() *AntigravityQuotaManager {
	globalMu.RLock()
	m := globalQuotaManager
	globalMu.RUnlock()
	return m
}

// NewAntigravityQuotaManager 创建 quota manager。
func NewAntigravityQuotaManager(cfg *config.Config, coreManager *coreauth.Manager) *AntigravityQuotaManager {
	return &AntigravityQuotaManager{
		cfg:             cfg,
		coreManager:     coreManager,
		snapshots:       make(map[string]*AntigravityQuotaSnapshot),
		stopCh:          make(chan struct{}),
		lastPersistHash: make(map[string]string),
		lastPersistAt:   make(map[string]time.Time),
	}
}

// Start 启动定期轮询。
// enabled/poll/cacheTTL/persistInterval/concurrency 由配置控制；若 cfg 缺失则使用保守默认值。
func (m *AntigravityQuotaManager) Start() {
	if m == nil {
		return
	}
	enabled, _, _, _, _ := m.quotaCfgSnapshot()
	if !enabled {
		return
	}
	m.startPolling()
}

// startPolling 启动后台轮询 goroutine。
func (m *AntigravityQuotaManager) startPolling() {
	if m == nil {
		return
	}
	m.pollMu.Lock()
	defer m.pollMu.Unlock()

	// 若已有正在运行的轮询，先取消。
	if m.pollCancel != nil {
		m.pollCancel()
		m.pollCancel = nil
	}

	enabled, pollInterval, _, _, _ := m.quotaCfgSnapshot()
	if !enabled || pollInterval <= 0 {
		return
	}

	pollCtx, cancel := context.WithCancel(context.Background())
	m.pollCancel = cancel

	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		ticker := time.NewTicker(pollInterval)
		defer ticker.Stop()

		// warm up：启动时立即执行一次。
		m.pollOnce(pollCtx)

		for {
			select {
			case <-ticker.C:
				m.pollOnce(pollCtx)
			case <-pollCtx.Done():
				return
			case <-m.stopCh:
				return
			}
		}
	}()
	log.Infof("antigravity quota: polling started (interval=%s)", pollInterval)
}

// stopPolling 停止后台轮询（不关闭 stopCh，仅取消 pollCancel）。
func (m *AntigravityQuotaManager) stopPolling() {
	if m == nil {
		return
	}
	m.pollMu.Lock()
	defer m.pollMu.Unlock()
	if m.pollCancel != nil {
		m.pollCancel()
		m.pollCancel = nil
		log.Info("antigravity quota: polling stopped")
	}
}

// pollOnce 执行一次全量刷新。
func (m *AntigravityQuotaManager) pollOnce(ctx context.Context) {
	if m == nil {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	_, _ = m.RefreshAll(ctx, false, true)
}

// quotaCfgSnapshot 返回当前配置（带默认值回退和边界钳制）。
func (m *AntigravityQuotaManager) quotaCfgSnapshot() (enabled bool, pollInterval, cacheTTL, persistInterval time.Duration, concurrency int) {
	if m == nil {
		return false, 30 * time.Minute, 10 * time.Minute, time.Hour, 4
	}
	m.cfgMu.RLock()
	cfg := m.cfg
	m.cfgMu.RUnlock()

	// 默认值。
	enabled = false
	pollInterval = 30 * time.Minute
	cacheTTL = 10 * time.Minute
	persistInterval = time.Hour
	concurrency = 4

	if cfg == nil {
		return
	}
	qc := cfg.AntigravityQuota
	enabled = qc.Enabled

	if qc.PollIntervalSeconds > 0 {
		pollInterval = time.Duration(qc.PollIntervalSeconds) * time.Second
	}
	// 下限钳制：poll-interval >= 10s。
	if pollInterval < 10*time.Second {
		pollInterval = 10 * time.Second
	}

	if qc.CacheTTLSeconds > 0 {
		cacheTTL = time.Duration(qc.CacheTTLSeconds) * time.Second
	}
	// 下限钳制：cache-ttl >= 30s。
	if cacheTTL < 30*time.Second {
		cacheTTL = 30 * time.Second
	}

	if qc.PersistIntervalSeconds >= 0 {
		persistInterval = time.Duration(qc.PersistIntervalSeconds) * time.Second
	}
	// persist-interval < 0 → 钳制为 0（禁用节流）。
	if persistInterval < 0 {
		persistInterval = 0
	}

	if qc.Concurrency > 0 {
		concurrency = qc.Concurrency
	}
	// 边界：1 <= concurrency <= 32。
	if concurrency < 1 {
		concurrency = 1
	}
	if concurrency > 32 {
		concurrency = 32
	}
	return
}

// UpdateConfig 热更新配置。根据 enabled/pollInterval 变化启动/停止/重启轮询。
func (m *AntigravityQuotaManager) UpdateConfig(cfg *config.Config) {
	if m == nil {
		return
	}
	oldEnabled, oldPoll, _, _, _ := m.quotaCfgSnapshot()

	m.cfgMu.Lock()
	m.cfg = cfg
	m.cfgMu.Unlock()

	newEnabled, newPoll, _, _, _ := m.quotaCfgSnapshot()

	// enabled 变化。
	if !oldEnabled && newEnabled {
		m.startPolling()
	} else if oldEnabled && !newEnabled {
		m.stopPolling()
	} else if oldEnabled && newEnabled && oldPoll != newPoll {
		// poll-interval 变化，重启 ticker。
		m.stopPolling()
		m.startPolling()
	}
}

// Stop 停止后台轮询。
func (m *AntigravityQuotaManager) Stop() {
	if m == nil {
		return
	}
	m.stopOnce.Do(func() {
		close(m.stopCh)
	})
	m.wg.Wait()
}

// GetSnapshot 返回指定 authID 的配额快照（不会触发刷新）。
func (m *AntigravityQuotaManager) GetSnapshot(authID string) (*AntigravityQuotaSnapshot, bool) {
	if m == nil {
		return nil, false
	}
	authID = strings.TrimSpace(authID)
	if authID == "" {
		return nil, false
	}
	m.mu.RLock()
	s := m.snapshots[authID]
	m.mu.RUnlock()
	if s == nil {
		return nil, false
	}
	copy := *s
	return &copy, true
}

// ListSnapshots 返回当前缓存的全部快照（拷贝）。
func (m *AntigravityQuotaManager) ListSnapshots() map[string]*AntigravityQuotaSnapshot {
	if m == nil {
		return nil
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make(map[string]*AntigravityQuotaSnapshot, len(m.snapshots))
	for k, v := range m.snapshots {
		if v == nil {
			continue
		}
		c := *v
		out[k] = &c
	}
	return out
}

// RefreshAll 拉取所有 antigravity auth 的配额快照。
//
// force: 忽略 TTL，强制请求上游。
// persist: 是否允许写回 Auth.Metadata（并通过 coreManager.Update 持久化）。
func (m *AntigravityQuotaManager) RefreshAll(ctx context.Context, force bool, persist bool) (map[string]*AntigravityQuotaSnapshot, error) {
	if m == nil {
		return nil, fmt.Errorf("antigravity quota manager is nil")
	}
	if m.coreManager == nil {
		return nil, fmt.Errorf("core auth manager unavailable")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	auths := m.coreManager.List()
	if len(auths) == 0 {
		return map[string]*AntigravityQuotaSnapshot{}, nil
	}

	// 过滤 antigravity 类型的 auth。
	var antigravityAuths []*coreauth.Auth
	for _, a := range auths {
		if a == nil {
			continue
		}
		if !strings.EqualFold(strings.TrimSpace(a.Provider), "antigravity") {
			continue
		}
		antigravityAuths = append(antigravityAuths, a)
	}
	if len(antigravityAuths) == 0 {
		return map[string]*AntigravityQuotaSnapshot{}, nil
	}

	// 读取并发数配置。
	_, _, _, _, concurrency := m.quotaCfgSnapshot()
	if concurrency < 1 {
		concurrency = 1
	}

	out := make(map[string]*AntigravityQuotaSnapshot)
	var outMu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, concurrency)

	for _, a := range antigravityAuths {
		sem <- struct{}{}
		wg.Add(1)
		go func(auth *coreauth.Auth) {
			defer func() { <-sem; wg.Done() }()
			snap, err := m.RefreshOne(ctx, auth.ID, force, persist)
			if err != nil {
				// 单个失败不影响其他；错误放到快照里供调用方观察。
				log.Debugf("antigravity quota: refresh auth %s failed: %v", auth.ID, err)
			}
			if snap != nil {
				outMu.Lock()
				out[auth.ID] = snap
				outMu.Unlock()
			}
		}(a)
	}
	wg.Wait()
	return out, nil
}

// RefreshOne 拉取单个 antigravity auth 的配额快照。
func (m *AntigravityQuotaManager) RefreshOne(ctx context.Context, authID string, force bool, persist bool) (*AntigravityQuotaSnapshot, error) {
	if m == nil {
		return nil, fmt.Errorf("antigravity quota manager is nil")
	}
	if m.coreManager == nil {
		return nil, fmt.Errorf("core auth manager unavailable")
	}
	authID = strings.TrimSpace(authID)
	if authID == "" {
		return nil, fmt.Errorf("missing authID")
	}
	if ctx == nil {
		ctx = context.Background()
	}

	auth, ok := m.coreManager.GetByID(authID)
	if !ok || auth == nil {
		return nil, fmt.Errorf("auth not found: %s", authID)
	}
	if !strings.EqualFold(strings.TrimSpace(auth.Provider), "antigravity") {
		return nil, fmt.Errorf("auth provider is not antigravity: %s", auth.Provider)
	}

	// TTL：先用快照自带 expires 判断（后续接入配置）。
	if !force {
		m.mu.RLock()
		existing := m.snapshots[authID]
		m.mu.RUnlock()
		if existing != nil && !existing.ExpiresAt.IsZero() && time.Now().Before(existing.ExpiresAt) {
			copy := *existing
			return &copy, nil
		}
	}

	resp, err := m.fetchAvailableModels(ctx, auth)
	if err != nil {
		snap := &AntigravityQuotaSnapshot{AuthID: authID, FetchedAt: time.Now().UTC(), LastErrStr: err.Error()}
		m.mu.Lock()
		m.snapshots[authID] = snap
		m.mu.Unlock()
		return snap, err
	}

	snap := resp
	// 写回 metadata（节流策略：后续接入 persist-interval + hash 变化判断）。
	if persist {
		if errPersist := m.persistSnapshot(ctx, auth, snap, false); errPersist != nil {
			// 不把 persist 失败作为 refresh 失败，避免影响读取。
			log.Debugf("antigravity quota: persist snapshot failed (auth=%s): %v", authID, errPersist)
		}
	}

	m.mu.Lock()
	m.snapshots[authID] = snap
	m.mu.Unlock()
	copy := *snap
	return &copy, nil
}

func (m *AntigravityQuotaManager) persistSnapshot(ctx context.Context, auth *coreauth.Auth, snap *AntigravityQuotaSnapshot, force bool) error {
	if m == nil || m.coreManager == nil {
		return nil
	}
	if auth == nil || snap == nil {
		return nil
	}
	id := strings.TrimSpace(auth.ID)
	if id == "" {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}

	// 节流判断：hash 变化 + persist-interval。
	if !force {
		m.persistMu.Lock()
		lastHash := m.lastPersistHash[id]
		lastAt := m.lastPersistAt[id]
		m.persistMu.Unlock()

		// hash 未变化，跳过写回。
		if lastHash != "" && lastHash == snap.RawSHA256 {
			return nil
		}

		// persist-interval 未到，跳过写回。
		_, _, _, persistInterval, _ := m.quotaCfgSnapshot()
		if persistInterval > 0 && !lastAt.IsZero() && time.Since(lastAt) < persistInterval {
			return nil
		}
	}

	updated := auth.Clone()
	if updated.Metadata == nil {
		updated.Metadata = make(map[string]any)
	}

	var quotaObj any
	if len(snap.Raw) > 0 {
		if err := json.Unmarshal(snap.Raw, &quotaObj); err == nil {
			updated.Metadata["antigravity_quota"] = quotaObj
		}
	}
	updated.Metadata["antigravity_quota_fetched_at"] = snap.FetchedAt.UTC().Format(time.RFC3339)
	if strings.TrimSpace(snap.BaseURL) != "" {
		updated.Metadata["antigravity_quota_base_url"] = strings.TrimSpace(snap.BaseURL)
	}

	// 说明：Service.consumeAuthUpdates 使用 WithSkipPersist，避免 watcher 场景回写。
	// 这里是 quota manager 主动写回，需要持久化，因此不应使用 WithSkipPersist。
	updated.UpdatedAt = time.Now()
	_, err := m.coreManager.Update(ctx, updated)
	if err != nil {
		return err
	}

	m.persistMu.Lock()
	m.lastPersistHash[id] = snap.RawSHA256
	m.lastPersistAt[id] = time.Now()
	m.persistMu.Unlock()
	return nil
}

func (m *AntigravityQuotaManager) fetchAvailableModels(ctx context.Context, auth *coreauth.Auth) (*AntigravityQuotaSnapshot, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if auth == nil {
		return nil, fmt.Errorf("missing auth")
	}

	// 1) 获取 token：这里不依赖 AntigravityExecutor.PrepareRequest 来“顺便刷新”，
	// 因为 PrepareRequest 内部即使刷新成功也不会把 updatedAuth 回写到入参。
	// 我们采用：先本地判断 token 是否过期/缺失，再显式调用 executor.Refresh + coreManager.Update 持久化。

	// 2) 选择 baseURL：遵循方案（Prod + Fallback，同时尊重 auth base_url 覆盖）
	baseURLs := resolveQuotaBaseURLFallbackOrder(auth)
	if len(baseURLs) == 0 {
		return nil, fmt.Errorf("no base url available")
	}

	// 3) 构造请求 payload：优先带 project
	payload := []byte(`{}`)
	if auth.Metadata != nil {
		if pid, ok := auth.Metadata["project_id"].(string); ok {
			pid = strings.TrimSpace(pid)
			if pid != "" {
				payload = []byte(fmt.Sprintf(`{"project":%q}`, pid))
			}
		}
	}

	// 复用 executor 的 token 刷新实现：
	// - 仅当本地判断 token 已过期/缺失时才调用 Refresh（避免每次都刷新）。
	// - Refresh 成功后，通过 coreManager.Update 持久化到 auth 文件。
	//
	// 注意：AntigravityExecutor.PrepareRequest 内部会调用 ensureAccessToken 但不会把 updatedAuth 回写到入参，
	// 因此这里不能依赖 PrepareRequest 来完成持久化更新。
	accessToken := metaStringValueLocal(auth.Metadata, "access_token")
	expiry := tokenExpiryLocal(auth.Metadata)
	if strings.TrimSpace(accessToken) == "" || (!expiry.IsZero() && time.Now().After(expiry.Add(-30*time.Second))) {
		exec := executor.NewAntigravityExecutor(m.cfg)
		updated, errRefresh := exec.Refresh(ctx, auth)
		if errRefresh != nil {
			return nil, errRefresh
		}
		if updated != nil {
			updated.UpdatedAt = time.Now()
			// 这里是主动刷新，需要持久化，不能使用 WithSkipPersist。
			if m.coreManager != nil {
				_, _ = m.coreManager.Update(ctx, updated)
			}
			auth = updated
			accessToken = metaStringValueLocal(auth.Metadata, "access_token")
		}
	}
	accessToken = strings.TrimSpace(accessToken)
	if accessToken == "" {
		return nil, fmt.Errorf("missing access token")
	}

	httpClient := executorNewHTTPClient(ctx, m.cfg, auth)

	var lastErr error
	for idx, baseURL := range baseURLs {
		base := strings.TrimSuffix(strings.TrimSpace(baseURL), "/")
		if base == "" {
			continue
		}
		url := base + "/v1internal:fetchAvailableModels"
		req, errReq := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
		if errReq != nil {
			return nil, errReq
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", resolveQuotaUserAgent(auth))
		req.Header.Set("Authorization", "Bearer "+accessToken)

		resp, errDo := httpClient.Do(req)
		if errDo != nil {
			lastErr = errDo
			if errors.Is(errDo, context.Canceled) || errors.Is(errDo, context.DeadlineExceeded) {
				return nil, errDo
			}
			if idx+1 < len(baseURLs) {
				continue
			}
			return nil, errDo
		}

		body, errRead := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if errRead != nil {
			lastErr = errRead
			if idx+1 < len(baseURLs) {
				continue
			}
			return nil, errRead
		}
		if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
			lastErr = fmt.Errorf("upstream status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
			if resp.StatusCode == http.StatusTooManyRequests && idx+1 < len(baseURLs) {
				continue
			}
			if idx+1 < len(baseURLs) {
				continue
			}
			return nil, lastErr
		}

		raw := json.RawMessage(append([]byte(nil), body...))
		parsed := make(map[string]any)
		if err := json.Unmarshal(raw, &parsed); err != nil {
			// 解析失败也要保留 raw，供调用方排查
			parsed = nil
		}
		sum := sha256.Sum256(raw)
		// 使用配置中的 cache-ttl。
		_, _, cacheTTL, _, _ := m.quotaCfgSnapshot()
		snap := &AntigravityQuotaSnapshot{
			AuthID:    auth.ID,
			FetchedAt: time.Now().UTC(),
			BaseURL:   base,
			Raw:       raw,
			Parsed:    parsed,
			RawSHA256: hex.EncodeToString(sum[:]),
			ExpiresAt: time.Now().Add(cacheTTL),
		}
		return snap, nil
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, fmt.Errorf("no base url available")
}

// resolveQuotaBaseURLFallbackOrder 决定 quota 拉取时的 baseURL 顺序。
//
// 重要：这里不复用 executor.antigravityBaseURLFallbackOrder（其默认不包含 Prod），
// 以避免改变现有请求执行链路行为。
func resolveQuotaBaseURLFallbackOrder(auth *coreauth.Auth) []string {
	if base := resolveCustomAntigravityBaseURL(auth); base != "" {
		return []string{base}
	}
	return []string{
		"https://cloudcode-pa.googleapis.com",
		"https://daily-cloudcode-pa.googleapis.com",
		"https://daily-cloudcode-pa.sandbox.googleapis.com",
	}
}

func resolveCustomAntigravityBaseURL(auth *coreauth.Auth) string {
	if auth == nil {
		return ""
	}
	if auth.Attributes != nil {
		if v := strings.TrimSpace(auth.Attributes["base_url"]); v != "" {
			return strings.TrimSuffix(v, "/")
		}
	}
	if auth.Metadata != nil {
		if v, ok := auth.Metadata["base_url"].(string); ok {
			v = strings.TrimSpace(v)
			if v != "" {
				return strings.TrimSuffix(v, "/")
			}
		}
	}
	return ""
}

func resolveQuotaUserAgent(auth *coreauth.Auth) string {
	if auth != nil {
		if auth.Attributes != nil {
			if ua := strings.TrimSpace(auth.Attributes["user_agent"]); ua != "" {
				return ua
			}
		}
		if auth.Metadata != nil {
			if ua, ok := auth.Metadata["user_agent"].(string); ok && strings.TrimSpace(ua) != "" {
				return strings.TrimSpace(ua)
			}
		}
	}
	// 与 executor 中 defaultAntigravityAgent 保持一致，但不直接引用未导出常量。
	return "antigravity/1.104.0"
}

// executorNewHTTPClient 复用 executor 的代理优先级策略。
//
// 为什么不直接调用 internal/runtime/executor.newProxyAwareHTTPClient：
// - 它是未导出函数。
// - 为避免在 quota 包里引入不必要的包内可见性耦合，这里采用等价策略：
//   1) auth.ProxyURL
//   2) cfg.ProxyURL
//   3) ctx 中 cliproxy.roundtripper
func executorNewHTTPClient(ctx context.Context, cfg *config.Config, auth *coreauth.Auth) *http.Client {
	client := &http.Client{}

	// 直接复用 executor 包内部策略会更好，但受限于未导出；此处仅保留核心优先级。
	proxyURL := ""
	if auth != nil {
		proxyURL = strings.TrimSpace(auth.ProxyURL)
	}
	if proxyURL == "" && cfg != nil {
		proxyURL = strings.TrimSpace(cfg.ProxyURL)
	}
	if proxyURL != "" {
		transport := buildProxyTransport(proxyURL)
		if transport != nil {
			client.Transport = transport
		}
	}
	if client.Transport == nil {
		if rt, ok := ctx.Value("cliproxy.roundtripper").(http.RoundTripper); ok && rt != nil {
			client.Transport = rt
		}
	}
	return client
}

func tokenExpiryLocal(metadata map[string]any) time.Time {
	if metadata == nil {
		return time.Time{}
	}
	if expStr, ok := metadata["expired"].(string); ok {
		expStr = strings.TrimSpace(expStr)
		if expStr != "" {
			if parsed, errParse := time.Parse(time.RFC3339, expStr); errParse == nil {
				return parsed
			}
		}
	}
	expiresIn, hasExpires := int64ValueLocal(metadata["expires_in"])
	tsMs, hasTimestamp := int64ValueLocal(metadata["timestamp"])
	if hasExpires && hasTimestamp {
		return time.Unix(0, tsMs*int64(time.Millisecond)).Add(time.Duration(expiresIn) * time.Second)
	}
	return time.Time{}
}

func metaStringValueLocal(metadata map[string]any, key string) string {
	if metadata == nil {
		return ""
	}
	if v, ok := metadata[key]; ok {
		switch typed := v.(type) {
		case string:
			return strings.TrimSpace(typed)
		case []byte:
			return strings.TrimSpace(string(typed))
		}
	}
	return ""
}

func int64ValueLocal(value any) (int64, bool) {
	switch typed := value.(type) {
	case int:
		return int64(typed), true
	case int64:
		return typed, true
	case float64:
		return int64(typed), true
	case json.Number:
		if i, errParse := typed.Int64(); errParse == nil {
			return i, true
		}
	case string:
		trimmed := strings.TrimSpace(typed)
		if trimmed == "" {
			return 0, false
		}
		if i, errParse := strconv.ParseInt(trimmed, 10, 64); errParse == nil {
			return i, true
		}
	}
	return 0, false
}

// buildProxyTransport 创建支持 socks5/http/https 的 transport（与 executor/proxy_helpers.go 保持一致的优先级行为）。
func buildProxyTransport(proxyURL string) *http.Transport {
	proxyURL = strings.TrimSpace(proxyURL)
	if proxyURL == "" {
		return nil
	}
	parsedURL, errParse := url.Parse(proxyURL)
	if errParse != nil {
		return nil
	}
	if parsedURL.Scheme == "socks5" {
		var proxyAuth *proxy.Auth
		if parsedURL.User != nil {
			username := parsedURL.User.Username()
			password, _ := parsedURL.User.Password()
			proxyAuth = &proxy.Auth{User: username, Password: password}
		}
		dialer, errSOCKS5 := proxy.SOCKS5("tcp", parsedURL.Host, proxyAuth, proxy.Direct)
		if errSOCKS5 != nil {
			return nil
		}
		return &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return dialer.Dial(network, addr)
			},
		}
	}
	if parsedURL.Scheme == "http" || parsedURL.Scheme == "https" {
		return &http.Transport{Proxy: http.ProxyURL(parsedURL)}
	}
	return nil
}
