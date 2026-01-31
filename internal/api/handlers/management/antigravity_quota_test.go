package management

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/quota"
)

func init() {
	gin.SetMode(gin.TestMode)
}

// TestBuildQuotaItem_NilSnapshot 测试 nil snapshot 的处理。
func TestBuildQuotaItem_NilSnapshot(t *testing.T) {
	item := buildQuotaItem(nil)
	if item["auth_id"] != "" {
		t.Errorf("expected empty auth_id, got %v", item["auth_id"])
	}
	if item["parsed"] != nil {
		t.Errorf("expected nil parsed, got %v", item["parsed"])
	}
}

// TestBuildQuotaItem_WithParsedNil 测试 Parsed=nil 时仍返回 raw。
func TestBuildQuotaItem_WithParsedNil(t *testing.T) {
	snap := &quota.AntigravityQuotaSnapshot{
		AuthID:    "test-id",
		FetchedAt: time.Now().UTC(),
		ExpiresAt: time.Now().Add(10 * time.Minute).UTC(),
		BaseURL:   "https://example.com",
		Raw:       json.RawMessage(`{"invalid json`), // 故意的无效 JSON 使 Parsed 为 nil
		Parsed:    nil,                               // 显式设置为 nil
		RawSHA256: "abc123",
	}

	item := buildQuotaItem(snap)

	if item["auth_id"] != "test-id" {
		t.Errorf("expected auth_id=test-id, got %v", item["auth_id"])
	}
	// Parsed 可能是 nil 或空 map，都算正确
	if item["raw"] == nil {
		t.Error("expected raw to be present")
	}
	if item["base_url"] != "https://example.com" {
		t.Errorf("expected base_url=https://example.com, got %v", item["base_url"])
	}
}

// TestBuildQuotaItem_WithValidParsed 测试正常解析的情况。
func TestBuildQuotaItem_WithValidParsed(t *testing.T) {
	snap := &quota.AntigravityQuotaSnapshot{
		AuthID:    "test-id",
		FetchedAt: time.Now().UTC(),
		ExpiresAt: time.Now().Add(10 * time.Minute).UTC(),
		BaseURL:   "https://example.com",
		Raw:       json.RawMessage(`{"models":["a","b"]}`),
		Parsed:    map[string]any{"models": []any{"a", "b"}},
		RawSHA256: "abc123",
	}

	item := buildQuotaItem(snap)

	if item["auth_id"] != "test-id" {
		t.Errorf("expected auth_id=test-id, got %v", item["auth_id"])
	}
	if item["parsed"] == nil {
		t.Error("expected parsed to be non-nil")
	}
	if item["raw"] == nil {
		t.Error("expected raw to be present")
	}
}

// TestBuildQuotaItem_WithError 测试有错误时的情况。
func TestBuildQuotaItem_WithError(t *testing.T) {
	snap := &quota.AntigravityQuotaSnapshot{
		AuthID:     "test-id",
		FetchedAt:  time.Now().UTC(),
		LastErrStr: "connection timeout",
	}

	item := buildQuotaItem(snap)

	if item["error"] != "connection timeout" {
		t.Errorf("expected error='connection timeout', got %v", item["error"])
	}
}

// TestGetAntigravityQuota_ManagerUnavailable 测试 quota manager 不可用时的响应。
func TestGetAntigravityQuota_ManagerUnavailable(t *testing.T) {
	// 确保全局 manager 为 nil。
	quota.SetGlobalAntigravityQuotaManager(nil)

	h := &Handler{}
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/v0/management/antigravity/quota", nil)

	h.GetAntigravityQuota(c)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("expected status 503, got %d", w.Code)
	}

	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if resp["error"] == nil {
		t.Error("expected error in response")
	}
}

// TestGetAntigravityQuotaByID_MissingID 测试缺少 ID 参数时的响应。
func TestGetAntigravityQuotaByID_MissingID(t *testing.T) {
	// 需要设置一个 quota manager（即使是 mock）才能进入 ID 检查。
	// 由于 handler 先检查 quota manager，需要设置一个有效的 manager。
	cfg := &config.Config{}
	qm := quota.NewAntigravityQuotaManager(cfg, nil)
	quota.SetGlobalAntigravityQuotaManager(qm)
	defer quota.SetGlobalAntigravityQuotaManager(nil)

	h := &Handler{}
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/v0/management/antigravity/quota/", nil)
	c.Params = gin.Params{{Key: "id", Value: ""}}

	h.GetAntigravityQuotaByID(c)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", w.Code)
	}
}

// TestRefreshAntigravityQuota_InvalidJSON 测试无效 JSON body 的响应。
func TestRefreshAntigravityQuota_InvalidJSON(t *testing.T) {
	// 需要设置一个 quota manager 才能进入 JSON 解析检查。
	cfg := &config.Config{}
	qm := quota.NewAntigravityQuotaManager(cfg, nil)
	quota.SetGlobalAntigravityQuotaManager(qm)
	defer quota.SetGlobalAntigravityQuotaManager(nil)

	h := &Handler{}
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, "/v0/management/antigravity/quota/refresh", strings.NewReader("invalid json"))
	c.Request.Header.Set("Content-Type", "application/json")

	h.RefreshAntigravityQuota(c)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", w.Code)
	}
}

// TestRefreshAntigravityQuota_ManagerUnavailable 测试 quota manager 不可用时的响应。
func TestRefreshAntigravityQuota_ManagerUnavailable(t *testing.T) {
	quota.SetGlobalAntigravityQuotaManager(nil)

	h := &Handler{}
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	body := `{"auth_id":"test","force":true,"persist":false}`
	c.Request = httptest.NewRequest(http.MethodPost, "/v0/management/antigravity/quota/refresh", strings.NewReader(body))
	c.Request.Header.Set("Content-Type", "application/json")

	h.RefreshAntigravityQuota(c)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("expected status 503, got %d", w.Code)
	}
}

// TestRefreshAntigravityQuota_EmptyAuthID_WithNilCoreManager 测试空 auth_id 且 core manager 为 nil 时返回错误。
func TestRefreshAntigravityQuota_EmptyAuthID_WithNilCoreManager(t *testing.T) {
	// 创建一个 quota manager，core manager 为 nil。
	cfg := &config.Config{
		AntigravityQuota: config.AntigravityQuotaConfig{
			Enabled:         false,
			CacheTTLSeconds: 600,
		},
	}
	qm := quota.NewAntigravityQuotaManager(cfg, nil)
	quota.SetGlobalAntigravityQuotaManager(qm)
	defer quota.SetGlobalAntigravityQuotaManager(nil)

	h := &Handler{}
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	body := `{"auth_id":"","force":true,"persist":false}`
	c.Request = httptest.NewRequest(http.MethodPost, "/v0/management/antigravity/quota/refresh", strings.NewReader(body))
	c.Request.Header.Set("Content-Type", "application/json")

	h.RefreshAntigravityQuota(c)

	// core manager 为 nil 时，应该返回错误。
	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected status 500, got %d, body: %s", w.Code, w.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if resp["error"] == nil {
		t.Error("expected error in response")
	}
	errStr, _ := resp["error"].(string)
	if !strings.Contains(errStr, "unavailable") {
		t.Errorf("expected error to contain 'unavailable', got: %s", errStr)
	}
}

// TestRefreshAntigravityQuota_SingleAuthID_NotFound 测试刷新不存在的单个 authID。
func TestRefreshAntigravityQuota_SingleAuthID_NotFound(t *testing.T) {
	// 创建一个 quota manager，core manager 为 nil。
	cfg := &config.Config{}
	qm := quota.NewAntigravityQuotaManager(cfg, nil)
	quota.SetGlobalAntigravityQuotaManager(qm)
	defer quota.SetGlobalAntigravityQuotaManager(nil)

	h := &Handler{}
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	body := `{"auth_id":"non-existent-id","force":true,"persist":false}`
	c.Request = httptest.NewRequest(http.MethodPost, "/v0/management/antigravity/quota/refresh", strings.NewReader(body))
	c.Request.Header.Set("Content-Type", "application/json")

	h.RefreshAntigravityQuota(c)

	// 由于 core manager 为 nil，应该返回 500 错误。
	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected status 500, got %d, body: %s", w.Code, w.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if resp["error"] == nil {
		t.Error("expected error in response")
	}
}

// TestGetAntigravityQuotaByID_NotFound 测试获取不存在的 authID。
func TestGetAntigravityQuotaByID_NotFound(t *testing.T) {
	cfg := &config.Config{}
	qm := quota.NewAntigravityQuotaManager(cfg, nil)
	quota.SetGlobalAntigravityQuotaManager(qm)
	defer quota.SetGlobalAntigravityQuotaManager(nil)

	h := &Handler{}
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/v0/management/antigravity/quota/non-existent", nil)
	c.Params = gin.Params{{Key: "id", Value: "non-existent"}}

	h.GetAntigravityQuotaByID(c)

	// 由于找不到 auth，应该返回 500 错误。
	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected status 500, got %d, body: %s", w.Code, w.Body.String())
	}
}

// TestGetAntigravityQuota_WithForceAndPersist 测试 query 参数解析。
func TestGetAntigravityQuota_WithForceAndPersist(t *testing.T) {
	cfg := &config.Config{
		AntigravityQuota: config.AntigravityQuotaConfig{
			Enabled:         false,
			CacheTTLSeconds: 600,
		},
	}
	qm := quota.NewAntigravityQuotaManager(cfg, nil)
	quota.SetGlobalAntigravityQuotaManager(qm)
	defer quota.SetGlobalAntigravityQuotaManager(nil)

	h := &Handler{}
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/v0/management/antigravity/quota?force_refresh=1&persist=1", nil)

	h.GetAntigravityQuota(c)

	// core manager 为 nil 时应该返回 500 错误。
	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected status 500, got %d, body: %s", w.Code, w.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if resp["error"] == nil {
		t.Error("expected error in response")
	}
}
