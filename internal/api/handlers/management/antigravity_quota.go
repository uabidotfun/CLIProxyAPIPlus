package management

import (
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/quota"
)

// buildQuotaItem 构造统一的配额 item 结构。
// 始终返回 parsed（成功时为 object，失败/nil 时为 null）和 raw（始终返回，便于排查）。
func buildQuotaItem(snap *quota.AntigravityQuotaSnapshot) gin.H {
	if snap == nil {
		return gin.H{
			"auth_id": "",
			"parsed":  nil,
		}
	}
	item := gin.H{
		"auth_id": snap.AuthID,
		"parsed":  snap.Parsed, // 可能为 nil
	}
	if !snap.FetchedAt.IsZero() {
		item["fetched_at"] = snap.FetchedAt.UTC().Format(time.RFC3339)
	}
	if !snap.ExpiresAt.IsZero() {
		item["expires_at"] = snap.ExpiresAt.UTC().Format(time.RFC3339)
	}
	if strings.TrimSpace(snap.BaseURL) != "" {
		item["base_url"] = strings.TrimSpace(snap.BaseURL)
	}
	if strings.TrimSpace(snap.RawSHA256) != "" {
		item["raw_sha256"] = strings.TrimSpace(snap.RawSHA256)
	}
	if !snap.PersistAt.IsZero() {
		item["persisted_at"] = snap.PersistAt.UTC().Format(time.RFC3339)
	}
	if strings.TrimSpace(snap.LastErrStr) != "" {
		item["error"] = strings.TrimSpace(snap.LastErrStr)
	}
	// 始终返回 raw（若有），便于在 Parsed=nil 时排查。
	if len(snap.Raw) > 0 {
		item["raw"] = snap.Raw
	}
	return item
}

// GetAntigravityQuota 返回所有 antigravity auth 的配额快照。
//
// Query:
// - force_refresh=1：强制刷新（绕过内存 TTL）
// - persist=1：将快照写回 auth.Metadata 并持久化到 auth 文件
func (h *Handler) GetAntigravityQuota(c *gin.Context) {
	qm := quota.GetGlobalAntigravityQuotaManager()
	if qm == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "antigravity quota manager unavailable"})
		return
	}
	force := strings.TrimSpace(c.Query("force_refresh")) == "1"
	persist := strings.TrimSpace(c.Query("persist")) == "1"

	ctx := c.Request.Context()
	res, err := qm.RefreshAll(ctx, force, persist)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// 返回 []quotaItem 格式（不丢弃 Parsed=nil 的条目）。
	items := make([]gin.H, 0, len(res))
	for _, snap := range res {
		if snap == nil {
			continue
		}
		items = append(items, buildQuotaItem(snap))
	}
	c.JSON(http.StatusOK, gin.H{"items": items})
}

// GetAntigravityQuotaByID 返回单个 auth 的配额快照。
func (h *Handler) GetAntigravityQuotaByID(c *gin.Context) {
	qm := quota.GetGlobalAntigravityQuotaManager()
	if qm == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "antigravity quota manager unavailable"})
		return
	}
	id := strings.TrimSpace(c.Param("id"))
	if id == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing id"})
		return
	}
	force := strings.TrimSpace(c.Query("force_refresh")) == "1"
	persist := strings.TrimSpace(c.Query("persist")) == "1"

	ctx := c.Request.Context()
	snap, err := qm.RefreshOne(ctx, id, force, persist)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if snap == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "quota snapshot not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"item": buildQuotaItem(snap)})
}

type refreshAntigravityQuotaRequest struct {
	AuthID  string `json:"auth_id"`
	Force   bool   `json:"force"`
	Persist bool   `json:"persist"`
}

// RefreshAntigravityQuota 手动触发刷新。
// Body: {"auth_id":""|"<id>", "force":true|false, "persist":true|false}
func (h *Handler) RefreshAntigravityQuota(c *gin.Context) {
	qm := quota.GetGlobalAntigravityQuotaManager()
	if qm == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "antigravity quota manager unavailable"})
		return
	}
	var req refreshAntigravityQuotaRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	ctx := c.Request.Context()
	id := strings.TrimSpace(req.AuthID)
	if id == "" {
		// 刷新全部。
		res, err := qm.RefreshAll(ctx, req.Force, req.Persist)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		// 不丢弃 Parsed=nil 的条目。
		items := make([]gin.H, 0, len(res))
		for _, snap := range res {
			if snap == nil {
				continue
			}
			items = append(items, buildQuotaItem(snap))
		}
		c.JSON(http.StatusOK, gin.H{"items": items})
		return
	}
	// 刷新单个。
	one, err := qm.RefreshOne(ctx, id, req.Force, req.Persist)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if one == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "quota snapshot not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"item": buildQuotaItem(one)})
}
