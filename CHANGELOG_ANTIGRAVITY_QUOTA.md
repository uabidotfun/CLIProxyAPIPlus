# Antigravity Quota 功能说明文档

## 功能概述

本次更新为 CLIProxyAPIPlus 新增了 **Antigravity Quota 配额管理** 功能，用于查询、缓存和持久化 Antigravity 服务的配额信息。同时优化了 Service 层的 auth 更新逻辑，避免 token/quota 刷新触发不必要的模型重拉。

---

## 一、新增功能

### 1.1 Antigravity Quota Manager

**文件位置：** `internal/quota/antigravity_quota_manager.go`

**功能描述：**
- 遍历所有 `provider=antigravity` 的 auth 凭证
- 调用上游 `/v1internal:fetchAvailableModels` 接口拉取配额和可用模型信息
- 支持内存缓存，带 TTL 过期机制
- 支持将配额快照写回 `auth.Metadata` 并持久化到 auth 文件
- 支持定期后台轮询（可配置开关）
- 支持并发控制和写回节流

**核心数据结构：**
```go
type AntigravityQuotaSnapshot struct {
    AuthID     string          // 关联的 auth ID
    FetchedAt  time.Time       // 拉取时间
    BaseURL    string          // 请求的 base URL
    Raw        json.RawMessage // 原始 JSON 响应（保留完整信息）
    Parsed     map[string]any  // 解析后的数据（便于内部逻辑使用）
    RawSHA256  string          // 原始数据的哈希（用于去重和节流）
    ExpiresAt  time.Time       // 缓存过期时间
    PersistAt  time.Time       // 最后持久化时间
    LastErrStr string          // 最后错误信息
}
```

**主要方法：**
| 方法 | 说明 |
|-----|------|
| `RefreshAll(ctx, force, persist)` | 刷新全部 antigravity auth 的配额 |
| `RefreshOne(ctx, authID, force, persist)` | 刷新单个 auth 的配额 |
| `GetSnapshot(authID)` | 获取缓存的配额快照（不触发刷新）|
| `ListSnapshots()` | 列出所有缓存的快照 |
| `Start()` | 启动后台轮询 |
| `Stop()` | 停止后台轮询 |

---

### 1.2 Management API 端点

**文件位置：** `internal/api/handlers/management/antigravity_quota.go`

新增以下 REST API 端点用于运行时管理配额：

| 方法 | 路径 | 说明 |
|-----|------|-----|
| GET | `/v0/management/antigravity/quota` | 获取所有 antigravity auth 的配额快照 |
| GET | `/v0/management/antigravity/quota/:id` | 获取指定 auth 的配额快照 |
| POST | `/v0/management/antigravity/quota/refresh` | 手动触发配额刷新 |

**Query 参数：**
- `force_refresh=1` - 强制刷新（绕过内存 TTL 缓存）
- `persist=1` - 将快照写回 auth.Metadata 并持久化到文件

**POST 请求体：**
```json
{
  "auth_id": "",           // 空字符串=刷新全部，指定 ID=刷新单个
  "force": true,           // 是否强制刷新
  "persist": false         // 是否持久化
}
```

**响应示例：**
```json
{
  "items": [
    {
      "auth_id": "xxx-xxx-xxx",
      "parsed": { "models": [...], "quotaInfo": {...} },
      "raw": {...},
      "fetched_at": "2025-01-30T00:00:00Z",
      "expires_at": "2025-01-30T00:10:00Z",
      "base_url": "https://api.example.com",
      "raw_sha256": "abc123..."
    }
  ]
}
```

---

### 1.3 配置项

**文件位置：** `internal/config/config.go`

新增 `antigravity-quota` 配置节：

```yaml
antigravity-quota:
  enabled: false                 # 是否启用后台轮询（默认关闭）
  poll-interval: 1800            # 轮询间隔，单位秒（默认 30 分钟）
  cache-ttl: 600                 # 缓存 TTL，单位秒（默认 10 分钟）
  concurrency: 4                 # 并发刷新数量（默认 4）
```

**边界值钳制：**
- `poll-interval`: 10 ~ 86400 秒
- `cache-ttl`: 30 ~ 86400 秒
- `concurrency`: 1 ~ 32

---

## 二、功能优化

### 2.1 Service 层模型注册优化

**文件位置：** `sdk/cliproxy/service.go`

**问题背景：**
当 auth 文件的 metadata 发生变化（如 token 刷新、quota 写回）时，文件 watcher 会触发 auth 更新。原有逻辑会无条件调用 `registerModelsForAuth`，导致 antigravity 重新拉取模型列表，形成 "写回 → 触发 → 重拉" 的循环。

**解决方案：**
新增 `shouldRegisterModels(existing, next)` 函数，精细化判断是否需要重新拉取模型：

**触发重拉的条件：**
- 新增 auth（`existing == nil`）
- `Provider` 变化
- `Prefix` 变化
- `Disabled` 状态变化
- `base_url` 变化
- 非白名单 metadata 字段变化

**白名单字段（不触发重拉）：**
- Token 相关：`access_token`, `refresh_token`, `expires_in`, `timestamp`, `expired`, `expires_at`, `last_refresh`
- Quota 相关：所有以 `antigravity_quota` 开头的字段

---

### 2.2 AMP Proxy 空指针保护

**文件位置：** `internal/api/modules/amp/proxy.go`

**问题：** `ModifyResponse` 函数在记录日志时直接访问 `resp.Request.Method`，但某些边界情况下 `resp.Request` 可能为 nil，导致 panic。

**修复：**
```go
method := ""
path := ""
if resp.Request != nil {
    method = resp.Request.Method
    if resp.Request.URL != nil {
        path = resp.Request.URL.Path
    }
}
```

---

## 三、API 路由注册

**文件位置：** `internal/api/server.go`

在 Management API 路由组下新增：
```go
mgmt.GET("/antigravity/quota", s.mgmt.GetAntigravityQuota)
mgmt.GET("/antigravity/quota/:id", s.mgmt.GetAntigravityQuotaByID)
mgmt.POST("/antigravity/quota/refresh", s.mgmt.RefreshAntigravityQuota)
```

---

## 四、Service 层集成

**文件位置：** `sdk/cliproxy/service.go`

Service 结构体新增字段：
```go
// antigravityQuota 提供 antigravity 配额查询/缓存能力。
antigravityQuota *quota.AntigravityQuotaManager
```

新增公开方法供外部调用：
```go
// GetAntigravityQuota 返回指定 authID 的配额快照（不触发刷新）
func (s *Service) GetAntigravityQuota(authID string) (map[string]any, bool)

// RefreshAntigravityQuota 刷新指定 authID 的配额快照
func (s *Service) RefreshAntigravityQuota(ctx context.Context, authID string, force, persist bool) (map[string]any, error)

// RefreshAllAntigravityQuota 刷新全部 antigravity auth 的配额快照
func (s *Service) RefreshAllAntigravityQuota(ctx context.Context, force, persist bool) (map[string]map[string]any, error)
```

---

## 五、文件变更清单

| 文件 | 变更类型 | 说明 |
|-----|---------|------|
| `internal/quota/antigravity_quota_manager.go` | 新增 | Quota Manager 核心实现 |
| `internal/api/handlers/management/antigravity_quota.go` | 新增 | Management API Handler |
| `internal/config/config.go` | 修改 | 新增 AntigravityQuotaConfig 配置结构 |
| `internal/api/server.go` | 修改 | 注册新的 API 路由 |
| `sdk/cliproxy/service.go` | 修改 | 集成 Quota Manager，优化模型注册逻辑 |
| `internal/api/modules/amp/proxy.go` | 修改 | 修复空指针问题 |

---

## 六、使用示例

### 6.1 通过 Management API 查询配额

```bash
# 获取所有 antigravity auth 的配额
curl -X GET "http://localhost:8080/v0/management/antigravity/quota" \
  -H "Authorization: Bearer <secret-key>"

# 强制刷新并持久化
curl -X GET "http://localhost:8080/v0/management/antigravity/quota?force_refresh=1&persist=1" \
  -H "Authorization: Bearer 123456"

# 获取指定 auth 的配额
curl -X GET "http://localhost:8080/v0/management/antigravity/quota/<auth-id>" \
  -H "Authorization: Bearer <secret-key>"

# 手动触发刷新
curl -X POST "http://localhost:8080/v0/management/antigravity/quota/refresh" \
  -H "Authorization: Bearer <secret-key>" \
  -H "Content-Type: application/json" \
  -d '{"auth_id":"<auth-id>","force":true,"persist":true}'
```

### 6.2 配置示例

```yaml
# config.yaml
antigravity-quota:
  enabled: true          # 启用后台轮询
  poll-interval: 1800    # 每 30 分钟轮询一次
  cache-ttl: 600         # 缓存 10 分钟
  concurrency: 4         # 并发 4 个请求
```
