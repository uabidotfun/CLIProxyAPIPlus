# Backend 结构

> 更新时间: 2026-02-07

## 入口点

### cmd/server/main.go

应用程序启动和 CLI 参数处理:

```
命令行标志:
-login                 # Google/Gemini OAuth
-claude-login          # Claude OAuth
-codex-login           # OpenAI Codex OAuth
-kiro-login            # Kiro (Google OAuth)
-kiro-aws-authcode     # Kiro (AWS Builder ID)
-github-copilot-login  # GitHub Copilot
-qwen-login            # Qwen OAuth
-iflow-login           # iFlow OAuth
-vertex-import         # Vertex AI 凭证导入
-config                # 自定义配置文件路径
```

## SDK 层 (公共 API)

### sdk/cliproxy/service.go

**Service 结构体** - 核心服务生命周期管理

```go
type Service struct {
    cfg              *config.Config
    authManager      *sdkAuth.Manager
    accessManager    *sdkaccess.Manager
    coreManager      *coreauth.Manager
    server           *api.Server
    watcher          *WatcherWrapper
    wsGateway        *wsrelay.Manager
    antigravityQuota *quota.AntigravityQuotaManager
}
```

主要方法:
- `NewService()` - 初始化服务
- `Start()` - 启动 HTTP 服务器
- `Stop()` - 优雅关闭
- `Reload()` - 热重载配置

### sdk/cliproxy/auth/conductor.go

**Manager** - 核心认证协调器 (2261 行)

```go
type Manager struct {
    executors map[string]ProviderExecutor
    selector  Selector
    store     Store
    hooks     []Hook
}
```

职责:
- 执行器注册和生命周期管理
- 凭证选择策略 (round-robin/fill-first)
- 请求执行和错误处理
- 认证状态管理

### sdk/cliproxy/auth/selector.go

凭证选择策略:
- `RoundRobinSelector` - 轮询分配
- `FillFirstSelector` - 填满优先

### sdk/access/manager.go

请求认证管理:
- API Key 验证
- Bearer Token 验证
- 认证提供者链

### sdk/auth/manager.go

OAuth 和令牌管理:
- OAuth 流程处理
- 令牌存储和刷新
- 多后端支持

### sdk/translator/

格式转换接口:
- `RequestTransform` - 请求翻译
- `ResponseStreamTransform` - 流式响应翻译
- `ResponseNonStreamTransform` - 非流式响应翻译

## Internal 层 (私有实现)

### internal/api/

HTTP 服务器实现:

```
internal/api/
├── server.go           # Gin 服务器配置
├── handlers/           # API 端点处理器
│   ├── chat.go         # /v1/chat/completions
│   ├── models.go       # /v1/models
│   └── management/     # 管理 API
├── middleware/         # 中间件
│   ├── auth.go         # 认证中间件
│   └── logging.go      # 日志中间件
└── modules/            # 可插拔模块
    └── amp/            # Amp CLI 集成
```

### internal/auth/

各提供商认证实现:

```
internal/auth/
├── gemini/       # Google Gemini OAuth
├── claude/       # Anthropic Claude OAuth
├── codex/        # OpenAI Codex OAuth
├── copilot/      # GitHub Copilot (Device Flow)
├── kiro/         # AWS CodeWhisperer
├── vertex/       # GCP Vertex AI
├── antigravity/  # Antigravity
├── kimi/         # Kimi
├── qwen/         # 通义千问
├── iflow/        # iFlow
└── empty/        # 空提供商 (测试)
```

### internal/runtime/executor/

执行器实现:

| 文件 | 行数 | 提供商 |
|------|------|--------|
| kiro_executor.go | 4101 | AWS CodeWhisperer |
| antigravity_executor.go | 1598 | Antigravity |
| claude_executor.go | 1270 | Claude |
| gemini_vertex_executor.go | 1070 | Vertex AI |
| codex_executor.go | ~800 | OpenAI Codex |
| copilot_executor.go | ~600 | GitHub Copilot |

执行器接口:
```go
type ProviderExecutor interface {
    Identifier() string
    Execute(ctx, auth, req, opts) (Response, error)
    ExecuteStream(ctx, auth, req, opts) (<-chan StreamChunk, error)
    Refresh(ctx, auth) (*Auth, error)
    CountTokens(ctx, auth, req, opts) (Response, error)
    HttpRequest(ctx, auth, req) (*http.Response, error)
}
```

### internal/translator/

翻译器实现:

```
internal/translator/
├── antigravity/  # Antigravity ↔ OpenAI
├── claude/       # Claude ↔ OpenAI
├── codex/        # Codex ↔ OpenAI
├── gemini/       # Gemini ↔ OpenAI
├── gemini-cli/   # Gemini CLI ↔ OpenAI
├── kiro/         # Kiro ↔ OpenAI
└── openai/       # OpenAI 标准化
```

### internal/config/config.go

配置结构 (1834 行):

```go
type Config struct {
    Host                   string
    Port                   int
    TLS                    TLSConfig
    AuthDir                string
    Debug                  bool
    GeminiKey              []GeminiKey
    KiroKey                []KiroKey
    CodexKey               []CodexKey
    ClaudeKey              []ClaudeKey
    Routing                RoutingConfig
    QuotaExceeded          QuotaExceeded
    OAuthModelAlias        map[string][]OAuthModelAlias
    OAuthExcludedModels    map[string][]string
    // ...
}
```

### internal/watcher/

热重载系统:

```
internal/watcher/
├── watcher.go        # fsnotify 文件监控
├── dispatcher.go     # 事件分发
├── config_reload.go  # 配置重载逻辑
├── diff/             # 配置差异计算
│   ├── config_diff.go
│   ├── auth_diff.go
│   └── model_hash.go
└── synthesizer/      # 配置合成
    ├── config.go
    ├── file.go
    └── helpers.go
```

### internal/store/

存储后端实现:

| 文件 | 后端 | 环境变量 |
|------|------|----------|
| file_store.go | 本地文件 | - |
| postgres_store.go | PostgreSQL | `PGSTORE_DSN` |
| git_store.go | Git 仓库 | `GITSTORE_GIT_URL` |
| object_store.go | S3 兼容 | `OBJECTSTORE_*` |

### internal/quota/

配额管理:

- `AntigravityQuotaManager` (982 行)
- 配额快照缓存
- 定期轮询和持久化
- 配额超限检测
- 自动冷却机制

## 管理 API

```
/v0/management/
├── config        GET/POST    # 配置管理
├── auth          GET/DELETE  # 令牌管理
├── usage         GET         # 使用统计
├── quota         GET/POST    # 配额管理
├── models        GET         # 模型列表
└── oauth/callback            # OAuth 回调
```

## 依赖关系

```
cmd/server
    ↓
sdk/cliproxy (Service)
    ├─→ sdk/access
    ├─→ sdk/auth
    ├─→ sdk/cliproxy/auth (Manager)
    │       └─→ internal/runtime/executor
    ├─→ sdk/translator
    │       └─→ internal/translator
    ├─→ internal/api
    ├─→ internal/watcher
    ├─→ internal/config
    └─→ internal/store
```
