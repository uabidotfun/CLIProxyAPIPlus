# 数据模型和 Schema

> 更新时间: 2026-02-07

## 配置模型

### Config (internal/config/config.go)

主配置结构:

```go
type Config struct {
    // 服务器配置
    Host    string  `yaml:"host"`
    Port    int     `yaml:"port"`
    TLS     TLSConfig `yaml:"tls"`

    // 认证配置
    AuthDir     string   `yaml:"auth-dir"`
    APIKeys     []string `yaml:"api-keys"`
    SecretKey   string   `yaml:"secret-key"`

    // 提供商密钥
    GeminiKey   []GeminiKey   `yaml:"gemini-api-key"`
    KiroKey     []KiroKey     `yaml:"kiro-api-key"`
    CodexKey    []CodexKey    `yaml:"codex-api-key"`
    ClaudeKey   []ClaudeKey   `yaml:"claude-api-key"`

    // 路由配置
    Routing     RoutingConfig `yaml:"routing"`
    ForceModelPrefix bool `yaml:"force-model-prefix"`

    // 配额配置
    QuotaExceeded QuotaExceeded `yaml:"quota-exceeded"`

    // 模型映射
    OAuthModelAlias     map[string][]OAuthModelAlias `yaml:"oauth-model-mappings"`
    OAuthExcludedModels map[string][]string `yaml:"oauth-excluded-models"`

    // OpenAI 兼容配置
    OpenAICompatibility []OpenAICompatibility `yaml:"openai-compatibility"`

    // 远程管理
    RemoteManagement RemoteManagementConfig `yaml:"remote-management"`
}
```

### RoutingConfig

```go
type RoutingConfig struct {
    Strategy string `yaml:"strategy"` // "round-robin" | "fill-first"
}
```

### QuotaExceeded

```go
type QuotaExceeded struct {
    Behavior string `yaml:"behavior"` // "fail-fast" | "skip-model" | "skip-auth"
}
```

### TLSConfig

```go
type TLSConfig struct {
    Enabled  bool   `yaml:"enabled"`
    CertFile string `yaml:"cert-file"`
    KeyFile  string `yaml:"key-file"`
}
```

## 认证模型

### Auth (internal/auth/models.go)

通用认证结构:

```go
type Auth struct {
    ID           string    `json:"id"`
    Type         string    `json:"type"`
    AccessToken  string    `json:"access_token"`
    RefreshToken string    `json:"refresh_token,omitempty"`
    ExpiresAt    time.Time `json:"expires_at"`
    Metadata     map[string]interface{} `json:"metadata,omitempty"`
}
```

### TokenStore 接口

```go
type TokenStore interface {
    Load(authID string) ([]byte, error)
    Save(authID string, data []byte) error
    Delete(authID string) error
    List() ([]string, error)
}
```

### 提供商特定认证

#### GeminiAuth

```go
type GeminiAuth struct {
    Auth
    ProjectID string `json:"project_id,omitempty"`
}
```

#### ClaudeAuth

```go
type ClaudeAuth struct {
    Auth
    SessionID string `json:"session_id,omitempty"`
}
```

#### KiroAuth

```go
type KiroAuth struct {
    Auth
    AWSCredentials AWSCredentials `json:"aws_credentials"`
}

type AWSCredentials struct {
    AccessKeyID     string    `json:"access_key_id"`
    SecretAccessKey string    `json:"secret_access_key"`
    SessionToken    string    `json:"session_token"`
    Expiration      time.Time `json:"expiration"`
}
```

#### CopilotAuth

```go
type CopilotAuth struct {
    Auth
    DeviceCode string `json:"device_code,omitempty"`
    UserCode   string `json:"user_code,omitempty"`
}
```

## API 请求/响应模型

### ChatCompletionRequest (OpenAI 格式)

```go
type ChatCompletionRequest struct {
    Model            string          `json:"model"`
    Messages         []Message       `json:"messages"`
    Temperature      *float64        `json:"temperature,omitempty"`
    TopP             *float64        `json:"top_p,omitempty"`
    N                *int            `json:"n,omitempty"`
    Stream           bool            `json:"stream,omitempty"`
    Stop             []string        `json:"stop,omitempty"`
    MaxTokens        *int            `json:"max_tokens,omitempty"`
    PresencePenalty  *float64        `json:"presence_penalty,omitempty"`
    FrequencyPenalty *float64        `json:"frequency_penalty,omitempty"`
    Tools            []Tool          `json:"tools,omitempty"`
    ToolChoice       interface{}     `json:"tool_choice,omitempty"`
}
```

### Message

```go
type Message struct {
    Role       string      `json:"role"` // "system" | "user" | "assistant" | "tool"
    Content    interface{} `json:"content"` // string | []ContentPart
    Name       string      `json:"name,omitempty"`
    ToolCalls  []ToolCall  `json:"tool_calls,omitempty"`
    ToolCallID string      `json:"tool_call_id,omitempty"`
}
```

### ChatCompletionResponse

```go
type ChatCompletionResponse struct {
    ID                string   `json:"id"`
    Object            string   `json:"object"`
    Created           int64    `json:"created"`
    Model             string   `json:"model"`
    Choices           []Choice `json:"choices"`
    Usage             Usage    `json:"usage"`
    SystemFingerprint string   `json:"system_fingerprint,omitempty"`
}
```

### StreamChunk (SSE 格式)

```go
type StreamChunk struct {
    ID      string        `json:"id"`
    Object  string        `json:"object"`
    Created int64         `json:"created"`
    Model   string        `json:"model"`
    Choices []DeltaChoice `json:"choices"`
}
```

## 配额模型

### QuotaSnapshot

```go
type QuotaSnapshot struct {
    AuthID       string    `json:"auth_id"`
    Provider     string    `json:"provider"`
    Used         int64     `json:"used"`
    Limit        int64     `json:"limit"`
    ResetAt      time.Time `json:"reset_at"`
    LastUpdated  time.Time `json:"last_updated"`
    CooldownUntil time.Time `json:"cooldown_until,omitempty"`
}
```

## 使用统计模型

### UsageRecord

```go
type UsageRecord struct {
    Timestamp      time.Time `json:"timestamp"`
    AuthID         string    `json:"auth_id"`
    Provider       string    `json:"provider"`
    Model          string    `json:"model"`
    PromptTokens   int       `json:"prompt_tokens"`
    CompletionTokens int     `json:"completion_tokens"`
    TotalTokens    int       `json:"total_tokens"`
    Latency        int64     `json:"latency_ms"`
    Success        bool      `json:"success"`
    ErrorCode      string    `json:"error_code,omitempty"`
}
```

## 存储 Schema

### PostgreSQL (internal/store/postgres_store.go)

```sql
CREATE TABLE IF NOT EXISTS tokens (
    auth_id VARCHAR(255) PRIMARY KEY,
    data JSONB NOT NULL,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_tokens_updated_at ON tokens(updated_at);
```

### 文件系统结构

```
auths/
├── gemini/
│   ├── auth_001.json
│   └── auth_002.json
├── claude/
│   └── auth_001.json
├── copilot/
│   └── auth_001.json
└── kiro/
    └── auth_001.json
```

## 配置文件示例

### config.yaml

```yaml
host: "0.0.0.0"
port: 8317

# API 密钥 (用于客户端认证)
api-keys:
  - "sk-your-api-key"

# 提供商配置
gemini-api-key:
  - key: "your-gemini-api-key"

claude-api-key:
  - key: "your-claude-api-key"

# 路由策略
routing:
  strategy: "round-robin"  # 或 "fill-first"

# 配额超限行为
quota-exceeded:
  behavior: "skip-model"  # 或 "fail-fast" | "skip-auth"

# 模型别名
oauth-model-mappings:
  gemini:
    - from: "gpt-4"
      to: "gemini-pro"

# 排除的模型
oauth-excluded-models:
  gemini:
    - "gemini-ultra"

# 远程管理 API
remote-management:
  enabled: true
  localhost-only: true
```
