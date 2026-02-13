# CLIProxyAPI Plus 架构概览

> 更新时间: 2026-02-07

## 项目概述

**类型**: Go API 代理服务器
**版本**: Plus (第三方提供商扩展版)
**代码规模**: ~118,763 行 Go 代码，426 个源文件

## 核心架构

```
┌─────────────────────────────────────────────────────────────────┐
│                         客户端请求                               │
│                    (OpenAI 兼容 API 格式)                        │
└────────────────────────────┬────────────────────────────────────┘
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│                      Gin HTTP 服务器                             │
│                  internal/api/server.go                          │
├─────────────────────────────────────────────────────────────────┤
│  中间件链: 认证 → 日志 → 限流 → 路由                              │
└────────────────────────────┬────────────────────────────────────┘
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│                    三层认证架构                                   │
├─────────────────────────────────────────────────────────────────┤
│ L1: 请求认证 (sdk/access)     - API Key / Bearer Token 验证      │
│ L2: OAuth 管理 (sdk/auth)      - OAuth 流程和令牌存储            │
│ L3: 核心认证 (sdk/cliproxy/auth) - 凭证选择和执行协调            │
└────────────────────────────┬────────────────────────────────────┘
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│                      翻译器管道                                   │
│                   sdk/translator                                  │
├─────────────────────────────────────────────────────────────────┤
│ 请求翻译: OpenAI → 提供商格式                                     │
│ 响应翻译: 提供商格式 → OpenAI                                     │
└────────────────────────────┬────────────────────────────────────┘
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│                      执行器层                                     │
│              internal/runtime/executor                            │
├─────────────────────────────────────────────────────────────────┤
│ Gemini │ Claude │ Codex │ Copilot │ Kiro │ Vertex │ ...         │
└─────────────────────────────────────────────────────────────────┘
```

## 目录结构

```
CLIProxyAPIPlus/
├── cmd/server/          # 入口点，CLI 参数处理
├── sdk/                 # 公共 SDK 包
│   ├── access/          # 请求认证管理
│   ├── api/             # API 处理器基础
│   ├── auth/            # OAuth 操作
│   ├── cliproxy/        # 核心服务生命周期
│   │   └── auth/        # 凭证选择和执行
│   └── translator/      # 格式转换接口
├── internal/            # 私有实现
│   ├── api/             # HTTP 服务器和处理器
│   │   ├── handlers/    # API 端点处理器
│   │   ├── middleware/  # 认证/日志中间件
│   │   └── modules/     # 可插拔模块 (Amp)
│   ├── auth/            # 各提供商认证实现
│   ├── config/          # 配置加载和解析
│   ├── runtime/         # 执行器实现
│   ├── translator/      # 翻译器实现
│   ├── watcher/         # 热重载系统
│   ├── store/           # 令牌存储后端
│   └── quota/           # 配额管理
├── auths/               # OAuth 令牌存储
├── logs/                # 日志文件
└── config.yaml          # 主配置文件
```

## 关键组件

### 1. Service (sdk/cliproxy/service.go)

服务生命周期管理器，协调所有子系统:
- 配置加载和热重载
- 认证管理器初始化
- HTTP 服务器启动
- 文件监控系统

### 2. Manager (sdk/cliproxy/auth/conductor.go)

核心认证和执行协调器 (2261 行):
- 执行器注册和管理
- 凭证选择策略
- 请求执行和响应处理
- 生命周期钩子

### 3. 执行器 (internal/runtime/executor/)

各提供商的 API 客户端实现:
- `kiro_executor.go` (4101 行) - AWS CodeWhisperer
- `antigravity_executor.go` (1598 行)
- `claude_executor.go` (1270 行)
- `gemini_vertex_executor.go` (1070 行)

### 4. 翻译器 (internal/translator/)

API 格式转换:
- OpenAI ↔ Gemini
- OpenAI ↔ Claude
- OpenAI ↔ Kiro
- 工具调用和思维链处理

## 请求流程

1. **请求到达** → Gin 路由匹配
2. **认证验证** → API Key / Bearer Token
3. **模型路由** → 前缀解析 / 别名映射
4. **凭证选择** → Round-robin / Fill-first
5. **请求翻译** → OpenAI → 提供商格式
6. **执行请求** → 调用提供商 API
7. **响应翻译** → 提供商 → OpenAI 格式
8. **返回客户端** → SSE 流式 / JSON 响应

## 支持的提供商

| 提供商 | 目录 | 认证方式 |
|--------|------|----------|
| Gemini | internal/auth/gemini/ | Google OAuth |
| Claude | internal/auth/claude/ | Anthropic OAuth |
| Codex | internal/auth/codex/ | OpenAI OAuth |
| Copilot | internal/auth/copilot/ | GitHub Device Flow |
| Kiro | internal/auth/kiro/ | AWS Builder ID |
| Vertex | internal/auth/vertex/ | GCP Service Account |
| Antigravity | internal/auth/antigravity/ | Google OAuth |
| Kimi | internal/auth/kimi/ | OAuth |
| Qwen | internal/auth/qwen/ | OAuth |
| iFlow | internal/auth/iflow/ | OAuth |

## 存储后端

| 类型 | 文件 | 配置 |
|------|------|------|
| 文件系统 | 默认 | `auth-dir` |
| PostgreSQL | internal/store/postgres_store.go | `PGSTORE_DSN` |
| Git | internal/store/git_store.go | `GITSTORE_GIT_URL` |
| S3 | internal/store/object_store.go | `OBJECTSTORE_*` |

## 设计模式

- **策略模式**: 凭证选择器、存储后端
- **工厂模式**: 执行器和翻译器创建
- **观察者模式**: 文件监控和配置热重载
- **管道模式**: 翻译器链
- **适配器模式**: 多提供商 API 统一
