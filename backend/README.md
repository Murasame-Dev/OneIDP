# OneIDP

基于 Onebot-V11 协议的 IDP 提供者，帮助 QQ 群群友绑定 SSO 账号并完成登录授权。

## 功能特性

- **SSO 账号绑定**：QQ 用户可通过机器人命令绑定 SSO 账号
- **OAuth 2.0 IDP**：作为身份提供者，支持第三方应用通过 OAuth 2.0 获取用户授权
- **双向 WebSocket**：支持客户端模式（主动连接）和服务端模式（被动接收连接）
- **多数据库支持**：支持 SQLite 和 PostgreSQL (14+)
- **安全特性**：PKCE、速率限制、安全头、输入验证

## 快速开始

### 环境要求

- Python 3.11+
- [uv](https://github.com/astral-sh/uv) 包管理器

### 安装

```bash
cd backend
uv sync
```

### 启动

```bash
uv run python main.py
```

首次运行会自动生成 `config.yaml` 配置文件，请根据实际情况修改后重新启动。

## 机器人命令

| 命令 | 说明 |
|------|------|
| `/sso bind <用户名>` | 绑定 SSO 账号 |
| `/sso unbind <用户名>` | 发起解绑请求 |
| `/sso unbind confirm` | 确认解绑 |
| `/sso auth <验证码>` | 批准 OAuth 授权请求 |
| `/sso cancel` | 取消当前操作 |
| `/sso status` | 查看绑定状态 |
| `/sso help` | 显示帮助信息 |

## OAuth 2.0 端点

| 端点 | 说明 |
|------|------|
| `GET /oauth/authorize` | 授权端点 |
| `POST /oauth/token` | 令牌端点 |
| `GET /oauth/userinfo` | 用户信息端点 |
| `POST /oauth/revoke` | 令牌撤销端点 |
| `GET /oauth/.well-known/openid-configuration` | OIDC 发现端点 |

## 配置文件说明

配置文件 `config.yaml` 会在首次运行时自动生成，以下是完整的配置示例及说明：

```yaml
# ============================================
# OneIDP 配置文件
# 请根据实际情况修改以下配置
# ============================================

# ==================== 服务器配置 ====================
server:
  # 监听地址，0.0.0.0 表示监听所有网卡
  host: 0.0.0.0
  # 监听端口
  port: 8000
  # 调试模式，生产环境请设为 false
  debug: false
  # 加密密钥，用于签名 JWT 等，请勿泄露！
  # 建议使用随机生成的 32 字节 base64 字符串
  secret_key: your_secret_key_here
  # 外部访问地址，用于生成回调链接
  external_url: http://localhost:8000

# ==================== 数据库配置 ====================
database:
  # 数据库类型: sqlite 或 postgresql
  type: sqlite
  
  # --- SQLite 配置 ---
  sqlite_path: data/idp.db
  
  # --- PostgreSQL 配置 (版本 14+) ---
  pg_host: localhost
  pg_port: 5432
  pg_user: postgres
  pg_password: ''
  pg_database: oneidp

# ==================== 机器人配置 ====================
bot:
  # --- WebSocket 客户端模式 ---
  # 主动连接到 OneBot 实现（如 go-cqhttp、Lagrange 等）
  ws_client_enabled: true
  # OneBot WebSocket 地址
  ws_client_url: ws://127.0.0.1:6700
  # 访问令牌（如果 OneBot 实现设置了的话）
  ws_client_access_token: ''
  
  # --- WebSocket 服务端模式 ---
  # 被动接收 OneBot 实现的连接
  ws_server_enabled: false
  ws_server_host: 0.0.0.0
  ws_server_port: 8080
  ws_server_access_token: ''
  
  # 命令前缀，用户需要以此开头发送命令
  command_prefix: /sso
  # 允许使用的群号列表，空列表表示所有群都可用
  allowed_groups: []
  # 管理员 QQ 号列表
  admin_users: []

# ==================== SSO 客户端配置 ====================
# 用于绑定流程，本项目作为客户端向 SSO 请求用户信息
# 需要在你的 SSO 服务（如 Authentik、Keycloak 等）中注册应用
sso_client:
  # 是否启用绑定功能
  enabled: true
  # SSO 提供者名称（用于显示）
  provider_name: SSO
  
  # --- OIDC 自动发现配置（推荐） ---
  # 启用后，将通过 /.well-known/openid-configuration 自动获取端点配置
  # 开启此选项后，下方的 authorization_url、token_url、userinfo_url 将被忽略
  use_wellknown: true
  # OIDC 发现端点地址
  # 例如: https://sso.example.com/.well-known/openid-configuration
  # 或 Authentik: https://sso.example.com/application/o/<app>/.well-known/openid-configuration
  wellknown_url: https://sso.example.com/.well-known/openid-configuration
  
  # --- 手动端点配置 ---
  # 仅在 use_wellknown: false 时使用
  # SSO 授权端点
  authorization_url: https://sso.example.com/application/o/authorize/
  # SSO 令牌端点
  token_url: https://sso.example.com/application/o/token/
  # SSO 用户信息端点
  userinfo_url: https://sso.example.com/application/o/userinfo/
  
  # --- 客户端凭证配置 ---
  # 在 SSO 注册的客户端 ID
  client_id: ''
  # 在 SSO 注册的客户端密钥
  client_secret: ''
  # 回调地址，需要在 SSO 中配置允许
  # 格式: {external_url}/callback
  redirect_uri: http://localhost:8000/callback
  # 请求的权限范围
  scope: email openid profile

# ==================== OAuth 提供者配置 ====================
# 本项目作为 IDP 提供者的配置
oauth_provider:
  # 是否启用 IDP 功能
  enabled: true
  # 签发者标识（通常是本服务的外部 URL）
  issuer: http://localhost:8000
  # 授权码有效期（秒），默认 5 分钟
  auth_code_expire: 300
  # 访问令牌有效期（秒），默认 1 小时
  access_token_expire: 3600
  # 刷新令牌有效期（秒），默认 30 天
  refresh_token_expire: 2592000
  # 验证码长度，用于用户在 QQ 中确认授权
  verification_code_length: 6
  # 验证码有效期（秒），默认 5 分钟
  verification_code_expire: 300

# ==================== OAuth 客户端列表 ====================
# 注册的 RP（依赖方）应用列表
# 这些是要通过本 IDP 进行登录的第三方应用
oauth_clients:
  # ----- 示例应用 -----
  - client_id: example_client_id
    # 客户端密钥，请修改为安全的随机字符串！
    client_secret: example_client_secret_change_me
    # 应用显示名称
    name: 示例应用
    # 允许的回调地址列表
    redirect_uris:
      - http://localhost:3000/callback
    # 允许请求的权限范围
    # 可选: uin, openid, email, profile, preferred_username
    allowed_scopes:
      - uin
      - openid
      - email
      - preferred_username

# ==================== 绑定配置 ====================
binding:
  # 要存储到数据库的用户信息字段（从 SSO 获取）
  # 可选值取决于 SSO 返回的用户信息
  stored_fields:
    - sub
    - email
    - preferred_username
  # 是否存储绑定时间
  store_bind_time: true
  # 绑定链接有效期（秒），默认 5 分钟
  bind_link_expire: 300
```

## 流程说明

### 绑定流程

```
用户 ──/sso bind 用户名──> 机器人
                              │
                              ▼
                        生成绑定链接
                              │
                              ▼
用户 <────返回授权链接───── 机器人
  │
  │ 点击链接
  ▼
SSO 服务 ──授权──> 回调到本服务
                       │
                       ▼
                  保存绑定信息
                       │
                       ▼
                  显示绑定成功页面
```

### 授权流程（本项目作为 IDP）

```
第三方应用 ──重定向──> /oauth/authorize
                            │
                            ▼
                      显示授权页面
                      (含验证码)
                            │
用户 ──/sso auth 验证码──> 机器人
                            │
                            ▼
                        批准授权
                            │
                            ▼
第三方应用 <──授权码回调──  本服务
      │
      │ POST /oauth/token
      ▼
获取访问令牌和用户信息
```

## 数据库表结构

| 表名 | 说明 |
|------|------|
| `bind_user` | 绑定用户表 |
| `authorization_log` | 授权日志表 |
| `unbind_log` | 解绑日志表 |
| `pending_bind` | 待绑定请求表 |
| `pending_auth` | 待授权请求表 |
| `pending_unbind` | 待解绑请求表 |
| `oauth_token` | OAuth 令牌表 |

## 项目结构

```
backend/
├── main.py              # 主入口文件
├── config.py            # 配置管理
├── config.yaml          # 配置文件（自动生成）
├── bot/                 # 机器人模块
│   ├── websocket.py     # WebSocket 连接管理
│   └── handlers.py      # 命令处理器
├── database/            # 数据库模块
│   ├── models.py        # 数据模型
│   ├── session.py       # 会话管理
│   └── crud.py          # CRUD 操作
├── oauth/               # OAuth 模块
│   ├── client.py        # OAuth 客户端（绑定用）
│   └── provider.py      # OAuth 提供者（IDP）
├── page/                # 页面路由
│   ├── routes.py        # 通用页面
│   └── oauth_routes.py  # OAuth 端点
└── utils/               # 工具模块
    └── security.py      # 安全工具
```

## 安全特性

- **PKCE 支持**：支持 `S256` 和 `plain` 方法
- **速率限制**：授权、令牌、绑定等端点有请求频率限制
- **安全头**：自动添加 HSTS、X-Frame-Options 等安全头
- **输入验证**：严格验证所有用户输入
- **常量时间比较**：防止时序攻击

## 许可证

MIT License
