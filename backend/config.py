"""
配置管理模块
初次启动时生成默认配置文件供修改
"""

import os
import secrets
import yaml
from pathlib import Path
from typing import Any, Literal
from pydantic import BaseModel, Field, field_validator
from pydantic_settings import BaseSettings


CONFIG_FILE = Path("config.yaml")


class DatabaseConfig(BaseModel):
    """数据库配置"""
    type: Literal["sqlite", "postgresql"] = "sqlite"
    # SQLite 配置
    sqlite_path: str = "data/idp.db"
    # PostgreSQL 配置 (版本 14+)
    pg_host: str = "localhost"
    pg_port: int = 5432
    pg_user: str = "postgres"
    pg_password: str = ""
    pg_database: str = "oneidp"


class BotConfig(BaseModel):
    """机器人配置"""
    # WebSocket 客户端模式（主动连接）
    ws_client_enabled: bool = False
    ws_client_url: str = "ws://127.0.0.1:6700"
    ws_client_access_token: str = ""
    
    # WebSocket 服务端模式（被动接收连接）
    ws_server_enabled: bool = True
    ws_server_host: str = "0.0.0.0"
    ws_server_port: int = 8001
    ws_server_access_token: str = ""
    
    # 机器人通用配置
    command_prefix: str = "/sso"
    allowed_groups: list[int] = Field(default_factory=list)  # 空列表表示所有群
    admin_users: list[int] = Field(default_factory=list)  # 管理员QQ号


class SSOClientConfig(BaseModel):
    """SSO 客户端配置（用于绑定流程，本项目作为客户端）"""
    enabled: bool = True
    provider_name: str = "SSO"
    # 使用 OpenID Connect Discovery 自动配置
    use_wellknown: bool = False
    wellknown_url: str = ""  # 例如: https://sso.example.com/.well-known/openid-configuration
    # 手动配置（use_wellknown=false 时使用）
    authorization_url: str = "https://sso.example.com/application/o/authorize/"
    token_url: str = "https://sso.example.com/application/o/token/"
    userinfo_url: str = "https://sso.example.com/application/o/userinfo/"
    client_id: str = ""
    client_secret: str = ""
    redirect_uri: str = "http://localhost:8000/callback"
    scope: str = "email openid profile"


class OAuthProviderConfig(BaseModel):
    """OAuth 提供者配置（本项目作为 IDP 提供者）"""
    enabled: bool = True
    issuer: str = "http://localhost:8000"
    # 授权码有效期（秒）
    auth_code_expire: int = 300
    # 访问令牌有效期（秒）
    access_token_expire: int = 3600
    # 刷新令牌有效期（秒）
    refresh_token_expire: int = 86400 * 30
    # 验证码长度
    verification_code_length: int = 6
    # 验证码有效期（秒）
    verification_code_expire: int = 300


class OAuthClient(BaseModel):
    """OAuth 客户端（注册的 RP）"""
    client_id: str
    client_secret: str
    name: str = "未命名应用"
    redirect_uris: list[str] = Field(default_factory=list)
    allowed_scopes: list[str] = Field(default_factory=lambda: ["uin", "openid"])
    
    @field_validator("allowed_scopes")
    @classmethod
    def validate_scopes(cls, v: list[str]) -> list[str]:
        if "uin" not in v:
            v.insert(0, "uin")
        return v


class BindingConfig(BaseModel):
    """绑定配置"""
    # 要存储的用户信息字段
    stored_fields: list[str] = Field(
        default_factory=lambda: ["sub", "email", "preferred_username"]
    )
    # 是否存储绑定时间
    store_bind_time: bool = True
    # 绑定链接有效期（秒）
    bind_link_expire: int = 300


class ServerConfig(BaseModel):
    """服务器配置"""
    host: str = "0.0.0.0"
    port: int = 8000
    debug: bool = False
    # 用于加密的密钥
    secret_key: str = Field(default_factory=lambda: secrets.token_urlsafe(32))
    # 外部访问地址
    external_url: str = "http://localhost:8000"


class Config(BaseModel):
    """主配置"""
    server: ServerConfig = Field(default_factory=ServerConfig)
    database: DatabaseConfig = Field(default_factory=DatabaseConfig)
    bot: BotConfig = Field(default_factory=BotConfig)
    sso_client: SSOClientConfig = Field(default_factory=SSOClientConfig)
    oauth_provider: OAuthProviderConfig = Field(default_factory=OAuthProviderConfig)
    oauth_clients: list[OAuthClient] = Field(default_factory=list)
    binding: BindingConfig = Field(default_factory=BindingConfig)


def generate_default_config() -> Config:
    """生成默认配置"""
    config = Config()
    # 添加一个示例 OAuth 客户端
    example_client = OAuthClient(
        client_id="example_client_id",
        client_secret="example_client_secret_change_me",
        name="示例应用",
        redirect_uris=["http://localhost:3000/callback"],
        allowed_scopes=["uin", "openid", "email", "preferred_username"]
    )
    config.oauth_clients.append(example_client)
    return config


def load_config() -> Config:
    """加载配置文件，如果不存在则创建默认配置"""
    if not CONFIG_FILE.exists():
        config = generate_default_config()
        save_config(config)
        print(f"已生成默认配置文件: {CONFIG_FILE.absolute()}")
        print("请修改配置文件后重新启动程序")
        return config
    
    with open(CONFIG_FILE, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    
    return Config.model_validate(data)


def save_config(config: Config) -> None:
    """保存配置到文件"""
    CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
    
    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        yaml.dump(
            config.model_dump(),
            f,
            default_flow_style=False,
            allow_unicode=True,
            sort_keys=False
        )


# 全局配置实例
_config: Config | None = None


def get_config() -> Config:
    """获取配置实例"""
    global _config
    if _config is None:
        _config = load_config()
    return _config


def reload_config() -> Config:
    """重新加载配置"""
    global _config
    _config = load_config()
    return _config
