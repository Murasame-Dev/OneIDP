"""
数据库模型定义
"""

from datetime import datetime
from typing import Optional
from sqlalchemy import String, BigInteger, Boolean, DateTime, Text, JSON, Index
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    """基础模型类"""
    pass


class BindUser(Base):
    """绑定用户表"""
    __tablename__ = "bind_user"
    
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    # QQ号
    uin: Mapped[int] = mapped_column(BigInteger, unique=True, nullable=False, index=True)
    # SSO 唯一标识符
    sub: Mapped[str] = mapped_column(String(256), unique=True, nullable=False, index=True)
    # 邮箱
    email: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)
    # 首选用户名
    preferred_username: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)
    # 额外存储的字段（JSON格式）
    extra_data: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    # 绑定时间
    bind_time: Mapped[datetime] = mapped_column(
        DateTime, 
        nullable=False, 
        default=datetime.utcnow
    )
    # 是否有效
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    
    __table_args__ = (
        Index("ix_bind_user_uin_active", "uin", "is_active"),
    )


class AuthorizationLog(Base):
    """授权日志表"""
    __tablename__ = "authorization_log"
    
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    # QQ号
    uin: Mapped[int] = mapped_column(BigInteger, nullable=False, index=True)
    # 客户端ID
    client_id: Mapped[str] = mapped_column(String(256), nullable=False, index=True)
    # 授权地址（redirect_uri）
    address: Mapped[str] = mapped_column(Text, nullable=False)
    # 授权域
    scope: Mapped[str] = mapped_column(String(512), nullable=False)
    # 授权时间
    authorization_time: Mapped[datetime] = mapped_column(
        DateTime,
        nullable=False,
        default=datetime.utcnow
    )
    # 授权是否成功
    is_success: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    # 客户端 IP
    client_ip: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    # 用户代理
    user_agent: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    
    __table_args__ = (
        Index("ix_auth_log_uin_time", "uin", "authorization_time"),
    )


class UnbindLog(Base):
    """解绑日志表"""
    __tablename__ = "unbind_log"
    
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    # QQ号
    uin: Mapped[int] = mapped_column(BigInteger, nullable=False, index=True)
    # 解绑用户名
    unbind_user: Mapped[str] = mapped_column(String(256), nullable=False)
    # 原 sub
    sub: Mapped[str] = mapped_column(String(256), nullable=False)
    # 绑定时间
    bind_time: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    # 解绑请求时间
    unbind_request_time: Mapped[datetime] = mapped_column(
        DateTime,
        nullable=False,
        default=datetime.utcnow
    )
    # 解绑确认时间
    unbind_time: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    # 是否成功解绑
    is_unbind: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    # 解绑原因（confirm/timeout/cancel）
    reason: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    
    __table_args__ = (
        Index("ix_unbind_log_uin_time", "uin", "unbind_request_time"),
    )


class PendingBind(Base):
    """待绑定请求表（用于存储绑定流程中的状态）"""
    __tablename__ = "pending_bind"
    
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    # 状态令牌
    state: Mapped[str] = mapped_column(String(128), unique=True, nullable=False, index=True)
    # QQ号
    uin: Mapped[int] = mapped_column(BigInteger, nullable=False, index=True)
    # 请求的用户名
    username: Mapped[str] = mapped_column(String(256), nullable=False)
    # 创建时间
    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        nullable=False,
        default=datetime.utcnow
    )
    # 过期时间
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    # 是否已使用
    is_used: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    # 来源（group/private）
    source_type: Mapped[str] = mapped_column(String(16), nullable=False)
    # 来源ID（群号或QQ号）
    source_id: Mapped[int] = mapped_column(BigInteger, nullable=False)


class PendingAuth(Base):
    """待授权请求表（用于存储授权流程中的状态）"""
    __tablename__ = "pending_auth"
    
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    # 验证码
    verification_code: Mapped[str] = mapped_column(String(32), unique=True, nullable=False, index=True)
    # OAuth 授权码
    auth_code: Mapped[str] = mapped_column(String(128), unique=True, nullable=False, index=True)
    # 客户端ID
    client_id: Mapped[str] = mapped_column(String(256), nullable=False, index=True)
    # 重定向URI
    redirect_uri: Mapped[str] = mapped_column(Text, nullable=False)
    # 请求的scope
    scope: Mapped[str] = mapped_column(String(512), nullable=False)
    # state 参数
    state: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)
    # code_challenge (PKCE)
    code_challenge: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)
    # code_challenge_method (PKCE)
    code_challenge_method: Mapped[Optional[str]] = mapped_column(String(16), nullable=True)
    # 绑定用户ID
    bind_user_id: Mapped[int] = mapped_column(nullable=False)
    # QQ号
    uin: Mapped[int] = mapped_column(BigInteger, nullable=False, index=True)
    # 创建时间
    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        nullable=False,
        default=datetime.utcnow
    )
    # 过期时间
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    # 是否已批准
    is_approved: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    # 是否已使用（授权码已兑换）
    is_used: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    # 客户端IP
    client_ip: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    # 用户代理
    user_agent: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)


class PendingUnbind(Base):
    """待解绑请求表"""
    __tablename__ = "pending_unbind"
    
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    # QQ号
    uin: Mapped[int] = mapped_column(BigInteger, nullable=False, index=True)
    # 请求的用户名
    username: Mapped[str] = mapped_column(String(256), nullable=False)
    # 绑定用户ID
    bind_user_id: Mapped[int] = mapped_column(nullable=False)
    # 创建时间
    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        nullable=False,
        default=datetime.utcnow
    )
    # 过期时间
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    # 是否已处理
    is_processed: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    # 来源类型
    source_type: Mapped[str] = mapped_column(String(16), nullable=False)
    # 来源ID
    source_id: Mapped[int] = mapped_column(BigInteger, nullable=False)


class OAuthToken(Base):
    """OAuth 令牌表"""
    __tablename__ = "oauth_token"
    
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    # 访问令牌
    access_token: Mapped[str] = mapped_column(String(512), unique=True, nullable=False, index=True)
    # 刷新令牌
    refresh_token: Mapped[Optional[str]] = mapped_column(String(512), unique=True, nullable=True, index=True)
    # 令牌类型
    token_type: Mapped[str] = mapped_column(String(32), default="Bearer", nullable=False)
    # 客户端ID
    client_id: Mapped[str] = mapped_column(String(256), nullable=False, index=True)
    # 绑定用户ID
    bind_user_id: Mapped[int] = mapped_column(nullable=False)
    # QQ号
    uin: Mapped[int] = mapped_column(BigInteger, nullable=False, index=True)
    # scope
    scope: Mapped[str] = mapped_column(String(512), nullable=False)
    # 创建时间
    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        nullable=False,
        default=datetime.utcnow
    )
    # 访问令牌过期时间
    access_token_expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    # 刷新令牌过期时间
    refresh_token_expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    # 是否已撤销
    is_revoked: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
