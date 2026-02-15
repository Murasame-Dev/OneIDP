"""
数据库操作辅助函数
"""

from datetime import datetime, timedelta
from typing import Optional
from sqlalchemy import select, update, and_
from sqlalchemy.ext.asyncio import AsyncSession

from .models import (
    BindUser, 
    AuthorizationLog, 
    UnbindLog, 
    PendingBind, 
    PendingAuth,
    PendingUnbind,
    OAuthToken,
)


# ==================== 绑定用户操作 ====================

async def get_bind_user_by_uin(
    session: AsyncSession, 
    uin: int,
    active_only: bool = True
) -> Optional[BindUser]:
    """根据QQ号获取绑定用户"""
    query = select(BindUser).where(BindUser.uin == uin)
    if active_only:
        query = query.where(BindUser.is_active == True)
    result = await session.execute(query)
    return result.scalar_one_or_none()


async def get_bind_user_by_sub(
    session: AsyncSession, 
    sub: str,
    active_only: bool = True
) -> Optional[BindUser]:
    """根据 sub 获取绑定用户"""
    query = select(BindUser).where(BindUser.sub == sub)
    if active_only:
        query = query.where(BindUser.is_active == True)
    result = await session.execute(query)
    return result.scalar_one_or_none()


async def create_bind_user(
    session: AsyncSession,
    uin: int,
    sub: str,
    email: Optional[str] = None,
    preferred_username: Optional[str] = None,
    extra_data: Optional[dict] = None,
) -> BindUser:
    """创建绑定用户"""
    bind_user = BindUser(
        uin=uin,
        sub=sub,
        email=email,
        preferred_username=preferred_username,
        extra_data=extra_data,
        bind_time=datetime.utcnow(),
        is_active=True,
    )
    session.add(bind_user)
    await session.flush()
    return bind_user


async def deactivate_bind_user(
    session: AsyncSession,
    bind_user_id: int
) -> bool:
    """停用绑定用户"""
    result = await session.execute(
        update(BindUser)
        .where(BindUser.id == bind_user_id)
        .values(is_active=False)
    )
    return result.rowcount > 0


# ==================== 待绑定请求操作 ====================

async def create_pending_bind(
    session: AsyncSession,
    state: str,
    uin: int,
    username: str,
    source_type: str,
    source_id: int,
    expires_in: int = 300,
) -> PendingBind:
    """创建待绑定请求"""
    pending = PendingBind(
        state=state,
        uin=uin,
        username=username,
        created_at=datetime.utcnow(),
        expires_at=datetime.utcnow() + timedelta(seconds=expires_in),
        is_used=False,
        source_type=source_type,
        source_id=source_id,
    )
    session.add(pending)
    await session.flush()
    return pending


async def get_pending_bind_by_state(
    session: AsyncSession,
    state: str,
    valid_only: bool = True,
) -> Optional[PendingBind]:
    """根据状态码获取待绑定请求"""
    query = select(PendingBind).where(PendingBind.state == state)
    if valid_only:
        query = query.where(
            and_(
                PendingBind.is_used == False,
                PendingBind.expires_at > datetime.utcnow()
            )
        )
    result = await session.execute(query)
    return result.scalar_one_or_none()


async def mark_pending_bind_used(
    session: AsyncSession,
    pending_id: int
) -> bool:
    """标记待绑定请求为已使用"""
    result = await session.execute(
        update(PendingBind)
        .where(PendingBind.id == pending_id)
        .values(is_used=True)
    )
    return result.rowcount > 0


# ==================== 待授权请求操作 ====================

async def create_pending_auth(
    session: AsyncSession,
    verification_code: str,
    auth_code: str,
    client_id: str,
    redirect_uri: str,
    scope: str,
    bind_user_id: int,
    uin: int,
    state: Optional[str] = None,
    code_challenge: Optional[str] = None,
    code_challenge_method: Optional[str] = None,
    client_ip: Optional[str] = None,
    user_agent: Optional[str] = None,
    expires_in: int = 300,
) -> PendingAuth:
    """创建待授权请求"""
    pending = PendingAuth(
        verification_code=verification_code,
        auth_code=auth_code,
        client_id=client_id,
        redirect_uri=redirect_uri,
        scope=scope,
        state=state,
        code_challenge=code_challenge,
        code_challenge_method=code_challenge_method,
        bind_user_id=bind_user_id,
        uin=uin,
        created_at=datetime.utcnow(),
        expires_at=datetime.utcnow() + timedelta(seconds=expires_in),
        is_approved=False,
        is_used=False,
        client_ip=client_ip,
        user_agent=user_agent,
    )
    session.add(pending)
    await session.flush()
    return pending


async def get_pending_auth_by_code(
    session: AsyncSession,
    verification_code: str,
    valid_only: bool = True,
) -> Optional[PendingAuth]:
    """根据验证码获取待授权请求（包括待认领的请求 uin=0）"""
    query = select(PendingAuth).where(PendingAuth.verification_code == verification_code)
    if valid_only:
        query = query.where(
            and_(
                PendingAuth.is_used == False,
                PendingAuth.is_approved == False,  # 未批准的才能使用验证码
                PendingAuth.expires_at > datetime.utcnow()
            )
        )
    result = await session.execute(query)
    return result.scalar_one_or_none()


async def get_pending_auth_by_auth_code(
    session: AsyncSession,
    auth_code: str,
    valid_only: bool = True,
) -> Optional[PendingAuth]:
    """根据授权码获取待授权请求"""
    query = select(PendingAuth).where(PendingAuth.auth_code == auth_code)
    if valid_only:
        query = query.where(
            and_(
                PendingAuth.is_approved == True,
                PendingAuth.is_used == False,
                PendingAuth.expires_at > datetime.utcnow()
            )
        )
    result = await session.execute(query)
    return result.scalar_one_or_none()


async def approve_pending_auth(
    session: AsyncSession,
    pending_id: int
) -> bool:
    """批准待授权请求"""
    result = await session.execute(
        update(PendingAuth)
        .where(PendingAuth.id == pending_id)
        .values(is_approved=True)
    )
    return result.rowcount > 0


async def mark_pending_auth_used(
    session: AsyncSession,
    pending_id: int
) -> bool:
    """标记待授权请求为已使用"""
    result = await session.execute(
        update(PendingAuth)
        .where(PendingAuth.id == pending_id)
        .values(is_used=True)
    )
    return result.rowcount > 0


# ==================== 待解绑请求操作 ====================

async def create_pending_unbind(
    session: AsyncSession,
    uin: int,
    username: str,
    bind_user_id: int,
    source_type: str,
    source_id: int,
    expires_in: int = 300,
) -> PendingUnbind:
    """创建待解绑请求"""
    pending = PendingUnbind(
        uin=uin,
        username=username,
        bind_user_id=bind_user_id,
        created_at=datetime.utcnow(),
        expires_at=datetime.utcnow() + timedelta(seconds=expires_in),
        is_processed=False,
        source_type=source_type,
        source_id=source_id,
    )
    session.add(pending)
    await session.flush()
    return pending


async def get_pending_unbind_by_uin(
    session: AsyncSession,
    uin: int,
    valid_only: bool = True,
) -> Optional[PendingUnbind]:
    """根据QQ号获取待解绑请求"""
    query = select(PendingUnbind).where(PendingUnbind.uin == uin)
    if valid_only:
        query = query.where(
            and_(
                PendingUnbind.is_processed == False,
                PendingUnbind.expires_at > datetime.utcnow()
            )
        )
    result = await session.execute(query)
    return result.scalar_one_or_none()


async def mark_pending_unbind_processed(
    session: AsyncSession,
    pending_id: int
) -> bool:
    """标记待解绑请求为已处理"""
    result = await session.execute(
        update(PendingUnbind)
        .where(PendingUnbind.id == pending_id)
        .values(is_processed=True)
    )
    return result.rowcount > 0


# ==================== 授权日志操作 ====================

async def create_authorization_log(
    session: AsyncSession,
    uin: int,
    client_id: str,
    address: str,
    scope: str,
    is_success: bool = True,
    client_ip: Optional[str] = None,
    user_agent: Optional[str] = None,
) -> AuthorizationLog:
    """创建授权日志"""
    log = AuthorizationLog(
        uin=uin,
        client_id=client_id,
        address=address,
        scope=scope,
        authorization_time=datetime.utcnow(),
        is_success=is_success,
        client_ip=client_ip,
        user_agent=user_agent,
    )
    session.add(log)
    await session.flush()
    return log


# ==================== 解绑日志操作 ====================

async def create_unbind_log(
    session: AsyncSession,
    uin: int,
    unbind_user: str,
    sub: str,
    bind_time: datetime,
    is_unbind: bool,
    reason: str,
) -> UnbindLog:
    """创建解绑日志"""
    log = UnbindLog(
        uin=uin,
        unbind_user=unbind_user,
        sub=sub,
        bind_time=bind_time,
        unbind_request_time=datetime.utcnow(),
        unbind_time=datetime.utcnow() if is_unbind else None,
        is_unbind=is_unbind,
        reason=reason,
    )
    session.add(log)
    await session.flush()
    return log


# ==================== OAuth 令牌操作 ====================

async def create_oauth_token(
    session: AsyncSession,
    access_token: str,
    client_id: str,
    bind_user_id: int,
    uin: int,
    scope: str,
    access_token_expires_in: int,
    refresh_token: Optional[str] = None,
    refresh_token_expires_in: Optional[int] = None,
) -> OAuthToken:
    """创建 OAuth 令牌"""
    now = datetime.utcnow()
    token = OAuthToken(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="Bearer",
        client_id=client_id,
        bind_user_id=bind_user_id,
        uin=uin,
        scope=scope,
        created_at=now,
        access_token_expires_at=now + timedelta(seconds=access_token_expires_in),
        refresh_token_expires_at=(
            now + timedelta(seconds=refresh_token_expires_in)
            if refresh_token_expires_in else None
        ),
        is_revoked=False,
    )
    session.add(token)
    await session.flush()
    return token


async def get_token_by_access_token(
    session: AsyncSession,
    access_token: str,
    valid_only: bool = True,
) -> Optional[OAuthToken]:
    """根据访问令牌获取令牌记录"""
    query = select(OAuthToken).where(OAuthToken.access_token == access_token)
    if valid_only:
        query = query.where(
            and_(
                OAuthToken.is_revoked == False,
                OAuthToken.access_token_expires_at > datetime.utcnow()
            )
        )
    result = await session.execute(query)
    return result.scalar_one_or_none()


async def get_token_by_refresh_token(
    session: AsyncSession,
    refresh_token: str,
    valid_only: bool = True,
) -> Optional[OAuthToken]:
    """根据刷新令牌获取令牌记录"""
    query = select(OAuthToken).where(OAuthToken.refresh_token == refresh_token)
    if valid_only:
        query = query.where(
            and_(
                OAuthToken.is_revoked == False,
                OAuthToken.refresh_token_expires_at > datetime.utcnow()
            )
        )
    result = await session.execute(query)
    return result.scalar_one_or_none()


async def revoke_token(
    session: AsyncSession,
    token_id: int
) -> bool:
    """撤销令牌"""
    result = await session.execute(
        update(OAuthToken)
        .where(OAuthToken.id == token_id)
        .values(is_revoked=True)
    )
    return result.rowcount > 0


async def revoke_all_user_tokens(
    session: AsyncSession,
    uin: int,
    client_id: Optional[str] = None,
) -> int:
    """撤销用户的所有令牌"""
    query = update(OAuthToken).where(OAuthToken.uin == uin)
    if client_id:
        query = query.where(OAuthToken.client_id == client_id)
    query = query.values(is_revoked=True)
    result = await session.execute(query)
    return result.rowcount
