"""
OAuth 2.0 授权端点
本项目作为 IDP 提供者的 OAuth 接口
"""

import logging
import secrets
from datetime import datetime, timedelta
from typing import Optional
from urllib.parse import urlencode, urlparse, parse_qs

from fastapi import APIRouter, Request, HTTPException, Depends, Form, Header
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel

from config import get_config
from database.session import get_db
from database import crud
from database.models import BindUser
from oauth.provider import get_oauth_provider, TokenResponse, ErrorResponse
from bot.websocket import get_bot_manager
from utils.security import get_rate_limiter, RATE_LIMITS, validate_redirect_uri

logger = logging.getLogger(__name__)

oauth_router = APIRouter(prefix="/oauth")


def get_error_redirect(redirect_uri: str, error: str, description: str, state: Optional[str] = None) -> str:
    """构建错误重定向 URL"""
    params = {"error": error, "error_description": description}
    if state:
        params["state"] = state
    return f"{redirect_uri}?{urlencode(params)}"


def get_base_template(title: str, content: str) -> str:
    """获取基础 HTML 模板"""
    return f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
            padding: 20px;
        }}
        .container {{
            background: white;
            border-radius: 16px;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
            padding: 40px;
            max-width: 520px;
            width: 100%;
        }}
        .header {{ text-align: center; margin-bottom: 24px; }}
        .icon {{ font-size: 48px; margin-bottom: 16px; }}
        h1 {{ color: #2c3e50; font-size: 22px; margin-bottom: 8px; }}
        .subtitle {{ color: #7f8c8d; font-size: 14px; }}
        .app-info {{
            background: #f8f9fa;
            border-radius: 12px;
            padding: 20px;
            margin: 20px 0;
            text-align: center;
        }}
        .app-name {{ font-size: 18px; font-weight: 600; color: #2c3e50; }}
        .app-desc {{ color: #7f8c8d; font-size: 14px; margin-top: 4px; }}
        .scope-section {{ margin: 24px 0; }}
        .scope-title {{
            font-size: 14px;
            color: #7f8c8d;
            margin-bottom: 12px;
            padding-bottom: 8px;
            border-bottom: 1px solid #e9ecef;
        }}
        .scope-list {{ list-style: none; }}
        .scope-item {{
            display: flex;
            align-items: center;
            padding: 12px 0;
            border-bottom: 1px solid #f1f3f5;
        }}
        .scope-item:last-child {{ border-bottom: none; }}
        .scope-icon {{ font-size: 20px; margin-right: 12px; }}
        .scope-info {{ flex: 1; }}
        .scope-name {{ font-weight: 500; color: #2c3e50; }}
        .scope-value {{ font-size: 13px; color: #868e96; margin-top: 2px; }}
        .code-section {{
            background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
            border-radius: 12px;
            padding: 24px;
            text-align: center;
            margin: 24px 0;
            color: white;
        }}
        .code-label {{ font-size: 12px; opacity: 0.9; margin-bottom: 8px; }}
        .code-value {{
            font-family: 'Monaco', 'Consolas', monospace;
            font-size: 32px;
            letter-spacing: 6px;
            font-weight: 700;
        }}
        .code-hint {{ font-size: 12px; opacity: 0.8; margin-top: 8px; }}
        .warning {{
            background: #fff3cd;
            border: 1px solid #ffc107;
            border-radius: 8px;
            padding: 12px 16px;
            margin: 16px 0;
            font-size: 13px;
            color: #856404;
        }}
        .footer {{ text-align: center; margin-top: 24px; font-size: 12px; color: #adb5bd; }}
        .error {{ color: #e74c3c; }}
    </style>
</head>
<body>
    <div class="container">
        {content}
    </div>
</body>
</html>"""


@oauth_router.get("/authorize")
async def authorize(
    request: Request,
    client_id: str,
    redirect_uri: str,
    response_type: str,
    scope: str,
    state: Optional[str] = None,
    code_challenge: Optional[str] = None,
    code_challenge_method: Optional[str] = None,
    nonce: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
):
    """OAuth 2.0 授权端点"""
    # 速率限制检查
    limiter = get_rate_limiter()
    rule = RATE_LIMITS["authorize"]
    key = limiter.get_key(request, "authorize")
    allowed, retry_after = limiter.check(key, rule)
    if not allowed:
        raise HTTPException(
            status_code=429,
            detail="Too many requests",
            headers={"Retry-After": str(retry_after)}
        )
    
    config = get_config()
    provider = get_oauth_provider()
    
    # 基本输入验证
    if not validate_redirect_uri(redirect_uri):
        content = """
            <div class="header">
                <div class="icon error">⚠️</div>
                <h1>授权请求无效</h1>
                <p class="subtitle">重定向地址格式不正确</p>
            </div>
            <div class="footer">请联系应用开发者</div>
        """
        return HTMLResponse(get_base_template("授权错误", content), status_code=400)
    
    # 验证 response_type
    if response_type != "code":
        if redirect_uri:
            return RedirectResponse(
                get_error_redirect(redirect_uri, "unsupported_response_type", "Only 'code' response type is supported", state)
            )
        raise HTTPException(400, "unsupported_response_type")
    
    # 验证客户端
    valid, client, error = provider.validate_client(client_id, redirect_uri=redirect_uri)
    if not valid:
        if error == "invalid_redirect_uri":
            # redirect_uri 无效时不能重定向
            content = f"""
                <div class="header">
                    <div class="icon error">⚠️</div>
                    <h1>授权请求无效</h1>
                    <p class="subtitle">重定向地址未被允许</p>
                </div>
                <div class="footer">请联系应用开发者</div>
            """
            return HTMLResponse(get_base_template("授权错误", content), status_code=400)
        return RedirectResponse(
            get_error_redirect(redirect_uri, error, "Invalid client", state)
        )
    
    # 验证 scope
    scope_valid, scope_error = provider.validate_scope(scope, client)
    if not scope_valid:
        return RedirectResponse(
            get_error_redirect(redirect_uri, "invalid_scope", scope_error, state)
        )
    
    # 验证 PKCE（如果提供）
    if code_challenge:
        if code_challenge_method not in ["plain", "S256"]:
            return RedirectResponse(
                get_error_redirect(redirect_uri, "invalid_request", "Invalid code_challenge_method", state)
            )
    
    # 从 scope 中解析出需要的用户信息
    scopes = scope.split()
    
    # 生成验证码和授权码
    verification_code = provider.generate_verification_code()
    auth_code = provider.generate_auth_code()
    
    # 获取客户端信息
    client_ip = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")
    
    # 创建待授权请求（uin 为 0 表示等待用户认领）
    await crud.create_pending_auth(
        db,
        verification_code=verification_code,
        auth_code=auth_code,
        client_id=client_id,
        redirect_uri=redirect_uri,
        scope=scope,
        bind_user_id=0,  # 待认领
        uin=0,  # 待认领
        state=state,
        code_challenge=code_challenge,
        code_challenge_method=code_challenge_method,
        client_ip=client_ip,
        user_agent=user_agent,
        expires_in=config.oauth_provider.verification_code_expire,
    )
    
    # 构建 scope 显示信息
    scope_display = []
    scope_icons = {
        "uin": ("👤", "QQ 号", "你的 QQ 号码"),
        "openid": ("🔑", "身份标识", "唯一身份标识符"),
        "email": ("📧", "邮箱", "你的邮箱地址"),
        "profile": ("📝", "基本资料", "用户名、昵称等"),
        "preferred_username": ("🏷️", "用户名", "你的用户名"),
    }
    
    for s in scopes:
        if s in scope_icons:
            icon, name, desc = scope_icons[s]
            scope_display.append({"icon": icon, "name": name, "description": desc})
        else:
            scope_display.append({"icon": "📄", "name": s, "description": f"请求访问 {s}"})
    
    scope_items = "\n".join([
        f"""<li class="scope-item">
            <span class="scope-icon">{s['icon']}</span>
            <div class="scope-info">
                <div class="scope-name">{s['name']}</div>
                <div class="scope-value">{s['description']}</div>
            </div>
        </li>"""
        for s in scope_display
    ])
    
    expire_minutes = config.oauth_provider.verification_code_expire // 60
    
    content = f"""
        <div class="header">
            <div class="icon">🔐</div>
            <h1>授权请求</h1>
            <p class="subtitle">请在 QQ 中确认此授权</p>
        </div>
        
        <div class="app-info">
            <div class="app-name">{client.name}</div>
            <div class="app-desc">正在请求访问你的账号信息</div>
        </div>
        
        <div class="scope-section">
            <div class="scope-title">🎯 目标客户端想请求你的以下信息：</div>
            <ul class="scope-list">
                {scope_items}
            </ul>
        </div>
        
        <div class="code-section">
            <div class="code-label">请在 QQ 中发送以下命令批准授权</div>
            <div class="code-value">{verification_code}</div>
            <div class="code-hint">{config.bot.command_prefix} auth {verification_code}</div>
        </div>
        
        <div class="warning">
            ⏱️ 验证码将在 {expire_minutes} 分钟后过期。授权后，应用将能够访问上述信息。
        </div>
        
        <script>
            // 自动轮询检查授权状态
            const checkInterval = setInterval(async () => {{
                try {{
                    const response = await fetch('/oauth/authorize/check?verification_code={verification_code}');
                    const data = await response.json();
                    if (data.approved && data.redirect_uri) {{
                        clearInterval(checkInterval);
                        window.location.href = data.redirect_uri;
                    }}
                }} catch (e) {{
                    console.error('检查状态失败:', e);
                }}
            }}, 2000);
            
            // 5分钟后停止轮询
            setTimeout(() => clearInterval(checkInterval), {config.oauth_provider.verification_code_expire * 1000});
        </script>
        
        <div class="footer">
            如果你没有发起此请求，请忽略此页面
        </div>
    """
    
    return HTMLResponse(get_base_template("授权请求", content))


@oauth_router.get("/authorize/pending")
async def authorize_pending(
    request: Request,
    client_id: str,
    redirect_uri: str,
    scope: str,
    state: Optional[str] = None,
    code_challenge: Optional[str] = None,
    code_challenge_method: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
):
    """创建待授权请求并返回验证码（API 版本）"""
    config = get_config()
    provider = get_oauth_provider()
    
    # 验证客户端
    valid, client, error = provider.validate_client(client_id, redirect_uri=redirect_uri)
    if not valid:
        return JSONResponse({"error": error, "error_description": "Invalid client"}, status_code=400)
    
    # 验证 scope
    scope_valid, scope_error = provider.validate_scope(scope, client)
    if not scope_valid:
        return JSONResponse({"error": "invalid_scope", "error_description": scope_error}, status_code=400)
    
    # 生成验证码和授权码
    verification_code = provider.generate_verification_code()
    auth_code = provider.generate_auth_code()
    
    # 获取客户端信息
    client_ip = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")
    
    # 注意：此时我们还不知道是哪个用户，所以 uin 和 bind_user_id 先设为 0
    # 当用户在 QQ 中输入验证码时，会更新这些信息
    pending = await crud.create_pending_auth(
        db,
        verification_code=verification_code,
        auth_code=auth_code,
        client_id=client_id,
        redirect_uri=redirect_uri,
        scope=scope,
        bind_user_id=0,  # 待认领
        uin=0,  # 待认领
        state=state,
        code_challenge=code_challenge,
        code_challenge_method=code_challenge_method,
        client_ip=client_ip,
        user_agent=user_agent,
        expires_in=config.oauth_provider.verification_code_expire,
    )
    
    return JSONResponse({
        "verification_code": verification_code,
        "expires_in": config.oauth_provider.verification_code_expire,
        "message": f"请在 QQ 中发送: {config.bot.command_prefix} auth {verification_code}",
    })


@oauth_router.get("/authorize/check")
async def authorize_check(
    verification_code: str,
    db: AsyncSession = Depends(get_db),
):
    """检查授权状态"""
    pending = await crud.get_pending_auth_by_code(db, verification_code.upper(), valid_only=False)
    
    if not pending:
        return JSONResponse({"error": "not_found", "approved": False}, status_code=404)
    
    if pending.expires_at < datetime.utcnow():
        return JSONResponse({"error": "expired", "approved": False}, status_code=410)
    
    if pending.is_approved:
        # 已批准，返回授权码重定向
        params = {"code": pending.auth_code}
        if pending.state:
            params["state"] = pending.state
        redirect_url = f"{pending.redirect_uri}?{urlencode(params)}"
        return JSONResponse({
            "approved": True,
            "redirect_uri": redirect_url,
        })
    
    return JSONResponse({
        "approved": False,
        "pending": True,
    })


@oauth_router.post("/token")
async def token(
    request: Request,
    grant_type: str = Form(...),
    code: Optional[str] = Form(None),
    redirect_uri: Optional[str] = Form(None),
    client_id: Optional[str] = Form(None),
    client_secret: Optional[str] = Form(None),
    code_verifier: Optional[str] = Form(None),
    refresh_token: Optional[str] = Form(None),
    authorization: Optional[str] = Header(None),
    db: AsyncSession = Depends(get_db),
):
    """OAuth 2.0 令牌端点"""
    # 速率限制检查
    limiter = get_rate_limiter()
    rule = RATE_LIMITS["token"]
    key = limiter.get_key(request, "token")
    allowed, retry_after = limiter.check(key, rule)
    if not allowed:
        return JSONResponse(
            {"error": "rate_limit_exceeded", "error_description": "Too many requests"},
            status_code=429,
            headers={"Retry-After": str(retry_after)}
        )
    
    config = get_config()
    provider = get_oauth_provider()
    
    # 支持 Basic Auth 提取 client credentials
    if authorization and authorization.startswith("Basic "):
        import base64
        try:
            decoded = base64.b64decode(authorization[6:]).decode("utf-8")
            if ":" in decoded:
                client_id, client_secret = decoded.split(":", 1)
        except Exception:
            pass
    
    if not client_id:
        return JSONResponse(
            {"error": "invalid_request", "error_description": "client_id is required"},
            status_code=400
        )
    
    # 验证客户端
    valid, client, error = provider.validate_client(client_id, client_secret=client_secret)
    if not valid:
        return JSONResponse(
            {"error": "invalid_client", "error_description": "Client authentication failed"},
            status_code=401
        )
    
    if grant_type == "authorization_code":
        if not code:
            return JSONResponse(
                {"error": "invalid_request", "error_description": "code is required"},
                status_code=400
            )
        
        # 获取并验证授权码
        pending = await crud.get_pending_auth_by_auth_code(db, code)
        if not pending:
            return JSONResponse(
                {"error": "invalid_grant", "error_description": "Invalid or expired authorization code"},
                status_code=400
            )
        
        # 验证 redirect_uri
        if redirect_uri and redirect_uri != pending.redirect_uri:
            return JSONResponse(
                {"error": "invalid_grant", "error_description": "redirect_uri mismatch"},
                status_code=400
            )
        
        # 验证 PKCE
        if pending.code_challenge:
            if not code_verifier:
                return JSONResponse(
                    {"error": "invalid_request", "error_description": "code_verifier is required"},
                    status_code=400
                )
            if not provider.verify_pkce(code_verifier, pending.code_challenge, pending.code_challenge_method or "plain"):
                return JSONResponse(
                    {"error": "invalid_grant", "error_description": "Invalid code_verifier"},
                    status_code=400
                )
        
        # 获取绑定用户
        bind_user = await crud.get_bind_user_by_uin(db, pending.uin)
        if not bind_user:
            return JSONResponse(
                {"error": "invalid_grant", "error_description": "User not found"},
                status_code=400
            )
        
        # 标记授权码为已使用
        await crud.mark_pending_auth_used(db, pending.id)
        
        # 构建用户数据
        user_data = {
            "uin": bind_user.uin,
            "email": bind_user.email,
            "preferred_username": bind_user.preferred_username,
            "sub": bind_user.sub,
        }
        if bind_user.extra_data:
            user_data.update(bind_user.extra_data)
        
        # 生成令牌
        token_response = provider.create_token_response(
            uin=bind_user.uin,
            client_id=client_id,
            scope=pending.scope,
            user_data=user_data,
        )
        
        # 存储令牌
        await crud.create_oauth_token(
            db,
            access_token=token_response.access_token,
            client_id=client_id,
            bind_user_id=bind_user.id,
            uin=bind_user.uin,
            scope=pending.scope,
            access_token_expires_in=config.oauth_provider.access_token_expire,
            refresh_token=token_response.refresh_token,
            refresh_token_expires_in=config.oauth_provider.refresh_token_expire if token_response.refresh_token else None,
        )
        
        return JSONResponse(token_response.model_dump(exclude_none=True))
    
    elif grant_type == "refresh_token":
        if not refresh_token:
            return JSONResponse(
                {"error": "invalid_request", "error_description": "refresh_token is required"},
                status_code=400
            )
        
        # 获取并验证刷新令牌
        token_record = await crud.get_token_by_refresh_token(db, refresh_token)
        if not token_record:
            return JSONResponse(
                {"error": "invalid_grant", "error_description": "Invalid or expired refresh token"},
                status_code=400
            )
        
        # 验证客户端
        if token_record.client_id != client_id:
            return JSONResponse(
                {"error": "invalid_grant", "error_description": "Client mismatch"},
                status_code=400
            )
        
        # 撤销旧令牌
        await crud.revoke_token(db, token_record.id)
        
        # 获取绑定用户
        bind_user = await crud.get_bind_user_by_uin(db, token_record.uin)
        if not bind_user:
            return JSONResponse(
                {"error": "invalid_grant", "error_description": "User not found"},
                status_code=400
            )
        
        # 构建用户数据
        user_data = {
            "uin": bind_user.uin,
            "email": bind_user.email,
            "preferred_username": bind_user.preferred_username,
            "sub": bind_user.sub,
        }
        if bind_user.extra_data:
            user_data.update(bind_user.extra_data)
        
        # 生成新令牌
        token_response = provider.create_token_response(
            uin=bind_user.uin,
            client_id=client_id,
            scope=token_record.scope,
            user_data=user_data,
        )
        
        # 存储新令牌
        await crud.create_oauth_token(
            db,
            access_token=token_response.access_token,
            client_id=client_id,
            bind_user_id=bind_user.id,
            uin=bind_user.uin,
            scope=token_record.scope,
            access_token_expires_in=config.oauth_provider.access_token_expire,
            refresh_token=token_response.refresh_token,
            refresh_token_expires_in=config.oauth_provider.refresh_token_expire if token_response.refresh_token else None,
        )
        
        return JSONResponse(token_response.model_dump(exclude_none=True))
    
    else:
        return JSONResponse(
            {"error": "unsupported_grant_type", "error_description": f"Grant type '{grant_type}' is not supported"},
            status_code=400
        )


@oauth_router.get("/userinfo")
async def userinfo(
    request: Request,
    authorization: Optional[str] = Header(None),
    db: AsyncSession = Depends(get_db),
):
    """OAuth 2.0 用户信息端点"""
    provider = get_oauth_provider()
    
    # 提取访问令牌
    access_token = None
    if authorization and authorization.startswith("Bearer "):
        access_token = authorization[7:]
    
    if not access_token:
        return JSONResponse(
            {"error": "invalid_request", "error_description": "Access token is required"},
            status_code=401,
            headers={"WWW-Authenticate": "Bearer"}
        )
    
    # 验证访问令牌
    token_record = await crud.get_token_by_access_token(db, access_token)
    if not token_record:
        return JSONResponse(
            {"error": "invalid_token", "error_description": "Invalid or expired access token"},
            status_code=401,
            headers={"WWW-Authenticate": "Bearer error=\"invalid_token\""}
        )
    
    # 获取绑定用户
    bind_user = await crud.get_bind_user_by_uin(db, token_record.uin)
    if not bind_user:
        return JSONResponse(
            {"error": "invalid_token", "error_description": "User not found"},
            status_code=401
        )
    
    # 构建用户数据
    user_data = {
        "uin": bind_user.uin,
        "email": bind_user.email,
        "preferred_username": bind_user.preferred_username,
        "sub": bind_user.sub,
    }
    if bind_user.extra_data:
        user_data.update(bind_user.extra_data)
    
    # 根据 scope 返回用户声明
    claims = provider.get_user_claims(token_record.scope, user_data)
    
    return JSONResponse(claims)


@oauth_router.post("/revoke")
async def revoke(
    token: str = Form(...),
    token_type_hint: Optional[str] = Form(None),
    client_id: Optional[str] = Form(None),
    client_secret: Optional[str] = Form(None),
    authorization: Optional[str] = Header(None),
    db: AsyncSession = Depends(get_db),
):
    """OAuth 2.0 令牌撤销端点"""
    provider = get_oauth_provider()
    
    # 支持 Basic Auth
    if authorization and authorization.startswith("Basic "):
        import base64
        try:
            decoded = base64.b64decode(authorization[6:]).decode("utf-8")
            if ":" in decoded:
                client_id, client_secret = decoded.split(":", 1)
        except Exception:
            pass
    
    if not client_id:
        return JSONResponse(
            {"error": "invalid_request", "error_description": "client_id is required"},
            status_code=400
        )
    
    # 验证客户端
    valid, _, _ = provider.validate_client(client_id, client_secret=client_secret)
    if not valid:
        return JSONResponse(
            {"error": "invalid_client", "error_description": "Client authentication failed"},
            status_code=401
        )
    
    # 尝试作为访问令牌撤销
    token_record = await crud.get_token_by_access_token(db, token, valid_only=False)
    if not token_record:
        # 尝试作为刷新令牌撤销
        token_record = await crud.get_token_by_refresh_token(db, token, valid_only=False)
    
    if token_record:
        # 验证客户端是否匹配
        if token_record.client_id == client_id:
            await crud.revoke_token(db, token_record.id)
    
    # 无论令牌是否存在，都返回成功（RFC 7009）
    return JSONResponse({})


@oauth_router.get("/.well-known/openid-configuration")
async def openid_configuration():
    """OpenID Connect 发现端点"""
    config = get_config()
    issuer = config.oauth_provider.issuer
    
    return JSONResponse({
        "issuer": issuer,
        "authorization_endpoint": f"{issuer}/oauth/authorize",
        "token_endpoint": f"{issuer}/oauth/token",
        "userinfo_endpoint": f"{issuer}/oauth/userinfo",
        "revocation_endpoint": f"{issuer}/oauth/revoke",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["HS256"],
        "scopes_supported": ["openid", "uin", "email", "profile", "preferred_username"],
        "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
        "code_challenge_methods_supported": ["plain", "S256"],
        "claims_supported": ["sub", "uin", "email", "preferred_username", "nickname"],
    })
