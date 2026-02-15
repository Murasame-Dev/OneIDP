"""
页面路由
处理绑定流程的回调和用户界面
"""

import logging
from typing import Optional
from datetime import datetime

from fastapi import APIRouter, Request, HTTPException, Depends
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.ext.asyncio import AsyncSession

from config import get_config
from database.session import get_db
from database import crud
from oauth.client import get_oauth_client_async

logger = logging.getLogger(__name__)

router = APIRouter()


def get_base_template(title: str, content: str) -> str:
    """获取基础 HTML 模板"""
    return f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title}</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
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
            max-width: 480px;
            width: 100%;
            text-align: center;
        }}
        .icon {{
            font-size: 64px;
            margin-bottom: 20px;
        }}
        .success {{ color: #2ecc71; }}
        .error {{ color: #e74c3c; }}
        .warning {{ color: #f39c12; }}
        .info {{ color: #3498db; }}
        h1 {{
            color: #2c3e50;
            margin-bottom: 16px;
            font-size: 24px;
        }}
        p {{
            color: #7f8c8d;
            line-height: 1.6;
            margin-bottom: 12px;
        }}
        .highlight {{
            color: #2c3e50;
            font-weight: 600;
        }}
        .code {{
            background: #f8f9fa;
            border: 2px dashed #dee2e6;
            border-radius: 8px;
            padding: 20px;
            margin: 20px 0;
            font-family: 'Monaco', 'Consolas', monospace;
            font-size: 28px;
            letter-spacing: 4px;
            color: #2c3e50;
        }}
        .scope-list {{
            text-align: left;
            background: #f8f9fa;
            border-radius: 8px;
            padding: 16px 24px;
            margin: 20px 0;
        }}
        .scope-item {{
            padding: 8px 0;
            border-bottom: 1px solid #e9ecef;
            display: flex;
            justify-content: space-between;
        }}
        .scope-item:last-child {{
            border-bottom: none;
        }}
        .scope-name {{
            color: #495057;
            font-weight: 500;
        }}
        .scope-value {{
            color: #6c757d;
        }}
        .btn {{
            display: inline-block;
            padding: 12px 32px;
            border-radius: 8px;
            text-decoration: none;
            font-weight: 600;
            transition: all 0.3s ease;
            margin: 8px;
        }}
        .btn-primary {{
            background: #667eea;
            color: white;
        }}
        .btn-primary:hover {{
            background: #5a67d8;
            transform: translateY(-2px);
        }}
        .btn-danger {{
            background: #e74c3c;
            color: white;
        }}
        .btn-danger:hover {{
            background: #c0392b;
        }}
        .footer {{
            margin-top: 24px;
            font-size: 14px;
            color: #95a5a6;
        }}
    </style>
</head>
<body>
    <div class="container">
        {content}
    </div>
</body>
</html>"""


@router.get("/", response_class=HTMLResponse)
async def index():
    """首页"""
    content = """
        <div class="icon info">🔐</div>
        <h1>OneIDP - SSO 绑定服务</h1>
        <p>这是一个基于 QQ 的 SSO 账号绑定和授权服务。</p>
        <p>请在 QQ 群聊或私聊中使用机器人命令进行操作。</p>
        <div class="footer">Powered by OneIDP</div>
    """
    return get_base_template("OneIDP", content)


@router.get("/callback")
async def oauth_callback(
    request: Request,
    code: Optional[str] = None,
    state: Optional[str] = None,
    error: Optional[str] = None,
    error_description: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
):
    """SSO 授权回调（用于绑定流程）"""
    config = get_config()
    
    # 处理错误
    if error:
        logger.warning(f"SSO 授权错误: {error} - {error_description}")
        content = f"""
            <div class="icon error">❌</div>
            <h1>授权失败</h1>
            <p>SSO 授权过程中发生错误:</p>
            <p class="highlight">{error_description or error}</p>
            <div class="footer">请返回 QQ 重新尝试绑定</div>
        """
        return HTMLResponse(get_base_template("授权失败", content))
    
    # 验证参数
    if not code or not state:
        content = """
            <div class="icon error">❌</div>
            <h1>参数错误</h1>
            <p>缺少必要的授权参数</p>
            <div class="footer">请返回 QQ 重新尝试绑定</div>
        """
        return HTMLResponse(get_base_template("参数错误", content), status_code=400)
    
    # 验证 state
    pending = await crud.get_pending_bind_by_state(db, state)
    if not pending:
        content = """
            <div class="icon error">❌</div>
            <h1>链接已失效</h1>
            <p>绑定链接已过期或已被使用</p>
            <div class="footer">请返回 QQ 重新发起绑定请求</div>
        """
        return HTMLResponse(get_base_template("链接已失效", content), status_code=400)
    
    # 检查用户是否已绑定
    existing = await crud.get_bind_user_by_uin(db, pending.uin)
    if existing:
        await crud.mark_pending_bind_used(db, pending.id)
        content = """
            <div class="icon warning">⚠️</div>
            <h1>已存在绑定</h1>
            <p>你的 QQ 号已经绑定了 SSO 账号</p>
            <p>如需更换绑定，请先在 QQ 中使用解绑命令</p>
            <div class="footer">Powered by OneIDP</div>
        """
        return HTMLResponse(get_base_template("已存在绑定", content))
    
    # 获取 OAuth 客户端
    oauth_client = await get_oauth_client_async()
    if not oauth_client:
        content = """
            <div class="icon error">❌</div>
            <h1>服务配置错误</h1>
            <p>SSO 客户端未正确配置</p>
            <div class="footer">请联系管理员</div>
        """
        return HTMLResponse(get_base_template("配置错误", content), status_code=500)
    
    # 换取用户信息
    userinfo = await oauth_client.exchange_and_get_userinfo(code)
    if not userinfo:
        content = """
            <div class="icon error">❌</div>
            <h1>获取用户信息失败</h1>
            <p>无法从 SSO 服务器获取你的用户信息</p>
            <div class="footer">请返回 QQ 重新尝试绑定</div>
        """
        return HTMLResponse(get_base_template("获取信息失败", content))
    
    # 检查 sub 是否已被绑定
    existing_sub = await crud.get_bind_user_by_sub(db, userinfo.sub)
    if existing_sub:
        await crud.mark_pending_bind_used(db, pending.id)
        content = """
            <div class="icon warning">⚠️</div>
            <h1>账号已被绑定</h1>
            <p>此 SSO 账号已被其他 QQ 号绑定</p>
            <p>每个 SSO 账号只能绑定一个 QQ 号</p>
            <div class="footer">如有疑问请联系管理员</div>
        """
        return HTMLResponse(get_base_template("账号已被绑定", content))
    
    # 构建额外数据
    extra_data = {}
    stored_fields = config.binding.stored_fields
    raw_data = userinfo.raw_data or {}
    
    for field in stored_fields:
        if field not in ["sub", "email", "preferred_username"]:
            if field in raw_data:
                extra_data[field] = raw_data[field]
    
    # 创建绑定
    bind_user = await crud.create_bind_user(
        db,
        uin=pending.uin,
        sub=userinfo.sub,
        email=userinfo.email,
        preferred_username=userinfo.preferred_username,
        extra_data=extra_data if extra_data else None,
    )
    
    # 标记待绑定请求为已使用
    await crud.mark_pending_bind_used(db, pending.id)
    
    display_name = userinfo.preferred_username or userinfo.email or userinfo.sub[:16]
    
    content = f"""
        <div class="icon success">✅</div>
        <h1>绑定成功</h1>
        <p>你的 QQ 号已成功绑定到 SSO 账号:</p>
        <p class="highlight">{display_name}</p>
        <div class="scope-list">
            <div class="scope-item">
                <span class="scope-name">QQ 号</span>
                <span class="scope-value">{pending.uin}</span>
            </div>
            <div class="scope-item">
                <span class="scope-name">用户名</span>
                <span class="scope-value">{userinfo.preferred_username or '-'}</span>
            </div>
            <div class="scope-item">
                <span class="scope-name">邮箱</span>
                <span class="scope-value">{userinfo.email or '-'}</span>
            </div>
        </div>
        <div class="footer">现在你可以关闭此页面，返回 QQ 使用授权功能</div>
    """
    return HTMLResponse(get_base_template("绑定成功", content))


@router.get("/health")
async def health_check():
    """健康检查"""
    return {"status": "ok", "timestamp": datetime.utcnow().isoformat()}
