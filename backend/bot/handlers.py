"""
机器人命令处理
"""

import re
import secrets
import logging
from datetime import datetime, timedelta
from typing import Optional
from urllib.parse import urlencode

from aiocqhttp import CQHttp, Event

from config import get_config
from database.session import get_async_session
from database import crud
from bot.websocket import get_bot_manager
from oauth.client import fetch_wellknown_config

logger = logging.getLogger(__name__)


def register_handlers(bot: CQHttp) -> None:
    """注册所有消息处理器"""
    
    @bot.on_message()
    async def handle_message(event: Event) -> None:
        """处理消息"""
        config = get_config()
        
        # 获取消息内容
        message = event.message
        if isinstance(message, list):
            # CQ 码格式，提取纯文本
            message = "".join(
                seg.get("data", {}).get("text", "")
                for seg in message
                if seg.get("type") == "text"
            )
        
        message = message.strip()
        
        # 检查是否是命令
        prefix = config.bot.command_prefix
        if not message.startswith(prefix):
            return
        
        # 解析命令
        cmd_text = message[len(prefix):].strip()
        parts = cmd_text.split(maxsplit=2)
        
        if not parts:
            await send_help(event, bot)
            return
        
        cmd = parts[0].lower()
        args = parts[1:] if len(parts) > 1 else []
        
        # 获取消息来源信息
        user_id = event.user_id
        message_type = event.message_type
        source_id = event.group_id if message_type == "group" else user_id
        
        # 检查群组权限
        if message_type == "group":
            allowed_groups = config.bot.allowed_groups
            if allowed_groups and source_id not in allowed_groups:
                return
        
        # 路由命令
        try:
            if cmd == "bind":
                await handle_bind(event, bot, args, user_id, message_type, source_id)
            elif cmd == "unbind":
                await handle_unbind(event, bot, args, user_id, message_type, source_id)
            elif cmd == "auth":
                await handle_auth(event, bot, args, user_id, message_type, source_id)
            elif cmd == "cancel":
                await handle_cancel(event, bot, user_id, message_type, source_id)
            elif cmd == "status":
                await handle_status(event, bot, user_id)
            elif cmd == "help":
                await send_help(event, bot)
            else:
                await reply(event, bot, f"未知命令: {cmd}\n使用 {prefix} help 查看帮助")
        except Exception as e:
            logger.error(f"命令处理错误: {e}", exc_info=True)
            await reply(event, bot, "命令处理时发生错误，请稍后再试")


async def reply(event: Event, bot: CQHttp, message: str) -> None:
    """回复消息"""
    try:
        bot_manager = get_bot_manager()
        if event.message_type == "group":
            # 群聊中 @ 用户
            await bot_manager.send_message(
                "group",
                event.group_id,
                f"[CQ:at,qq={event.user_id}] {message}"
            )
        else:
            await bot_manager.send_message(
                "private",
                event.user_id,
                message
            )
    except Exception as e:
        logger.error(f"发送消息失败: {e}", exc_info=True)


async def send_help(event: Event, bot: CQHttp) -> None:
    """发送帮助信息"""
    config = get_config()
    prefix = config.bot.command_prefix
    
    help_text = f"""SSO 绑定助手
    
命令列表:
{prefix} bind <用户名> - 绑定 SSO 账号
{prefix} unbind <用户名> - 解绑 SSO 账号
{prefix} unbind confirm - 确认解绑
{prefix} auth <验证码> - 批准授权请求
{prefix} cancel - 取消当前操作
{prefix} status - 查看绑定状态
{prefix} help - 显示此帮助"""
    
    await reply(event, bot, help_text)


async def handle_bind(
    event: Event,
    bot: CQHttp,
    args: list[str],
    user_id: int,
    message_type: str,
    source_id: int,
) -> None:
    """处理绑定命令"""
    config = get_config()
    
    if not args:
        await reply(event, bot, f"请提供用户名\n用法: {config.bot.command_prefix} bind <用户名>")
        return
    
    username = args[0]
    
    # 检查 SSO 客户端是否启用
    if not config.sso_client.enabled:
        await reply(event, bot, "SSO 绑定功能未启用")
        return
    
    async with get_async_session() as session:
        # 检查是否已绑定
        existing = await crud.get_bind_user_by_uin(session, user_id)
        if existing:
            await reply(
                event, bot,
                f"你已绑定账号: {existing.preferred_username or existing.email or existing.sub}\n"
                f"如需更换，请先解绑: {config.bot.command_prefix} unbind <用户名>"
            )
            return
        
        # 生成状态码
        state = secrets.token_urlsafe(32)
        
        # 创建待绑定请求
        await crud.create_pending_bind(
            session,
            state=state,
            uin=user_id,
            username=username,
            source_type=message_type,
            source_id=source_id,
            expires_in=config.binding.bind_link_expire,
        )
        
        # 获取授权端点
        if config.sso_client.use_wellknown and config.sso_client.wellknown_url:
            try:
                wellknown = await fetch_wellknown_config(config.sso_client.wellknown_url)
                authorization_endpoint = wellknown.get("authorization_endpoint", config.sso_client.authorization_url)
            except Exception as e:
                logger.error(f"获取 wellknown 配置失败: {e}")
                authorization_endpoint = config.sso_client.authorization_url
        else:
            authorization_endpoint = config.sso_client.authorization_url
        
        # 构建授权 URL
        params = {
            "client_id": config.sso_client.client_id,
            "redirect_uri": config.sso_client.redirect_uri,
            "response_type": "code",
            "scope": config.sso_client.scope,
            "state": state,
        }
        auth_url = f"{authorization_endpoint}?{urlencode(params)}"
        
        await reply(
            event, bot,
            f"请在 {config.binding.bind_link_expire // 60} 分钟内点击以下链接完成绑定:\n{auth_url}"
        )


async def handle_unbind(
    event: Event,
    bot: CQHttp,
    args: list[str],
    user_id: int,
    message_type: str,
    source_id: int,
) -> None:
    """处理解绑命令"""
    config = get_config()
    
    if not args:
        await reply(event, bot, f"请提供用户名或使用 confirm 确认解绑\n用法: {config.bot.command_prefix} unbind <用户名>")
        return
    
    async with get_async_session() as session:
        # 检查是否有待解绑请求
        pending = await crud.get_pending_unbind_by_uin(session, user_id)
        
        if args[0].lower() == "confirm":
            # 确认解绑
            if not pending:
                await reply(event, bot, "没有待确认的解绑请求")
                return
            
            # 获取绑定用户
            bind_user = await crud.get_bind_user_by_uin(session, user_id)
            if not bind_user:
                await crud.mark_pending_unbind_processed(session, pending.id)
                await reply(event, bot, "你尚未绑定任何账号")
                return
            
            # 停用绑定
            await crud.deactivate_bind_user(session, bind_user.id)
            
            # 记录解绑日志
            await crud.create_unbind_log(
                session,
                uin=user_id,
                unbind_user=pending.username,
                sub=bind_user.sub,
                bind_time=bind_user.bind_time,
                is_unbind=True,
                reason="confirm",
            )
            
            # 标记待解绑请求为已处理
            await crud.mark_pending_unbind_processed(session, pending.id)
            
            await reply(event, bot, f"已成功解绑账号: {pending.username}")
            return
        
        # 发起解绑请求
        username = args[0]
        
        # 检查是否已绑定
        bind_user = await crud.get_bind_user_by_uin(session, user_id)
        if not bind_user:
            await reply(event, bot, "你尚未绑定任何账号")
            return
        
        # 验证用户名是否匹配（防止误解绑）
        bound_username = bind_user.preferred_username or bind_user.email or bind_user.sub
        if username.lower() != bound_username.lower() and username != bind_user.sub:
            await reply(
                event, bot,
                f"用户名不匹配，你绑定的账号是: {bound_username}"
            )
            return
        
        # 如果已有待解绑请求，先取消
        if pending:
            await crud.mark_pending_unbind_processed(session, pending.id)
        
        # 创建待解绑请求
        await crud.create_pending_unbind(
            session,
            uin=user_id,
            username=username,
            bind_user_id=bind_user.id,
            source_type=message_type,
            source_id=source_id,
            expires_in=300,  # 5分钟有效期
        )
        
        await reply(
            event, bot,
            f"你正在解绑账号: {username}\n"
            f"请在 5 分钟内发送 {config.bot.command_prefix} unbind confirm 确认解绑\n"
            f"或发送 {config.bot.command_prefix} cancel 取消"
        )


async def handle_auth(
    event: Event,
    bot: CQHttp,
    args: list[str],
    user_id: int,
    message_type: str,
    source_id: int,
) -> None:
    """处理授权命令"""
    config = get_config()
    
    if not args:
        await reply(event, bot, f"请提供验证码\n用法: {config.bot.command_prefix} auth <验证码>")
        return
    
    verification_code = args[0].upper()  # 验证码不区分大小写
    
    async with get_async_session() as session:
        # 检查是否已绑定
        bind_user = await crud.get_bind_user_by_uin(session, user_id)
        if not bind_user:
            await reply(
                event, bot,
                f"你尚未绑定 SSO 账号，请先绑定: {config.bot.command_prefix} bind <用户名>"
            )
            return
        
        # 获取待授权请求（包括 uin 为 0 的待认领请求）
        pending = await crud.get_pending_auth_by_code(session, verification_code)
        if not pending:
            await reply(event, bot, "无效或已过期的验证码")
            return
        
        # 如果 uin 为 0，表示待认领，设置为当前用户
        if pending.uin == 0:
            # 认领此授权请求
            from sqlalchemy import update
            from database.models import PendingAuth
            await session.execute(
                update(PendingAuth)
                .where(PendingAuth.id == pending.id)
                .values(uin=user_id, bind_user_id=bind_user.id)
            )
        elif pending.uin != user_id:
            # 验证是否是本人的请求
            await reply(event, bot, "此验证码不属于你")
            return
        
        # 批准授权
        await crud.approve_pending_auth(session, pending.id)
        
        # 获取客户端信息
        client_name = "未知应用"
        for client in config.oauth_clients:
            if client.client_id == pending.client_id:
                client_name = client.name
                break
        
        # 记录授权日志
        await crud.create_authorization_log(
            session,
            uin=user_id,
            client_id=pending.client_id,
            address=pending.redirect_uri,
            scope=pending.scope,
            is_success=True,
            client_ip=pending.client_ip,
            user_agent=pending.user_agent,
        )
        
        await reply(
            event, bot,
            f"已批准授权请求\n"
            f"应用: {client_name}\n"
            f"权限: {pending.scope}"
        )


async def handle_cancel(
    event: Event,
    bot: CQHttp,
    user_id: int,
    message_type: str,
    source_id: int,
) -> None:
    """处理取消命令"""
    config = get_config()
    
    async with get_async_session() as session:
        cancelled = False
        
        # 取消待解绑请求
        pending_unbind = await crud.get_pending_unbind_by_uin(session, user_id)
        if pending_unbind:
            # 获取绑定用户信息
            bind_user = await crud.get_bind_user_by_uin(session, user_id)
            
            # 记录取消日志
            if bind_user:
                await crud.create_unbind_log(
                    session,
                    uin=user_id,
                    unbind_user=pending_unbind.username,
                    sub=bind_user.sub,
                    bind_time=bind_user.bind_time,
                    is_unbind=False,
                    reason="cancel",
                )
            
            await crud.mark_pending_unbind_processed(session, pending_unbind.id)
            cancelled = True
            await reply(event, bot, "已取消解绑请求")
        
        if not cancelled:
            await reply(event, bot, "没有可取消的操作")


async def handle_status(event: Event, bot: CQHttp, user_id: int) -> None:
    """处理状态查询命令"""
    async with get_async_session() as session:
        bind_user = await crud.get_bind_user_by_uin(session, user_id)
        
        if not bind_user:
            await reply(event, bot, "你尚未绑定 SSO 账号")
            return
        
        status_text = f"""绑定状态: 已绑定
用户名: {bind_user.preferred_username or '未设置'}
邮箱: {bind_user.email or '未设置'}
绑定时间: {bind_user.bind_time.strftime('%Y-%m-%d %H:%M:%S')}"""
        
        await reply(event, bot, status_text)
