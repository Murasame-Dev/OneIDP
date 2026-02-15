"""
机器人模块
支持 WebSocket 客户端和服务端模式
"""

from .websocket import BotManager, get_bot_manager
from .handlers import register_handlers

__all__ = [
    "BotManager",
    "get_bot_manager",
    "register_handlers",
]
