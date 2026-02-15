"""
WebSocket 连接管理
支持客户端模式（主动连接）和服务端模式（被动接收连接）
"""

import asyncio
import json
import logging
from typing import Optional, Callable, Any
from dataclasses import dataclass, field
from contextlib import asynccontextmanager

import websockets
from websockets.client import WebSocketClientProtocol
from websockets.server import WebSocketServerProtocol, serve
from websockets.exceptions import ConnectionClosed

from aiocqhttp import CQHttp

logger = logging.getLogger(__name__)


@dataclass
class BotManager:
    """机器人管理器"""
    
    # WebSocket 客户端配置
    ws_client_enabled: bool = False
    ws_client_url: str = ""
    ws_client_access_token: str = ""
    
    # WebSocket 服务端配置
    ws_server_enabled: bool = False
    ws_server_host: str = "0.0.0.0"
    ws_server_port: int = 8080
    ws_server_access_token: str = ""
    
    # 内部状态
    _bot: CQHttp = field(default_factory=lambda: CQHttp())
    _client_ws: Optional[WebSocketClientProtocol] = field(default=None, repr=False)
    _server: Any = field(default=None, repr=False)
    _server_connections: dict[str, WebSocketServerProtocol] = field(default_factory=dict, repr=False)
    _running: bool = field(default=False, repr=False)
    _reconnect_delay: int = field(default=5, repr=False)
    _max_reconnect_delay: int = field(default=60, repr=False)
    _tasks: list[asyncio.Task] = field(default_factory=list, repr=False)
    _pending_responses: dict[str, asyncio.Future] = field(default_factory=dict, repr=False)
    
    @property
    def bot(self) -> CQHttp:
        """获取 CQHttp 实例"""
        return self._bot
    
    async def start(self) -> None:
        """启动机器人管理器"""
        if self._running:
            logger.warning("机器人管理器已在运行中")
            return
        
        self._running = True
        logger.info("启动机器人管理器...")
        
        # 启动客户端模式
        if self.ws_client_enabled:
            task = asyncio.create_task(self._run_client())
            self._tasks.append(task)
            logger.info(f"WebSocket 客户端模式已启用，目标: {self.ws_client_url}")
        
        # 启动服务端模式
        if self.ws_server_enabled:
            task = asyncio.create_task(self._run_server())
            self._tasks.append(task)
            logger.info(f"WebSocket 服务端模式已启用，监听: {self.ws_server_host}:{self.ws_server_port}")
    
    async def stop(self) -> None:
        """停止机器人管理器"""
        if not self._running:
            return
        
        logger.info("停止机器人管理器...")
        self._running = False
        
        # 关闭客户端连接
        if self._client_ws:
            await self._client_ws.close()
            self._client_ws = None
        
        # 关闭服务端
        if self._server:
            self._server.close()
            await self._server.wait_closed()
            self._server = None
        
        # 关闭所有服务端连接
        for ws in self._server_connections.values():
            await ws.close()
        self._server_connections.clear()
        
        # 取消所有任务
        for task in self._tasks:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
        self._tasks.clear()
        
        logger.info("机器人管理器已停止")
    
    async def _run_client(self) -> None:
        """运行 WebSocket 客户端"""
        delay = self._reconnect_delay
        
        while self._running:
            try:
                # 构建连接参数
                connect_kwargs = {
                    "ping_interval": 30,
                    "ping_timeout": 10,
                }
                
                # 新版 websockets 使用 additional_headers
                if self.ws_client_access_token:
                    connect_kwargs["additional_headers"] = {
                        "Authorization": f"Bearer {self.ws_client_access_token}"
                    }
                
                async with websockets.connect(
                    self.ws_client_url,
                    **connect_kwargs,
                ) as ws:
                    self._client_ws = ws
                    delay = self._reconnect_delay  # 重置重连延迟
                    logger.info("WebSocket 客户端已连接")
                    
                    async for message in ws:
                        # 使用 create_task 避免阻塞消息接收循环
                        asyncio.create_task(self._handle_message(message))
                        
            except ConnectionClosed as e:
                logger.warning(f"WebSocket 客户端连接已关闭: {e}")
            except Exception as e:
                logger.error(f"WebSocket 客户端错误: {e}")
            finally:
                self._client_ws = None
            
            if self._running:
                logger.info(f"将在 {delay} 秒后重连...")
                await asyncio.sleep(delay)
                delay = min(delay * 2, self._max_reconnect_delay)
    
    async def _run_server(self) -> None:
        """运行 WebSocket 服务端"""
        async def handler(ws: WebSocketServerProtocol, path: str) -> None:
            # 验证 access token
            if self.ws_server_access_token:
                auth_header = ws.request_headers.get("Authorization", "")
                token = auth_header.replace("Bearer ", "") if auth_header.startswith("Bearer ") else ""
                
                if token != self.ws_server_access_token:
                    logger.warning(f"无效的 access token，拒绝连接: {ws.remote_address}")
                    await ws.close(4001, "Unauthorized")
                    return
            
            conn_id = f"{ws.remote_address[0]}:{ws.remote_address[1]}"
            self._server_connections[conn_id] = ws
            logger.info(f"新的服务端连接: {conn_id}")
            
            try:
                async for message in ws:
                    # 使用 create_task 避免阻塞消息接收循环
                    asyncio.create_task(self._handle_message(message))
            except ConnectionClosed as e:
                logger.info(f"服务端连接已关闭: {conn_id}, {e}")
            finally:
                self._server_connections.pop(conn_id, None)
        
        try:
            self._server = await serve(
                handler,
                self.ws_server_host,
                self.ws_server_port,
                ping_interval=30,
                ping_timeout=10,
            )
            logger.info(f"WebSocket 服务端已启动: {self.ws_server_host}:{self.ws_server_port}")
            await self._server.wait_closed()
        except Exception as e:
            logger.error(f"WebSocket 服务端错误: {e}")
    
    async def _handle_message(self, message: str) -> None:
        """处理收到的消息"""
        try:
            data = json.loads(message)
            
            # 检查是否是 API 响应（有 echo 字段）
            echo = data.get("echo")
            if echo and echo in self._pending_responses:
                future = self._pending_responses.pop(echo)
                if not future.done():
                    future.set_result(data)
                return
            
            # 否则是事件，通过 CQHttp 实例处理
            if "post_type" in data:
                await self._bot._handle_event(data)
        except json.JSONDecodeError as e:
            logger.error(f"JSON 解析错误: {e}")
        except Exception as e:
            logger.error(f"消息处理错误: {e}", exc_info=True)
    
    async def send_message(
        self,
        message_type: str,
        target_id: int,
        message: str,
        auto_escape: bool = False,
    ) -> Optional[dict]:
        """发送消息"""
        if message_type == "group":
            return await self.call_api("send_group_msg", group_id=target_id, message=message, auto_escape=auto_escape)
        elif message_type == "private":
            return await self.call_api("send_private_msg", user_id=target_id, message=message, auto_escape=auto_escape)
        else:
            logger.error(f"未知的消息类型: {message_type}")
            return None
    
    async def call_api(self, action: str, **params) -> Optional[dict]:
        """调用 OneBot API"""
        import uuid
        echo = f"{action}_{uuid.uuid4().hex[:8]}"
        
        request = {
            "action": action,
            "params": params,
            "echo": echo,
        }
        
        message = json.dumps(request, ensure_ascii=False)
        
        # 创建 Future 等待响应
        loop = asyncio.get_event_loop()
        future: asyncio.Future = loop.create_future()
        self._pending_responses[echo] = future
        
        try:
            # 优先使用客户端连接
            if self._client_ws:
                await self._client_ws.send(message)
                response = await asyncio.wait_for(future, timeout=30)
                return response
            
            # 尝试服务端连接
            for conn_id, ws in list(self._server_connections.items()):
                try:
                    await ws.send(message)
                    response = await asyncio.wait_for(future, timeout=30)
                    return response
                except Exception as e:
                    logger.error(f"API 调用失败 (服务端 {conn_id}): {e}")
            
            logger.error("没有可用的连接来调用 API")
            return None
        except asyncio.TimeoutError:
            logger.error(f"API 调用超时: {action}")
            return None
        except Exception as e:
            logger.error(f"API 调用失败: {e}")
            return None
        finally:
            self._pending_responses.pop(echo, None)


# 全局实例
_bot_manager: Optional[BotManager] = None


def get_bot_manager() -> BotManager:
    """获取机器人管理器实例"""
    global _bot_manager
    if _bot_manager is None:
        _bot_manager = BotManager()
    return _bot_manager


def init_bot_manager(
    ws_client_enabled: bool = False,
    ws_client_url: str = "",
    ws_client_access_token: str = "",
    ws_server_enabled: bool = False,
    ws_server_host: str = "0.0.0.0",
    ws_server_port: int = 8080,
    ws_server_access_token: str = "",
) -> BotManager:
    """初始化机器人管理器"""
    global _bot_manager
    _bot_manager = BotManager(
        ws_client_enabled=ws_client_enabled,
        ws_client_url=ws_client_url,
        ws_client_access_token=ws_client_access_token,
        ws_server_enabled=ws_server_enabled,
        ws_server_host=ws_server_host,
        ws_server_port=ws_server_port,
        ws_server_access_token=ws_server_access_token,
    )
    return _bot_manager
