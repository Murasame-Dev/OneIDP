"""
OneIDP - 基于 Onebot-V11 协议的 IDP 提供者
帮助 QQ 群群友绑定 SSO 账号并完成登录授权
"""

import asyncio
import logging
import sys
from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware

from config import get_config, CONFIG_FILE
from database import init_db, close_db
from bot import get_bot_manager, register_handlers
from bot.websocket import init_bot_manager
from page import router, oauth_router
from oauth.client import close_oauth_client


# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
    ]
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """应用生命周期管理"""
    config = get_config()
    
    # 启动时
    logger.info("正在启动 OneIDP...")
    
    # 初始化数据库
    logger.info("初始化数据库...")
    await init_db()
    
    # 初始化并启动机器人
    if config.bot.ws_client_enabled or config.bot.ws_server_enabled:
        logger.info("初始化机器人...")
        bot_manager = init_bot_manager(
            ws_client_enabled=config.bot.ws_client_enabled,
            ws_client_url=config.bot.ws_client_url,
            ws_client_access_token=config.bot.ws_client_access_token,
            ws_server_enabled=config.bot.ws_server_enabled,
            ws_server_host=config.bot.ws_server_host,
            ws_server_port=config.bot.ws_server_port,
            ws_server_access_token=config.bot.ws_server_access_token,
        )
        
        # 注册消息处理器
        register_handlers(bot_manager.bot)
        
        # 启动机器人
        await bot_manager.start()
    
    logger.info("OneIDP 启动完成!")
    logger.info(f"服务地址: http://{config.server.host}:{config.server.port}")
    
    yield
    
    # 关闭时
    logger.info("正在关闭 OneIDP...")
    
    # 停止机器人
    bot_manager = get_bot_manager()
    if bot_manager:
        await bot_manager.stop()
    
    # 关闭 OAuth 客户端
    await close_oauth_client()
    
    # 关闭数据库
    await close_db()
    
    logger.info("OneIDP 已关闭")


def create_app() -> FastAPI:
    """创建 FastAPI 应用"""
    config = get_config()
    
    app = FastAPI(
        title="OneIDP",
        description="基于 Onebot-V11 协议的 IDP 提供者",
        version="1.0.0",
        lifespan=lifespan,
        docs_url="/docs" if config.server.debug else None,
        redoc_url="/redoc" if config.server.debug else None,
    )
    
    # 添加 CORS 中间件
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],  # 生产环境应该限制
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    
    # 添加安全头中间件
    @app.middleware("http")
    async def add_security_headers(request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        if not config.server.debug:
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response
    
    # 注册路由
    app.include_router(router)
    app.include_router(oauth_router)
    
    return app


def main():
    """主函数"""
    # 加载配置
    config = get_config()
    
    # 检查配置文件
    if not CONFIG_FILE.exists():
        logger.warning(f"配置文件不存在，已生成默认配置: {CONFIG_FILE.absolute()}")
        logger.warning("请修改配置文件后重新启动程序")
        return
    
    # 检查关键配置
    if config.sso_client.enabled and not config.sso_client.client_id:
        logger.warning("SSO 客户端已启用但未配置 client_id")
    
    if not config.oauth_clients:
        logger.warning("未配置任何 OAuth 客户端")
    
    # 创建并运行应用
    app = create_app()
    
    uvicorn.run(
        app,
        host=config.server.host,
        port=config.server.port,
        log_level="info" if config.server.debug else "warning",
        access_log=config.server.debug,
    )


if __name__ == "__main__":
    main()
