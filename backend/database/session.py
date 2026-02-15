"""
数据库会话管理
"""

import os
from pathlib import Path
from typing import AsyncGenerator
from contextlib import asynccontextmanager

from sqlalchemy.ext.asyncio import (
    AsyncSession,
    AsyncEngine,
    create_async_engine,
    async_sessionmaker,
)

from .models import Base


_engine: AsyncEngine | None = None
_session_factory: async_sessionmaker[AsyncSession] | None = None


def get_database_url() -> str:
    """根据配置获取数据库连接URL"""
    # 延迟导入避免循环依赖
    from config import get_config
    
    config = get_config()
    db_config = config.database
    
    if db_config.type == "sqlite":
        # 确保数据目录存在
        db_path = Path(db_config.sqlite_path)
        db_path.parent.mkdir(parents=True, exist_ok=True)
        return f"sqlite+aiosqlite:///{db_config.sqlite_path}"
    
    elif db_config.type == "postgresql":
        return (
            f"postgresql+asyncpg://{db_config.pg_user}:{db_config.pg_password}"
            f"@{db_config.pg_host}:{db_config.pg_port}/{db_config.pg_database}"
        )
    
    else:
        raise ValueError(f"不支持的数据库类型: {db_config.type}")


async def init_db() -> None:
    """初始化数据库连接和表结构"""
    global _engine, _session_factory
    
    database_url = get_database_url()
    
    # 创建引擎
    _engine = create_async_engine(
        database_url,
        echo=False,  # 生产环境关闭SQL日志
        pool_pre_ping=True,  # 连接池健康检查
        pool_recycle=3600,  # 连接回收时间（秒）
    )
    
    # 创建会话工厂
    _session_factory = async_sessionmaker(
        _engine,
        class_=AsyncSession,
        expire_on_commit=False,
        autoflush=False,
    )
    
    # 创建所有表
    async with _engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def close_db() -> None:
    """关闭数据库连接"""
    global _engine, _session_factory
    
    if _engine is not None:
        await _engine.dispose()
        _engine = None
        _session_factory = None


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """获取数据库会话（用于 FastAPI 依赖注入）"""
    if _session_factory is None:
        await init_db()
    
    async with _session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


@asynccontextmanager
async def get_async_session() -> AsyncGenerator[AsyncSession, None]:
    """获取数据库会话（上下文管理器方式）"""
    if _session_factory is None:
        await init_db()
    
    async with _session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
