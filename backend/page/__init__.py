"""
页面路由模块
"""

from .routes import router
from .oauth_routes import oauth_router

__all__ = [
    "router",
    "oauth_router",
]
