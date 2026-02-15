"""
OAuth 模块
包含客户端（用于绑定）和提供者（作为 IDP）功能
"""

from .client import OAuthClient, get_oauth_client, get_oauth_client_async, fetch_wellknown_config
from .provider import OAuthProvider, get_oauth_provider

__all__ = [
    "OAuthClient",
    "get_oauth_client",
    "get_oauth_client_async",
    "fetch_wellknown_config",
    "OAuthProvider",
    "get_oauth_provider",
]
