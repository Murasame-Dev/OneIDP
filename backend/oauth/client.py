"""
OAuth 客户端
用于绑定流程，本项目作为客户端向 SSO 请求用户信息
"""

import logging
from typing import Optional
from dataclasses import dataclass, field

import httpx

from config import get_config

logger = logging.getLogger(__name__)

# 缓存 wellknown 配置
_wellknown_cache: dict[str, dict] = {}


@dataclass
class UserInfo:
    """用户信息"""
    sub: str
    email: Optional[str] = None
    email_verified: Optional[bool] = None
    name: Optional[str] = None
    given_name: Optional[str] = None
    preferred_username: Optional[str] = None
    nickname: Optional[str] = None
    groups: Optional[list[str]] = None
    raw_data: Optional[dict] = None


class OAuthClient:
    """OAuth 客户端"""
    
    def __init__(
        self,
        authorization_url: str,
        token_url: str,
        userinfo_url: str,
        client_id: str,
        client_secret: str,
        redirect_uri: str,
        scope: str = "openid email profile",
    ):
        self.authorization_url = authorization_url
        self.token_url = token_url
        self.userinfo_url = userinfo_url
        self.client_id = client_id
        self.client_secret = client_secret
        self.redirect_uri = redirect_uri
        self.scope = scope
        
        self._http_client = httpx.AsyncClient(
            timeout=30.0,
            follow_redirects=True,
        )
    
    async def close(self) -> None:
        """关闭 HTTP 客户端"""
        await self._http_client.aclose()
    
    async def exchange_code(self, code: str) -> Optional[dict]:
        """用授权码换取令牌"""
        try:
            response = await self._http_client.post(
                self.token_url,
                data={
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": self.redirect_uri,
                    "client_id": self.client_id,
                    "client_secret": self.client_secret,
                },
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Accept": "application/json",
                },
            )
            
            if response.status_code != 200:
                logger.error(f"令牌交换失败: {response.status_code} - {response.text}")
                return None
            
            return response.json()
            
        except Exception as e:
            logger.error(f"令牌交换错误: {e}", exc_info=True)
            return None
    
    async def get_userinfo(self, access_token: str) -> Optional[UserInfo]:
        """获取用户信息"""
        try:
            response = await self._http_client.get(
                self.userinfo_url,
                headers={
                    "Authorization": f"Bearer {access_token}",
                    "Accept": "application/json",
                },
            )
            
            if response.status_code != 200:
                logger.error(f"获取用户信息失败: {response.status_code} - {response.text}")
                return None
            
            data = response.json()
            
            return UserInfo(
                sub=data.get("sub", ""),
                email=data.get("email"),
                email_verified=data.get("email_verified"),
                name=data.get("name"),
                given_name=data.get("given_name"),
                preferred_username=data.get("preferred_username"),
                nickname=data.get("nickname"),
                groups=data.get("groups"),
                raw_data=data,
            )
            
        except Exception as e:
            logger.error(f"获取用户信息错误: {e}", exc_info=True)
            return None
    
    async def exchange_and_get_userinfo(self, code: str) -> Optional[UserInfo]:
        """用授权码换取令牌并获取用户信息"""
        token_data = await self.exchange_code(code)
        if not token_data:
            return None
        
        access_token = token_data.get("access_token")
        if not access_token:
            logger.error("令牌响应中没有 access_token")
            return None
        
        return await self.get_userinfo(access_token)


# 全局实例
_oauth_client: Optional[OAuthClient] = None


async def fetch_wellknown_config(wellknown_url: str) -> Optional[dict]:
    """获取 OpenID Connect Discovery 配置"""
    global _wellknown_cache
    
    # 检查缓存
    if wellknown_url in _wellknown_cache:
        return _wellknown_cache[wellknown_url]
    
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.get(wellknown_url)
            
            if response.status_code != 200:
                logger.error(f"获取 wellknown 配置失败: {response.status_code} - {response.text}")
                return None
            
            config_data = response.json()
            
            # 验证必要字段
            required_fields = ["authorization_endpoint", "token_endpoint"]
            for field in required_fields:
                if field not in config_data:
                    logger.error(f"wellknown 配置缺少必要字段: {field}")
                    return None
            
            # 缓存配置
            _wellknown_cache[wellknown_url] = config_data
            logger.info(f"已从 {wellknown_url} 获取 OIDC 配置")
            
            return config_data
            
    except Exception as e:
        logger.error(f"获取 wellknown 配置错误: {e}", exc_info=True)
        return None


async def get_oauth_client_async() -> Optional[OAuthClient]:
    """异步获取 OAuth 客户端实例（支持 wellknown 自动配置）"""
    global _oauth_client
    
    config = get_config()
    
    if not config.sso_client.enabled:
        return None
    
    if _oauth_client is not None:
        return _oauth_client
    
    sso_config = config.sso_client
    
    # 确定端点 URL
    if sso_config.use_wellknown and sso_config.wellknown_url:
        # 从 wellknown 端点获取配置
        wellknown_config = await fetch_wellknown_config(sso_config.wellknown_url)
        if not wellknown_config:
            logger.error("无法从 wellknown 端点获取配置，请检查 wellknown_url 是否正确")
            return None
        
        authorization_url = wellknown_config.get("authorization_endpoint", "")
        token_url = wellknown_config.get("token_endpoint", "")
        userinfo_url = wellknown_config.get("userinfo_endpoint", sso_config.userinfo_url)
    else:
        # 使用手动配置
        authorization_url = sso_config.authorization_url
        token_url = sso_config.token_url
        userinfo_url = sso_config.userinfo_url
    
    _oauth_client = OAuthClient(
        authorization_url=authorization_url,
        token_url=token_url,
        userinfo_url=userinfo_url,
        client_id=sso_config.client_id,
        client_secret=sso_config.client_secret,
        redirect_uri=sso_config.redirect_uri,
        scope=sso_config.scope,
    )
    
    return _oauth_client


def get_oauth_client() -> Optional[OAuthClient]:
    """获取 OAuth 客户端实例（同步版本，仅用于非 wellknown 模式）"""
    global _oauth_client
    
    config = get_config()
    
    if not config.sso_client.enabled:
        return None
    
    # 如果使用 wellknown 模式，需要使用异步版本
    if config.sso_client.use_wellknown:
        logger.warning("使用 wellknown 模式时请使用 get_oauth_client_async()")
        return _oauth_client  # 可能为 None
    
    if _oauth_client is None:
        _oauth_client = OAuthClient(
            authorization_url=config.sso_client.authorization_url,
            token_url=config.sso_client.token_url,
            userinfo_url=config.sso_client.userinfo_url,
            client_id=config.sso_client.client_id,
            client_secret=config.sso_client.client_secret,
            redirect_uri=config.sso_client.redirect_uri,
            scope=config.sso_client.scope,
        )
    
    return _oauth_client


async def close_oauth_client() -> None:
    """关闭 OAuth 客户端"""
    global _oauth_client, _wellknown_cache
    if _oauth_client:
        await _oauth_client.close()
        _oauth_client = None
    _wellknown_cache.clear()
