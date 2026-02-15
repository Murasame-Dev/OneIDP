"""
OAuth 提供者
本项目作为 IDP 提供者，实现 OAuth 2.0 授权服务器
"""

import secrets
import hashlib
import base64
import time
import logging
from datetime import datetime, timedelta
from typing import Optional
from dataclasses import dataclass
from urllib.parse import urlparse, urlencode

import jwt
from pydantic import BaseModel

from config import get_config, OAuthClient as OAuthClientConfig

logger = logging.getLogger(__name__)


class TokenResponse(BaseModel):
    """令牌响应"""
    access_token: str
    token_type: str = "Bearer"
    expires_in: int
    refresh_token: Optional[str] = None
    scope: str
    id_token: Optional[str] = None


class ErrorResponse(BaseModel):
    """错误响应"""
    error: str
    error_description: Optional[str] = None
    error_uri: Optional[str] = None


@dataclass
class AuthorizationRequest:
    """授权请求"""
    client_id: str
    redirect_uri: str
    response_type: str
    scope: str
    state: Optional[str] = None
    code_challenge: Optional[str] = None
    code_challenge_method: Optional[str] = None
    nonce: Optional[str] = None


class OAuthProvider:
    """OAuth 提供者"""
    
    def __init__(self):
        self.config = get_config()
    
    def validate_client(
        self,
        client_id: str,
        client_secret: Optional[str] = None,
        redirect_uri: Optional[str] = None,
    ) -> tuple[bool, Optional[OAuthClientConfig], Optional[str]]:
        """
        验证客户端
        返回: (是否有效, 客户端配置, 错误信息)
        """
        # 查找客户端
        client = None
        for c in self.config.oauth_clients:
            if c.client_id == client_id:
                client = c
                break
        
        if not client:
            return False, None, "invalid_client"
        
        # 验证客户端密钥（如果提供）
        if client_secret is not None:
            if not secrets.compare_digest(client_secret, client.client_secret):
                return False, None, "invalid_client"
        
        # 验证重定向 URI（如果提供）
        if redirect_uri is not None:
            if not self._validate_redirect_uri(redirect_uri, client.redirect_uris):
                return False, None, "invalid_redirect_uri"
        
        return True, client, None
    
    def _validate_redirect_uri(self, uri: str, allowed_uris: list[str]) -> bool:
        """验证重定向 URI"""
        if not allowed_uris:
            return False
        
        # 精确匹配
        if uri in allowed_uris:
            return True
        
        # 解析 URI 进行安全比较
        parsed = urlparse(uri)
        for allowed in allowed_uris:
            parsed_allowed = urlparse(allowed)
            
            # 检查 scheme 和 host 必须匹配
            if (parsed.scheme == parsed_allowed.scheme and
                parsed.netloc == parsed_allowed.netloc and
                parsed.path == parsed_allowed.path):
                return True
        
        return False
    
    def validate_scope(self, requested_scope: str, client: OAuthClientConfig) -> tuple[bool, Optional[str]]:
        """
        验证请求的 scope
        返回: (是否有效, 错误信息)
        """
        scopes = requested_scope.split()
        
        # 检查是否在允许范围内
        for scope in scopes:
            if scope not in client.allowed_scopes:
                return False, f"scope '{scope}' not allowed"
        
        return True, None
    
    def generate_verification_code(self) -> str:
        """生成验证码"""
        length = self.config.oauth_provider.verification_code_length
        # 使用数字和大写字母，排除容易混淆的字符
        alphabet = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ"
        return "".join(secrets.choice(alphabet) for _ in range(length))
    
    def generate_auth_code(self) -> str:
        """生成授权码"""
        return secrets.token_urlsafe(32)
    
    def generate_access_token(self) -> str:
        """生成访问令牌"""
        return secrets.token_urlsafe(48)
    
    def generate_refresh_token(self) -> str:
        """生成刷新令牌"""
        return secrets.token_urlsafe(48)
    
    def verify_pkce(
        self,
        code_verifier: str,
        code_challenge: str,
        code_challenge_method: str,
    ) -> bool:
        """验证 PKCE"""
        if code_challenge_method == "plain":
            return secrets.compare_digest(code_verifier, code_challenge)
        elif code_challenge_method == "S256":
            # SHA256 哈希并 base64url 编码
            computed = hashlib.sha256(code_verifier.encode("ascii")).digest()
            computed_b64 = base64.urlsafe_b64encode(computed).rstrip(b"=").decode("ascii")
            return secrets.compare_digest(computed_b64, code_challenge)
        else:
            return False
    
    def generate_id_token(
        self,
        uin: int,
        client_id: str,
        scope: str,
        user_data: dict,
        nonce: Optional[str] = None,
    ) -> str:
        """生成 ID Token (JWT)"""
        now = int(time.time())
        
        payload = {
            "iss": self.config.oauth_provider.issuer,
            "sub": user_data.get("sub", str(uin)),  # 使用绑定的 SSO sub
            "aud": client_id,
            "iat": now,
            "exp": now + self.config.oauth_provider.access_token_expire,
            "uin": uin,  # uin 作为额外字段
        }
        
        # 根据 scope 添加声明
        scopes = scope.split()
        
        if "email" in scopes and "email" in user_data:
            payload["email"] = user_data.get("email")
            payload["email_verified"] = user_data.get("email_verified", False)
        
        if "profile" in scopes:
            if "preferred_username" in user_data:
                payload["preferred_username"] = user_data.get("preferred_username")
            if "nickname" in user_data:
                payload["nickname"] = user_data.get("nickname")
            if "name" in user_data:
                payload["name"] = user_data.get("name")
        
        if "preferred_username" in scopes and "preferred_username" in user_data:
            payload["preferred_username"] = user_data.get("preferred_username")
        
        if nonce:
            payload["nonce"] = nonce
        
        # 使用 HS256 签名
        token = jwt.encode(
            payload,
            self.config.server.secret_key,
            algorithm="HS256",
        )
        
        return token
    
    def create_token_response(
        self,
        uin: int,
        client_id: str,
        scope: str,
        user_data: dict,
        include_refresh_token: bool = True,
        nonce: Optional[str] = None,
    ) -> TokenResponse:
        """创建令牌响应"""
        access_token = self.generate_access_token()
        refresh_token = self.generate_refresh_token() if include_refresh_token else None
        
        # 生成 ID Token（如果请求了 openid scope）
        id_token = None
        if "openid" in scope.split():
            id_token = self.generate_id_token(uin, client_id, scope, user_data, nonce)
        
        return TokenResponse(
            access_token=access_token,
            token_type="Bearer",
            expires_in=self.config.oauth_provider.access_token_expire,
            refresh_token=refresh_token,
            scope=scope,
            id_token=id_token,
        )
    
    def get_user_claims(
        self,
        scope: str,
        bind_user_data: dict,
    ) -> dict:
        """根据 scope 获取用户声明"""
        scopes = scope.split()
        claims = {}
        
        # uin
        if "uin" in scopes:
            claims["uin"] = bind_user_data.get("uin")
        
        # openid
        if "openid" in scopes:
            # sub 使用绑定的 SSO sub，如果没有则回退到 uin
            claims["sub"] = bind_user_data.get("sub") or str(bind_user_data.get("uin"))
        
        # email
        if "email" in scopes:
            if "email" in bind_user_data:
                claims["email"] = bind_user_data.get("email")
        
        # profile 相关
        if "profile" in scopes or "preferred_username" in scopes:
            if "preferred_username" in bind_user_data:
                claims["preferred_username"] = bind_user_data.get("preferred_username")
        
        # 额外数据
        extra_data = bind_user_data.get("extra_data") or {}
        for scope in scopes:
            if scope in extra_data and scope not in claims:
                claims[scope] = extra_data[scope]
        
        return claims


# 全局实例
_oauth_provider: Optional[OAuthProvider] = None


def get_oauth_provider() -> OAuthProvider:
    """获取 OAuth 提供者实例"""
    global _oauth_provider
    
    if _oauth_provider is None:
        _oauth_provider = OAuthProvider()
    
    return _oauth_provider
