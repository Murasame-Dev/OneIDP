"""
安全工具模块
包含速率限制、输入验证等安全功能
"""

import time
import hashlib
import secrets
import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Optional
from functools import wraps

from fastapi import HTTPException, Request


@dataclass
class RateLimitRule:
    """速率限制规则"""
    max_requests: int  # 最大请求数
    window_seconds: int  # 时间窗口（秒）


@dataclass
class RateLimitEntry:
    """速率限制条目"""
    requests: list[float] = field(default_factory=list)


class RateLimiter:
    """内存速率限制器"""
    
    def __init__(self):
        self._storage: dict[str, RateLimitEntry] = defaultdict(RateLimitEntry)
        self._last_cleanup = time.time()
        self._cleanup_interval = 300  # 5分钟清理一次过期条目
    
    def _cleanup(self) -> None:
        """清理过期条目"""
        now = time.time()
        if now - self._last_cleanup < self._cleanup_interval:
            return
        
        keys_to_delete = []
        for key, entry in self._storage.items():
            # 移除超过1小时的记录
            entry.requests = [t for t in entry.requests if now - t < 3600]
            if not entry.requests:
                keys_to_delete.append(key)
        
        for key in keys_to_delete:
            del self._storage[key]
        
        self._last_cleanup = now
    
    def check(self, key: str, rule: RateLimitRule) -> tuple[bool, Optional[int]]:
        """
        检查是否超过速率限制
        返回: (是否允许, 重试等待秒数)
        """
        self._cleanup()
        
        now = time.time()
        entry = self._storage[key]
        
        # 移除窗口外的请求
        cutoff = now - rule.window_seconds
        entry.requests = [t for t in entry.requests if t > cutoff]
        
        if len(entry.requests) >= rule.max_requests:
            # 计算需要等待的时间
            oldest = min(entry.requests) if entry.requests else now
            retry_after = int(oldest + rule.window_seconds - now) + 1
            return False, retry_after
        
        # 记录本次请求
        entry.requests.append(now)
        return True, None
    
    def get_key(self, request: Request, prefix: str = "") -> str:
        """获取速率限制键"""
        # 使用客户端 IP 作为键
        client_ip = request.client.host if request.client else "unknown"
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            client_ip = forwarded.split(",")[0].strip()
        
        return f"{prefix}:{client_ip}"


# 全局速率限制器实例
_rate_limiter: Optional[RateLimiter] = None


def get_rate_limiter() -> RateLimiter:
    """获取速率限制器实例"""
    global _rate_limiter
    if _rate_limiter is None:
        _rate_limiter = RateLimiter()
    return _rate_limiter


# 预定义的速率限制规则
RATE_LIMITS = {
    # 授权请求：每分钟最多 10 次
    "authorize": RateLimitRule(max_requests=10, window_seconds=60),
    # 令牌请求：每分钟最多 20 次
    "token": RateLimitRule(max_requests=20, window_seconds=60),
    # 绑定请求：每分钟最多 5 次
    "bind": RateLimitRule(max_requests=5, window_seconds=60),
    # 验证码尝试：每分钟最多 10 次
    "auth_code": RateLimitRule(max_requests=10, window_seconds=60),
}


def rate_limit(rule_name: str):
    """速率限制装饰器"""
    def decorator(func):
        @wraps(func)
        async def wrapper(request: Request, *args, **kwargs):
            limiter = get_rate_limiter()
            rule = RATE_LIMITS.get(rule_name)
            
            if rule:
                key = limiter.get_key(request, rule_name)
                allowed, retry_after = limiter.check(key, rule)
                
                if not allowed:
                    raise HTTPException(
                        status_code=429,
                        detail="Too many requests",
                        headers={"Retry-After": str(retry_after)}
                    )
            
            return await func(request, *args, **kwargs)
        return wrapper
    return decorator


# 输入验证函数

def sanitize_username(username: str, max_length: int = 64) -> str:
    """清理用户名输入"""
    # 移除前后空白
    username = username.strip()
    # 限制长度
    username = username[:max_length]
    # 只允许安全字符
    username = re.sub(r'[<>"\'\\/;]', '', username)
    return username


def validate_redirect_uri(uri: str) -> bool:
    """验证重定向 URI 的安全性"""
    if not uri:
        return False
    
    # 必须是 http 或 https
    if not uri.startswith(("http://", "https://")):
        # 允许自定义协议（移动应用）
        if "://" not in uri:
            return False
    
    # 不允许包含危险字符
    dangerous_patterns = [
        "javascript:",
        "data:",
        "vbscript:",
        "<script",
        "onclick",
        "onerror",
    ]
    
    uri_lower = uri.lower()
    for pattern in dangerous_patterns:
        if pattern in uri_lower:
            return False
    
    return True


def validate_scope(scope: str) -> bool:
    """验证 scope 的安全性"""
    if not scope:
        return False
    
    # scope 只能包含字母数字和空格
    if not re.match(r'^[a-zA-Z0-9_\s]+$', scope):
        return False
    
    return True


def generate_secure_token(length: int = 32) -> str:
    """生成安全令牌"""
    return secrets.token_urlsafe(length)


def hash_token(token: str) -> str:
    """哈希令牌（用于存储）"""
    return hashlib.sha256(token.encode()).hexdigest()


def constant_time_compare(a: str, b: str) -> bool:
    """常量时间比较（防止时序攻击）"""
    return secrets.compare_digest(a, b)
