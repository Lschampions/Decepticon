"""
Authentication Module for Decepticon MCP Servers
Provides JWT-based authentication and authorization
"""

import os
import secrets
import hashlib
import hmac
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, Callable
from functools import wraps
from dataclasses import dataclass

# Import JWT for token handling
try:
    import jwt
    JWT_AVAILABLE = True
except ImportError:
    JWT_AVAILABLE = False


@dataclass
class AuthConfig:
    """Authentication configuration"""
    secret_key: str = os.getenv("MCP_SECRET_KEY", "")
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 60
    refresh_token_expire_days: int = 7
    api_key_header: str = "X-API-Key"
    auth_enabled: bool = True


# Global config
_config: Optional[AuthConfig] = None


def get_config() -> AuthConfig:
    """Get or create auth configuration"""
    global _config
    if _config is None:
        _config = AuthConfig()
        if not _config.secret_key:
            # Generate a random secret key if not provided
            _config.secret_key = secrets.token_hex(32)
            print("WARNING: MCP_SECRET_KEY not set. Using generated key.")
    return _config


def generate_api_key() -> str:
    """Generate a secure API key"""
    return secrets.token_urlsafe(32)


def hash_api_key(api_key: str) -> str:
    """Hash an API key for storage"""
    config = get_config()
    return hmac.new(
        config.secret_key.encode(),
        api_key.encode(),
        hashlib.sha256
    ).hexdigest()


def create_access_token(
    data: Dict[str, Any],
    expires_delta: Optional[timedelta] = None
) -> str:
    """
    Create a JWT access token.
    
    Args:
        data: Payload data to encode
        expires_delta: Optional custom expiration time
        
    Returns:
        Encoded JWT token
    """
    if not JWT_AVAILABLE:
        raise RuntimeError("PyJWT is required for token-based authentication")
    
    config = get_config()
    
    to_encode = data.copy()
    
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=config.access_token_expire_minutes)
    
    to_encode.update({
        "exp": expire,
        "iat": datetime.utcnow(),
        "type": "access"
    })
    
    return jwt.encode(to_encode, config.secret_key, algorithm=config.algorithm)


def create_refresh_token(
    data: Dict[str, Any],
    expires_delta: Optional[timedelta] = None
) -> str:
    """
    Create a JWT refresh token.
    
    Args:
        data: Payload data to encode
        expires_delta: Optional custom expiration time
        
    Returns:
        Encoded JWT refresh token
    """
    if not JWT_AVAILABLE:
        raise RuntimeError("PyJWT is required for token-based authentication")
    
    config = get_config()
    
    to_encode = data.copy()
    
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(days=config.refresh_token_expire_days)
    
    to_encode.update({
        "exp": expire,
        "iat": datetime.utcnow(),
        "type": "refresh"
    })
    
    return jwt.encode(to_encode, config.secret_key, algorithm=config.algorithm)


def verify_token(token: str) -> Dict[str, Any]:
    """
    Verify and decode a JWT token.
    
    Args:
        token: The JWT token to verify
        
    Returns:
        Decoded token payload
        
    Raises:
        ValueError: If token is invalid or expired
    """
    if not JWT_AVAILABLE:
        raise RuntimeError("PyJWT is required for token-based authentication")
    
    config = get_config()
    
    try:
        payload = jwt.decode(
            token,
            config.secret_key,
            algorithms=[config.algorithm]
        )
        return payload
    except jwt.ExpiredSignatureError:
        raise ValueError("Token has expired")
    except jwt.InvalidTokenError as e:
        raise ValueError(f"Invalid token: {str(e)}")


# In-memory store for API keys (in production, use a database)
_api_keys: Dict[str, Dict[str, Any]] = {}


def register_api_key(
    api_key: str,
    name: str,
    permissions: Optional[list] = None,
    rate_limit: int = 100
) -> None:
    """
    Register a new API key.
    
    Args:
        api_key: The API key to register
        name: Human-readable name for the key
        permissions: List of allowed operations
        rate_limit: Maximum requests per hour
    """
    _api_keys[hash_api_key(api_key)] = {
        "name": name,
        "permissions": permissions or ["all"],
        "rate_limit": rate_limit,
        "created_at": datetime.utcnow().isoformat()
    }


def validate_api_key(api_key: str) -> Optional[Dict[str, Any]]:
    """
    Validate an API key.
    
    Args:
        api_key: The API key to validate
        
    Returns:
        Key metadata if valid, None otherwise
    """
    key_hash = hash_api_key(api_key)
    return _api_keys.get(key_hash)


def authenticate_request(
    api_key: Optional[str] = None,
    token: Optional[str] = None
) -> Dict[str, Any]:
    """
    Authenticate a request using API key or JWT token.
    
    Args:
        api_key: Optional API key
        token: Optional JWT token
        
    Returns:
        Authentication result with user info
        
    Raises:
        ValueError: If authentication fails
    """
    config = get_config()
    
    if not config.auth_enabled:
        return {"authenticated": True, "method": "disabled"}
    
    # Try API key first
    if api_key:
        key_info = validate_api_key(api_key)
        if key_info:
            return {
                "authenticated": True,
                "method": "api_key",
                "name": key_info["name"],
                "permissions": key_info["permissions"]
            }
        raise ValueError("Invalid API key")
    
    # Try JWT token
    if token:
        payload = verify_token(token)
        return {
            "authenticated": True,
            "method": "jwt",
            "user_id": payload.get("sub"),
            "permissions": payload.get("permissions", ["all"])
        }
    
    raise ValueError("No valid authentication provided")


def require_auth(func: Callable) -> Callable:
    """
    Decorator to require authentication for a function.
    
    Usage:
        @require_auth
        def protected_function(api_key: str, ...):
            ...
    """
    @wraps(func)
    def wrapper(*args, **kwargs):
        config = get_config()
        
        if not config.auth_enabled:
            return func(*args, **kwargs)
        
        # Look for api_key or token in kwargs
        api_key = kwargs.pop('api_key', None)
        token = kwargs.pop('token', None)
        
        # Also check for header-style kwargs
        if api_key is None:
            api_key = kwargs.pop('X-API-Key', None)
        if token is None:
            token = kwargs.pop('Authorization', None)
            if token and token.startswith('Bearer '):
                token = token[7:]
        
        try:
            auth_result = authenticate_request(api_key, token)
            kwargs['_auth'] = auth_result
            return func(*args, **kwargs)
        except ValueError as e:
            raise PermissionError(f"Authentication failed: {str(e)}")
    
    return wrapper


# Rate limiting (simple in-memory implementation)
_request_counts: Dict[str, list] = {}


def check_rate_limit(
    identifier: str,
    max_requests: int = 100,
    window_hours: int = 1
) -> bool:
    """
    Check if a request is within rate limits.
    
    Args:
        identifier: Unique identifier (API key hash, IP, etc.)
        max_requests: Maximum requests allowed in window
        window_hours: Time window in hours
        
    Returns:
        True if within limits, False otherwise
    """
    now = datetime.utcnow()
    window_start = now - timedelta(hours=window_hours)
    
    # Get or create request list
    if identifier not in _request_counts:
        _request_counts[identifier] = []
    
    # Clean old requests
    _request_counts[identifier] = [
        ts for ts in _request_counts[identifier]
        if ts > window_start
    ]
    
    # Check limit
    if len(_request_counts[identifier]) >= max_requests:
        return False
    
    # Record this request
    _request_counts[identifier].append(now)
    return True


def get_remaining_requests(
    identifier: str,
    max_requests: int = 100,
    window_hours: int = 1
) -> int:
    """
    Get remaining requests for an identifier.
    
    Args:
        identifier: Unique identifier
        max_requests: Maximum requests allowed
        window_hours: Time window in hours
        
    Returns:
        Number of remaining requests
    """
    now = datetime.utcnow()
    window_start = now - timedelta(hours=window_hours)
    
    if identifier not in _request_counts:
        return max_requests
    
    # Count requests in window
    recent = [
        ts for ts in _request_counts[identifier]
        if ts > window_start
    ]
    
    return max(0, max_requests - len(recent))