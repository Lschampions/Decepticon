"""
Reconnaissance MCP Server - SECURED VERSION
Network reconnaissance tools with input validation and sanitization
"""

from mcp.server.fastmcp import FastMCP
from typing_extensions import Annotated
from typing import List, Optional, Union, Tuple
import subprocess
import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from src.utils.security.sanitization import (
    validate_target,
    validate_options,
    build_safe_command,
    InputValidationError,
    ALLOWED_NMAP_OPTIONS,
    ALLOWED_CURL_OPTIONS
)
from src.utils.security.auth import require_auth, check_rate_limit, authenticate_request

mcp = FastMCP("reconnaissance", port=3001)

CONTAINER_NAME = os.getenv("MCP_CONTAINER_NAME", "attacker")

# Rate limit configuration
RATE_LIMIT_REQUESTS = int(os.getenv("RATE_LIMIT_REQUESTS", "100"))
RATE_LIMIT_WINDOW = int(os.getenv("RATE_LIMIT_WINDOW_HOURS", "1"))


def command_execution(
    command: str,
    api_key: Optional[str] = None
) -> Annotated[str, "Command Execution Result"]:
    """
    Run a command in a Kali Linux environment and return the result.
    
    SECURITY: This function only accepts pre-validated and sanitized commands.
    """
    # Authenticate if API key provided
    if api_key:
        try:
            auth_result = authenticate_request(api_key=api_key)
            identifier = api_key[:16]  # Use first 16 chars for rate limiting
            
            if not check_rate_limit(identifier, RATE_LIMIT_REQUESTS, RATE_LIMIT_WINDOW):
                return "[-] Rate limit exceeded. Please try again later."
        except ValueError as e:
            return f"[-] Authentication failed: {str(e)}"
    
    try:
        # Docker availability check
        docker_check = subprocess.run(
            ["docker", "ps"],
            capture_output=True, text=True, encoding="utf-8", errors="ignore"
        )
        
        if docker_check.returncode != 0:
            return f"[-] Docker is not available: {docker_check.stderr.strip()}"
        
        # Container existence check
        container_check = subprocess.run(
            ["docker", "ps", "-a", "--filter", f"name={CONTAINER_NAME}"],
            capture_output=True, text=True, encoding="utf-8", errors="ignore"
        )
        
        if CONTAINER_NAME not in container_check.stdout:
            return f"[-] Container '{CONTAINER_NAME}' does not exist"
        
        # Container running status check
        running_check = subprocess.run(
            ["docker", "ps", "--filter", f"name={CONTAINER_NAME}"],
            capture_output=True, text=True, encoding="utf-8", errors="ignore"
        )
        
        # Start container if not running
        if CONTAINER_NAME not in running_check.stdout:
            start_result = subprocess.run(
                ["docker", "start", CONTAINER_NAME],
                capture_output=True, text=True, encoding="utf-8", errors="ignore"
            )
            
            if start_result.returncode != 0:
                return f"[-] Failed to start container '{CONTAINER_NAME}': {start_result.stderr.strip()}"
        
        # Execute command - using list format to prevent shell injection
        # The command should already be validated and safe
        result = subprocess.run(
            ["docker", "exec", CONTAINER_NAME, "sh", "-c", command],
            capture_output=True, text=True, encoding="utf-8", errors="ignore"
        )
        
        if result.returncode != 0:
            return f"[-] Command execution error: {result.stderr.strip()}"
        
        return f"{result.stdout.strip()}"
    
    except FileNotFoundError:
        return "[-] Docker command not found. Is Docker installed and in PATH?"
    
    except Exception as e:
        return f"[-] Error: {str(e)} (Type: {type(e).__name__})"


@mcp.tool(description="Network discovery and port scanning")
def nmap(
    target: str,
    options: Optional[Union[str, List[str]]] = None,
    api_key: Optional[str] = None
) -> Annotated[str, "Command execution Result"]:
    """
    Execute nmap scan on target.
    
    Args:
        target: IP address, hostname, or network range to scan
        options: Nmap options (e.g., '-sV', '-p 80,443')
        api_key: Optional API key for authentication
        
    Returns:
        Scan results
    """
    try:
        # Validate target
        validated_target, target_type = validate_target(target)
        
        # Validate options
        validated_options = validate_options(options, ALLOWED_NMAP_OPTIONS)
        
        # Build safe command
        args = validated_options + [validated_target]
        command = build_safe_command("nmap", args)
        
        return command_execution(command, api_key)
    
    except InputValidationError as e:
        return f"[-] Input validation error: {e.message}"
    except Exception as e:
        return f"[-] Error: {str(e)}"


@mcp.tool(description="Web service analysis and content retrieval")
def curl(
    target: str = "",
    options: str = "",
    api_key: Optional[str] = None
) -> Annotated[str, "Command execution Result"]:
    """
    Execute curl request to target URL.
    
    Args:
        target: URL to request
        options: Curl options
        api_key: Optional API key for authentication
        
    Returns:
        Request results
    """
    try:
        # Validate target as URL
        validated_target, target_type = validate_target(target)
        
        if target_type != 'url' and not target.startswith(('http://', 'https://')):
            # Add https prefix if missing
            validated_target = f"https://{validated_target}"
        
        # Validate options
        validated_options = validate_options(options, ALLOWED_CURL_OPTIONS)
        
        # Build safe command
        args = validated_options + [validated_target]
        command = build_safe_command("curl", args)
        
        return command_execution(command, api_key)
    
    except InputValidationError as e:
        return f"[-] Input validation error: {e.message}"
    except Exception as e:
        return f"[-] Error: {str(e)}"


@mcp.tool(description="DNS information gathering")
def dig(
    target: str,
    options: str = "",
    api_key: Optional[str] = None
) -> Annotated[str, "Command execution Result"]:
    """
    Execute DNS lookup using dig.
    
    Args:
        target: Domain name to query
        options: Dig options (limited to safe options)
        api_key: Optional API key for authentication
        
    Returns:
        DNS query results
    """
    # Allowed dig options
    ALLOWED_DIG_OPTIONS = {
        '@',  # DNS server
        '-t',  # Query type
        '-x',  # Reverse lookup
        '+short', '+trace', '+short',
        'A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME', 'PTR'
    }
    
    try:
        # Validate target
        validated_target, target_type = validate_target(target)
        
        # Validate options
        validated_options = validate_options(options, ALLOWED_DIG_OPTIONS)
        
        # Build safe command
        args = validated_options + [validated_target]
        command = build_safe_command("dig", args)
        
        return command_execution(command, api_key)
    
    except InputValidationError as e:
        return f"[-] Input validation error: {e.message}"
    except Exception as e:
        return f"[-] Error: {str(e)}"


@mcp.tool(description="Domain registration and ownership lookup")
def whois(
    target: str,
    options: str = "",
    api_key: Optional[str] = None
) -> Annotated[str, "Command execution Result"]:
    """
    Execute WHOIS lookup.
    
    Args:
        target: Domain name or IP to query
        options: Whois options
        api_key: Optional API key for authentication
        
    Returns:
        WHOIS results
    """
    # Allowed whois options
    ALLOWED_WHOIS_OPTIONS = {
        '-h',  # Server
        '-p',  # Port
        '-a',  # All
    }
    
    try:
        # Validate target
        validated_target, target_type = validate_target(target)
        
        # Validate options
        validated_options = validate_options(options, ALLOWED_WHOIS_OPTIONS)
        
        # Build safe command
        args = validated_options + [validated_target]
        command = build_safe_command("whois", args)
        
        return command_execution(command, api_key)
    
    except InputValidationError as e:
        return f"[-] Input validation error: {e.message}"
    except Exception as e:
        return f"[-] Error: {str(e)}"


if __name__ == "__main__":
    mcp.run(transport="streamable-http")