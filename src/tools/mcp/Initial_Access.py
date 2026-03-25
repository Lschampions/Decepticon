"""
Initial Access MCP Server - SECURED VERSION
Authentication attack tools with input validation and sanitization
"""

from mcp.server.fastmcp import FastMCP
from typing_extensions import Annotated
from typing import List, Optional, Union
import subprocess
import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from src.utils.security.sanitization import (
    validate_target,
    validate_options,
    build_safe_command,
    sanitize_command_input,
    InputValidationError
)
from src.utils.security.auth import check_rate_limit, authenticate_request

mcp = FastMCP("initial_access", port=3002)

CONTAINER_NAME = os.getenv("MCP_CONTAINER_NAME", "attacker")

# Rate limit configuration (stricter for attack tools)
RATE_LIMIT_REQUESTS = int(os.getenv("RATE_LIMIT_REQUESTS", "50"))
RATE_LIMIT_WINDOW = int(os.getenv("RATE_LIMIT_WINDOW_HOURS", "1"))

# Allowed hydra options (whitelist)
ALLOWED_HYDRA_OPTIONS = {
    '-l', '-L',  # Username options
    '-p', '-P',  # Password options
    '-s',  # Port
    '-t',  # Tasks
    '-w',  # Wait
    '-f',  # Fast mode
    '-v', '-V',  # Verbose
    '-o',  # Output
    '-q',  # Quiet
    '-e',  # Error level
    '-S',  # SSL
    '-C',  # Combo list
    '-M',  # Module
    '-h',  # Help
}

# Allowed searchsploit options
ALLOWED_SEARCHSPLOIT_OPTIONS = {
    '-t',  # Title only
    '-j',  # JSON output
    '-w',  # URL format
    '-c',  # Case sensitive
    '-x',  # Execute
    '-m',  # Mirror
    '-p',  # Path
    '--exclude',  # Exclude
    '--colour',  # Color
}


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
            identifier = api_key[:16]
            
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
        
        # Execute command
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


@mcp.tool(description="Brute-force authentication attacks")
def hydra(
    target: str,
    options: Optional[Union[str, List[str]]] = None,
    api_key: Optional[str] = None
) -> Annotated[str, "Command"]:
    """
    Execute Hydra brute-force attack on target.
    
    Args:
        target: Target specification (protocol://target)
        options: Hydra options
        api_key: Optional API key for authentication
        
    Returns:
        Attack results
    """
    try:
        # Validate target
        validated_target, target_type = validate_target(target)
        
        # Validate options
        validated_options = validate_options(options, ALLOWED_HYDRA_OPTIONS)
        
        # Build safe command
        args = validated_options + [validated_target]
        command = build_safe_command("hydra", args)
        
        return command_execution(command, api_key)
    
    except InputValidationError as e:
        return f"[-] Input validation error: {e.message}"
    except Exception as e:
        return f"[-] Error: {str(e)}"


@mcp.tool(description="Search exploit database for vulnerabilities")
def searchsploit(
    service_name: str,
    options: Optional[Union[str, List[str]]] = None,
    api_key: Optional[str] = None
) -> Annotated[str, "Command"]:
    """
    Search Exploit-DB for vulnerabilities.
    
    Args:
        service_name: Service name to search
        options: Searchsploit options
        api_key: Optional API key for authentication
        
    Returns:
        Search results
    """
    try:
        # Validate service name (alphanumeric with some special chars)
        if not service_name or len(service_name) > 100:
            raise InputValidationError(
                message="Service name must be 1-100 characters",
                field="service_name",
                value=service_name[:50] if service_name else ""
            )
        
        # Only allow alphanumeric, hyphens, underscores, and spaces
        import re
        if not re.match(r'^[a-zA-Z0-9_\-\s]+$', service_name):
            raise InputValidationError(
                message="Service name contains invalid characters",
                field="service_name",
                value=service_name
            )
        
        # Validate options
        validated_options = validate_options(options, ALLOWED_SEARCHSPLOIT_OPTIONS)
        
        # Build safe command
        args = validated_options + [service_name]
        command = build_safe_command("searchsploit", args)
        
        return command_execution(command, api_key)
    
    except InputValidationError as e:
        return f"[-] Input validation error: {e.message}"
    except Exception as e:
        return f"[-] Error: {str(e)}"


if __name__ == "__main__":
    mcp.run(transport="streamable-http")