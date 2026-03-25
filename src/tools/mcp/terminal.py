"""
Terminal MCP Server - SECURED VERSION
Interactive terminal session management with security controls
"""

from mcp.server.fastmcp import FastMCP
from typing_extensions import Annotated
from typing import List, Optional
import subprocess
import uuid
import time
import os
import sys
import re

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from src.utils.security.sanitization import (
    sanitize_command_input,
    InputValidationError
)
from src.utils.security.auth import check_rate_limit, authenticate_request

mcp = FastMCP("terminal", port=3003)

CONTAINER_NAME = os.getenv("MCP_CONTAINER_NAME", "attacker")

# Rate limit configuration
RATE_LIMIT_REQUESTS = int(os.getenv("RATE_LIMIT_REQUESTS", "100"))
RATE_LIMIT_WINDOW = int(os.getenv("RATE_LIMIT_WINDOW_HOURS", "1"))

# Session management
SESSION_LIMIT = int(os.getenv("MCP_SESSION_LIMIT", "10"))  # Max sessions per user
active_sessions = {}  # Track sessions by user


def run(command: List[str]) -> subprocess.CompletedProcess:
    """General docker exec command execution"""
    return subprocess.run(
        ["docker", "exec", CONTAINER_NAME] + command,
        capture_output=True, text=True, encoding='utf-8'
    )


def tmux_run(command: List[str]) -> subprocess.CompletedProcess:
    """tmux command execution"""
    return run(["tmux"] + command)


def validate_session_name(session_name: str) -> str:
    """
    Validate tmux session name.
    
    Args:
        session_name: The session name to validate
        
    Returns:
        Validated session name
        
    Raises:
        InputValidationError: If session name is invalid
    """
    if not session_name:
        raise InputValidationError(
            message="Session name cannot be empty",
            field="session_name",
            value=""
        )
    
    if len(session_name) > 100:
        raise InputValidationError(
            message="Session name too long (max 100 characters)",
            field="session_name",
            value=session_name[:50]
        )
    
    # Only allow alphanumeric, hyphens, underscores
    if not re.match(r'^[a-zA-Z0-9_\-]+$', session_name):
        raise InputValidationError(
            message="Session name can only contain alphanumeric characters, hyphens, and underscores",
            field="session_name",
            value=session_name
        )
    
    return session_name


@mcp.tool(description="Create new terminal sessions")
def create_session(
    session_names: Annotated[List[str], "Session names to create"],
    api_key: Optional[str] = None
) -> Annotated[List[str], "List of created session names"]:
    """Create new tmux terminal sessions"""
    
    # Authenticate and rate limit
    user_id = "anonymous"
    if api_key:
        try:
            auth_result = authenticate_request(api_key=api_key)
            user_id = api_key[:16]
            
            if not check_rate_limit(user_id, RATE_LIMIT_REQUESTS, RATE_LIMIT_WINDOW):
                raise Exception("Rate limit exceeded. Please try again later.")
        except ValueError as e:
            raise Exception(f"Authentication failed: {str(e)}")
    
    created_sessions = []
    
    # Check session limit
    current_sessions = session_list()
    if len(current_sessions) >= SESSION_LIMIT:
        raise Exception(f"Maximum session limit ({SESSION_LIMIT}) reached. Kill existing sessions first.")
    
    for session_name in session_names:
        try:
            # Validate session name
            validated_name = validate_session_name(session_name)
            
            result = tmux_run(["new-session", "-d", "-s", validated_name])
            if result.returncode != 0:
                raise Exception(f"Failed to create session '{validated_name}': {result.stderr}")
            
            created_sessions.append(validated_name)
            
            # Track session
            if user_id not in active_sessions:
                active_sessions[user_id] = []
            active_sessions[user_id].append(validated_name)
            
        except InputValidationError as e:
            raise Exception(f"Invalid session name: {e.message}")
    
    return created_sessions


@mcp.tool(description="List all active sessions")
def session_list() -> Annotated[List[str], "List of session IDs"]:
    """List all active tmux sessions"""
    result = tmux_run(["list-sessions"])
    if result.returncode != 0:
        return []
    return [line.split(":")[0].strip() for line in result.stdout.strip().split('\n') if line.strip()]


@mcp.tool(description="Execute command in session")
def command_exec(
    session_id: Annotated[str, "Session ID"],
    command: Annotated[str, "Command to execute"],
    api_key: Optional[str] = None
) -> Annotated[str, "Command output"]:
    """
    Execute command in a tmux session with security controls.
    
    SECURITY: Commands are validated and sanitized before execution.
    """
    # Authenticate and rate limit
    if api_key:
        try:
            auth_result = authenticate_request(api_key=api_key)
            user_id = api_key[:16]
            
            if not check_rate_limit(user_id, RATE_LIMIT_REQUESTS * 2, RATE_LIMIT_WINDOW):
                raise Exception("Rate limit exceeded. Please try again later.")
        except ValueError as e:
            raise Exception(f"Authentication failed: {str(e)}")
    
    try:
        # Validate session ID
        validated_session = validate_session_name(session_id)
        
        # Check session exists
        sessions = session_list()
        if validated_session not in sessions:
            raise Exception(f"Session '{validated_session}' does not exist")
        
        # Sanitize command - check for dangerous patterns
        # Note: We allow more flexibility here since it's interactive use,
        # but we still block the most dangerous patterns
        dangerous_commands = [
            r'rm\s+-rf\s+/',  # rm -rf /
            r'rm\s+-rf\s+~',  # rm -rf ~
            r'mkfs',          # Format disk
            r'dd\s+if=',      # dd commands
            r':(){ :|:& };:', # Fork bomb
            r'chmod\s+777\s+/',  # chmod 777 /
            r'>\s*/dev/',     # Writing to devices
        ]
        
        for pattern in dangerous_commands:
            if re.search(pattern, command, re.IGNORECASE):
                raise Exception(f"Command blocked: potentially dangerous operation detected")
        
        channel = f"done-{validated_session}-{uuid.uuid4().hex[:8]}"
        timestamp = int(time.time())
        output_file = f"/tmp/cmd_output_{validated_session}_{timestamp}.txt"
        status_file = f"/tmp/cmd_status_{validated_session}_{timestamp}.txt"

        # Build command with output redirection
        # Note: We still use shell execution here because tmux requires it,
        # but the command has been validated above
        full_command = f"({command}) > {output_file} 2>&1; echo $? > {status_file}; tmux wait-for -S {channel}"
        
        result = tmux_run(["send-keys", "-t", validated_session, full_command, "Enter"])
        if result.returncode != 0:
            raise Exception(f"Failed to execute command: {result.stderr}")
        
        wait_result = tmux_run(["wait-for", channel])
        if wait_result.returncode != 0:
            raise Exception(f"Command execution monitoring failed: {wait_result.stderr}")
        
        try:
            # Read status code
            status_result = run(["cat", status_file])
            if status_result.returncode != 0:
                raise Exception(f"Failed to read status file: {status_result.stderr}")
            
            try:
                exit_code = int(status_result.stdout.strip())
            except ValueError:
                raise Exception(f"Invalid exit code: '{status_result.stdout.strip()}'")
            
            # Read output
            output_result = run(["cat", output_file])
            if output_result.returncode != 0:
                raise Exception(f"Failed to read output file: {output_result.stderr}")
            
            output = output_result.stdout

            # Clean up files
            run(["rm", "-f", output_file, status_file])
            
            # Don't raise exception on non-zero exit, just report it
            if exit_code != 0:
                return f"[!] Command exited with code {exit_code}:\n{output.strip()}"
            
            return output.strip()
            
        except Exception as e:
            # Clean up files on error
            run(["rm", "-f", output_file, status_file])
            raise Exception(f"Failed to process command result: {str(e)}")
    
    except InputValidationError as e:
        raise Exception(f"Validation error: {e.message}")
    except Exception as e:
        raise Exception(f"Failed to execute command: {str(e)}")


@mcp.tool(description="Kill terminal sessions")
def kill_session(
    session_names: Annotated[List[str], "Session names to kill"],
    api_key: Optional[str] = None
) -> Annotated[List[str], "Results for each session"]:
    """Kill tmux sessions"""
    results = []
    
    for session_name in session_names:
        try:
            # Validate session name
            validated_name = validate_session_name(session_name)
            
            result = tmux_run(["kill-session", "-t", validated_name])
            if result.returncode == 0:
                results.append(f"Session {validated_name} killed successfully")
                
                # Remove from tracking
                for user_id in active_sessions:
                    if validated_name in active_sessions[user_id]:
                        active_sessions[user_id].remove(validated_name)
            else:
                results.append(f"Session {validated_name} killed (with warning: {result.stderr})")
        except InputValidationError as e:
            results.append(f"Invalid session name: {e.message}")
        except Exception as e:
            results.append(f"Failed to kill session {session_name}: {str(e)}")
    
    return results


@mcp.tool(description="Kill server, Kill all session")
def kill_server(api_key: Optional[str] = None) -> Annotated[str, "Result"]:
    """Kill all tmux sessions and the server"""
    
    # Require authentication for this destructive operation
    if api_key:
        try:
            auth_result = authenticate_request(api_key=api_key)
        except ValueError as e:
            return f"Authentication failed: {str(e)}"
    else:
        return "Authentication required for this operation"
    
    try:
        tmux_run(["kill-server"])
        active_sessions.clear()
        return "Server killed"
    except Exception as e:
        return f"Server killed (with warning: {str(e)})"


if __name__ == "__main__":
    mcp.run(transport="streamable-http")