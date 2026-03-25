"""
Input Sanitization Module for Decepticon
Protects against command injection and validates inputs
"""

import re
import shlex
import ipaddress
from urllib.parse import urlparse
from typing import Optional, Union, List, Tuple
from dataclasses import dataclass


@dataclass
class InputValidationError(Exception):
    """Raised when input validation fails"""
    message: str
    field: str
    value: str


# Allowed characters for different input types
SAFE_COMMAND_CHARS = re.compile(r'^[a-zA-Z0-9_\-\.\,\s\/\:\@\[\]]+$')
IPV4_PATTERN = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
IPV6_PATTERN = re.compile(r'^[0-9a-fA-F:]+$')
HOSTNAME_PATTERN = re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$')

# Dangerous patterns to block
DANGEROUS_PATTERNS = [
    r';',           # Command separator
    r'\|',          # Pipe
    r'`',           # Command substitution
    r'\$\(',        # Command substitution
    r'\$\{',        # Variable expansion
    r'&&',          # AND operator
    r'\|\|',        # OR operator
    r'\.\.',        # Directory traversal
    r'>',           # Output redirection
    r'<',           # Input redirection
    r'\n',          # Newline injection
    r'\r',          # Carriage return
    r'\x00',        # Null byte
    r'\!\!',        # History expansion
    r'\$\{IFS\}',   # IFS variable manipulation
]

# Allowed nmap options (whitelist)
ALLOWED_NMAP_OPTIONS = {
    '-sS', '-sT', '-sU', '-sA', '-sF', '-sX', '-sN',  # Scan types
    '-sV', '-sC', '-O',  # Version/OS detection
    '-p', '-p-', '-F',  # Port specification
    '-T0', '-T1', '-T2', '-T3', '-T4', '-T5',  # Timing templates
    '-Pn', '-PS', '-PA', '-PU', '-PE', '-PP', '-PM',  # Host discovery
    '-n', '-R',  # DNS resolution
    '-v', '-vv', '-d',  # Verbosity
    '-A',  # Aggressive scan
    '--open', '--closed', '--filtered',  # Port states
    '-oN', '-oX', '-oG', '-oA',  # Output formats
    '--script', '--script-help',  # NSE scripts
    '-6',  # IPv6
    '--top-ports', '--max-retries', '--host-timeout',
}

# Allowed curl options (whitelist)
ALLOWED_CURL_OPTIONS = {
    '-X', '--request',
    '-H', '--header',
    '-d', '--data', '--data-raw', '--data-binary',
    '-u', '--user',
    '-k', '--insecure',
    '-L', '--location',
    '-I', '--head',
    '-s', '--silent',
    '-v', '--verbose',
    '-o', '--output',
    '-w', '--write-out',
    '--connect-timeout', '--max-time',
    '-A', '--user-agent',
    '-e', '--referer',
    '-b', '--cookie',
    '-c', '--cookie-jar',
    '--compressed',
}


def sanitize_command_input(value: str, max_length: int = 4096) -> str:
    """
    Sanitize user input to prevent command injection.
    
    Args:
        value: The input string to sanitize
        max_length: Maximum allowed length
        
    Returns:
        Sanitized string safe for command execution
        
    Raises:
        InputValidationError: If input contains dangerous patterns
    """
    if not value:
        return ""
    
    if len(value) > max_length:
        raise InputValidationError(
            message=f"Input exceeds maximum length of {max_length}",
            field="input",
            value=value[:50] + "..."
        )
    
    # Check for dangerous patterns
    for pattern in DANGEROUS_PATTERNS:
        if re.search(pattern, value):
            raise InputValidationError(
                message=f"Input contains forbidden pattern: {pattern}",
                field="input",
                value=value[:50]
            )
    
    # Use shlex.quote for shell-safe escaping
    return shlex.quote(value)


def validate_ip_address(ip: str, allow_private: bool = True) -> str:
    """
    Validate an IP address (IPv4 or IPv6).
    
    Args:
        ip: The IP address to validate
        allow_private: Whether to allow private IP ranges
        
    Returns:
        The validated IP address
        
    Raises:
        InputValidationError: If IP is invalid
    """
    try:
        ip_obj = ipaddress.ip_address(ip.strip())
        
        # Check if it's a private IP and if those are allowed
        if not allow_private and ip_obj.is_private:
            raise InputValidationError(
                message="Private IP addresses are not allowed",
                field="ip",
                value=ip
            )
        
        # Block multicast and reserved addresses
        if ip_obj.is_multicast or ip_obj.is_reserved:
            raise InputValidationError(
                message="Multicast and reserved IP addresses are not allowed",
                field="ip",
                value=ip
            )
        
        return str(ip_obj)
        
    except ValueError:
        raise InputValidationError(
            message=f"Invalid IP address format: {ip}",
            field="ip",
            value=ip
        )


def validate_hostname(hostname: str) -> str:
    """
    Validate a hostname or domain name.
    
    Args:
        hostname: The hostname to validate
        
    Returns:
        The validated hostname
        
    Raises:
        InputValidationError: If hostname is invalid
    """
    hostname = hostname.strip().lower()
    
    if len(hostname) > 253:
        raise InputValidationError(
            message="Hostname exceeds maximum length of 253 characters",
            field="hostname",
            value=hostname[:50]
        )
    
    if not HOSTNAME_PATTERN.match(hostname):
        raise InputValidationError(
            message=f"Invalid hostname format: {hostname}",
            field="hostname",
            value=hostname
        )
    
    return hostname


def validate_url(url: str, allowed_schemes: List[str] = None) -> str:
    """
    Validate a URL.
    
    Args:
        url: The URL to validate
        allowed_schemes: List of allowed URL schemes (default: ['http', 'https'])
        
    Returns:
        The validated URL
        
    Raises:
        InputValidationError: If URL is invalid
    """
    if allowed_schemes is None:
        allowed_schemes = ['http', 'https']
    
    try:
        parsed = urlparse(url.strip())
        
        if parsed.scheme.lower() not in allowed_schemes:
            raise InputValidationError(
                message=f"URL scheme '{parsed.scheme}' is not allowed. Allowed: {allowed_schemes}",
                field="url",
                value=url
            )
        
        if not parsed.netloc:
            raise InputValidationError(
                message="URL must have a valid network location",
                field="url",
                value=url
            )
        
        return url.strip()
        
    except Exception as e:
        if isinstance(e, InputValidationError):
            raise
        raise InputValidationError(
            message=f"Invalid URL format: {url}",
            field="url",
            value=url
        )


def validate_port(port: Union[str, int]) -> int:
    """
    Validate a port number.
    
    Args:
        port: The port number to validate
        
    Returns:
        The validated port number as integer
        
    Raises:
        InputValidationError: If port is invalid
    """
    try:
        port_int = int(port)
        
        if port_int < 1 or port_int > 65535:
            raise InputValidationError(
                message=f"Port must be between 1 and 65535, got: {port_int}",
                field="port",
                value=str(port)
            )
        
        return port_int
        
    except ValueError:
        raise InputValidationError(
            message=f"Invalid port number: {port}",
            field="port",
            value=str(port)
        )


def validate_target(target: str, allow_private_ips: bool = True) -> Tuple[str, str]:
    """
    Validate a target (IP address, hostname, or URL).
    
    Args:
        target: The target to validate
        allow_private_ips: Whether to allow private IP ranges
        
    Returns:
        Tuple of (validated_target, target_type)
        target_type is one of: 'ip', 'hostname', 'url'
        
    Raises:
        InputValidationError: If target is invalid
    """
    target = target.strip()
    
    if not target:
        raise InputValidationError(
            message="Target cannot be empty",
            field="target",
            value=""
        )
    
    # Try to validate as URL first (if it has a scheme)
    if target.startswith(('http://', 'https://', 'ftp://')):
        return validate_url(target), 'url'
    
    # Try to validate as IP address
    try:
        return validate_ip_address(target, allow_private_ips), 'ip'
    except InputValidationError:
        pass
    
    # Try to validate as hostname
    try:
        return validate_hostname(target), 'hostname'
    except InputValidationError:
        pass
    
    raise InputValidationError(
        message=f"Invalid target format: {target}. Must be a valid IP, hostname, or URL.",
        field="target",
        value=target
    )


def validate_options(options: Optional[Union[str, List[str]]], 
                     allowed_options: set,
                     allow_values: bool = True) -> List[str]:
    """
    Validate command options against a whitelist.
    
    Args:
        options: The options to validate (string or list)
        allowed_options: Set of allowed option flags
        allow_values: Whether to allow values after options (e.g., -p 80)
        
    Returns:
        List of validated and sanitized options
        
    Raises:
        InputValidationError: If options contain invalid values
    """
    if options is None:
        return []
    
    # Convert string to list
    if isinstance(options, str):
        options_list = options.split()
    else:
        options_list = list(options)
    
    validated = []
    i = 0
    
    while i < len(options_list):
        opt = options_list[i]
        
        # Check if option is in whitelist
        if opt in allowed_options:
            validated.append(opt)
        elif allow_values and i > 0 and options_list[i-1] in allowed_options:
            # This is a value for a previous option
            sanitized = sanitize_command_input(opt)
            validated.append(sanitized)
        elif opt.startswith('-'):
            raise InputValidationError(
                message=f"Option '{opt}' is not allowed. Allowed options: {allowed_options}",
                field="options",
                value=opt
            )
        else:
            raise InputValidationError(
                message=f"Invalid option: {opt}",
                field="options",
                value=opt
            )
        
        i += 1
    
    return validated


def build_safe_command(base_cmd: str, args: List[str]) -> str:
    """
    Build a safe command string from base command and validated arguments.
    
    Args:
        base_cmd: The base command (e.g., 'nmap')
        args: List of validated arguments
        
    Returns:
        Safe command string
    """
    # Verify base command is alphanumeric
    if not re.match(r'^[a-zA-Z0-9_\-]+$', base_cmd):
        raise InputValidationError(
            message=f"Invalid base command: {base_cmd}",
            field="command",
            value=base_cmd
        )
    
    # All args should already be validated, but double-check
    safe_args = []
    for arg in args:
        # If already quoted by shlex.quote, keep it
        if arg.startswith("'") and arg.endswith("'"):
            safe_args.append(arg)
        else:
            safe_args.append(sanitize_command_input(arg))
    
    return f"{base_cmd} {' '.join(safe_args)}"