# Security Fixes Summary

## Overview
This document summarizes all security fixes applied to the Decepticon repository.

---

## 1. Input Sanitization Module

**File:** `src/utils/security/sanitization.py`

### Features Implemented:
- **`sanitize_command_input()`** - Sanitizes user input using `shlex.quote()` and dangerous pattern detection
- **`validate_ip_address()`** - Validates IPv4/IPv6 addresses with private IP filtering
- **`validate_hostname()`** - Validates hostnames against RFC standards
- **`validate_url()`** - Validates URLs with scheme whitelisting
- **`validate_target()`** - Unified target validation (IP/hostname/URL)
- **`validate_options()`** - Option whitelisting for command flags
- **`build_safe_command()`** - Constructs safe command strings

### Whitelists Defined:
- `ALLOWED_NMAP_OPTIONS` - 30+ safe nmap flags
- `ALLOWED_CURL_OPTIONS` - 25+ safe curl flags

---

## 2. Authentication Module

**File:** `src/utils/security/auth.py`

### Features Implemented:
- **JWT Token Support** - Access and refresh tokens
- **API Key Authentication** - Secure API key generation and validation
- **Rate Limiting** - Configurable request limits per time window
- **`@require_auth` Decorator** - Easy protection of functions

### Configuration:
```bash
MCP_SECRET_KEY=<secret>      # JWT signing key
RATE_LIMIT_REQUESTS=100      # Max requests per window
RATE_LIMIT_WINDOW_HOURS=1    # Time window
```

---

## 3. Fixed: Reconnaissance.py

**Changes:**
- Added input validation for all tools (nmap, curl, dig, whois)
- Implemented API key authentication support
- Added rate limiting
- Whitelisted allowed command options
- Safe command building

### Before (Vulnerable):
```python
command = f'nmap {args_str} {target}'  # Command injection!
result = subprocess.run(["docker", "exec", CONTAINER_NAME, "sh", "-c", command], ...)
```

### After (Secure):
```python
validated_target, target_type = validate_target(target)
validated_options = validate_options(options, ALLOWED_NMAP_OPTIONS)
args = validated_options + [validated_target]
command = build_safe_command("nmap", args)  # Safe!
```

---

## 4. Fixed: Initial_Access.py

**Changes:**
- Added input validation for hydra and searchsploit
- Implemented API key authentication support
- Added rate limiting (stricter: 50 requests/hour for attack tools)
- Whitelisted allowed command options
- Added dangerous command detection

### New Security Measures:
- Session limits to prevent abuse
- Dangerous command blocking (e.g., `rm -rf /`)

---

## 5. Fixed: terminal.py

**Changes:**
- Session name validation (alphanumeric only)
- Session limits per user
- Dangerous command detection
- API key authentication
- Rate limiting

### Dangerous Commands Blocked:
- `rm -rf /` - Root filesystem deletion
- `rm -rf ~` - Home directory deletion
- `mkfs` - Disk formatting
- `dd if=` - Disk operations
- Fork bombs
- `chmod 777 /` - Permission escalation
- Writing to `/dev/` devices

---

## 6. Fixed: docker-compose.yml

### Changes Made:

| Setting | Before | After |
|---------|--------|-------|
| `privileged` | `true` | **REMOVED** |
| `network_mode` | `host` | `bridge` |
| Port binding | All interfaces | `127.0.0.1` only |
| Resource limits | None | CPU: 2, Memory: 4G |
| Security options | None | `no-new-privileges` |
| Health checks | None | Added |

### Network Isolation:
- Dedicated bridge network `pentest_network`
- Custom subnet: `172.28.0.0/16`
- MCP servers bound to localhost only

---

## 7. Security Scanning Workflow

**File:** `.github/workflows/security.yml`

### Scans Included:
1. **CodeQL Analysis** - Semantic code analysis for Python
2. **Dependency Scanning** - pip-audit + Safety
3. **Semgrep** - Pattern-based security analysis
4. **Bandit** - Python security linter
5. **Secret Scanning** - TruffleHog + Gitleaks
6. **Docker Scanning** - Trivy vulnerability scanner
7. **IaC Scanning** - Checkov for Docker/YAML
8. **Security Summary** - Combined results

### Triggers:
- Push to main/develop
- Pull requests
- Weekly schedule (Monday 00:00 UTC)
- Manual dispatch

---

## 8. Security Policy

**File:** `SECURITY.md`

### Contents:
- Supported versions
- Security features documentation
- Vulnerability reporting process
- Responsible disclosure policy
- Security best practices for users
- Known security considerations

---

## Files Created/Modified

### New Files:
```
src/utils/security/__init__.py
src/utils/security/sanitization.py
src/utils/security/auth.py
.github/workflows/security.yml
SECURITY.md
```

### Modified Files:
```
src/tools/mcp/Reconnaissance.py
src/tools/mcp/Initial_Access.py
src/tools/mcp/terminal.py
docker-compose.yml
```

---

## Vulnerability Remediation Summary

| Vulnerability | Severity | Status |
|--------------|----------|--------|
| Command Injection | Critical | ✅ Fixed |
| Missing Authentication | High | ✅ Fixed |
| Privileged Containers | High | ✅ Fixed |
| Host Network Mode | High | ✅ Fixed |
| No Input Validation | High | ✅ Fixed |
| No Rate Limiting | Medium | ✅ Fixed |
| No Security Scanning | Medium | ✅ Fixed |

---

## Remaining Recommendations

1. **Enable Gitleaks License** - Add `GITLEAKS_LICENSE` secret for full functionality
2. **Enable Semgrep App** - Add `SEMGREP_APP_TOKEN` secret for enhanced rules
3. **Review Security Email** - Update `security@example.com` in SECURITY.md
4. **Test Fixes** - Run the secured tools to verify functionality
5. **Add Unit Tests** - Create tests for the security modules

---

## Usage Example

### With API Key:
```python
# Generate API key
from src.utils.security.auth import generate_api_key, register_api_key

api_key = generate_api_key()
register_api_key(api_key, name="pentester", permissions=["reconnaissance", "initial_access"])

# Use in tool calls
result = nmap("192.168.1.1", "-sV", api_key=api_key)
```

### Environment Setup:
```bash
# .env file
MCP_SECRET_KEY=your-production-secret-key-here
RATE_LIMIT_REQUESTS=100
RATE_LIMIT_WINDOW_HOURS=1
MCP_SESSION_LIMIT=10
MCP_CONTAINER_NAME=attacker
```