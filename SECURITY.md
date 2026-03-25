# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.x.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Security Features

This repository implements the following security measures:

### Input Validation
- All user inputs are validated and sanitized using the `src/utils/security/sanitization.py` module
- Command injection prevention through input whitelisting
- Target validation for IP addresses, hostnames, and URLs

### Authentication
- API key-based authentication for MCP servers
- JWT token support for session management
- Rate limiting to prevent abuse

### Container Security
- Non-privileged Docker containers
- Network isolation using bridge networking
- Resource limits to prevent DoS

### Dependency Security
- Automated dependency vulnerability scanning via GitHub Actions
- Weekly security scans scheduled
- SARIF output integration with GitHub Security tab

## Reporting a Vulnerability

We take security vulnerabilities seriously. If you discover a vulnerability, please follow these steps:

### How to Report

1. **Do NOT** open a public issue
2. Email security details to: [security@example.com] (replace with actual email)
3. Include the following information:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

### What to Expect

- **Acknowledgment**: Within 48 hours
- **Initial Assessment**: Within 7 days
- **Status Update**: Every 7 days until resolved
- **Resolution**: Critical vulnerabilities within 30 days

### Disclosure Policy

- We follow responsible disclosure
- We request 90 days to fix vulnerabilities before public disclosure
- We will credit researchers who report vulnerabilities (unless anonymity is requested)

## Security Best Practices for Users

When using this tool:

1. **Never run as root** on production systems
2. **Keep API keys secret** - use environment variables
3. **Limit network exposure** - bind MCP servers to localhost only
4. **Regular updates** - keep dependencies updated
5. **Audit logs** - monitor for suspicious activity
6. **Authorization** - only authorized users should have access

## Security Configuration

### Environment Variables

```bash
# Required for production
MCP_SECRET_KEY=<your-secret-key-here>
RATE_LIMIT_REQUESTS=100
RATE_LIMIT_WINDOW_HOURS=1
MCP_SESSION_LIMIT=10
```

### Docker Security

The `docker-compose.yml` has been secured with:
- Network isolation (bridge mode)
- Resource limits
- Non-privileged containers
- Localhost-only port binding

## Known Security Considerations

This is a penetration testing tool. Be aware of:

1. **Legal Compliance**: Ensure you have authorization to test targets
2. **Network Traffic**: The tool generates network traffic that may trigger IDS/IPS
3. **Container Isolation**: While secured, containers are not impenetrable
4. **Data Handling**: Scan results may contain sensitive information

## Security Audit History

| Date | Auditor | Scope | Status |
|------|---------|-------|--------|
| 2025-06-13 | Internal | Code Review | Completed |

## Contact

For security concerns:
- Security Team: [security@example.com]
- GitHub Security: Use the "Report a vulnerability" feature