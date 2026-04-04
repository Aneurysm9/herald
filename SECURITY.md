# Security Policy

## Supported Versions

Herald is pre-1.0 software. Security fixes are applied to the latest release on the `main` branch only.

| Version | Supported |
|---------|-----------|
| Latest on `main` | Yes |
| Older releases | No |

## Reporting a Vulnerability

**Please do not open public issues for security vulnerabilities.**

Instead, use [GitHub's private vulnerability reporting](https://github.com/Aneurysm9/herald/security/advisories/new) to report security issues. This ensures the report is visible only to maintainers until a fix is available.

### What to include

- A description of the vulnerability and its impact
- Steps to reproduce (or a proof of concept)
- Affected versions or commits, if known
- Any suggested fixes or mitigations

### Response timeline

- **Acknowledgment**: within 48 hours of report
- **Initial assessment**: within 7 days
- **Fix or mitigation**: best effort, targeting 30 days for critical issues
- **Public disclosure**: coordinated with the reporter, typically within 90 days

### Scope

The following are in scope for security reports:

- Authentication or authorization bypass
- Token leakage (in logs, error messages, API responses)
- TLS misconfiguration or downgrade attacks
- Injection vulnerabilities (command injection, header injection, etc.)
- Unauthorized access to DNS records across client boundaries

The following are **not** in scope:

- Feature requests or non-security bugs (please use [regular issues](https://github.com/Aneurysm9/herald/issues))
- Denial of service via resource exhaustion (Herald is designed for trusted networks)
- Vulnerabilities in dependencies without a demonstrated impact on Herald

### Credit

We are happy to credit reporters in release notes (with permission). Let us know how you would like to be credited when you submit the report.
