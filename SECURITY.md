# Security Policy

This document describes how security issues in the PyPNM project are handled. It is intended for users, contributors, and operators who discover or suspect a vulnerability in the code, configuration, or release artifacts.

## Supported Versions

PyPNM is under active development. At this time, security fixes are generally provided for:

- The latest release on the `main` branch
- The most recent tagged release, when applicable

Older releases may not receive security fixes. If you are running an older version and discover a vulnerability, please test against the latest version and include that information when reporting the issue.

## Reporting a Vulnerability

If you believe you have found a security vulnerability in PyPNM, any of its dependencies, or related release artifacts (containers, example configs, scripts), please notify the maintainer privately.

### Preferred Contact

- Email: `pypnm.docsis@gmail.com`

When reporting, include as much detail as possible so the issue can be reproduced and evaluated:

- A description of the suspected vulnerability
- Steps to reproduce the issue
- The impact you believe it may have
- The environment details:
  - PyPNM version (commit hash or tag)
  - Python version
  - Operating system and architecture
- Any relevant configuration details (sanitize or anonymize sensitive values)

### What Not To Do

- Do not open public GitHub issues or pull requests that contain exploit details, stack traces with sensitive data, or real credentials.
- Do not share real SNMP communities, API keys, passwords, or private IP addresses in any public location.
- Do not test discovered vulnerabilities against systems or networks you do not own or have explicit permission to test.

## Handling Process

When a security report is received, the general process is:

1. **Acknowledgement**  
   The maintainer will acknowledge receipt of the report as soon as reasonably possible.

2. **Triage and Verification**  
   The issue will be reviewed to confirm whether it is a valid security concern, to understand impact, scope, and affected components.

3. **Fix Development**  
   If the issue is confirmed, a fix or mitigation will be developed. In some cases this may include updates to dependencies, container images, or documentation.

4. **Release and Advisory**  
   Once a fix is ready, a new release may be published and, if necessary, a security advisory created through GitHub or the project documentation. Reporters will be notified of the outcome.

5. **Post-Resolution Review**  
   When appropriate, build and review additional safeguards (for example, additional tests, configuration hardening, or CI checks) to prevent regressions.

## Scope

Security reports are especially welcome for issues related to:

- Remote code execution, privilege escalation, or arbitrary file access in PyPNM services
- Authentication, authorization, or access control bypass in the FastAPI interface
- Leakage of secrets (SNMP communities, encryption keys, access tokens) through logs, endpoints, or generated artifacts
- Insecure default configurations that could lead to exposure when using recommended example settings
- Vulnerabilities introduced by dependencies (for example, high or critical CVEs)

The following are generally **out of scope** for security reporting, unless they directly lead to a concrete security impact:

- General performance problems
- Non-sensitive information leaks (for example, error messages without sensitive content)
- Denial-of-service scenarios that require unrealistic or abusive local access

If you are unsure whether something qualifies, you are encouraged to report it privately anyway. It is better to over-report potential issues than to overlook a real vulnerability.

## Responsible Disclosure

The PyPNM project follows a responsible disclosure approach:

- Please report vulnerabilities privately first and allow reasonable time for analysis and remediation before public disclosure.
- The maintainer will work with you to coordinate timelines for any public announcement, if warranted.
- If you intend to publish your findings, please mention this in your initial report so timelines can be discussed.

## Development and Hardening Practices

To reduce the likelihood of security issues, the project adopts the following general practices:

- Avoid committing secrets to the repository; use local configuration files and environment variables instead.
- Use secret-scanning tools (such as gitleaks and TruffleHog) before making repositories public or cutting releases.
- Keep dependencies up to date and monitor vulnerability advisories.
- Prefer least-privilege access for any external services or credentials used in examples or automation.
- Treat all user-provided input as untrusted when designing new APIs or features.

If you have suggestions for improving the security posture of PyPNM (for example, hardening configuration defaults, recommended deployment patterns, or CI checks), you are welcome to share them via a non-public security report or a regular GitHub issue if they do not disclose sensitive information.
