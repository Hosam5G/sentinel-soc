# Security Policy

## Reporting a vulnerability

If you discover a security vulnerability in Sentinel SOC, please report it
**privately** rather than opening a public issue.

- Do **not** disclose the issue publicly until it has been addressed.
- Provide enough detail to reproduce: affected version, steps, and impact.
- You will receive an acknowledgement and, where possible, a timeline for a fix.

## Scope

Because Sentinel SOC is a security tool that runs with elevated privileges and
executes system commands, the following are of particular interest:

- Command/argument injection in any endpoint that calls `netsh`, `net`,
  `powershell`, `wevtutil`, or `icacls`.
- Authentication / session / CSRF bypass.
- Path traversal in any file-reading or report endpoint.
- Privilege escalation via the isolation or remediation features.

## Known design limitations (not vulnerabilities)

These are documented trade-offs, not bugs:

- Sentinel runs in **user space** and cannot prevent code execution before it
  runs (unlike a signed kernel driver). It detects and responds, not prevents.
- **Auto-isolation is opt-in** and off by default; Monitor-Only mode is on by
  default to reduce false positives.
- The tool is **not a replacement for antivirus** — keep Defender enabled.

## Hardening already in place

- Passwords hashed with PBKDF2-HMAC-SHA256 (120k iterations) + per-user salt.
- Session tokens and CSRF tokens generated with `secrets`.
- Account lockout after repeated failed logins; per-IP rate limiting on
  mutating endpoints.
- Server binds to `127.0.0.1` only (not exposed to the network).
- All `subprocess` calls use argument lists (no `shell=True`); IP inputs to the
  firewall are strictly validated with `ipaddress`.
- Data encrypted at rest.
