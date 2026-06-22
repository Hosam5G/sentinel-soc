# Sentinel SOC

> A privacy-first, local-only security monitoring dashboard for Windows.
> **An educational / supplementary security tool — not a replacement for antivirus.**

Sentinel SOC is a desktop security dashboard that runs entirely on your own
machine. It scans for real vulnerabilities, watches running processes and files
in real time, and explains what it finds using a local AI model. **Nothing is
ever uploaded** — all detection and analysis happen on your device.

---

## ⚠️ Important: what this is and isn't

**Sentinel SOC is a supplementary monitoring layer, not antivirus.**

- ✅ It **detects and responds** to suspicious activity within ~1 second.
- ❌ It does **not** block threats before they execute the way Microsoft Defender
  does. Defender runs in the Windows kernel; Sentinel runs in user space and
  cannot intercept code before it runs.
- 👉 **Keep Microsoft Defender (or your antivirus) enabled.** Sentinel is a layer
  *on top of* it, not a replacement.

Treat Sentinel as an extra set of eyes that explains your security posture in
plain language — useful for learning, monitoring, and incident awareness.

---

## Features

- **Vulnerability scanner** — checks firewall, Defender status, SMBv1, RDP/NLA,
  UAC, guest account, risky open ports, and installed software (real checks via
  the Windows registry and `netsh`/`net`, not mock data).
- **Real-time protection** — always-on, event-driven monitoring of new processes,
  outbound connections, and document folders. Uses a **risk-scoring model** that
  aggregates multiple behavioral signals (encoded commands, download/exec,
  suspicious paths, parent→child chains) and subtracts trust signals (valid code
  signature, trusted parent, user allowlist) before deciding to alert or isolate.
- **Behavioral heuristics** — signature-less detection of ransomware-style mass
  file changes, beaconing, and living-off-the-land process chains.
- **Auto-isolation** (opt-in, off by default) — suspends (never kills) a
  confirmed-malicious process so it can be inspected and resumed. Critical OS
  processes are protected and never touched.
- **Monitor-Only mode** (on by default) — alerts without isolating, so you can
  tune the allowlist from real usage before enabling active response.
- **Six detection engines** — processes, persistence, network, accounts,
  rootkit (cross-view), and file-integrity monitoring (FIM).
- **Threat intelligence** — matches installed software against the CISA KEV
  catalog (read-only public feed).
- **YARA scanning** — scans files against local rules (yara-python or a built-in
  fallback engine).
- **Local AI analysis** — uses Foundation-Sec-8B via [Ollama](https://ollama.com)
  to explain findings and generate reports. The model runs **locally**.
- **Professional PDF reports** — bilingual (English / Arabic) enterprise-style
  security assessment reports.
- **Authentication** — PBKDF2 password hashing (120k iterations), TOTP MFA,
  role-based access (admin / analyst / viewer), account lockout, CSRF protection,
  and an audit log.

---

## Privacy

- **100% local.** No telemetry, no cloud, no account required.
- The only optional outbound calls are: the **CISA KEV** public feed, **community
  YARA rule** updates, and — only if *you* enable it with *your* API key — a
  **VirusTotal hash lookup** (sends a file hash, never the file).
- All data is stored encrypted at rest on your machine.

---

## Requirements

- Windows 10 / 11
- Python 3.10+
- [Ollama](https://ollama.com) with a Foundation-Sec model pulled (for AI
  analysis; the tool works without it, with reduced analysis features)
- Recommended: run **as Administrator** so isolation can act on high-privilege
  processes
- Optional: [Sysmon](https://learn.microsoft.com/sysinternals/downloads/sysmon)
  for richer, ETW-grade telemetry; `pywin32` for WMI events

## Installation

```bash
# 1. install Python dependencies
pip install -r requirements.txt

# 2. (optional) install Ollama and pull the model
ollama pull hf.co/fdtn-ai/Foundation-Sec-8B-Instruct-Q8_0-GGUF

# 3. run the server
set SENTINEL_PORT=8765
python dashboard_routes.py
```

Then open <http://127.0.0.1:8765> in your browser. The first account you create
becomes the admin.

## Configuration (environment variables)

| Variable | Default | Description |
|---|---|---|
| `SENTINEL_PORT` | `8765` | Port to listen on (localhost only) |
| `SENTINEL_REALTIME` | `1` | Real-time protection on/off |
| `SENTINEL_MONITOR_ONLY` | `1` | Alert without isolating (recommended at first) |
| `SENTINEL_AUTO_ISOLATE` | `0` | Allow automatic isolation of clear threats |
| `SENTINEL_SCAN_MINUTES` | `60` | Periodic full-scan interval |

---

## How real-time detection decides (risk scoring)

Instead of single-signal triggers (which cause false positives), Sentinel
aggregates signals into a score:

```
LOLBin host           +20      signed/trusted binary    -30
encoded command       +30      trusted parent launcher  -30
download/remote-exec  +40      user allowlist           -60
hidden window         +15
-NoProfile            +10      0–39   → ignore
ExecutionPolicy Bypass+15      40–69  → alert only
temp/writable path    +25      70+    → alert + isolate
suspicious chain      +45
```

This keeps legitimate admin tools, updaters, and your own scripts quiet while
still catching real attack patterns.

---

## Limitations (read before relying on it)

- **User-space only.** Detects and responds within ~1 s; cannot prevent execution
  like a signed kernel driver (Defender) can.
- **Not independently audited.** This project has not undergone a third-party
  penetration test. Do not treat it as a guaranteed security control.
- **AI analysis quality** depends on the local model. Foundation-Sec is
  English-first; Arabic output falls back to hand-written text when needed.
- **Isolation needs privilege.** Suspending SYSTEM-level processes requires
  running as Administrator.

---

## License

See [LICENSE](LICENSE). Provided **as-is, without warranty of any kind**. The
authors are not liable for any damages arising from use. This is not a certified
security product.

## Contributing

Issues and pull requests are welcome. Because this is a security tool, please
report security concerns privately first (see SECURITY.md).
