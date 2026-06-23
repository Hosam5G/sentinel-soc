# Sentinel SOC

<p align="center">
  <img src="https://img.shields.io/badge/platform-Windows%2010%20%7C%2011-0078D6?logo=windows&logoColor=white" alt="Platform">
  <img src="https://img.shields.io/badge/python-3.10%2B-3776AB?logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/license-MIT-green" alt="License">
  <img src="https://img.shields.io/badge/AI-local%20via%20Ollama-FF6B35" alt="Local AI">
  <img src="https://img.shields.io/badge/privacy-100%25%20local-success" alt="Privacy">
  <img src="https://img.shields.io/badge/tests-99%20passing-brightgreen" alt="Tests">
</p>

> A privacy-first, local-only security monitoring dashboard for Windows.
> **An educational / supplementary security tool — not a replacement for antivirus.**

Sentinel SOC is a desktop security dashboard that runs entirely on your own
machine. It scans for real vulnerabilities, watches running processes and files
in real time, and explains what it finds using a local AI model. **Nothing is
ever uploaded** — all detection and analysis happen on your device.

---

## Screenshots

> Replace these placeholders with real screenshots. To add an image: drag it into
> a GitHub issue to get a URL, or commit the files to a `docs/` folder and
> reference them like `![Overview](docs/overview.png)`.

| Overview | Security & Live Detection |
|----------|---------------------------|
| `![Overview](docs/screenshot-overview.png)` | `![Security](docs/screenshot-security.png)` |

| Reports | Real-time Protection |
|---------|----------------------|
| `![Reports](docs/screenshot-reports.png)` | `![Protection](docs/screenshot-protection.png)` |

<!-- Once you add real images, delete the backticks and the note above so they render. -->

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

- **Detection and AI run 100% locally.** No telemetry, no cloud inference, no
  account required. Process/network/file monitoring, the behavioral baseline,
  YARA scanning, and the AI model all run on your machine.
- **The local AI model never leaves your device.** It runs through Ollama on
  `127.0.0.1:11434` — prompts and responses stay local.
- The only **optional** outbound calls are threat-intelligence updates, and they
  are not required for the tool to work:
  - **CISA KEV** public feed (known-exploited-vulnerabilities catalog)
  - **community YARA rule** updates (from public GitHub repos)
  - **IP geolocation** database (public, for network analysis)
  - **VirusTotal hash lookup** — only if *you* enable it with *your* API key
    (sends a file hash, never the file itself)
  - **Telegram alerts** — only if *you* configure them
- Disable all of the above and the core detection still works fully offline.
- All data is stored encrypted at rest on your machine.

---

## AI models

Sentinel talks to a **local** large language model through
[Ollama](https://ollama.com) for its analysis and report-writing features.

**Default:** [Foundation-Sec-8B](https://huggingface.co/fdtn-ai) — an
open-weights model specialized for cybersecurity, in two presets:
- `Q4` — lighter (~4.9 GB), runs on modest hardware
- `Q8` — full (~8.5 GB), higher accuracy

**It works with any Ollama model, not just Foundation-Sec.** Sentinel queries
Ollama for the models you actually have installed and lists them in the model
picker — so you can switch to Llama 3, Qwen, Mistral, or anything else you've
pulled, with one click. (Foundation-Sec is recommended because it's tuned for
security, but it's not required.)

To point the presets at different tags, set environment variables:
```bash
set SENTINEL_MODEL_Q4=your-model:tag
set SENTINEL_MODEL_Q8=your-other-model:tag
```

The tool also runs **without any model** — detection, scanning, and reports
still work; only the AI-written analysis is reduced to built-in summaries.

> Note: the integration targets the **Ollama API** (`/api/generate`,
> `/api/chat`). Models served through other runtimes (LM Studio, llama.cpp
> directly, GPT4All) would need a small adapter.

---

## Requirements

- Windows 10 / 11
- Python 3.10+
- [Ollama](https://ollama.com) with any model pulled (for AI analysis; the tool
  works without it, with reduced analysis features)
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
