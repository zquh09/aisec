# 🛡️ AISEC — AI Security Toolkit

**A modern, GUI-based cybersecurity toolkit written in Rust, built for gamers, privacy enthusiasts, and AI developers.**

AISEC combines real-time protection, malware analysis, privacy auditing, and AI-specific security tools in a single, fast desktop application. Written from scratch in Rust with a custom dark theme and a system tray icon.

## ✨ Features

### 🛡️ Real-Time Protection (RTP)
- Watches **Downloads, Desktop, Temp, Startup** folders in real time.
- Automatically quarantines new threats before you run them.
- Uses SHA-256 hash check, YARA signatures, and heuristic analysis.
- Sends native Windows notifications when a threat is blocked.

### 🔌 USB Guard
- Automatically scans any USB drive you plug in.

### ⏰ Scheduled Scans
- Automatic scan every N days (configurable: 0–30 days).

### ☁️ MalwareBazaar Cloud Database
- Auto-downloads fresh hashes from abuse.ch.
- Requires a free Auth-Key from [auth.abuse.ch](https://auth.abuse.ch).
- Put the key in `config/abusech_auth_key.txt`.

### 🧬 YARA Scanner
- Download thousands of community rules from `Yara-Rules/rules` with one click.
- Scan any file against the YARA rules engine (`yara-x`).

### ☣️ Anti-Ransomware Shield
- Monitors mass file modifications in Documents, Pictures, and Desktop.
- Triggers an alert if 30+ files are changed within 5 seconds.

### 🖥️ System Auditor
- **HOSTS file check** — detects malicious redirects.
- **Windows Defender status**.
- **Scheduled Tasks audit** — finds hidden tasks.
- **Process Killer** — terminate any non-critical process by PID.

### 🔒 Quarantine (ChaCha20-Poly1305)
- Threat files are encrypted with **ChaCha20-Poly1305** and stored safely.
- Restore files with a single click.

### 🧠 Prompt Injection Protection
- Detects jailbreak attempts in AI prompts before sending them to LLMs.

### ☁️ VirusTotal Integration
- Check any file by SHA-256 against 70+ antivirus engines.

### ✅ Digital Signature Check
- Verifies Authenticode signatures.

### 🔄 Tray Icon & Auto-Update
- Minimizes to system tray, keeps protecting in background.
- Checks GitHub Releases for new versions.

### 🛡️ Self-Defense
- AISEC locks its own `.exe` file while running, preventing deletion or tampering.

## 🚀 Installation

### Option 1: Download Release (Windows)
Go to [Releases](https://github.com/zquh09/aisec/releases) and download the latest `aisec.exe`.
Place `icon.png` next to the executable to enable the tray icon.

### Option 2: Build from Source
```bash
git clone https://github.com/zquh09/aisec.git
cd aisec
cargo build --release
