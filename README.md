
<div align="center">

# 🛡️ AISEC — AI Security Toolkit

**A modern, GUI-based cybersecurity toolkit written in Rust.**

Built for gamers, privacy enthusiasts, and AI developers who want real protection without the bloat.

[![Rust](https://img.shields.io/badge/rust-1.75%2B-orange?style=for-the-badge&logo=rust)](https://www.rust-lang.org/)
[![Platform](https://img.shields.io/badge/platform-Windows-blue?style=for-the-badge&logo=windows)](https://github.com/zquh09/aisec)
[![License](https://img.shields.io/badge/license-MIT-green?style=for-the-badge)](LICENSE)
[![Release](https://img.shields.io/github/v/release/zquh09/aisec?style=for-the-badge&color=yellow)](https://github.com/zquh09/aisec/releases)
[![Downloads](https://img.shields.io/github/downloads/zquh09/aisec/total?style=for-the-badge&color=blue)](https://github.com/zquh09/aisec/releases)

</div>

---

## ✨ Why AISEC?

Most antivirus software is **heavy, noisy, and treats gamers like criminals**. AISEC is different:

| Feature | AISEC | Traditional AV |
|---------|-------|----------------|
| 🎮 Doesn't delete game cracks | ✅ | ❌ |
| 🔒 Open source (MIT) | ✅ | ❌ |
| 📊 No telemetry | ✅ | ❌ |
| 🧠 Prompt Injection protection | ✅ | ❌ |
| ⚡ Real-Time Protection | ✅ | ✅ |
| 🧬 YARA signatures | ✅ | Sometimes |
| 💾 Encrypted quarantine (ChaCha20) | ✅ | Sometimes |
| 🪶 Lightweight (no kernel driver) | ✅ | ❌ |

---

## 🚀 Features

### 🛡️ Real-Time Protection (RTP)
Monitors **Downloads, Desktop, Temp, Startup** folders and blocks new threats before you run them.

- ✅ SHA-256 hash check against MalwareBazaar cloud database
- ✅ YARA signature scanning
- ✅ Heuristic analysis (PE structure, imports, entropy)
- ✅ Automatic quarantine with encryption
- ✅ Windows toast notifications

### 🔌 USB Guard
Every time you plug in a USB drive, AISEC automatically scans it for threats.

### ⏰ Scheduled Scans
Set it and forget it. Scan every N days (configurable from 0 to 30).

### ☣️ Anti-Ransomware Shield
Detects **mass file modifications** (30+ files in 5 seconds) — the classic signature of ransomware.

### 🧬 YARA Scanner
One-click download of **thousands of community rules** from [Yara-Rules/rules](https://github.com/Yara-Rules/rules).

### 🔒 ChaCha20-Poly1305 Quarantine
Threat files are **encrypted**, not just moved. You can restore them safely if it was a false positive.

### 🖥️ System Auditor
- **HOSTS file check** — detects malicious redirects
- **Windows Defender status**
- **Registry scanner** — Run, RunOnce, Services, Winlogon
- **WMI scanner** — hidden event subscriptions
- **Scheduled Tasks audit**
- **NTFS Scanner** — hidden files and Alternate Data Streams (ADS)
- **Process Killer** — terminate any non-critical process by PID

### 🧠 Prompt Injection Guard
Detects jailbreak attempts in AI prompts before you send them to ChatGPT, Claude, or any LLM.

### ☁️ VirusTotal Integration
Check any file by SHA-256 against **70+ antivirus engines**.

### ✅ Digital Signature Check
Verifies Authenticode signatures to distinguish signed software from cracks and tampered binaries.

### 📄 PDF & HTML Reports
Export scan and analysis reports to PDF or HTML for sharing or archiving.

### 📜 Threat History (SQLite)
Full log of all detected threats with timestamps, file paths, and actions.

### 🔄 Tray Icon & Auto-Update
- Minimizes to system tray, keeps protecting in the background
- Checks GitHub Releases for new versions on startup

### 🛡️ Self-Defense
AISEC **locks its own `.exe`** while running — nobody (not even a virus) can delete or overwrite it.

---

## 📦 Installation

### Option 1: Download Release (recommended)

1. Go to [**Releases**](https://github.com/zquh09/aisec/releases)
2. Download `aisec.exe`
3. Run it. No installation required.

> **⚠️ Note:** AISEC is not code-signed (yet). Windows SmartScreen may show a warning. Click "More info" → "Run anyway". You can also check the source code yourself — it's 100% open source.

### Option 2: Build from Source

```bash
git clone https://github.com/zquh09/aisec.git
cd aisec
cargo build --release
```

The executable will be at `target/release/aisec.exe`.

---

## 🔑 Cloud Database Setup (optional)

AISEC can download fresh malware hashes from [abuse.ch](https://abuse.ch).

1. Register for a free Auth-Key at [auth.abuse.ch](https://auth.abuse.ch)
2. Save it to `config/abusech_auth_key.txt`
3. Click **"Update Database"** in the app

Without a key, AISEC still works using local YARA rules and heuristics.

---

## 🛡️ Why is it safe?

<details>
<summary><b>Click to expand</b></summary>

1. **Open Source** — audit every line of code
2. **No Telemetry** — nothing is sent anywhere except:
   - VirusTotal (only if you provide an API key)
   - GitHub (update checks only)
3. **User-Space** — no kernel drivers, no admin rights required
4. **Non-Destructive** — files are encrypted and quarantined, **never deleted without your consent**
5. **Smart Classification** — distinguishes harmless game cracks from actual malware

</details>

---

## 🛠️ Tech Stack

- **Language:** Rust 1.75+
- **GUI:** [eframe/egui 0.29](https://github.com/emilk/egui)
- **Database:** SQLite (via `rusqlite`)
- **Crypto:** ChaCha20-Poly1305
- **YARA:** [yara-x](https://github.com/VirusTotal/yara-x)
- **HTTP:** reqwest + rustls
- **Windows API:** `windows` crate
- **PDF:** `printpdf`

---

## 📁 Project Structure

```
aisec/
├── src/
│   ├── main.rs                    # Entry point
│   ├── gui.rs                     # GUI (eframe/egui)
│   ├── config.rs                  # Configuration
│   ├── real_time_protection.rs    # RTP engine
│   ├── yara_scanner.rs            # YARA scanner
│   ├── yara_manager.rs            # YARA rules updater
│   ├── cloud_db.rs                # MalwareBazaar integration
│   ├── hash_cache.rs              # SHA-256 cache
│   ├── quarantine.rs              # Quarantine manager
│   ├── quarantine_crypto.rs       # ChaCha20-Poly1305
│   ├── registry_scanner.rs        # Registry audit
│   ├── wmi_scanner.rs             # WMI & tasks audit
│   ├── ntfs_scanner.rs            # NTFS ADS scanner
│   ├── threat_history.rs          # SQLite history
│   ├── pdf_export.rs              # PDF reports
│   ├── usb_guard.rs               # USB monitoring
│   ├── ransomware_shield.rs       # Anti-ransomware
│   ├── process_killer.rs          # Process manager
│   ├── self_defense.rs            # Self-protection
│   ├── tray.rs                    # System tray
│   └── updater.rs                 # Auto-update
├── Cargo.toml
├── build.rs
├── icon.ico
└── README.md
```

---

## 🤝 Contributing

Contributions are welcome! Whether it's:

- 🐛 Bug reports
- 💡 Feature suggestions
- 📝 Documentation improvements
- 🔧 Code fixes

Just open an Issue or Pull Request.

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

---

<div align="center">

**Made with ❤️ and a lot of ☕ in Rust**

[⬆ Back to top](#️-aisec--ai-security-toolkit)

</div>
```
