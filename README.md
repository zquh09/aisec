# 🛡️ AISEC — AI Security Toolkit

**A fast, modern, GUI-based cybersecurity toolkit written in Rust.**

AISEC is a desktop application designed to protect your digital space from modern threats. It combines secret scanners, malware analyzers, privacy audits, and data control tools in a single, fast, and stylish interface.

Thanks to **Rust** and **eframe/egui**, the app runs blazingly fast, consumes minimal resources, and features a sleek dark theme with yellow accents.

![AISEC Screenshot](https://via.placeholder.com/800x450.png?text=AISEC+Interface) <!-- Replace with a real screenshot later -->

## ✨ Features

*   🔑 **Secret Scanner**: Automatically finds leaked API keys, tokens, and passwords in your files.
*   🧠 **Prompt Injection Protection**: Analyzes input text for LLM jailbreaks and malicious prompts.
*   💿 **PE Analysis**: Detects modified executables (cracks) and distinguishes them from actual malware.
*   ☁️ **VirusTotal Integration**: Checks file hashes against 70+ antivirus engines.
*   ✅ **Digital Signature Check**: Verifies Authenticode signatures to ensure file authenticity.
*   🚀 **Startup & Process Scanner**: Monitors active processes and autorun programs to spot hidden miners or spyware.
*   🔒 **Privacy Audit**: Checks for DNS and IPv6 leaks without breaking any laws or bypassing blocks.
*   👁️ **Folder Watcher**: Automatically scans new EXE/DLL files in your Downloads folder.

## 🚀 Installation & Usage

### Option 1: Download Release (Windows)
Go to the [Releases](https://github.com/your-username/aisec/releases) page, download the latest `aisec.exe`, and run it. No installation required.

### Option 2: Build from Source
Make sure you have [Rust](https://rustup.rs/) installed.

```bash
git clone https://github.com/your-username/aisec.git
cd aisec
cargo build --release