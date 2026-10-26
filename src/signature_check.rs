use std::path::Path;
use std::process::Command;
use base64::Engine;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignatureStatus {
    Valid(String),
    Invalid,
    Unsigned,
}

pub fn check_signature(path: &Path) -> SignatureStatus {
    #[cfg(not(windows))]
    {
        let _ = path;
        return SignatureStatus::Invalid;
    }

    #[cfg(windows)]
    {
        check_signature_windows(path)
    }
}

#[cfg(windows)]
fn check_signature_windows(path: &Path) -> SignatureStatus {
    let output = match Command::new("powershell.exe")
        .args([
            "-NoLogo", "-NoProfile", "-NonInteractive", "-Command",
            "$s = Get-AuthenticodeSignature -LiteralPath $env:AISEC_TARGET -ErrorAction Stop; \
             $subject = if ($null -ne $s.SignerCertificate) { $s.SignerCertificate.Subject } else { '' }; \
             [Console]::Out.WriteLine([string]$s.Status); \
             [Console]::Out.WriteLine([Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($subject)))",
        ])
        .env("AISEC_TARGET", path)
        .output()
    {
        Ok(output) => output,
        Err(_) => return SignatureStatus::Invalid,
    };

    if !output.status.success() {
        return SignatureStatus::Invalid;
    }

    let stdout = match String::from_utf8(output.stdout) {
        Ok(text) => text,
        Err(_) => return SignatureStatus::Invalid,
    };

    let mut lines = stdout.lines();
    let status = match lines.next() {
        Some(value) => value.trim(),
        None => return SignatureStatus::Invalid,
    };

    let subject = lines
        .next()
        .and_then(|line| base64::engine::general_purpose::STANDARD.decode(line.trim()).ok())
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .unwrap_or_default();

    match status {
        "Valid" if !subject.trim().is_empty() => SignatureStatus::Valid(subject),
        "NotSigned" => SignatureStatus::Unsigned,
        _ => SignatureStatus::Invalid,
    }
}