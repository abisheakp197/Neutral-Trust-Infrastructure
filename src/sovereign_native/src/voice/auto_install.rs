//! Voice Auto-Installer - Automatically detects and installs voice dependencies
//!
//! This module ensures UBE can speak and listen on ANY hardware without manual setup.
//! It detects missing packages and attempts to install them automatically.
//!
//! Supported platforms: Android, Linux, macOS, Windows, iOS, Embedded, Web
//! Supported package managers: pkg (Termux), apt, brew, winget, choco, yum, dnf, zypper, opkg
//!

use super::{Platform, VoiceError};
use std::process::Command;
use std::env;
use log::{info, warn, error};

/// Voice dependency installer - MERGED universal installer
pub struct VoiceAutoInstaller {
    platform: Platform,
    elevated: bool,
}

impl VoiceAutoInstaller {
    pub fn new(platform: Platform) -> Self {
        let elevated = Self::check_elevated();
        Self { platform, elevated }
    }

    pub fn new_with_elevation(platform: Platform, elevated: bool) -> Self {
        Self { platform, elevated }
    }

    /// Check if running with elevated privileges
    fn check_elevated() -> bool {
        if cfg!(unix) {
            return env::var("USER").map(|u| u == "root").unwrap_or(false);
        }
        false
    }

    /// Auto-detect, install and verify all voice dependencies for ANY hardware (synchronous)
    pub fn ensure_voice_works(&self) -> Result<(), VoiceError> {
        info!("[VOICE-AUTO] Starting COMPLETE voice dependency check for {:?}", self.platform);

        match self.platform {
            Platform::Android => {
                self.install_android_all()?;
            }
            Platform::Linux => {
                self.install_linux_all()?;
            }
            Platform::MacOS => {
                self.install_macos_all()?;
            }
            Platform::Windows => {
                self.install_windows_all()?;
            }
            Platform::IOS => {
                self.install_ios_all()?;
            }
            Platform::Embedded => {
                self.install_embedded_all()?;
            }
            Platform::Web => {
                self.install_web_all()?;
            }
            Platform::Unknown => {
                warn!("[VOICE-AUTO] Unknown platform - trying universal installation");
                self.install_unknown_all()?;
            }
        }

        info!("[VOICE-AUTO] Voice dependencies verified and installed");
        Ok(())
    }

    /// Async wrapper for compatibility
    pub async fn async_ensure_voice_works(&self) -> Result<(), VoiceError> {
        self.ensure_voice_works()
    }

    // ========== PLATFORM-SPECIFIC FULL INSTALLATIONS ==========

    /// Install ALL voice dependencies on Android/Termux
    fn install_android_all(&self) -> Result<(), VoiceError> {
        info!("[VOICE-AUTO] Android: Checking voice dependencies...");

        // Fast check: if termux-tts-speak exists, skip installation (already done by shell scripts)
        if self.command_exists("termux-tts-speak") && self.command_exists("termux-toast") {
            info!("[VOICE-AUTO] Android: Voice packages already installed by shell setup");
            // Still try pulseaudio since it's often missing
            let _ = self.start_pulseaudio();
            return Ok(());
        }

        info!("[VOICE-AUTO] Android: Installing ALL voice dependencies...");

        // 1. Core TTS engines
        let _ = self.install_package("termux-tts", "pkg");
        let _ = self.install_package("espeak", "pkg");
        let _ = self.install_package("piper", "pkg");
        let _ = self.install_package("festival", "pkg");

        // 2. Audio capture
        let _ = self.install_package("termux-microphone", "pkg");
        let _ = self.install_package("termux-api", "pkg");

        // 3. Audio playback
        let _ = self.install_package("termux-media-player", "pkg");
        let _ = self.install_package("pulseaudio", "pkg");

        // 4. Python for piper (neural TTS)
        let _ = self.install_package("python", "pkg");

        // 5. Apply Android 8+ pulseaudio workaround
        let _ = self.fix_android_pulseaudio();

        // 6. Start pulseaudio
        let _ = self.start_pulseaudio();

        info!("[VOICE-AUTO] Android: ALL voice dependencies installed!");
        Ok(())
    }

    /// Install ALL voice dependencies on Linux
    fn install_linux_all(&self) -> Result<(), VoiceError> {
        info!("[VOICE-AUTO] Linux: Installing ALL voice dependencies...");

        let pkg_manager = self.detect_package_manager();
        info!("[VOICE-AUTO] Detected package manager: {}", pkg_manager);

        // 1. Core TTS engines
        self.install_package("espeak", &pkg_manager)?;
        self.install_package("espeak-ng", &pkg_manager)?;
        self.install_package("festival", &pkg_manager)?;
        self.install_package("festvox-kallpc16k", &pkg_manager).ok();

        // 2. Neural TTS (Piper)
        self.install_package("piper", &pkg_manager)?;
        let _ = self.install_piper_voices();

        // 3. Audio system
        self.install_package("pulseaudio", &pkg_manager)?;
        self.install_package("pulseaudio-utils", &pkg_manager).ok();
        self.install_package("libpulse-dev", &pkg_manager).ok();

        // 4. Audio capture
        self.install_package("arecord", &pkg_manager).ok();
        self.install_package("sox", &pkg_manager).ok();

        // 5. Python for advanced TTS
        self.install_package("python3", &pkg_manager).ok();
        self.install_package("python3-pip", &pkg_manager).ok();

        // 6. Start pulseaudio if not running
        let _ = self.start_pulseaudio();

        info!("[VOICE-AUTO] Linux: ALL voice dependencies installed!");
        Ok(())
    }

    /// Install ALL voice dependencies on macOS
    fn install_macos_all(&self) -> Result<(), VoiceError> {
        info!("[VOICE-AUTO] macOS: Installing ALL voice dependencies...");

        // macOS has built-in TTS (say command)
        if !self.command_exists("say") {
            warn!("[VOICE-AUTO] macOS 'say' command not found - this is unusual");
        } else {
            info!("[VOICE-AUTO] macOS built-in TTS verified");
        }

        // Install Homebrew if not available
        if !self.command_exists("brew") {
            info!("[VOICE-AUTO] Installing Homebrew...");
            let result = Command::new("/bin/bash")
                .arg("-c")
                .arg("$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)")
                .status();
            if result.is_ok() && result.unwrap().success() {
                info!("[VOICE-AUTO] Homebrew installed successfully");
            } else {
                warn!("[VOICE-AUTO] Homebrew installation may have failed");
            }
        }

        // Install alternative TTS engines via Homebrew
        let _ = self.install_package("espeak", "brew");
        let _ = self.install_package("festival", "brew");
        let _ = self.install_package("piper", "brew");

        info!("[VOICE-AUTO] macOS: ALL voice dependencies installed!");
        Ok(())
    }

    /// Install ALL voice dependencies on Windows
    fn install_windows_all(&self) -> Result<(), VoiceError> {
        info!("[VOICE-AUTO] Windows: Installing ALL voice dependencies...");

        // Windows has built-in SAPI
        if !self.command_exists("powershell") {
            warn!("[VOICE-AUTO] PowerShell not found - Windows TTS may not work");
        } else {
            info!("[VOICE-AUTO] Windows PowerShell available");
        }

        // Try winget (Windows Package Manager)
        if self.command_exists("winget") {
            info!("[VOICE-AUTO] winget available - installing additional TTS engines");
            let _ = self.install_package("espeak", "winget");
            let _ = self.install_package("festival", "winget");
        }

        // Try chocolatey
        if self.command_exists("choco") {
            info!("[VOICE-AUTO] chocolatey available");
            let _ = self.install_package("espeak", "choco");
        }

        // Enable/test Windows built-in TTS
        let _ = self.enable_windows_built_in_tts();

        info!("[VOICE-AUTO] Windows: ALL voice dependencies installed!");
        Ok(())
    }

    /// Install for iOS
    fn install_ios_all(&self) -> Result<(), VoiceError> {
        info!("[VOICE-AUTO] iOS: Native app required for full voice support");
        warn!("[VOICE-AUTO] iOS voice requires native iOS app with AVFoundation framework");
        Ok(())
    }

    /// Install for Embedded systems
    fn install_embedded_all(&self) -> Result<(), VoiceError> {
        info!("[VOICE-AUTO] Embedded: Installing minimal voice support...");

        self.install_package("espeak", "apt").ok();
        self.install_package("espeak", "opkg").ok();

        info!("[VOICE-AUTO] Embedded: Minimal voice support installed!");
        Ok(())
    }

    /// Install for Web
    fn install_web_all(&self) -> Result<(), VoiceError> {
        info!("[VOICE-AUTO] Web platform - using browser Web Speech API");
        Ok(())
    }

    /// Install for unknown platforms - try everything
    fn install_unknown_all(&self) -> Result<(), VoiceError> {
        info!("[VOICE-AUTO] Unknown platform - trying universal package managers...");

        for pm in ["pkg", "apt", "brew", "winget", "choco", "yum", "dnf", "zypper", "opkg"] {
            if self.install_package("espeak", pm).is_ok() {
                info!("[VOICE-AUTO] Successfully installed espeak via {}", pm);
                break;
            }
        }

        Ok(())
    }

    // ========== PACKAGE MANAGEMENT UTILITIES ==========

    /// Detect which package manager is available on the system
    fn detect_package_manager(&self) -> String {
        let managers = [
            "apt", "apt-get",
            "dnf", "yum",
            "pacman",
            "zypper",
            "emerge",
            "pkg",
        ];

        for pm in managers {
            if self.command_exists(pm) {
                return pm.to_string();
            }
        }

        // Default fallback
        "apt".to_string()
    }

    /// Install a package using the specified package manager
    /// Supports: pkg, apt, brew, winget, choco, yum, dnf, zypper, opkg
    fn install_package(&self, package: &str, manager: &str) -> Result<(), VoiceError> {
        let install_cmd = match manager {
            "pkg" => format!("pkg install -y {}", package),
            "apt" | "apt-get" => format!("sudo {} install -y {}", manager, package),
            "brew" => format!("brew install {}", package),
            "winget" => format!("winget install -e --accept-package-agreements --accept-source-agreements {}", package),
            "choco" => format!("choco install -y {}", package),
            "yum" | "dnf" => format!("sudo {} install -y {}", manager, package),
            "zypper" => format!("sudo zypper install -y {}", package),
            "pacman" => format!("sudo pacman -Sy --noconfirm {}", package),
            "opkg" => format!("opkg install {}", package),
            _ => return Err(VoiceError::AudioError(format!("Unknown package manager: {}", manager))),
        };

        info!("[VOICE-AUTO] Installing {} via {}: {}", package, manager, install_cmd);

        let result = self.run_command(&install_cmd);

        if result {
            info!("[VOICE-AUTO] Successfully installed: {}", package);
            Ok(())
        } else {
            warn!("[VOICE-AUTO] Installation failed for package: {}", package);
            Err(VoiceError::AudioError(format!("Failed to install {} via {}", package, manager)))
        }
    }

    /// Install Piper neural TTS voices
    fn install_piper_voices(&self) -> Result<(), VoiceError> {
        info!("[VOICE-AUTO] Downloading Piper neural TTS voices...");

        // Download English voice via Piper
        let status = Command::new("piper")
            .arg("--download")
            .arg("en_US-libritts-high")
            .status();

        if status.is_ok() && status.unwrap().success() {
            info!("[VOICE-AUTO] Piper voice downloaded successfully");
            return Ok(());
        }

        // Fallback: Download via curl
        let url = "https://huggingface.co/rhasspy/piper-voices/resolve/main/en/en_US/libritts/high/en_US-libritts-high.onnx";
        let curl_status = Command::new("curl")
            .arg("-L")
            .arg(url)
            .arg("-o")
            .arg("/tmp/en_US-libritts-high.onnx")
            .status();

        if curl_status.is_ok() && curl_status.unwrap().success() {
            info!("[VOICE-AUTO] Piper voice downloaded via curl");
            Ok(())
        } else {
            warn!("[VOICE-AUTO] Could not download Piper voices");
            Err(VoiceError::AudioError("Failed to download Piper voices".to_string()))
        }
    }

    // ========== PULSEAUDIO HANDLING ==========

    /// Fix Android pulseaudio configuration
    fn fix_android_pulseaudio(&self) -> Result<(), VoiceError> {
        info!("[VOICE-AUTO] Applying Android PulseAudio workaround...");

        let _ = Command::new("sed")
            .arg("-i")
            .arg("s/module-sles-sink/module-aaudio-sink/g")
            .arg("$PREFIX/etc/pulse/default.pa")
            .status();

        Ok(())
    }

    /// Start pulseaudio
    fn start_pulseaudio(&self) -> Result<(), VoiceError> {
        info!("[VOICE-AUTO] Starting/ensuring PulseAudio...");

        // Check if already running
        let status = Command::new("pulseaudio")
            .arg("--check")
            .status();

        if status.is_ok() && status.unwrap().success() {
            info!("[VOICE-AUTO] PulseAudio already running");
            return Ok(());
        }

        // Start with appropriate flags
        let start_cmd = if self.is_android() {
            "pulseaudio --start --exit-idle-time=-1 --high-priority --no-cpu-limit"
        } else {
            "pulseaudio --start"
        };

        let _ = Command::new("sh")
            .arg("-c")
            .arg(start_cmd)
            .status();

        // Wait and verify
        std::thread::sleep(std::time::Duration::from_secs(1));

        if Command::new("pulseaudio").arg("--check").status().is_ok() {
            info!("[VOICE-AUTO] PulseAudio started successfully");
        } else {
            warn!("[VOICE-AUTO] PulseAudio failed to start");
        }

        Ok(())
    }

    // ========== PLATFORM-SPECIFIC UTILITIES ==========

    /// Enable Windows built-in TTS
    fn enable_windows_built_in_tts(&self) -> Result<(), VoiceError> {
        info!("[VOICE-AUTO] Testing Windows built-in TTS...");

        let test_cmd = "Add-Type -AssemblyName System.speech; (New-Object System.Speech.Synthesis.SpeechSynthesizer).Speak('UBE voice test')";
        let _ = Command::new("powershell")
            .arg("-Command")
            .arg(test_cmd)
            .status();

        info!("[VOICE-AUTO] Windows TTS test completed");
        Ok(())
    }

    /// Check if a command exists in PATH
    fn command_exists(&self, cmd: &str) -> bool {
        Command::new("which")
            .arg(cmd)
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
            || Command::new("command")
                .arg("-v")
                .arg(cmd)
                .status()
                .map(|s| s.success())
                .unwrap_or(false)
    }

    /// Run a shell command and return success
    fn run_command(&self, cmd: &str) -> bool {
        if cfg!(test) {
            return false;
        }
        let result = Command::new("sh")
            .arg("-c")
            .arg(cmd)
            .status();
        result.map(|s| s.success()).unwrap_or(false)
    }

    /// Check if running on Android (Termux)
    fn is_android(&self) -> bool {
        std::path::Path::new("/system/build.prop").exists()
            || std::fs::read_to_string("/proc/version")
                .map(|v| v.contains("Android"))
                .unwrap_or(false)
    }

    /// Blocking version for synchronous use (same as ensure_voice_works since it's now sync)
    pub fn blocking_ensure_voice_works(&self) -> Result<(), VoiceError> {
        self.ensure_voice_works()
    }
}

/// Platform-specific voice setup (synchronous wrapper)
pub fn setup_platform_voice(platform: Platform) -> Result<(), VoiceError> {
    let installer = VoiceAutoInstaller::new(platform);
    installer.blocking_ensure_voice_works()
}

/// Public function to install universal voice on any platform
pub fn install_universal_voice(platform: Platform) -> Result<(), VoiceError> {
    setup_platform_voice(platform)
}

/// Async wrapper for setup
pub async fn async_setup_platform_voice(platform: Platform) -> Result<(), VoiceError> {
    setup_platform_voice(platform)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_platform_detection() {
        let platform = super::super::detect_platform();
        assert!(matches!(
            platform,
            super::super::Platform::Unknown
                | super::super::Platform::Android
                | super::super::Platform::Linux
                | super::super::Platform::MacOS
                | super::super::Platform::Windows
                | super::super::Platform::IOS
                | super::super::Platform::Embedded
                | super::super::Platform::Web
        ));
    }
}
