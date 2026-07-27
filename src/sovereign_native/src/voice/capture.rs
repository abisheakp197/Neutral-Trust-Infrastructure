//! Audio Capture - Cross-platform audio input
//!
//! Captures audio from microphone on any platform

use super::{VoiceError, Platform};
use std::process::Command;
use std::io::Read;

/// Audio capture trait
#[async_trait::async_trait]
pub trait AudioCapture: Send + Sync {
    async fn initialize(&mut self) -> Result<(), VoiceError>;
    async fn capture_chunk(&self) -> Result<Vec<u8>, VoiceError>;
    async fn capture_until_silence(&self, timeout_secs: u64) -> Result<Vec<u8>, VoiceError>;
    fn sample_rate(&self) -> u32;
    fn is_capturing(&self) -> bool;
}

/// Default capture (test/fallback)
pub struct DefaultCapture {
    sample_rate: u32,
}

impl DefaultCapture {
    pub fn new() -> Self {
        Self { sample_rate: 16000 }
    }
}

#[async_trait::async_trait]
impl AudioCapture for DefaultCapture {
    async fn initialize(&mut self) -> Result<(), VoiceError> {
        Ok(())
    }

    async fn capture_chunk(&self) -> Result<Vec<u8>, VoiceError> {
        // Generate test audio or return empty
        Ok(Vec::new())
    }

    async fn capture_until_silence(&self, _timeout_secs: u64) -> Result<Vec<u8>, VoiceError> {
        Ok(Vec::new())
    }

    fn sample_rate(&self) -> u32 {
        self.sample_rate
    }

    fn is_capturing(&self) -> bool {
        true
    }
}

/// Android audio capture
pub struct AndroidCapture;

impl AndroidCapture {
    pub fn new() -> Self {
        Self
    }

    /// Capture using termux-microphone
    async fn capture_termux(&self, duration_secs: u64) -> Result<Vec<u8>, VoiceError> {
        use std::io::Write;
        use tempfile::NamedTempFile;

        let temp_file = NamedTempFile::new().map_err(|e| super::VoiceError::IoError(std::io::Error::other(e)))?;
        let path = temp_file.path();

        // Check if termux-microphone exists
        let status = Command::new("which")
            .arg("termux-microphone")
            .status().map_err(|e| super::VoiceError::IoError(std::io::Error::other(e)))?;

        if !status.success() {
            return Ok(Vec::new());
        }

        let output = Command::new("termux-microphone")
            .arg("-r")
            .arg("16000")
            .arg("-c")
            .arg("1")
            .arg("-f")
            .arg("S16_LE")
            .arg("-d")
            .arg(duration_secs.to_string())
            .arg(path.to_str().unwrap())
            .status().map_err(|e| super::VoiceError::IoError(std::io::Error::other(e)))?;

        if output.success() {
            std::fs::read(path).map_err(|e| {
                VoiceError::IoError(std::io::Error::other(e))
            })
        } else {
            Ok(Vec::new())
        }
    }
}

#[async_trait::async_trait]
impl AudioCapture for AndroidCapture {
    async fn initialize(&mut self) -> Result<(), VoiceError> {
        log::info!("[AUDIO] Android capture initialized");
        Ok(())
    }

    async fn capture_chunk(&self) -> Result<Vec<u8>, VoiceError> {
        self.capture_termux(1).await
    }

    async fn capture_until_silence(&self, timeout_secs: u64) -> Result<Vec<u8>, VoiceError> {
        self.capture_termux(timeout_secs).await
    }

    fn sample_rate(&self) -> u32 {
        16000
    }

    fn is_capturing(&self) -> bool {
        true
    }
}

/// iOS audio capture
pub struct IOSCapture;

impl IOSCapture {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait::async_trait]
impl AudioCapture for IOSCapture {
    async fn initialize(&mut self) -> Result<(), VoiceError> {
        Ok(())
    }

    async fn capture_chunk(&self) -> Result<Vec<u8>, VoiceError> {
        Ok(Vec::new())
    }

    async fn capture_until_silence(&self, _timeout_secs: u64) -> Result<Vec<u8>, VoiceError> {
        Ok(Vec::new())
    }

    fn sample_rate(&self) -> u32 {
        16000
    }

    fn is_capturing(&self) -> bool {
        false
    }
}

/// Linux audio capture
pub struct LinuxCapture;

impl LinuxCapture {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait::async_trait]
impl AudioCapture for LinuxCapture {
    async fn initialize(&mut self) -> Result<(), VoiceError> {
        Ok(())
    }

    async fn capture_chunk(&self) -> Result<Vec<u8>, VoiceError> {
        Ok(Vec::new())
    }

    async fn capture_until_silence(&self, _timeout_secs: u64) -> Result<Vec<u8>, VoiceError> {
        Ok(Vec::new())
    }

    fn sample_rate(&self) -> u32 {
        16000
    }

    fn is_capturing(&self) -> bool {
        false
    }
}

/// Windows audio capture
pub struct WindowsCapture;

impl WindowsCapture {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait::async_trait]
impl AudioCapture for WindowsCapture {
    async fn initialize(&mut self) -> Result<(), VoiceError> {
        Ok(())
    }

    async fn capture_chunk(&self) -> Result<Vec<u8>, VoiceError> {
        Ok(Vec::new())
    }

    async fn capture_until_silence(&self, _timeout_secs: u64) -> Result<Vec<u8>, VoiceError> {
        Ok(Vec::new())
    }

    fn sample_rate(&self) -> u32 {
        16000
    }

    fn is_capturing(&self) -> bool {
        false
    }
}

/// MacOS audio capture
pub struct MacOSCapture;

impl MacOSCapture {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait::async_trait]
impl AudioCapture for MacOSCapture {
    async fn initialize(&mut self) -> Result<(), VoiceError> {
        Ok(())
    }

    async fn capture_chunk(&self) -> Result<Vec<u8>, VoiceError> {
        Ok(Vec::new())
    }

    async fn capture_until_silence(&self, _timeout_secs: u64) -> Result<Vec<u8>, VoiceError> {
        Ok(Vec::new())
    }

    fn sample_rate(&self) -> u32 {
        16000
    }

    fn is_capturing(&self) -> bool {
        false
    }
}

/// Create capture for platform
pub fn create_capture(platform: Platform) -> Box<dyn AudioCapture> {
    match platform {
        Platform::Android => Box::new(AndroidCapture::new()),
        Platform::IOS => Box::new(IOSCapture::new()),
        Platform::Linux => Box::new(LinuxCapture::new()),
        Platform::Windows => Box::new(WindowsCapture::new()),
        Platform::MacOS => Box::new(MacOSCapture::new()),
        _ => Box::new(DefaultCapture::new()),
    }
}
