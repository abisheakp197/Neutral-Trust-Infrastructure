//! Wake Phrase Detection
//!
//! Continuously monitors audio for wake phrase ("UBE")
//! Uses efficient streaming recognition to minimize CPU usage

use super::{VoiceConfig, VoiceError, capture::AudioCapture};
use super::speech::SpeechRecognizer;
use std::time::Duration;

/// Wake phrase detector
pub struct WakeDetector {
    wake_phrase: String,
    min_confidence: f32,
}

impl WakeDetector {
    pub fn new(wake_phrase: String, min_confidence: f32) -> Self {
        Self {
            wake_phrase,
            min_confidence,
        }
    }
}

/// Detect wake phrase from audio stream
/// Returns true if wake phrase was detected
pub async fn detect_wake_phrase(
    config: &VoiceConfig,
    capture: &mut dyn AudioCapture,
    speech: &mut SpeechRecognizer,
) -> Result<bool, super::VoiceError> {
    let wake_phrase = config.wake_phrase.to_lowercase();

    // Capture small chunks and check for wake phrase
    let chunk_duration = Duration::from_millis(500); // Check every 500ms
    let timeout = Duration::from_secs(60); // Timeout after 60 seconds of inactivity

    let start = std::time::Instant::now();

    loop {
        if start.elapsed() >= timeout {
            // Timeout - return false to trigger reconnection
            return Ok(false);
        }

        // Capture a chunk of audio
        let audio = match capture.capture_chunk().await {
            Ok(a) => a,
            Err(_) => {
                // Audio capture error - wait and retry
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };

        if audio.is_empty() {
            // No audio data - wait and retry
            tokio::time::sleep(Duration::from_millis(50)).await;
            continue;
        }

        // Recognize speech from chunk
        let text = match speech.recognize(&audio).await {
            Ok(t) => t.to_lowercase(),
            Err(_) => {
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
        };

        // Check if wake phrase is in the recognized text
        if text.contains(&wake_phrase) {
            log::info!("[WAKE] Detected wake phrase: {}", wake_phrase);
            return Ok(true);
        }

        // Small delay before next chunk
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// Create a dedicated wake detector task
pub fn spawn_wake_detector(
    config: VoiceConfig,
    mut capture: Box<dyn AudioCapture>,
    mut speech: SpeechRecognizer,
) -> tokio::task::JoinHandle<bool> {
    tokio::spawn(async move {
        loop {
            if let Ok(detected) = detect_wake_phrase(&config, &mut *capture, &mut speech).await {
                if detected {
                    return true;
                }
            }
            // If error, wait and retry
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    })
}

/// Pre-compiled wake phrase patterns for efficiency
pub struct WakePhrasePatterns {
    patterns: Vec<String>,
}

impl WakePhrasePatterns {
    pub fn new(phrase: &str) -> Self {
        // Common variations of the wake phrase
        let mut patterns = vec![
            phrase.to_lowercase(),
            phrase.to_uppercase(),
            capitalized(phrase),
        ];

        // Add common mispronunciations if phrase is "UBE"
        if phrase.eq_ignore_ascii_case("UBE") {
            patterns.extend(vec![
                "you bee".to_string(),
                "yOU bee".to_string(),
                "ubee".to_string(),
                "u b e".to_string(),
            ]);
        }

        Self { patterns }
    }

    pub fn matches(&self, text: &str) -> bool {
        let text_lower = text.to_lowercase();
        self.patterns.iter().any(|p| text_lower.contains(p))
    }
}

/// Helper to capitalize first letter
fn capitalized(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        None => String::new(),
        Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wake_patterns() {
        let patterns = WakePhrasePatterns::new("UBE");
        assert!(patterns.matches("UBE"));
        assert!(patterns.matches("ube"));
        assert!(patterns.matches("UBE"));
        assert!(patterns.matches("you bee"));
    }

    #[test]
    fn test_capitalized() {
        assert_eq!(capitalized("ube"), "Ube");
        assert_eq!(capitalized("hello"), "Hello");
    }
}
