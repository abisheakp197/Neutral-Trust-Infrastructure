//! Command Parser - Converts natural language to structured commands
//!
//! Parses voice/text input into CommandIntent and entities

use regex::Regex;
use super::{CommandIntent, CommandEntity, VoiceCommand, VoiceError};

/// Command Parser
#[derive(Clone)]
pub struct CommandParser {
    intent_patterns: Vec<(Regex, CommandIntent)>,
    entity_patterns: Vec<(Regex, String, f32)>,
}

/// Automation duration extracted from command
#[derive(Debug, Clone)]
pub struct AutomationConfig {
    pub action: String,
    pub is_permanent: bool,
    pub duration_days: Option<u64>,
}

impl CommandParser {
    pub fn new() -> Self {
        let mut parser = Self {
            intent_patterns: Vec::new(),
            entity_patterns: Vec::new(),
        };
        parser.load_default_patterns();
        parser
    }

    /// Parse text into voice command
    pub fn parse(&self, text: &str) -> Result<VoiceCommand, VoiceError> {
        let text = text.trim().to_lowercase();
        if text.is_empty() {
            return Err(VoiceError::ParseError("Empty input".to_string()));
        }

        let intent = self.detect_intent(&text);
        let entities = self.extract_entities(&text, intent.clone());
        let confidence = self.calculate_confidence(&text, &intent, &entities);

        Ok(VoiceCommand {
            text: text.clone(),
            intent,
            entities,
            confidence,
        })
    }

    /// Detect intent from text
    fn detect_intent(&self, text: &str) -> CommandIntent {
        for (pattern, intent) in &self.intent_patterns {
            if pattern.is_match(text) {
                return intent.clone();
            }
        }
        self.classify_by_keywords(text)
    }

    /// Parse automation config from natural language
    /// Examples:
    /// - "automate deployment permanently" -> permanent
    /// - "automate backup for 3 days" -> 3 days
    /// - "automate this for 1 week" -> 7 days
    pub fn parse_automation_config(&self, text: &str) -> Option<AutomationConfig> {
        let t = text.to_lowercase();

        // Check for automation keywords
        if !t.contains("automate") && !t.contains("automation") {
            return None;
        }

        // Extract action (what to automate)
        let action = self.extract_action(&t)?;

        // Check for permanent
        if t.contains("permanent") || t.contains("permanently") || t.contains("forever") || t.contains("always") {
            return Some(AutomationConfig {
                action,
                is_permanent: true,
                duration_days: None,
            });
        }

        // Extract duration
        let duration_days = self.extract_duration(&t);

        Some(AutomationConfig {
            action,
            is_permanent: false,
            duration_days,
        })
    }

    /// Extract the action to automate
    fn extract_action(&self, text: &str) -> Option<String> {
        let t = text.to_lowercase();

        // Remove automate/automation prefixes
        let action_part = t
            .replace("automate", "")
            .replace("automation", "")
            .replace("ube", "")
            .trim()
            .to_string();

        // Remove duration phrases
        let action_part = action_part
            .replace("for", "")
            .replace("permanent", "")
            .replace("permanently", "")
            .replace("forever", "")
            .replace("always", "")
            .trim()
            .to_string();

        // Remove common suffixes
        let action_part = action_part
            .replace("days", "")
            .replace("day", "")
            .replace("weeks", "")
            .replace("week", "")
            .replace("months", "")
            .replace("month", "")
            .replace("hours", "")
            .replace("hour", "")
            .replace("minutes", "")
            .replace("minute", "")
            .trim()
            .to_string();

        if action_part.is_empty() {
            None
        } else {
            Some(action_part)
        }
    }

    /// Extract duration in days from text
    fn extract_duration(&self, text: &str) -> Option<u64> {
        let t = text.to_lowercase();

        // Match numbers followed by time units
        let re = Regex::new(r"(\d+)\s*(days?|weeks?|months?|hours?|minutes?)").ok()?;

        let cap = re.captures_iter(&t).next()?;

        let num: u64 = cap[1].parse().ok()?;
        let unit = &cap[2];

        match unit {
            "day" | "days" => Some(num),
            "week" | "weeks" => Some(num * 7),
            "month" | "months" => Some(num * 30),
            "hour" | "hours" => Some(num / 24 + if !num.is_multiple_of(24) { 1 } else { 0 }),
            "minute" | "minutes" => Some(num / (24 * 60) + if !num.is_multiple_of(24 * 60) { 1 } else { 0 }),
            _ => None,
        }
    }

    /// Classify by keywords (fallback)
    fn classify_by_keywords(&self, text: &str) -> CommandIntent {
        let t = text.to_lowercase();

        // Rule commands
        if t.contains("rule") || t.contains("law") {
            if t.contains("add") || t.contains("create") || t.contains("new") {
                return CommandIntent::AddRule;
            }
            if t.contains("remove") || t.contains("delete") || t.contains("erase") || t.contains("clear") {
                return CommandIntent::RemoveRule;
            }
            if t.contains("query") || t.contains("check") || t.contains("view") || t.contains("show") || t.contains("exists") {
                return CommandIntent::QueryRule;
            }
            return CommandIntent::QueryRule; // Default for rule mentions
        }

        // Task commands
        if t.contains("task") || t.contains("job") {
            if t.contains("add") || t.contains("create") || t.contains("new") {
                return CommandIntent::AddTask;
            }
            if t.contains("remove") || t.contains("delete") {
                return CommandIntent::RemoveTask;
            }
            return CommandIntent::QueryTask;
        }

        // Automation commands
        if t.contains("automation") || t.contains("auto") || t.contains("schedule") {
            if t.contains("add") || t.contains("create") || t.contains("new") || t.contains("set") {
                return CommandIntent::AddAutomation;
            }
            if t.contains("remove") || t.contains("delete") || t.contains("stop") {
                return CommandIntent::RemoveAutomation;
            }
        }

        // History
        if t.contains("history") || t.contains("log") || t.contains("past") || t.contains("before") || t.contains("commands") {
            return CommandIntent::QueryHistory;
        }

        // Status
        if t.contains("status") || t.contains("state") || t.contains("how are you") || t.contains("what's up") || t.contains("working") {
            return CommandIntent::QueryStatus;
        }

        // Learn/Forget
        if t.contains("learn") || t.contains("remember") || t.contains("train") || t.contains("teach") {
            return CommandIntent::Learn;
        }
        if t.contains("forget") || t.contains("unlearn") || t.contains("erase") || t.contains("clear memory") {
            return CommandIntent::Forget;
        }

        // Lock/Unlock
        if t.contains("lock") || t.contains("secure") {
            return CommandIntent::Lock;
        }
        if t.contains("unlock") || t.contains("open") || t.contains("unsecure") {
            return CommandIntent::Unlock;
        }

        // System commands
        if t.contains("shutdown") || t.contains("power off") || t.contains("exit") || t.contains("quit") {
            return CommandIntent::Shutdown;
        }
        if t.contains("reboot") || t.contains("restart") {
            return CommandIntent::Reboot;
        }
        if t.contains("update") || t.contains("upgrade") {
            return CommandIntent::Update;
        }

        // Start/Stop
        if t.contains("start") || t.contains("begin") || t.contains("launch") || t.contains("activate") || t.contains("enable") {
            return CommandIntent::Start;
        }
        if t.contains("stop") || t.contains("end") || t.contains("halt") || t.contains("deactivate") || t.contains("disable") {
            return CommandIntent::Stop;
        }
        if t.contains("pause") || t.contains("freeze") || t.contains("suspend") || t.contains("hold") {
            return CommandIntent::Pause;
        }
        if t.contains("resume") || t.contains("continue") || t.contains("unpause") {
            return CommandIntent::Resume;
        }

        // Authenticate
        if t.contains("authenticate") || t.contains("verify") || t.contains("identify") || t.contains("login") {
            return CommandIntent::Authenticate;
        }

        // Custom/Unknown
        CommandIntent::Custom(text.trim().to_string())
    }

    /// Extract entities from text
    fn extract_entities(&self, text: &str, intent: CommandIntent) -> Vec<CommandEntity> {
        let mut entities = Vec::new();

        // Always extract numbers and common patterns
        entities.extend(self.extract_common_entities(text));

        // Intent-specific extraction
        match intent {
            CommandIntent::AddRule | CommandIntent::RemoveRule | CommandIntent::QueryRule => {
                entities.extend(self.extract_rule_entities(text));
            }
            CommandIntent::AddTask | CommandIntent::RemoveTask | CommandIntent::QueryTask => {
                entities.extend(self.extract_task_entities(text));
            }
            CommandIntent::Learn | CommandIntent::Forget => {
                entities.extend(self.extract_learn_entities(text));
            }
            _ => {}
        }

        entities
    }

    /// Extract rule entities
    fn extract_rule_entities(&self, text: &str) -> Vec<CommandEntity> {
        self.extract_named_entities(text, &["rule", "named", "called"], "rule_name")
    }

    /// Extract task entities
    fn extract_task_entities(&self, text: &str) -> Vec<CommandEntity> {
        self.extract_named_entities(text, &["task", "named", "called"], "task_name")
    }

    /// Extract learn entities
    fn extract_learn_entities(&self, text: &str) -> Vec<CommandEntity> {
        // Extract text after learn/remember/forget
        for keyword in ["learn", "remember", "train", "teach", "forget", "unlearn", "erase"] {
            if text.contains(keyword) {
                if let Some(idx) = text.find(keyword) {
                    let content = text[idx + keyword.len()..].trim();
                    if !content.is_empty() {
                        return vec![CommandEntity {
                            entity_type: "content".to_string(),
                            value: content.to_string(),
                            start: idx + keyword.len(),
                            end: text.len(),
                            confidence: 0.8,
                        }];
                    }
                }
            }
        }
        Vec::new()
    }

    /// Extract common entities (numbers, times, dates)
    fn extract_common_entities(&self, text: &str) -> Vec<CommandEntity> {
        let mut entities = Vec::new();

        // Numbers
        if let Ok(re) = Regex::new(r"\b(\d+(\.\d+)?)\b") {
            for m in re.find_iter(text) {
                entities.push(CommandEntity {
                    entity_type: "number".to_string(),
                    value: m.as_str().to_string(),
                    start: m.start(),
                    end: m.end(),
                    confidence: 0.95,
                });
            }
        }

        // Time (HH:MM or HH:MM:SS)
        if let Ok(re) = Regex::new(r"\b(\d{1,2}:\d{2}(:\d{2})?)\b") {
            for m in re.find_iter(text) {
                entities.push(CommandEntity {
                    entity_type: "time".to_string(),
                    value: m.as_str().to_string(),
                    start: m.start(),
                    end: m.end(),
                    confidence: 0.9,
                });
            }
        }

        entities
    }

    /// Extract named entities by keywords
    fn extract_named_entities(&self, text: &str, keywords: &[&str], entity_type: &str) -> Vec<CommandEntity> {
        let mut entities = Vec::new();
        let t = text.to_lowercase();

        for keyword in keywords {
            if t.contains(keyword) {
                // Find the keyword and extract the word after it
                if let Ok(re) = Regex::new(&format!(r"{}\s+(\w+)", regex::escape(keyword))) {
                    if let Some(m) = re.find(&t) {
                        let full_match = m.as_str();
                        let value = full_match.trim().to_string();
                        entities.push(CommandEntity {
                            entity_type: entity_type.to_string(),
                            value,
                            start: m.start(),
                            end: m.end(),
                            confidence: 0.85,
                        });
                        return entities;
                    }
                }
            }
        }

        // Try to find any word that looks like a name
        if let Ok(re) = Regex::new(r"\b(\w+)\b") {
            for m in re.find_iter(&t) {
                let word = m.as_str();
                // Skip common words
                if word.len() > 2 && !["add", "remove", "rule", "task", "the", "a", "an", "to", "for"].contains(&word) {
                    entities.push(CommandEntity {
                        entity_type: entity_type.to_string(),
                        value: word.to_string(),
                        start: m.start(),
                        end: m.end(),
                        confidence: 0.6,
                    });
                    break;
                }
            }
        }

        entities
    }

    /// Calculate confidence score
    fn calculate_confidence(&self, text: &str, intent: &CommandIntent, entities: &[CommandEntity]) -> f32 {
        let mut confidence = 0.5;

        match intent {
            CommandIntent::Unknown => confidence -= 0.2,
            CommandIntent::Custom(_) => confidence -= 0.1,
            _ => confidence += 0.1,
        }

        if !entities.is_empty() {
            confidence += 0.1 * (entities.len() as f32).min(0.3);
        }

        if text.contains("ube") || text.contains("sovereign") {
            confidence += 0.1;
        }

        confidence.clamp(0.0, 1.0)
    }

    /// Load default intent patterns
    fn load_default_patterns(&mut self) {
        // Rule patterns
        self.intent_patterns.extend([
            (Regex::new(r"add\s+(a\s+)?rule").unwrap(), CommandIntent::AddRule),
            (Regex::new(r"create\s+(a\s+)?rule").unwrap(), CommandIntent::AddRule),
            (Regex::new(r"new\s+(rule|law)").unwrap(), CommandIntent::AddRule),
            (Regex::new(r"remove\s+(a\s+)?rule").unwrap(), CommandIntent::RemoveRule),
            (Regex::new(r"delete\s+(a\s+)?rule").unwrap(), CommandIntent::RemoveRule),
            (Regex::new(r"erase\s+(a\s+)?rule").unwrap(), CommandIntent::RemoveRule),
            (Regex::new(r"clear\s+(a\s+)?rule").unwrap(), CommandIntent::RemoveRule),
            (Regex::new(r"(check|view|show|query)\s+(a\s+)?rule").unwrap(), CommandIntent::QueryRule),
        ]);

        // Task patterns
        self.intent_patterns.extend([
            (Regex::new(r"add\s+(a\s+)?task").unwrap(), CommandIntent::AddTask),
            (Regex::new(r"create\s+(a\s+)?task").unwrap(), CommandIntent::AddTask),
            (Regex::new(r"remove\s+(a\s+)?task").unwrap(), CommandIntent::RemoveTask),
            (Regex::new(r"delete\s+(a\s+)?task").unwrap(), CommandIntent::RemoveTask),
        ]);

        // History patterns
        self.intent_patterns.extend([
            (Regex::new(r"(show|view|query)?\s*(my\s+)?(command\s+)?history").unwrap(), CommandIntent::QueryHistory),
            (Regex::new(r"history\s+(of\s+)?commands").unwrap(), CommandIntent::QueryHistory),
        ]);

        // Lock/Unlock
        self.intent_patterns.extend([
            (Regex::new(r"lock\s+ube").unwrap(), CommandIntent::Lock),
            (Regex::new(r"unlock\s+ube").unwrap(), CommandIntent::Unlock),
        ]);

        // Learn/Forget
        self.intent_patterns.extend([
            (Regex::new(r"learn\s+(\w+)").unwrap(), CommandIntent::Learn),
            (Regex::new(r"forget\s+(\w+)").unwrap(), CommandIntent::Forget),
        ]);
    }
}

impl Default for CommandParser {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_add_rule() {
        let parser = CommandParser::new();
        let result = parser.parse("add rule stop payment").unwrap();
        assert_eq!(result.intent, CommandIntent::AddRule);
    }

    #[test]
    fn test_parse_remove_rule() {
        let parser = CommandParser::new();
        let result = parser.parse("remove the rule stop payment").unwrap();
        assert_eq!(result.intent, CommandIntent::RemoveRule);
    }

    #[test]
    fn test_parse_query_history() {
        let parser = CommandParser::new();
        let result = parser.parse("show me my command history").unwrap();
        assert_eq!(result.intent, CommandIntent::QueryHistory);
    }

    #[test]
    fn test_parse_lock() {
        let parser = CommandParser::new();
        let result = parser.parse("lock UBE").unwrap();
        assert_eq!(result.intent, CommandIntent::Lock);
    }

    #[test]
    fn test_parse_learn() {
        let parser = CommandParser::new();
        let result = parser.parse("learn stop payment on weekends").unwrap();
        assert_eq!(result.intent, CommandIntent::Learn);
    }
}
