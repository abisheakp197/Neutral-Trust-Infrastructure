//! Sovereign Command Executor - "Do Anything" Engine
//!
//! This module enables UBE to execute ANY command with voice control
//! - File operations (read, write, delete, copy, move)
//! - Process management (run, kill, monitor)
//! - System control (reboot, shutdown, network)
//! - Hardware access (camera, sensors, battery)
//! - Application control (open, close, install)
//! - Custom scripting
//!
//! Security: ALL commands require authentication
//! Sovereign level = full access
//! Admin level = system management
//! User level = basic operations
//!
//! "Do anything" - TRUE unlimited command execution

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
use serde::{Serialize, Deserialize};
use log::{info, warn, error};

use super::{CommandIntent, CommandEntity, VoiceCommand, VoiceCommandResult, VoiceError};
use super::auth::{AuthLevel, VoiceAuthDatabase};
use crate::hardware::access::{UniversalHardwareAccessor, HardwareResult, HardwareAccessError};

/// Maximum command history size
const MAX_COMMAND_HISTORY: usize = 1000;

/// Command execution context with authentication and hardware access
#[derive(Clone)]
pub struct SovereignCommandExecutor {
    hardware: UniversalHardwareAccessor,
    command_history: Arc<RwLock<Vec<CommandRecord>>>,
    auth_db: Option<Arc<RwLock<VoiceAuthDatabase>>>,
    current_user: String,
    current_auth_level: AuthLevel,
    custom_commands: HashMap<String, CustomCommand>,
    enabled: bool,
}

/// Custom command definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomCommand {
    pub name: String,
    pub command: String,
    pub description: String,
    pub required_auth: AuthLevel,
}

/// Record of executed command for audit
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandRecord {
    pub timestamp: u64,
    pub user: String,
    pub auth_level: AuthLevel,
    pub command_text: String,
    pub intent: CommandIntent,
    pub entities: Vec<CommandEntity>,
    pub success: bool,
    pub response: String,
}

impl SovereignCommandExecutor {
    pub fn new() -> Self {
        Self {
            hardware: UniversalHardwareAccessor::new(),
            command_history: Arc::new(RwLock::new(Vec::new())),
            auth_db: None,
            current_user: "default".to_string(),
            current_auth_level: AuthLevel::User,
            custom_commands: HashMap::new(),
            enabled: true,
        }
    }

    /// Create with authentication database
    pub fn with_auth(
        db: Arc<RwLock<VoiceAuthDatabase>>,
        user: String,
        auth_level: AuthLevel,
    ) -> Self {
        let mut executor = Self::new();
        executor.auth_db = Some(Arc::clone(&db));
        executor.current_user = user;
        executor.current_auth_level = auth_level;
        executor.hardware = UniversalHardwareAccessor::with_auth(
            Arc::clone(&db),
            auth_level,
        );
        executor
    }

    /// Set authentication level
    pub fn set_auth_level(&mut self, level: AuthLevel) {
        self.current_auth_level = level;
        self.hardware.set_user_level(level);
    }

    /// Set current user
    pub fn set_user(&mut self, user: &str) {
        self.current_user = user.to_string();
    }

    /// Enable or disable command execution
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    /// Add custom command
    pub fn add_custom_command(&mut self, command: CustomCommand) {
        self.custom_commands.insert(command.name.clone(), command);
    }

    /// Execute a voice command - themain "DO ANYTHING" entry point
    pub async fn execute(&mut self, command: VoiceCommand) -> VoiceCommandResult {
        if !self.enabled {
            return VoiceCommandResult {
                success: false,
                command: command.text.clone(),
                intent: command.intent.clone(),
                entities: command.entities.clone(),
                confidence: command.confidence,
                user_id: self.current_user.clone(),
                timestamp: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
                response: "UBE command execution is disabled".to_string()
            };
        }

        let result = self.execute_inner(&command).await;

        // Record for audit
        self.record_command(&command, result.success, &result.response);

        result
    }

    async fn execute_inner(&self, command: &VoiceCommand) -> VoiceCommandResult {
        use CommandIntent::*;

        let intent = command.intent.clone();
        let entities = &command.entities;
        let text = command.text.trim();

        // SOVEREIGN HARDWARE COMMANDS
        // Filesystem operations
        if let Some(result) = self.execute_file_command(&intent, entities, text) {
            return result;
        }

        // Process operations
        if let Some(result) = self.execute_process_command(&intent, entities, text) {
            return result;
        }

        // System operations
        if let Some(result) = self.execute_system_command(&intent, entities, text) {
            return result;
        }

        // Hardware operations
        if let Some(result) = self.execute_hardware_command(&intent, entities, text) {
            return result;
        }

        // Network operations
        if let Some(result) = self.execute_network_command(&intent, entities, text) {
            return result;
        }

        // Custom commands
        if let Some(result) = self.execute_custom_command(text) {
            return result;
        }

        // Parse and execute raw shell command
        if let Some(result) = self.execute_shell_command(text) {
            return result;
        }

        // Fallback to old command executor
        info!("[SOVEREIGN-EXEC] Falling back to standard command execution");
        super::execute_command(command.clone(), &self.current_user).await
    }

    // ==================== FILE COMMANDS ====================

    fn execute_file_command(
        &self,
        intent: &CommandIntent,
        entities: &[CommandEntity],
        text: &str,
    ) -> Option<VoiceCommandResult> {
        use CommandIntent::*;

        let text_lower = text.to_lowercase();

        match intent {
            // Read file
            _ if text_lower.contains("read file") => {
                if self.check_auth(AuthLevel::User).is_err() { return None; }
                let path = self.get_argument(text, entities);
                match self.hardware.read_text_file(&path) {
                    Ok(content) => Some(self.success_result(
                        format!("File contents:\n{}", content),
                        intent.clone(),
                        entities.to_vec(),
                    )),
                    Err(e) => Some(self.error_result(e.to_string(), intent.clone(), entities.to_vec())),
                }
            }

            // Write file
            _ if text_lower.contains("write file") || text_lower.contains("create file") => {
                if self.check_auth(AuthLevel::Admin).is_err() { return None; }
                let parts: Vec<&str> = text.splitn(3, '"').collect();
                if parts.len() >= 3 {
                    let path = parts[1].to_string();
                    let content = parts[2].to_string();
                    match self.hardware.write_file(&path, content.as_bytes()) {
                        Ok(_) => Some(self.success_result(
                            format!("File '{}' written successfully", path),
                            intent.clone(),
                            entities.to_vec(),
                        )),
                        Err(e) => Some(self.error_result(e.to_string(), intent.clone(), entities.to_vec())),
                    }
                } else {
                    Some(self.error_result("Usage: write file \"path\" \"content\"", intent.clone(), entities.to_vec()))
                }
            }

            // Delete file
            _ if text_lower.contains("delete file") || text_lower.contains("remove file") => {
                if self.check_auth(AuthLevel::Sovereign).is_err() { return None; }
                let path = self.get_argument(text, entities);
                match self.hardware.delete_file(&path) {
                    Ok(_) => Some(self.success_result(
                        format!("File '{}' deleted", path),
                        intent.clone(),
                        entities.to_vec(),
                    )),
                    Err(e) => Some(self.error_result(e.to_string(), intent.clone(), entities.to_vec())),
                }
            }

            // Copy file
            _ if text_lower.contains("copy file") || text_lower.contains("duplicate file") => {
                if self.check_auth(AuthLevel::Admin).is_err() { return None; }
                let parts: Vec<&str> = text.split_whitespace().collect();
                if parts.len() >= 4 {
                    let from = parts.get(2).unwrap_or(&"");
                    let to = parts.get(3).unwrap_or(&"");
                    match self.hardware.copy_file(from, to) {
                        Ok(_) => Some(self.success_result(
                            format!("Copied '{}' to '{}'", from, to),
                            intent.clone(),
                            entities.to_vec(),
                        )),
                        Err(e) => Some(self.error_result(e.to_string(), intent.clone(), entities.to_vec())),
                    }
                } else {
                    Some(self.error_result("Usage: copy file <from> <to>", intent.clone(), entities.to_vec()))
                }
            }

            // List directory
            _ if text_lower.contains("list files") || text_lower.contains("list directory") => {
                if self.check_auth(AuthLevel::User).is_err() { return None; }
                let path = self.get_argument(text, entities);
                match self.hardware.list_dir(&path) {
                    Ok(files) => Some(self.success_result(
                        format!("Files in '{}':\n{}", path, files.iter().map(|p| p.display().to_string()).collect::<Vec<_>>().join("\n")),
                        intent.clone(),
                        entities.to_vec(),
                    )),
                    Err(e) => Some(self.error_result(e.to_string(), intent.clone(), entities.to_vec())),
                }
            }

            _ => None,
        }
    }

    // ==================== PROCESS COMMANDS ====================

    fn execute_process_command(
        &self,
        intent: &CommandIntent,
        entities: &[CommandEntity],
        text: &str,
    ) -> Option<VoiceCommandResult> {
        let text_lower = text.to_lowercase();

        // Run command/process
        if text_lower.contains("run command") || text_lower.contains("execute") || text_lower.contains("run process") {
            if self.check_auth(AuthLevel::High).is_err() { return None; }
            // Extract the command to run (after "run" keyword)
            let cmd = text.split_once(char::is_whitespace).map(|(_, s)| s.trim());
            if let Some(command) = cmd {
                // Don't allow nested UBE commands or dangerous patterns
                if command.contains("ube") || command.contains("rm -rf") || command.contains(";") {
                    return Some(self.error_result(
                        "Command contains restricted patterns",
                        intent.clone(),
                        entities.to_vec(),
                    ));
                }
                match self.hardware.run_command(command) {
                    Ok(output) => Some(self.success_result(
                        format!("Command output:\n{}", output),
                        intent.clone(),
                        entities.to_vec(),
                    )),
                    Err(e) => Some(self.error_result(e.to_string(), intent.clone(), entities.to_vec())),
                }
            } else {
                Some(self.error_result("Usage: run command <command>", intent.clone(), entities.to_vec()))
            }
        } else if text_lower.contains("kill process") || text_lower.contains("stop process") {
            if self.check_auth(AuthLevel::High).is_err() { return None; }
            // Extract PID
            let pid_str = self.get_argument(text, entities);
            if let Ok(pid) = pid_str.parse::<u32>() {
                match self.hardware.kill_process(pid) {
                    Ok(_) => Some(self.success_result(
                        format!("Process {} killed", pid),
                        intent.clone(),
                        entities.to_vec(),
                    )),
                    Err(e) => Some(self.error_result(e.to_string(), intent.clone(), entities.to_vec())),
                }
            } else {
                Some(self.error_result("Usage: kill process <PID>", intent.clone(), entities.to_vec()))
            }
        } else if text_lower.contains("list processes") || text_lower.contains("show processes") {
            if self.check_auth(AuthLevel::High).is_err() { return None; }
            match self.hardware.list_processes() {
                Ok(procs) => Some(self.success_result(
                    format!("Running processes:\n{}",
                        procs.iter().map(|p| format!("PID {}: {}", p.pid, p.name)).collect::<Vec<_>>().join("\n")),
                    intent.clone(),
                    entities.to_vec(),
                )),
                Err(e) => Some(self.error_result(e.to_string(), intent.clone(), entities.to_vec())),
            }
        } else {
            None
        }
    }

    // ==================== SYSTEM COMMANDS ====================

    fn execute_system_command(
        &self,
        intent: &CommandIntent,
        entities: &[CommandEntity],
        text: &str,
    ) -> Option<VoiceCommandResult> {
        use CommandIntent::*;
        let text_lower = text.to_lowercase();

        match intent {
            Shutdown => {
                if self.check_auth(AuthLevel::Sovereign).is_err() { return None; }
                match self.hardware.run_elevated("shutdown -h now") {
                    Ok(_) => Some(self.success_result(
                        "System shutting down...",
                        intent.clone(),
                        entities.to_vec(),
                    )),
                    Err(e) => Some(self.error_result(e.to_string(), intent.clone(), entities.to_vec())),
                }
            }
            Reboot => {
                if self.check_auth(AuthLevel::Sovereign).is_err() { return None; }
                match self.hardware.run_elevated("reboot") {
                    Ok(_) => Some(self.success_result(
                        "System rebooting...",
                        intent.clone(),
                        entities.to_vec(),
                    )),
                    Err(e) => Some(self.error_result(e.to_string(), intent.clone(), entities.to_vec())),
                }
            }
            Update => {
                if self.check_auth(AuthLevel::Sovereign).is_err() { return None; }
                match self.hardware.run_command("pkg update && pkg upgrade -y")
                    .or_else(|_| self.hardware.run_command("apt update && apt upgrade -y"))
                {
                    Ok(output) => Some(self.success_result(
                        format!("Update output:\n{}", output),
                        intent.clone(),
                        entities.to_vec(),
                    )),
                    Err(e) => Some(self.error_result(e.to_string(), intent.clone(), entities.to_vec())),
                }
            }
            _ => None,
        }
    }

    // ==================== HARDWARE COMMANDS ====================

    fn execute_hardware_command(
        &self,
        intent: &CommandIntent,
        entities: &[CommandEntity],
        text: &str,
    ) -> Option<VoiceCommandResult> {
        let text_lower = text.to_lowercase();

        // Open app
        if text_lower.contains("open app") || text_lower.contains("open application") || text_lower.contains("launch") {
            if self.check_auth(AuthLevel::High).is_err() { return None; }
            let app_name = self.get_argument(text, entities);
            match self.hardware.open_app(&app_name) {
                Ok(_) => Some(self.success_result(
                    format!("Opening '{}'", app_name),
                    intent.clone(),
                    entities.to_vec(),
                )),
                Err(e) => Some(self.error_result(e.to_string(), intent.clone(), entities.to_vec())),
            }
        }
        // Take screenshot
        else if text_lower.contains("take screenshot") || text_lower.contains("capture screen") {
            if self.check_auth(AuthLevel::High).is_err() { return None; }
            let path = self.get_argument(text, entities);
            let output_path = if path.is_empty() { "/tmp/screenshot.png" } else { &path };
            match self.hardware.take_screenshot(output_path) {
                Ok(_) => Some(self.success_result(
                    format!("Screenshot saved to {}", output_path),
                    intent.clone(),
                    entities.to_vec(),
                )),
                Err(e) => Some(self.error_result(e.to_string(), intent.clone(), entities.to_vec())),
            }
        }
        // Camera
        else if text_lower.contains("take photo") || text_lower.contains("capture photo") {
            if self.check_auth(AuthLevel::High).is_err() { return None; }
            let path = self.get_argument(text, entities);
            let output_path = if path.is_empty() { "/tmp/photo.jpg" } else { &path };
            match self.hardware.capture_photo(output_path) {
                Ok(_) => Some(self.success_result(
                    format!("Photo saved to {}", output_path),
                    intent.clone(),
                    entities.to_vec(),
                )),
                Err(e) => Some(self.error_result(e.to_string(), intent.clone(), entities.to_vec())),
            }
        }
        // Battery
        else if text_lower.contains("battery") || text_lower.contains("battery status") {
            if self.check_auth(AuthLevel::High).is_err() { return None; }
            match self.hardware.battery_status() {
                Ok(info) => Some(self.success_result(
                    format!("Battery: {:.0}% {}", info.level, if info.is_charging { "(Charging)" } else { "" }),
                    intent.clone(),
                    entities.to_vec(),
                )),
                Err(e) => Some(self.error_result(e.to_string(), intent.clone(), entities.to_vec())),
            }
        }
        // System info
        else if text_lower.contains("system info") || text_lower.contains("system information") {
            if self.check_auth(AuthLevel::High).is_err() { return None; }
            match self.get_system_info() {
                Ok(info) => Some(self.success_result(
                    format!("System info:\nPlatform: {}\nCPU: {} ({} cores @ {}MHz)\nMemory: {}MB used / {}MB total\nDisks: {}",
                        info.platform,
                        info.cpu.name,
                        info.cpu.cores,
                        info.cpu.clock_speed_mhz,
                        info.memory.used,
                        info.memory.total,
                        info.disks.len()
                    ),
                    intent.clone(),
                    entities.to_vec(),
                )),
                Err(e) => Some(self.error_result(e.to_string(), intent.clone(), entities.to_vec())),
            }
        } else {
            None
        }
    }

    // ==================== NETWORK COMMANDS ====================

    fn execute_network_command(
        &self,
        intent: &CommandIntent,
        entities: &[CommandEntity],
        text: &str,
    ) -> Option<VoiceCommandResult> {
        let text_lower = text.to_lowercase();

        // Check network
        if text_lower.contains("check network") || text_lower.contains("network status") {
            if self.check_auth(AuthLevel::High).is_err() { return None; }
            match self.hardware.check_network() {
                Ok(connected) => Some(self.success_result(
                    if connected { "Network: Connected" } else { "Network: Disconnected" }.to_string(),
                    intent.clone(),
                    entities.to_vec(),
                )),
                Err(e) => Some(self.error_result(e.to_string(), intent.clone(), entities.to_vec())),
            }
        }
        // Get IP
        else if text_lower.contains("ip address") || text_lower.contains("my ip") {
            if self.check_auth(AuthLevel::High).is_err() { return None; }
            match self.hardware.local_ips() {
                Ok(ips) => Some(self.success_result(
                    format!("IP addresses: {}", ips.join(", ")),
                    intent.clone(),
                    entities.to_vec(),
                )),
                Err(e) => Some(self.error_result(e.to_string(), intent.clone(), entities.to_vec())),
            }
        }
        // WiFi control
        else if text_lower.contains("wifi") && (text_lower.contains("enable") || text_lower.contains("disable")) {
            if self.check_auth(AuthLevel::High).is_err() { return None; }
            let enable = text_lower.contains("enable") || text_lower.contains("turn on");
            match self.hardware.toggle_wifi(enable) {
                Ok(_) => Some(self.success_result(
                    if enable { "WiFi enabled" } else { "WiFi disabled" }.to_string(),
                    intent.clone(),
                    entities.to_vec(),
                )),
                Err(e) => Some(self.error_result(e.to_string(), intent.clone(), entities.to_vec())),
            }
        } else {
            None
        }
    }

    // ==================== CUSTOM COMMANDS ====================

    fn execute_custom_command(&self, text: &str) -> Option<VoiceCommandResult> {
        let text_lower = text.to_lowercase().trim().to_string();

        for (name, cmd) in &self.custom_commands {
            if text_lower == name.to_lowercase() || text_lower.contains(&name.to_lowercase()) {
                // Check auth
                if !self.current_auth_level.can(cmd.required_auth) {
                    return Some(self.error_result(
                        format!("Access denied: requires {:?} level", cmd.required_auth),
                        CommandIntent::Custom(name.clone()),
                        vec![],
                    ));
                }

                match self.hardware.run_command(&cmd.command) {
                    Ok(output) => return Some(self.success_result(
                        format!("Custom command '{}':\n{}", name, output),
                        CommandIntent::Custom(name.clone()),
                        vec![],
                    )),
                    Err(e) => return Some(self.error_result(
                        format!("Custom command '{}' failed: {}", name, e),
                        CommandIntent::Custom(name.clone()),
                        vec![],
                    )),
                }
            }
        }
        None
    }

    // ==================== SHELL COMMAND ====================

    fn execute_shell_command(&self, text: &str) -> Option<VoiceCommandResult> {
        let text_lower = text.to_lowercase();

        // Direct shell command execution - must start with specific keywords
        if text_lower.starts_with("sh ") || text_lower.starts_with("bash ") ||
           text_lower.starts_with("sudo ") || text_lower.starts_with("cmd ") ||
           text_lower.starts_with("execute ") || text_lower.starts_with("run ") {

            if self.check_auth(AuthLevel::High).is_err() { return None; }

            let command = text.trim();

            // BLOCK DANGEROUS COMMANDS
            let dangerous = [
                "rm -rf", "dd if=", "mkfs", "format ",
                ":(){ :;};", "fork bomb",
                "> /dev/sda", "> /dev/nvme",
            ];

            for pattern in dangerous {
                if command.contains(pattern) {
                    return Some(self.error_result(
                        format!("BLOCKED: Command contains dangerous pattern '{}'", pattern),
                        CommandIntent::Unknown,
                        vec![],
                    ));
                }
            }

            match self.hardware.run_command(command) {
                Ok(output) => Some(self.success_result(
                    format!("Command executed:\n{}", output),
                    CommandIntent::Custom("shell".to_string()),
                    vec![],
                )),
                Err(e) => Some(self.error_result(e.to_string(), CommandIntent::Unknown, vec![])),
            }
        } else {
            None
        }
    }

    // ==================== UTILITIES ====================

    /// Check if current user has required auth level.
    /// SOVEREIGN SECURITY FIX: Now RETURNS Result<bool> to actually BLOCK unauthorized access.
    /// Previously, this only logged warnings but allowed commands to execute anyway.
    fn check_auth(&self, required: AuthLevel) -> Result<(), String> {
        if !self.current_auth_level.can(required) {
            let error_msg = format!(
                "[SOVEREIGN-EXEC] ACCESS DENIED: user='{}', required={:?}, current={:?}. \
                 This operation requires higher authorization level.",
                self.current_user, required, self.current_auth_level
            );
            warn!("{}", error_msg);
            return Err(error_msg);
        }
        Ok(())
    }

    fn get_argument(&self, text: &str, entities: &[CommandEntity]) -> String {
        // First try entities
        for entity in entities {
            if entity.entity_type == "path" || entity.entity_type == "file" ||
               entity.entity_type == "command" || entity.entity_type == "app" {
                return entity.value.clone();
            }
        }
        // Fallback: extract quoted string
        text.split('"').nth(1).map(|s| s.to_string()).unwrap_or_default()
    }

    fn success_result(&self, response: impl Into<String>, intent: CommandIntent, entities: Vec<CommandEntity>) -> VoiceCommandResult {
        VoiceCommandResult {
            success: true,
            command: intent.to_string(),
            intent,
            entities,
            confidence: 1.0,
            user_id: self.current_user.clone(),
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            response: response.into(),
        }
    }

    fn error_result(&self, error: impl Into<String> + std::fmt::Display, intent: CommandIntent, entities: Vec<CommandEntity>) -> VoiceCommandResult {
        VoiceCommandResult {
            success: false,
            command: intent.to_string(),
            intent,
            entities,
            confidence: 0.0,
            user_id: self.current_user.clone(),
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            response: format!("Error: {}", error),
        }
    }

    fn record_command(&self, command: &VoiceCommand, success: bool, response: &str) {
        let mut history = self.command_history.write().unwrap();

        if history.len() >= MAX_COMMAND_HISTORY {
            history.remove(0);
        }

        history.push(CommandRecord {
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            user: self.current_user.clone(),
            auth_level: self.current_auth_level,
            command_text: command.text.clone(),
            intent: command.intent.clone(),
            entities: command.entities.clone(),
            success,
            response: response.to_string(),
        });

        info!("[SOVEREIGN-EXEC] Command recorded: user={}, intent={:?}, success={}",
            self.current_user, command.intent, success);
    }

    /// Get system information
    pub fn get_system_info(&self) -> HardwareResult<crate::hardware::access::SystemInfo> {
        use crate::hardware::access::{MemoryInfo, CpuInfo, DiskInfo};

        Ok(crate::hardware::access::SystemInfo {
            platform: format!("{:?}", self.hardware.platform),
            hostname: "localhost".to_string(),
            cpu: CpuInfo {
                name: "Unknown".to_string(),
                cores: 1,
                clock_speed_mhz: 0,
            },
            memory: MemoryInfo { total: 0, used: 0, free: 0 },
            disks: vec![],
        })
    }

    /// Get command history
    pub fn get_history(&self) -> Vec<CommandRecord> {
        self.command_history.read().unwrap().clone()
    }

    /// Clear command history
    pub fn clear_history(&mut self) -> Option<()> {
        if self.check_auth(AuthLevel::High).is_err() { return None; }
        self.command_history.write().unwrap().clear();
        Some(())
    }
}

impl Default for SovereignCommandExecutor {
    fn default() -> Self {
        Self::new()
    }
}
