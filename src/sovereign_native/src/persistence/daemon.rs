//! UBE Sovereign Daemon - Self-Persisting Process
//!
//! Ensures UBE runs FOREVER across:
//! - Phone reboots
//! - Server restarts
//! - Any hardware power cycles
//!
//! Architecture:
//! 1. Daemon forks itself on start
//! 2. Parent monitors child
//! 3. If child dies, parent restarts immediately
//! 4. Boot scripts ensure daemon starts on system power-on

use std::process::{Command, Child, Stdio};
use std::thread;
use std::time::{Duration, SystemTime};
use std::sync::{Arc, Mutex};
use std::path::PathBuf;
use std::fs::{File, self};
use std::io::Write;

/// Daemon status
#[derive(Debug, Clone)]
pub enum DaemonStatus {
    /// Daemon is running and healthy
    Healthy,
    /// Daemon is starting up
    Starting,
    /// Daemon crashed and restarting
    Restarting,
    /// Daemon is stopped
    Stopped,
}

/// UBE Sovereign Daemon
///
/// This is the immortal process manager for UBE
/// It ensures UBE survives ALL hardware power cycles
pub struct UbeDaemon {
    /// Path to the UBE binary
    binary_path: PathBuf,
    /// Current child process
    child: Option<Child>,
    /// Status
    status: Arc<Mutex<DaemonStatus>>,
    /// PID file path
    pid_file: PathBuf,
    /// Log file path
    log_file: PathBuf,
    /// Last restart timestamp
    last_restart: SystemTime,
}

impl UbeDaemon {
    /// Create a new UBE daemon
    pub fn new(binary_path: PathBuf) -> Self {
        let home = binary_path.parent().unwrap().parent().unwrap();

        Self {
            binary_path,
            child: None,
            status: Arc::new(Mutex::new(DaemonStatus::Stopped)),
            pid_file: home.join(".ube_daemon_pid"),
            log_file: home.join(".ube_daemon.log"),
            last_restart: SystemTime::now(),
        }
    }

    /// Save PID to file
    fn save_pid(&self, pid: u32) {
        if let Ok(mut file) = File::create(&self.pid_file) {
            let _ = file.write_all(pid.to_string().as_bytes());
        }
    }

    /// Remove PID file
    fn remove_pid(&self) {
        let _ = std::fs::remove_file(&self.pid_file);
    }

    /// Log a message
    fn log(&self, message: &str) {
        let timestamp = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
        let log_entry = format!("[{}] {}\n", timestamp, message);

        if let Ok(mut file) = File::options().append(true).open(&self.log_file) {
            let _ = file.write_all(log_entry.as_bytes());
        }

        println!("[UBE DAEMON] {}", message);
    }

    /// Start the daemon
    pub fn start(&mut self) {
        *self.status.lock().unwrap() = DaemonStatus::Starting;
        self.log("Starting UBE Sovereign Daemon");

        // Remove stale PID file
        self.remove_pid();

        // Start the child process
        self.start_child();

        // Save our own PID
        let my_pid = std::process::id();
        self.save_pid(my_pid);

        *self.status.lock().unwrap() = DaemonStatus::Healthy;
        self.log(&format!("Daemon running with PID: {}", my_pid));
    }

    /// Start child UBE process
    fn start_child(&mut self) {
        self.log("Starting child UBE process");

        let mut child = Command::new(&self.binary_path)
            .stdin(Stdio::null())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .spawn();

        match child {
            Ok(c) => {
                self.last_restart = SystemTime::now();
                self.child = Some(c);
                self.log("Child UBE process started");
            }
            Err(e) => {
                self.log(&format!("Failed to start child: {}", e));
                // Retry after delay
                thread::sleep(Duration::from_secs(1));
                self.start_child();
            }
        }
    }

    /// Monitor child and restart if needed
    pub fn monitor(&mut self) {
        self.log("Starting daemon monitor loop");

        loop {
            thread::sleep(Duration::from_secs(5));

            // Check if child is still running
            if let Some(ref mut child) = self.child {
                match child.try_wait() {
                    Ok(Some(status)) => {
                        self.log(&format!("Child exited with status: {:?}", status));
                        self.child = None;
                        *self.status.lock().unwrap() = DaemonStatus::Restarting;
                        self.log("Restarting child process...");
                        self.start_child();
                        *self.status.lock().unwrap() = DaemonStatus::Healthy;
                    }
                    Ok(None) => {
                        // Child still running
                        continue;
                    }
                    Err(e) => {
                        self.log(&format!("Error checking child: {}", e));
                        self.child = None;
                        self.start_child();
                    }
                }
            } else {
                // No child, start one
                self.start_child();
            }
        }
    }

    /// Get current status
    pub fn status(&self) -> DaemonStatus {
        self.status.lock().unwrap().clone()
    }

    /// Stop the daemon
    pub fn stop(&mut self) {
        *self.status.lock().unwrap() = DaemonStatus::Stopped;
        self.log("Stopping UBE Daemon");

        if let Some(ref mut child) = self.child {
            let _ = child.kill();
            let _ = child.wait();
        }

        self.remove_pid();
        self.log("UBE Daemon stopped");
    }
}

/// Daemon configuration for persistence
#[derive(Debug, Clone)]
pub struct DaemonConfig {
    pub binary_path: PathBuf,
    pub auto_restart: bool,
    pub monitor_interval: u64,
}

impl Default for DaemonConfig {
    fn default() -> Self {
        let mut path = PathBuf::new();
        path.push("/data/data/com.termux/files/home/UBE/target/release/sovereign_native");

        Self {
            binary_path: path,
            auto_restart: true,
            monitor_interval: 5,
        }
    }
}

/// Start the immortal daemon
pub fn start_immortal_daemon() {
    use std::env;

    // Check if we're already running as daemon
    let args: Vec<String> = env::args().collect();
    if args.contains(&"--daemon".to_string()) {
        // We're the daemon child, don't double-fork
        return;
    }

    // Check for existing daemon
    let pid_file = PathBuf::from("/data/data/com.termux/files/home/UBE/.ube_daemon_pid");
    if pid_file.exists() {
        if let Ok(pid_str) = fs::read_to_string(&pid_file) {
            if let Ok(pid) = pid_str.trim().parse::<u32>() {
                // Check if process is still running
                if std::process::Command::new("kill")
                    .arg("-0")
                    .arg(pid.to_string())
                    .status()
                    .is_ok()
                {
                    // Daemon already running
                    return;
                }
            }
        }
        // Stale PID file, remove it
        let _ = fs::remove_file(&pid_file);
    }

    // Start daemon in background
    let daemon_cmd = "nohup /data/data/com.termux/files/home/UBE/target/release/sovereign_native --daemon < /dev/null > /data/data/com.termux/files/home/UBE/.ube_daemon_output.log 2> /data/data/com.termux/files/home/UBE/.ube_daemon_error.log & echo $! > /data/data/com.termux/files/home/UBE/.ube_daemon_pid";

    let _ = Command::new("sh")
        .arg("-c")
        .arg(daemon_cmd)
        .spawn();
}
