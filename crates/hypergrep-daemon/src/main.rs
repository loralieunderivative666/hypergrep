use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Result;
use clap::Parser;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;
use tokio::sync::RwLock;
use tracing::{error, info, warn};

use hypergrep_core::index::Index;

mod watcher;

const DEFAULT_IDLE_TIMEOUT_SECS: u64 = 1800; // 30 minutes

#[derive(Parser)]
#[command(
    name = "hypergrep-daemon",
    about = "Hypergrep persistent index daemon",
    long_about = "Keeps a hypergrep index in memory for fast repeated queries.\n\
        Watches the filesystem and updates incrementally.\n\
        Auto-stops after 30 minutes of inactivity (configurable with --idle-timeout)."
)]
struct Cli {
    /// Root directory to index and watch
    #[arg(default_value = ".")]
    root: PathBuf,

    /// Unix socket path (auto-generated if not specified)
    #[arg(long)]
    socket: Option<PathBuf>,

    /// Idle timeout in seconds. Daemon exits if no queries for this long. 0 = never.
    #[arg(long, default_value_t = DEFAULT_IDLE_TIMEOUT_SECS)]
    idle_timeout: u64,

    /// Run in foreground (default). Use --background to daemonize.
    #[arg(long)]
    background: bool,

    /// Stop a running daemon for this directory
    #[arg(long)]
    stop: bool,

    /// Check if a daemon is running for this directory
    #[arg(long)]
    status: bool,
}

/// Shared daemon state.
pub struct DaemonState {
    pub index: RwLock<Index>,
    pub root: PathBuf,
    /// Unix timestamp of last query (for idle timeout)
    pub last_activity: AtomicU64,
}

impl DaemonState {
    fn touch(&self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.last_activity.store(now, Ordering::Relaxed);
    }

    fn idle_secs(&self) -> u64 {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let last = self.last_activity.load(Ordering::Relaxed);
        now.saturating_sub(last)
    }
}

#[derive(serde::Deserialize)]
struct SearchRequest {
    pattern: String,
}

#[derive(serde::Serialize)]
struct SearchResponse {
    matches: Vec<MatchResult>,
    elapsed_us: u64,
}

#[derive(serde::Serialize)]
struct MatchResult {
    path: String,
    line_number: usize,
    line: String,
    match_start: usize,
    match_end: usize,
}

fn socket_path(root: &PathBuf) -> PathBuf {
    let hash = {
        use std::hash::{Hash, Hasher};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        root.hash(&mut hasher);
        hasher.finish()
    };

    let runtime_dir = std::env::var("XDG_RUNTIME_DIR")
        .or_else(|_| std::env::var("TMPDIR"))
        .unwrap_or_else(|_| "/tmp".to_string());

    PathBuf::from(runtime_dir).join(format!("hypergrep-{:x}.sock", hash))
}

fn pid_path(root: &PathBuf) -> PathBuf {
    let hash = {
        use std::hash::{Hash, Hasher};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        root.hash(&mut hasher);
        hasher.finish()
    };

    let runtime_dir = std::env::var("XDG_RUNTIME_DIR")
        .or_else(|_| std::env::var("TMPDIR"))
        .unwrap_or_else(|_| "/tmp".to_string());

    PathBuf::from(runtime_dir).join(format!("hypergrep-{:x}.pid", hash))
}

/// Check if a process with this PID is alive.
fn is_pid_alive(pid: u32) -> bool {
    // signal 0 checks existence without sending a signal
    unsafe { libc::kill(pid as i32, 0) == 0 }
}

/// Read PID from file and check if process is alive.
fn read_running_pid(root: &PathBuf) -> Option<u32> {
    let path = pid_path(root);
    let content = std::fs::read_to_string(&path).ok()?;
    let pid: u32 = content.trim().parse().ok()?;
    if is_pid_alive(pid) {
        Some(pid)
    } else {
        // Stale PID file, clean up
        let _ = std::fs::remove_file(&path);
        None
    }
}

fn write_pid(root: &PathBuf) {
    let path = pid_path(root);
    let _ = std::fs::write(&path, format!("{}", std::process::id()));
}

fn remove_pid(root: &PathBuf) {
    let _ = std::fs::remove_file(pid_path(root));
}

/// Get RSS of the current process in MB.
fn get_rss_mb() -> f64 {
    get_rss_of_pid_raw(std::process::id())
}

/// Get RSS of a PID as a human-readable string.
fn get_rss_of_pid(pid: u32) -> String {
    let mb = get_rss_of_pid_raw(pid);
    if mb > 0.0 {
        format!("{:.1} MB", mb)
    } else {
        "unknown".to_string()
    }
}

fn get_rss_of_pid_raw(pid: u32) -> f64 {
    let output = std::process::Command::new("ps")
        .args(["-o", "rss=", "-p", &pid.to_string()])
        .output()
        .ok();

    output
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .and_then(|s| s.trim().parse::<u64>().ok())
        .map(|kb| kb as f64 / 1024.0)
        .unwrap_or(0.0)
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter("hypergrep=info")
        .init();

    let cli = Cli::parse();
    let root = std::fs::canonicalize(&cli.root)?;
    let sock_path = cli.socket.unwrap_or_else(|| socket_path(&root));

    // --status: check if daemon is running + show resource usage
    if cli.status {
        if let Some(pid) = read_running_pid(&root) {
            let rss = get_rss_of_pid(pid);
            println!("Running");
            println!("  PID:    {}", pid);
            println!("  Socket: {}", sock_path.display());
            println!("  Memory: {}", rss);
            println!("  Root:   {}", root.display());
        } else {
            println!("Not running");
        }
        return Ok(());
    }

    // --stop: kill running daemon
    if cli.stop {
        if let Some(pid) = read_running_pid(&root) {
            unsafe {
                libc::kill(pid as i32, libc::SIGTERM);
            }
            // Wait briefly for shutdown
            std::thread::sleep(std::time::Duration::from_millis(500));
            remove_pid(&root);
            let _ = std::fs::remove_file(&sock_path);
            println!("Stopped daemon (PID {})", pid);
        } else {
            println!("No daemon running for {}", root.display());
        }
        return Ok(());
    }

    // Check for already running daemon
    if let Some(pid) = read_running_pid(&root) {
        eprintln!(
            "Daemon already running (PID {}). Use --stop to kill it first.",
            pid
        );
        std::process::exit(1);
    }

    // Daemonize if --background: re-launch self without --background
    if cli.background {
        let exe = std::env::current_exe()?;
        let mut args: Vec<String> = std::env::args().collect();
        // Remove --background from args
        args.retain(|a| a != "--background");

        let child = std::process::Command::new(exe)
            .args(&args[1..])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()?;

        println!("Daemon started (PID {})", child.id());
        std::process::exit(0);
    }

    // Build index
    info!("Building index for {}", root.display());
    let mut index = Index::build(&root)?;
    index.complete_index();
    let _ = index.save();
    let rss_mb = get_rss_mb();
    info!(
        "Index ready: {} files, {} trigrams, {} symbols, {} edges | Memory: {:.1} MB",
        index.file_count(),
        index.trigram_count(),
        index.symbol_count(),
        index.graph.edge_count(),
        rss_mb,
    );

    // Warn if memory usage is high
    if rss_mb > 200.0 {
        warn!(
            "High memory usage ({:.0} MB). Consider using CLI mode instead of daemon for large codebases.",
            rss_mb
        );
    }

    let state = Arc::new(DaemonState {
        index: RwLock::new(index),
        root: root.clone(),
        last_activity: AtomicU64::new(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        ),
    });

    // Write PID file
    write_pid(&root);

    // Clean up on exit
    let cleanup_root = root.clone();
    let cleanup_sock = sock_path.clone();
    ctrlc::set_handler(move || {
        remove_pid(&cleanup_root);
        let _ = std::fs::remove_file(&cleanup_sock);
        eprintln!("Daemon shutting down");
        std::process::exit(0);
    })?;

    // Start filesystem watcher
    let watcher_state = Arc::clone(&state);
    tokio::spawn(async move {
        if let Err(e) = watcher::watch(watcher_state).await {
            error!("Filesystem watcher error: {}", e);
        }
    });

    // Idle timeout + memory monitor
    let idle_timeout = cli.idle_timeout;
    {
        let monitor_state = Arc::clone(&state);
        let monitor_root = root.clone();
        let monitor_sock = sock_path.clone();
        tokio::spawn(async move {
            let mut check_count = 0u64;
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(60)).await;
                check_count += 1;
                let idle = monitor_state.idle_secs();
                let rss = get_rss_mb();

                // Log status every 5 minutes
                if check_count.is_multiple_of(5) {
                    info!(
                        "Daemon status: idle {}s, memory {:.1} MB, PID {}",
                        idle,
                        rss,
                        std::process::id()
                    );
                }

                // Idle timeout
                if idle_timeout > 0 && idle >= idle_timeout {
                    info!(
                        "Idle for {}s (timeout: {}s). Shutting down to free {:.0} MB.",
                        idle, idle_timeout, rss
                    );
                    remove_pid(&monitor_root);
                    let _ = std::fs::remove_file(&monitor_sock);
                    std::process::exit(0);
                }

                // Memory safety: hard limit at 500 MB
                if rss > 500.0 {
                    warn!(
                        "Memory limit exceeded ({:.0} MB > 500 MB). Shutting down.",
                        rss
                    );
                    remove_pid(&monitor_root);
                    let _ = std::fs::remove_file(&monitor_sock);
                    std::process::exit(1);
                }
            }
        });
    }

    // Listen on Unix socket
    let _ = std::fs::remove_file(&sock_path);

    // Set socket permissions to owner-only
    let listener = UnixListener::bind(&sock_path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&sock_path, std::fs::Permissions::from_mode(0o600));
    }

    info!("Listening on {}", sock_path.display());
    if idle_timeout > 0 {
        info!("Idle timeout: {}s", idle_timeout);
    } else {
        info!("Idle timeout: disabled");
    }

    loop {
        let (stream, _) = listener.accept().await?;
        let state = Arc::clone(&state);
        state.touch();

        tokio::spawn(async move {
            let (reader, mut writer) = stream.into_split();
            let mut reader = BufReader::new(reader);
            let mut line = String::new();

            loop {
                line.clear();
                match reader.read_line(&mut line).await {
                    Ok(0) => break,
                    Ok(_) => {}
                    Err(e) => {
                        error!("Read error: {}", e);
                        break;
                    }
                }

                state.touch();

                // Handle ping (for health checks)
                let trimmed = line.trim();
                if trimmed == "ping" || trimmed == "{\"type\":\"ping\"}" {
                    let _ = writer.write_all(b"{\"status\":\"ok\"}\n").await;
                    continue;
                }

                let request: SearchRequest = match serde_json::from_str(&line) {
                    Ok(r) => r,
                    Err(e) => {
                        let err = format!("{{\"error\":\"{}\"}}\n", e);
                        let _ = writer.write_all(err.as_bytes()).await;
                        continue;
                    }
                };

                let start = std::time::Instant::now();
                let index = state.index.read().await;
                let search_result = index.search(&request.pattern);
                drop(index);

                let response = match search_result {
                    Ok(matches) => SearchResponse {
                        matches: matches
                            .into_iter()
                            .map(|m| MatchResult {
                                path: m.path.display().to_string(),
                                line_number: m.line_number,
                                line: m.line,
                                match_start: m.match_start,
                                match_end: m.match_end,
                            })
                            .collect(),
                        elapsed_us: start.elapsed().as_micros() as u64,
                    },
                    Err(e) => {
                        let err = format!("{{\"error\":\"{}\"}}\n", e);
                        let _ = writer.write_all(err.as_bytes()).await;
                        continue;
                    }
                };

                let json = serde_json::to_string(&response).unwrap() + "\n";
                let _ = writer.write_all(json.as_bytes()).await;
            }
        });
    }
}
