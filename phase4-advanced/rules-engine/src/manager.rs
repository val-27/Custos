use crate::policy::{DynamicPolicy, Policy};
use arc_swap::ArcSwap;
use std::sync::Arc;
use std::time::Duration;
use tracing::{error, info, warn};

/// PolicyManager manages the active policy instance and allows hot-swapping it.
/// It can be cloned and shared safely across threads.
#[derive(Clone)]
pub struct PolicyManager {
    current: Arc<ArcSwap<DynamicPolicy>>,
}

impl PolicyManager {
    /// Creates a new `PolicyManager` with an initial policy configuration.
    pub fn new(initial: DynamicPolicy) -> Self {
        Self {
            current: Arc::new(ArcSwap::from_pointee(initial)),
        }
    }

    /// Fetches the currently active policy configuration.
    /// This is highly optimized for the hot path, only cloning an `Arc` pointer.
    pub fn get_policy(&self) -> Arc<DynamicPolicy> {
        self.current.load_full()
    }

    /// Hot-swaps the active configuration policy.
    pub fn reload(&self, new_policy: DynamicPolicy) {
        info!(
            "Hot-swapping configuration policies atomically to version {}",
            new_policy.version
        );
        self.current.store(Arc::new(new_policy));
    }

    /// Starts a background thread that watches a policy file (TOML/JSON) and reloads
    /// it dynamically when modified on disk.
    pub fn start_file_watcher<P>(
        &self,
        path: P,
        check_interval: Duration,
    ) -> std::thread::JoinHandle<()>
    where
        P: AsRef<std::path::Path> + Send + 'static,
    {
        let manager = self.clone();
        let path_buf = path.as_ref().to_path_buf();

        std::thread::spawn(move || {
            let mut last_modified = None;
            info!(
                "Starting background file watcher for policy: {:?}",
                path_buf
            );

            // Attempt initial load to populate last_modified if the file exists
            if let Ok(metadata) = std::fs::metadata(&path_buf) {
                if let Ok(modified) = metadata.modified() {
                    last_modified = Some(modified);
                }
            }

            loop {
                std::thread::sleep(check_interval);

                match std::fs::metadata(&path_buf) {
                    Ok(metadata) => {
                        if let Ok(modified) = metadata.modified() {
                            if last_modified.is_none() || last_modified.unwrap() != modified {
                                info!(
                                    "Change detected in policy file {:?}, reloading...",
                                    path_buf
                                );
                                match load_policy_from_file(&path_buf) {
                                    Ok(policy) => match DynamicPolicy::try_from(policy) {
                                        Ok(dyn_policy) => {
                                            manager.reload(dyn_policy);
                                            last_modified = Some(modified);
                                            info!("Successfully hot-reloaded policy from file");
                                        }
                                        Err(e) => {
                                            error!("Policy validation failed for reload: {}", e);
                                        }
                                    },
                                    Err(e) => {
                                        error!("Failed to load policy file: {}", e);
                                    }
                                }
                            }
                        }
                    }
                    Err(_) => {
                        // File might be temporarily deleted, warn but keep running
                        warn!("Policy file not found or inaccessible: {:?}", path_buf);
                    }
                }
            }
        })
    }

    /// Starts a background thread that listens to a control channel and reloads the
    /// policy when a new pre-validated `DynamicPolicy` is received.
    pub fn start_control_channel(
        &self,
        rx: std::sync::mpsc::Receiver<DynamicPolicy>,
    ) -> std::thread::JoinHandle<()> {
        let manager = self.clone();
        std::thread::spawn(move || {
            info!("Starting background control channel listener for policy reload");
            while let Ok(new_policy) = rx.recv() {
                manager.reload(new_policy);
            }
            info!("Control channel disconnected, shutting down control channel listener");
        })
    }
}

/// Helper function to load a policy from file, parsing as JSON if the extension is `.json`, otherwise TOML.
pub fn load_policy_from_file(path: &std::path::Path) -> Result<Policy, String> {
    let content = std::fs::read_to_string(path).map_err(|e| format!("Read error: {}", e))?;
    if path.extension().and_then(|s| s.to_str()) == Some("json") {
        Policy::from_json(&content)
    } else {
        Policy::from_toml(&content)
    }
}
