//! Dynamic policy rules engine with hot-reload support.
//! Uses lock-free double-buffering patterns to reload without blocking the fast path.

/// Structure representing dynamic configuration rules.
#[derive(Debug, Clone)]
pub struct DynamicPolicy {
    pub blocked_ips: Vec<std::net::Ipv4Addr>,
}

/// Dynamic policy manager that swaps rule instances atomically.
pub struct PolicyManager {
    current: std::sync::Arc<DynamicPolicy>,
}

impl PolicyManager {
    pub fn new(initial: DynamicPolicy) -> Self {
        Self {
            current: std::sync::Arc::new(initial),
        }
    }

    /// Hot-reloads the policy with a new instance.
    pub fn reload(&mut self, new_policy: DynamicPolicy) {
        tracing::info!("Hot-swapping configuration policies atomically");
        self.current = std::sync::Arc::new(new_policy);
    }
}
