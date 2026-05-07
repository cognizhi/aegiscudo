use std::{
    collections::{HashMap, VecDeque},
    net::IpAddr,
    time::{Duration, Instant},
};

use tokio::sync::Mutex;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateLimitConfig {
    pub window: Duration,
    pub burst: usize,
}

impl RateLimitConfig {
    pub const fn new(window: Duration, burst: usize) -> Self {
        Self { window, burst }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProxyRateLimitConfig {
    pub tenant_api: RateLimitConfig,
    pub client_package: RateLimitConfig,
}

impl Default for ProxyRateLimitConfig {
    fn default() -> Self {
        Self {
            tenant_api: RateLimitConfig::new(Duration::from_secs(60), 240),
            client_package: RateLimitConfig::new(Duration::from_secs(60), 120),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateLimitRejection {
    pub retry_after_seconds: u64,
}

#[derive(Debug, Default)]
struct SlidingWindowBuckets {
    entries: HashMap<String, VecDeque<Instant>>,
}

#[derive(Debug)]
struct SlidingWindowRateLimiter {
    config: RateLimitConfig,
    buckets: Mutex<SlidingWindowBuckets>,
}

impl SlidingWindowRateLimiter {
    fn new(config: RateLimitConfig) -> Self {
        Self {
            config,
            buckets: Mutex::new(SlidingWindowBuckets::default()),
        }
    }

    async fn check_and_record(&self, key: String) -> Result<(), RateLimitRejection> {
        let now = Instant::now();
        let mut buckets = self.buckets.lock().await;
        let entries = buckets.entries.entry(key.clone()).or_default();
        while let Some(first_seen) = entries.front().copied() {
            if now.duration_since(first_seen) >= self.config.window {
                entries.pop_front();
            } else {
                break;
            }
        }
        if entries.len() >= self.config.burst {
            let retry_after_seconds = entries
                .front()
                .copied()
                .map(|first_seen| {
                    let remaining = self
                        .config
                        .window
                        .saturating_sub(now.duration_since(first_seen));
                    let seconds = remaining.as_secs();
                    let rounded_up = if remaining.subsec_nanos() == 0 {
                        seconds
                    } else {
                        seconds.saturating_add(1)
                    };
                    rounded_up.max(1)
                })
                .unwrap_or(1);
            return Err(RateLimitRejection {
                retry_after_seconds,
            });
        }
        entries.push_back(now);
        Ok(())
    }
}

#[derive(Debug)]
pub struct ProxyRateLimiters {
    tenant_api: SlidingWindowRateLimiter,
    client_package: SlidingWindowRateLimiter,
}

impl ProxyRateLimiters {
    pub fn new(config: ProxyRateLimitConfig) -> Self {
        Self {
            tenant_api: SlidingWindowRateLimiter::new(config.tenant_api),
            client_package: SlidingWindowRateLimiter::new(config.client_package),
        }
    }

    pub async fn check_tenant(&self, tenant_id: Uuid) -> Result<(), RateLimitRejection> {
        self.tenant_api
            .check_and_record(tenant_id.to_string())
            .await
    }

    pub async fn check_client(&self, client_ip: IpAddr) -> Result<(), RateLimitRejection> {
        self.client_package
            .check_and_record(client_ip.to_string())
            .await
    }
}
