use std::sync::Arc;

use tower_governor::{governor::GovernorConfigBuilder, key_extractor::PeerIpKeyExtractor, GovernorLayer};

pub type RateLimitLayer =
    GovernorLayer<PeerIpKeyExtractor, governor::middleware::NoOpMiddleware, axum::body::Body>;

/// Builds a per-IP token-bucket rate limit: `burst` requests allowed immediately,
/// replenishing one every `period_ms` (i.e. steady-state rate = 1000/period_ms per second).
/// ponytail: keyed on peer IP, not per-token — per-token would need the bearer header parsed
/// inside the tower layer (before `TokenCtx` extraction runs), which is deeper plumbing than
/// this warrants; per-IP is the standard, simplest correct guard for this kind of abuse.
pub fn layer(period_ms: u64, burst: u32) -> RateLimitLayer {
    let config = Arc::new(
        GovernorConfigBuilder::default()
            .per_millisecond(period_ms)
            .burst_size(burst)
            .finish()
            .expect("valid governor config"),
    );
    GovernorLayer::new(config)
}

/// General safety net for every route (protects the `TokenCtx` DB lookup on each request).
/// Tunable: ~100 requests/min per IP.
pub fn general() -> RateLimitLayer {
    layer(600, 100)
}

/// Stricter quota for upload-heavy routers. Tunable: ~20 requests/min per IP.
pub fn upload() -> RateLimitLayer {
    layer(3_000, 20)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request, routing::get, Router};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use tower::ServiceExt;

    async fn ok() -> &'static str {
        "ok"
    }

    fn connect_info() -> axum::extract::ConnectInfo<SocketAddr> {
        axum::extract::ConnectInfo(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 12345))
    }

    #[tokio::test]
    async fn exceeding_quota_returns_429() {
        // burst of 2 requests per IP; PeerIpKeyExtractor reads the peer IP from axum's
        // `ConnectInfo<SocketAddr>` request extension (set for real traffic in main.rs via
        // `into_make_service_with_connect_info`; set manually here since there's no real
        // connection in a `oneshot` test).
        let app: Router<()> = Router::new().route("/x", get(ok)).layer(layer(60_000, 2));

        let mut saw_429 = false;
        for _ in 0..5 {
            let mut req = Request::builder().uri("/x").body(Body::empty()).unwrap();
            req.extensions_mut().insert(connect_info());
            let resp = app.clone().oneshot(req).await.unwrap();
            if resp.status() == axum::http::StatusCode::TOO_MANY_REQUESTS {
                saw_429 = true;
                break;
            }
        }
        assert!(saw_429, "expected a 429 after exceeding the configured burst");
    }
}
