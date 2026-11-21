//! GrandSlam transport regression checkpoint: original client behavior.

use std::time::Duration;

use http::Extensions;
use isideload::{anisette::AnisetteClientInfo, sideload::cert_identity::APPLE_ROOT};
use reqwest::{Client, Request, Response, header::HeaderMap};
use reqwest_middleware::{Middleware, Next};

fn build_http_client() -> Result<Client, reqwest::Error> {
    Client::builder()
        .add_root_certificate(reqwest::Certificate::from_der(APPLE_ROOT)?)
        .http1_title_case_headers()
        .build()
}

fn normalize_client_info(_info: &mut AnisetteClientInfo) {}

fn retry_wait(_headers: &HeaderMap, retry: u32) -> Option<Duration> {
    Some(Duration::from_secs(2 << retry))
}

struct DeveloperTokenRetry;

#[async_trait::async_trait]
impl Middleware for DeveloperTokenRetry {
    async fn handle(
        &self,
        request: Request,
        extensions: &mut Extensions,
        next: Next<'_>,
    ) -> reqwest_middleware::Result<Response> {
        next.run(request, extensions).await
    }
}

#[cfg(test)]
mod tests;
