//! Port of https://github.com/nab138/iloader/issues/971, scoped to app-token retries.

use std::{sync::Arc, time::Duration};

use http::Extensions;
use isideload::{
    anisette::AnisetteClientInfo, auth::apple_account::AppleAccount,
    sideload::cert_identity::APPLE_ROOT,
};
use reqwest::{
    Client, Request, Response, StatusCode, Version,
    header::{CONNECTION, HeaderMap, HeaderValue, RETRY_AFTER},
};
use reqwest_middleware::{ClientBuilder, Middleware, Next};
use rootcause::{option_ext::OptionExt, prelude::*};

const MAX_TOKEN_RETRIES: u32 = 2;
const MAX_RETRY_WAIT: Duration = Duration::from_secs(15);

/// Replace the initial lookup client before login creates shared GrandSlam references.
pub fn configure_transport(account: &mut AppleAccount) -> Result<(), Report> {
    let grandslam = Arc::get_mut(&mut account.grandslam_client)
        .context("Apple authentication transport is already in use")?;
    normalize_client_info(&mut grandslam.client_info);
    grandslam.client = ClientBuilder::new(build_http_client()?)
        .with(DeveloperTokenRetry)
        .build();
    Ok(())
}

fn build_http_client() -> Result<Client, reqwest::Error> {
    let mut headers = HeaderMap::new();
    headers.insert(CONNECTION, HeaderValue::from_static("close"));
    Client::builder()
        .add_root_certificate(reqwest::Certificate::from_der(APPLE_ROOT)?)
        // HTTP/2 ignores Connection: close. Do not reuse an old GrandSlam stream.
        .http1_only()
        .http1_title_case_headers()
        .pool_max_idle_per_host(0)
        .default_headers(headers)
        .connect_timeout(Duration::from_secs(15))
        .timeout(Duration::from_secs(45))
        // All replay decisions belong to the apptokens middleware below.
        .retry(reqwest::retry::never())
        .redirect(reqwest::redirect::Policy::none())
        .build()
}

fn normalize_client_info(info: &mut AnisetteClientInfo) {
    info.client_info = info.client_info.replace("<macOS;", "<Mac OS X;");
    const LEGACY_XCODE: &str = "com.apple.dt.Xcode/";
    if let Some(start) = info.client_info.find(LEGACY_XCODE) {
        let end = info.client_info[start..]
            .find([')', '>', ' ', '<'])
            .map_or(info.client_info.len(), |offset| start + offset);
        info.client_info
            .replace_range(start..end, "com.apple.akd/1.0");
        info.user_agent = "akd/1.0 CFNetwork/808.1.4".to_string();
    }
}

fn is_token_request(request: &Request) -> bool {
    if request.method() != reqwest::Method::POST || request.url().path() != "/grandslam/GsService2"
    {
        return false;
    }
    let Some(body) = request.body().and_then(|body| body.as_bytes()) else {
        return false;
    };
    if body.len() > 128 * 1024 {
        return false;
    }
    // Inspect only the operation; never log authentication headers or signed payloads.
    plist::Value::from_reader(std::io::Cursor::new(body))
        .ok()
        .and_then(|value| {
            value
                .as_dictionary()?
                .get("Request")?
                .as_dictionary()?
                .get("o")?
                .as_string()
                .map(|operation| operation == "apptokens")
        })
        .unwrap_or(false)
}

fn is_temporary_status(status: StatusCode) -> bool {
    matches!(
        status,
        StatusCode::BAD_GATEWAY | StatusCode::SERVICE_UNAVAILABLE | StatusCode::GATEWAY_TIMEOUT
    )
}

fn retry_wait(headers: &HeaderMap, retry: u32) -> Option<Duration> {
    let backoff = Duration::from_secs(2 << retry);
    let requested = headers
        .get(RETRY_AFTER)
        .and_then(|header| header.to_str().ok())
        .and_then(|value| {
            value
                .parse::<u64>()
                .ok()
                .map(Duration::from_secs)
                .or_else(|| {
                    chrono::DateTime::parse_from_rfc2822(value)
                        .ok()
                        .map(|date| {
                            Duration::from_secs(
                                (date.timestamp() - chrono::Utc::now().timestamp()).max(0) as u64,
                            )
                        })
                })
        });
    let delay = requested.map_or(backoff, |requested| requested.max(backoff));
    // Surface long server waits to the caller instead of retrying earlier than requested.
    (delay <= MAX_RETRY_WAIT).then_some(delay)
}

struct DeveloperTokenRetry;

#[async_trait::async_trait]
impl Middleware for DeveloperTokenRetry {
    async fn handle(
        &self,
        mut request: Request,
        extensions: &mut Extensions,
        next: Next<'_>,
    ) -> reqwest_middleware::Result<Response> {
        *request.version_mut() = Version::HTTP_11;
        request
            .headers_mut()
            .insert(CONNECTION, HeaderValue::from_static("close"));
        if !is_token_request(&request) {
            return next.run(request, extensions).await;
        }
        let mut retry = 0;
        loop {
            let Some(attempt) = request.try_clone() else {
                return next.run(request, extensions).await;
            };
            // A transport error is returned immediately, never automatically repeated.
            let response = next.clone().run(attempt, extensions).await?;
            if !is_temporary_status(response.status()) || retry >= MAX_TOKEN_RETRIES {
                return Ok(response);
            }
            let Some(delay) = retry_wait(response.headers(), retry) else {
                return Ok(response);
            };
            tracing::warn!(target: "apple_auth", status = response.status().as_u16(),
                retry = retry + 1, wait_seconds = delay.as_secs(),
                "Retrying Apple developer-token request");
            drop(response);
            tokio::time::sleep(delay).await;
            retry += 1;
        }
    }
}

#[cfg(test)]
mod tests;
