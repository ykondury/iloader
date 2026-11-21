use super::*;
use reqwest::{
    Method, StatusCode,
    header::{CONNECTION, HeaderValue, RETRY_AFTER},
};
use reqwest_middleware::ClientBuilder;
use std::{
    io::{Read, Write},
    net::TcpListener,
    thread,
    time::Instant,
};

struct ObservedRequest {
    headers: String,
    body: Vec<u8>,
}

// Keep each stream open, so accidentally reusing one cannot satisfy the next accept.
fn server(
    responses: Vec<(u16, Option<&'static str>)>,
) -> (String, thread::JoinHandle<Vec<ObservedRequest>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!(
        "http://{}/grandslam/GsService2",
        listener.local_addr().unwrap()
    );
    listener.set_nonblocking(true).unwrap();
    let worker = thread::spawn(move || {
        let mut connections = Vec::new();
        let mut observed = Vec::new();
        for (status, retry_after) in responses {
            let deadline = Instant::now() + Duration::from_secs(12);
            let mut stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(Instant::now() < deadline, "Expected a fresh connection");
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => panic!("Synthetic server failed: {error}"),
                }
            };
            stream.set_nonblocking(false).unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            let mut headers = Vec::new();
            let mut byte = [0];
            while !headers.ends_with(b"\r\n\r\n") {
                stream.read_exact(&mut byte).unwrap();
                headers.push(byte[0]);
                assert!(headers.len() < 8192);
            }
            let headers = String::from_utf8(headers).unwrap();
            let length = headers
                .lines()
                .find_map(|line| {
                    let (key, value) = line.split_once(':')?;
                    key.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().unwrap())
                })
                .unwrap_or(0);
            let mut body = vec![0; length];
            stream.read_exact(&mut body).unwrap();
            observed.push(ObservedRequest { headers, body });
            if status != 0 {
                let extra =
                    retry_after.map_or(String::new(), |value| format!("Retry-After: {value}\r\n"));
                write!(stream, "HTTP/1.1 {status} Synthetic\r\nContent-Length: 2\r\nConnection: keep-alive\r\n{extra}\r\nok").unwrap();
                stream.flush().unwrap();
                connections.push(stream);
            }
        }
        observed
    });
    (url, worker)
}

fn body(operation: &str) -> Vec<u8> {
    let request = plist_macro::plist!(dict {
        "Header": { "Version": "1.0.1" },
        "Request": {
            "o": operation,
            "app": ["com.apple.gs.xcode.auth"],
            "u": "synthetic-dsid",
            "t": "synthetic-session-token",
            "checksum": "synthetic-checksum"
        }
    });
    let mut xml = Vec::new();
    plist::to_writer_xml(&mut xml, &request).unwrap();
    xml
}

fn client() -> reqwest_middleware::ClientWithMiddleware {
    ClientBuilder::new(build_http_client().unwrap())
        .with(DeveloperTokenRetry)
        .build()
}

#[tokio::test]
async fn token_request_recovers_from_503_without_changing_payload_or_headers() {
    let (url, worker) = server(vec![(503, None), (200, None)]);
    let payload = body("apptokens");
    let response = client()
        .post(url)
        .header(
            "X-Mme-Client-Info",
            "<Synthetic> <Mac OS X;27.0> <com.apple.akd/1.0>",
        )
        .body(payload.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let observed = worker.join().unwrap();
    assert_eq!(observed.len(), 2);
    assert!(observed.iter().all(|request| request.body == payload));
    assert_eq!(observed[0].headers, observed[1].headers);
    assert!(
        observed[0]
            .headers
            .to_ascii_lowercase()
            .contains("\r\nconnection: close\r\n")
    );
}

#[tokio::test]
async fn auth_requests_use_separate_http1_connections() {
    let (url, worker) = server(vec![(200, None); 3]);
    let client = client();
    for operation in ["init", "complete", "apptokens"] {
        let response = client
            .post(&url)
            .body(body(operation))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        response.bytes().await.unwrap();
    }
    let observed = worker.join().unwrap();
    assert_eq!(observed.len(), 3);
    assert!(observed.iter().all(|request| {
        request
            .headers
            .lines()
            .next()
            .unwrap()
            .ends_with("HTTP/1.1")
    }));
    assert!(observed.iter().all(|request| {
        request
            .headers
            .to_ascii_lowercase()
            .contains("\r\nconnection: close\r\n")
    }));
}

#[tokio::test]
async fn persistent_502_503_504_stop_after_three_attempts() {
    for status in [502, 503, 504] {
        let (url, worker) = server(vec![(status, None); 3]);
        let response = client()
            .post(url)
            .body(body("apptokens"))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status().as_u16(), status);
        assert_eq!(worker.join().unwrap().len(), 3);
    }
}

#[tokio::test]
async fn authentication_password_and_2fa_operations_are_never_retried() {
    for operation in [
        "init",
        "complete",
        "verifyCode",
        "trustedDeviceSecondaryAuth",
        "secondaryAuth",
        "validateCode",
        "password",
    ] {
        let (url, worker) = server(vec![(503, None)]);
        let response = client()
            .post(url)
            .body(body(operation))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(worker.join().unwrap().len(), 1);
    }
}

#[tokio::test]
async fn statuses_outside_the_gateway_allowlist_are_never_retried() {
    for status in [200, 400, 401, 403, 404, 408, 429, 500, 501, 505] {
        let (url, worker) = server(vec![(status, None)]);
        let response = client()
            .post(url)
            .body(body("apptokens"))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status().as_u16(), status);
        assert_eq!(worker.join().unwrap().len(), 1);
    }
}

#[tokio::test]
async fn wrong_method_path_and_malformed_bodies_are_never_retried() {
    let cases = [
        (Method::GET, "/grandslam/GsService2", body("apptokens")),
        (Method::POST, "/other", body("apptokens")),
        (
            Method::POST,
            "/grandslam/GsService2/lookup",
            body("apptokens"),
        ),
        (Method::POST, "/grandslam/GsService2", b"apptokens".to_vec()),
        (
            Method::POST,
            "/grandslam/GsService2",
            vec![b'x'; 128 * 1024 + 1],
        ),
        (
            Method::POST,
            "/grandslam/GsService2",
            b"<plist><dict/></plist>".to_vec(),
        ),
    ];
    for (method, path, payload) in cases {
        let (url, worker) = server(vec![(503, None)]);
        let mut url = reqwest::Url::parse(&url).unwrap();
        url.set_path(path);
        let response = client()
            .request(method, url)
            .body(payload)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(worker.join().unwrap().len(), 1);
    }
}

#[tokio::test]
async fn network_errors_are_never_retried() {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    struct CountAttempts(Arc<AtomicUsize>);
    #[async_trait::async_trait]
    impl Middleware for CountAttempts {
        async fn handle(
            &self,
            request: Request,
            extensions: &mut Extensions,
            next: Next<'_>,
        ) -> reqwest_middleware::Result<Response> {
            self.0.fetch_add(1, Ordering::SeqCst);
            next.run(request, extensions).await
        }
    }
    let (url, worker) = server(vec![(0, None)]);
    let attempts = Arc::new(AtomicUsize::new(0));
    let client = ClientBuilder::new(build_http_client().unwrap())
        .with(DeveloperTokenRetry)
        .with(CountAttempts(attempts.clone()))
        .build();
    assert!(
        client
            .post(url)
            .body(body("apptokens"))
            .send()
            .await
            .is_err()
    );
    assert_eq!(attempts.load(Ordering::SeqCst), 1);
    assert_eq!(worker.join().unwrap().len(), 1);
}

#[tokio::test]
async fn retry_after_above_fifteen_seconds_stops_retrying() {
    let (url, worker) = server(vec![(503, Some("120"))]);
    let started = Instant::now();
    let response = client()
        .post(url)
        .body(body("apptokens"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(started.elapsed() < Duration::from_secs(2));
    assert_eq!(worker.join().unwrap().len(), 1);
}

#[tokio::test]
async fn retry_after_is_not_shortened() {
    let (url, worker) = server(vec![(503, Some("3")), (200, None)]);
    let started = Instant::now();
    let response = client()
        .post(url)
        .body(body("apptokens"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(started.elapsed() >= Duration::from_secs(3));
    assert_eq!(worker.join().unwrap().len(), 2);
}

#[tokio::test]
async fn explicit_keep_alive_cannot_reenable_pooling() {
    let (url, worker) = server(vec![(200, None)]);
    let response = client()
        .post(url)
        .header(CONNECTION, "keep-alive")
        .body(body("apptokens"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        worker.join().unwrap()[0]
            .headers
            .to_ascii_lowercase()
            .contains("\r\nconnection: close\r\n")
    );
}

#[test]
fn retry_after_and_backoff_have_bounded_waits() {
    let mut headers = HeaderMap::new();
    assert_eq!(retry_wait(&headers, 0), Some(Duration::from_secs(2)));
    assert_eq!(retry_wait(&headers, 1), Some(Duration::from_secs(4)));
    for (value, expected) in [
        ("0", Some(2)),
        ("3", Some(3)),
        ("15", Some(15)),
        ("16", None),
        ("120", None),
        ("invalid", Some(2)),
    ] {
        headers.insert(RETRY_AFTER, HeaderValue::from_str(value).unwrap());
        assert_eq!(retry_wait(&headers, 0), expected.map(Duration::from_secs));
    }
    headers.insert(
        RETRY_AFTER,
        HeaderValue::from_static("Fri, 01 Jan 2100 00:00:00 GMT"),
    );
    assert_eq!(retry_wait(&headers, 0), None);
    headers.insert(
        RETRY_AFTER,
        HeaderValue::from_static("Sat, 01 Jan 2000 00:00:00 GMT"),
    );
    assert_eq!(retry_wait(&headers, 1), Some(Duration::from_secs(4)));
}

#[test]
fn client_info_normalizes_only_the_os_component_and_legacy_xcode_identity() {
    let mut info = AnisetteClientInfo {
        client_info:
            "<Mac15,7> <macOS;27.0;26A5378j> <com.apple.AuthKit/1 (com.apple.dt.Xcode/1.0)>".into(),
        user_agent: "legacy-agent".into(),
    };
    normalize_client_info(&mut info);
    assert_eq!(
        info.client_info,
        "<Mac15,7> <Mac OS X;27.0;26A5378j> <com.apple.AuthKit/1 (com.apple.akd/1.0)>"
    );
    assert!(info.user_agent.starts_with("akd/1.0 "));
    let normalized = info.clone();
    normalize_client_info(&mut info);
    assert_eq!(info.client_info, normalized.client_info);
    assert_eq!(info.user_agent, normalized.user_agent);
    for value in [
        "<WindowsClient>",
        "<Mac> <Mac OS X;10.12.6;16G29> <com.apple.akd/1.0>",
        "<AppNameContainsmacOS;>",
    ] {
        let mut info = AnisetteClientInfo {
            client_info: value.into(),
            user_agent: "preserved-agent".into(),
        };
        normalize_client_info(&mut info);
        assert_eq!(info.client_info, value);
        assert_eq!(info.user_agent, "preserved-agent");
    }
}
