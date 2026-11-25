use std::{future::Future, sync::{Arc, Mutex, atomic::{AtomicBool, Ordering}}, time::Duration};

use isideload::{
    anisette::{AnisetteClientInfo, AnisetteDataResponse, AnisetteProvider, remote_v3::{ANISETTE_STATE_KEY, RemoteV3AnisetteProvider}},
    auth::{apple_account::{AppToken, TwoFactorCallbackParams}, grandslam::GrandSlam},
    util::storage::SideloadingStorage,
};
use rootcause::prelude::*;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use tauri::{Emitter, Listener, Window};

use crate::error::AppError;

static ACCOUNT_BUSY: AtomicBool = AtomicBool::new(false);

// Shared by login, logout, anisette reset and operations using the signing session.
// Taking the session out of its mutex must not let a second login replace it.
pub struct AccountOperation(&'static AtomicBool);

impl AccountOperation {
    pub fn acquire() -> Result<Self, AppError> {
        Self::acquire_from(&ACCOUNT_BUSY)
    }

    fn acquire_from(busy: &'static AtomicBool) -> Result<Self, AppError> {
        busy.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| AppError::Auth("An account operation is already running. Please wait for it to finish.".into()))?;
        Ok(Self(busy))
    }
}

impl Drop for AccountOperation {
    fn drop(&mut self) { self.0.store(false, Ordering::Release); }
}

pub fn client_info() -> AnisetteClientInfo {
    AnisetteClientInfo {
        // PR #1205: keep this pair consistent. Apple's edge requires "Mac OS X".
        client_info: "<MacBookAir10,1> <Mac OS X;27.3;26C5035r> <com.apple.AuthKit/1 (com.apple.akd/1.0)>".into(),
        user_agent: "akd/1.0 CFNetwork/3896.300.31 Darwin/27.3.0".into(),
    }
}

pub fn fingerprint(server: &str) -> String {
    let info = client_info();
    format!("{}\n{}\n{}", server, info.client_info, info.user_agent)
}

pub fn normalize_server(server: &str) -> Result<String, AppError> {
    let server = server.trim().trim_end_matches('/');
    let url = if server.contains("://") { server.into() } else { format!("https://{server}") };
    let parsed = reqwest::Url::parse(&url).map_err(|_| AppError::Anisette("Invalid anisette server URL".into()))?;
    if !matches!(parsed.scheme(), "http" | "https") || parsed.host_str().is_none()
        || !parsed.username().is_empty() || parsed.password().is_some()
        || parsed.query().is_some() || parsed.fragment().is_some() {
        return Err(AppError::Anisette("Invalid anisette server URL".into()));
    }
    Ok(parsed.as_str().trim_end_matches('/').to_string())
}

pub fn prepare_anisette(storage: &dyn SideloadingStorage, server: &str) -> Result<String, Report> {
    let identity = fingerprint(server);
    let mut generation = storage.retrieve("anisette_generation")?.filter(|s| !s.is_empty());
    if storage.retrieve("anisette_identity")?.as_deref() != Some(identity.as_str()) || generation.is_none() {
        // Invalidate first, then mark the identity. A failed write cannot bless stale data.
        // Empty data is deliberately not a valid anisette plist, including on FsStorage.
        storage.store_data(ANISETTE_STATE_KEY, &[])?;
        let fresh_generation = uuid::Uuid::new_v4().to_string();
        storage.store("anisette_generation", &fresh_generation)?;
        storage.store("anisette_identity", &identity)?;
        generation = Some(fresh_generation);
    }
    Ok(format!("{}\n{}", identity, generation.unwrap_or_default()))
}

pub async fn bounded<T>(label: &str, duration: Duration, future: impl Future<Output = Result<T, Report>>) -> Result<T, Report> {
    tokio::time::timeout(duration, future).await
        .map_err(|_| report!("{} timed out. Check the connection and try again.", label))?
}

// The upstream anisette HTTP client and provisioning WebSocket have no deadlines.
// Bound these individually, including when they are used later during signing.
pub struct TimedAnisette(pub RemoteV3AnisetteProvider);

#[async_trait::async_trait]
impl AnisetteProvider for TimedAnisette {
    async fn get_anisette_data(&self) -> Result<AnisetteDataResponse, Report> {
        bounded("Fetching anisette data", Duration::from_secs(45), self.0.get_anisette_data()).await
    }
    async fn resync(&self, sim: &str) -> Result<AnisetteDataResponse, Report> {
        bounded("Anisette resync", Duration::from_secs(45), self.0.resync(sim)).await
    }
    async fn get_client_info(&self) -> Result<AnisetteClientInfo, Report> {
        bounded("Fetching anisette identity", Duration::from_secs(45), self.0.get_client_info()).await
    }
    async fn provision(&mut self, client: &Arc<GrandSlam>, reset: bool) -> Result<(), Report> {
        bounded("Anisette provisioning", Duration::from_secs(90), self.0.provision(client, reset)).await
    }
}

struct Subscription { window: Window, id: tauri::EventId }
impl Drop for Subscription {
    fn drop(&mut self) { self.window.unlisten(self.id); }
}

pub async fn request_reply<T: DeserializeOwned + Send + 'static>(
    window: &Window, request_event: &str, response_event: &str,
    payload: impl Serialize + Clone, wait: Duration,
) -> Result<T, Report> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    let tx = Mutex::new(Some(tx));
    let id = window.listen(response_event.to_string(), move |event| {
        if let Ok(response) = serde_json::from_str::<T>(event.payload()) {
            if let Some(tx) = tx.lock().unwrap_or_else(|e| e.into_inner()).take() {
                let _ = tx.send(response);
            }
        }
    });
    let _subscription = Subscription { window: window.clone(), id };
    // The receiver exists before the frontend can possibly answer.
    window.emit(request_event, payload)?;
    bounded("Waiting for your response", wait, async { Ok(rx.await?) }).await
}

#[derive(Default)]
pub struct VerificationAttempts { prompts: u8 }
impl VerificationAttempts {
    pub fn next(&mut self, params: &TwoFactorCallbackParams) -> Result<(), Report> {
        if self.prompts > 0 && params.last_error.is_none() {
            bail!("Apple requested another verification code after accepting the previous one. Login stopped to prevent a verification loop.");
        }
        if self.prompts >= 3 { bail!("Too many verification attempts. Please start a new login."); }
        if params.unknown { bail!("Apple requires a different verification method. Please check your trusted device and try again."); }
        self.prompts += 1;
        Ok(())
    }
}

// Persist only the developer token needed to resume, and only in Keychain after opt-in.
// Never store the full SPD, Apple password or signing keys in data.json.
#[derive(Serialize, Deserialize)]
pub struct CachedSession {
    pub email: String,
    pub identity: String,
    pub token: String,
    pub adsid: String,
    pub expiry: u64,
    pub duration: u64,
    pub saved_at: u64,
}

impl CachedSession {
    pub fn expires_at(&self) -> u64 {
        let expiry = if self.expiry > 1_000_000_000_000 { self.expiry / 1000 } else { self.expiry };
        expiry.min(self.saved_at.saturating_add(self.duration))
    }

    pub fn usable(&self, email: &str, identity: &str, now: u64) -> bool {
        self.email == email && self.identity == identity && !self.token.is_empty() && !self.adsid.is_empty()
            && now >= self.saved_at && self.expires_at() > now.saturating_add(60)
    }

    pub fn app_token(&self) -> AppToken {
        AppToken { token: self.token.clone(), duration: self.duration, expiry: self.expiry }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use isideload::util::storage::InMemoryStorage;

    #[test]
    fn current_identity_avoids_the_legacy_secondary_auth_loop() {
        let info = client_info();
        assert!(info.client_info.contains("<Mac OS X;27.3;26C5035r>"));
        assert!(!info.client_info.contains("<macOS;"));
        assert!(info.user_agent.contains("CFNetwork/3896.300.31 Darwin/27.3.0"));
    }

    #[test]
    fn account_gate_rejects_concurrent_work_and_releases_on_drop() {
        static BUSY: AtomicBool = AtomicBool::new(false);
        let operation = AccountOperation::acquire_from(&BUSY).unwrap();
        assert!(AccountOperation::acquire_from(&BUSY).is_err());
        drop(operation);
        assert!(AccountOperation::acquire_from(&BUSY).is_ok());
    }

    #[test]
    fn legacy_anisette_is_reset_once_and_signing_material_is_preserved() {
        let storage = InMemoryStorage::new();
        storage.store_data(ANISETTE_STATE_KEY, b"legacy-state").unwrap();
        storage.store("certificate", "keep").unwrap();
        prepare_anisette(&storage, "https://server.test").unwrap();
        assert_eq!(storage.retrieve_data(ANISETTE_STATE_KEY).unwrap(), Some(vec![]));
        storage.store_data(ANISETTE_STATE_KEY, b"new-state").unwrap();
        prepare_anisette(&storage, "https://server.test").unwrap();
        assert_eq!(storage.retrieve_data(ANISETTE_STATE_KEY).unwrap(), Some(b"new-state".to_vec()));
        assert_eq!(storage.retrieve("certificate").unwrap().as_deref(), Some("keep"));
        prepare_anisette(&storage, "https://different.test").unwrap();
        assert_eq!(storage.retrieve_data(ANISETTE_STATE_KEY).unwrap(), Some(vec![]));
    }

    fn params(error: Option<&str>) -> TwoFactorCallbackParams {
        TwoFactorCallbackParams { last_error: error.map(str::to_string), unknown: false, sms: false, numbers: vec![], selected_number_id: None }
    }

    #[test]
    fn accepted_verification_does_not_start_another_code_loop() {
        let mut attempts = VerificationAttempts::default();
        attempts.next(&params(None)).unwrap();
        assert!(attempts.next(&params(None)).is_err());
    }

    #[test]
    fn incorrect_codes_allow_bounded_manual_correction() {
        let mut attempts = VerificationAttempts::default();
        attempts.next(&params(None)).unwrap();
        attempts.next(&params(Some("incorrect code"))).unwrap();
        attempts.next(&params(Some("incorrect code"))).unwrap();
        assert!(attempts.next(&params(Some("incorrect code"))).is_err());
    }

    #[tokio::test]
    async fn a_stalled_operation_times_out_instead_of_hanging() {
        let result: Result<(), Report> = bounded("test", Duration::from_millis(5), std::future::pending()).await;
        assert!(result.unwrap_err().to_string().contains("timed out"));
    }

    #[test]
    fn cached_session_checks_account_identity_expiry_and_clock() {
        let mut cache = CachedSession { email: "user@example.test".into(), identity: "identity".into(), token: "synthetic".into(), adsid: "synthetic".into(), expiry: 2_000_000_000_000, duration: 3600, saved_at: 1_999_999_000 };
        assert!(cache.usable("user@example.test", "identity", 1_999_999_100));
        assert!(!cache.usable("other@example.test", "identity", 1_999_999_100));
        assert!(!cache.usable("user@example.test", "changed", 1_999_999_100));
        assert!(!cache.usable("user@example.test", "identity", cache.saved_at - 1));
        assert!(!cache.usable("user@example.test", "identity", 1_999_999_950));
        cache.expiry /= 1000;
        assert!(cache.usable("user@example.test", "identity", 1_999_999_100));
        cache.duration = 100;
        assert!(!cache.usable("user@example.test", "identity", 1_999_999_100));
    }

    #[test]
    fn anisette_url_normalization_preserves_custom_servers() {
        assert_eq!(normalize_server(" mac-ani.jkcoxson.com/ ").unwrap(), "https://mac-ani.jkcoxson.com");
        assert_eq!(normalize_server("http://localhost:8080/").unwrap(), "http://localhost:8080");
        assert!(normalize_server("file:///tmp/state").is_err());
        assert!(normalize_server("https://user:pass@host.test").is_err());
    }
}
