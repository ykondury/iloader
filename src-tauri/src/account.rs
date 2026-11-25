use futures::FutureExt;
use isideload::{
    anisette::remote_v3::{ANISETTE_STATE_KEY, RemoteV3AnisetteProvider},
    auth::apple_account::{AppleAccount, TwoFactorCallbackParams, TwoFactorCallbackResponse},
    dev::{
        app_ids::{AppIdsApi, ListAppIdsResponse},
        certificates::{CertificatesApi, DevelopmentCertificate},
        developer_session::DeveloperSession,
        teams::TeamsApi,
    },
    sideload::{
        SideloaderBuilder,
        builder::{ExtensionsBehavior, ExtensionsBehaviorSelection, MaxCertsBehavior},
    },
    util::callbacks::{ExtensionsBehaviorCallbackBox, MaxCertsCallbackBox},
};
use keyring::Entry;
use rootcause::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{sync::{Arc, Mutex}, time::{Duration, SystemTime, UNIX_EPOCH}};
use tauri::{AppHandle, State, Window};
use tauri_plugin_store::StoreExt;
use tracing::{debug, warn};

use crate::{
    error::AppError,
    auth_session::{self, AccountOperation, CachedSession, TimedAnisette, VerificationAttempts},
    secure_storage::create_sideloading_storage,
    sideload::{AuthenticatedSideloader, SideloaderGuard, SideloaderMutex},
};

fn now() -> u64 { SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() }

fn session_key(email: &str) -> String { format!("developer-session:{}", email.trim().to_lowercase()) }

fn forget_session(email: &str) -> Result<(), AppError> {
    let entry = Entry::new("iloader", &session_key(email)).map_err(|e| AppError::Keyring(e.to_string()))?;
    match entry.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(AppError::Keyring(e.to_string())),
    }
}

fn cached_session(email: &str, identity: &str) -> Result<Option<CachedSession>, AppError> {
    if !crate::secure_storage::keyring_available() { return Ok(None); }
    let entry = Entry::new("iloader", &session_key(email)).map_err(|e| AppError::Keyring(e.to_string()))?;
    let value = match entry.get_password() {
        Ok(value) => value,
        Err(keyring::Error::NoEntry) => return Ok(None),
        Err(e) => return Err(AppError::Keyring(e.to_string())),
    };
    Ok(serde_json::from_str::<CachedSession>(&value).ok().filter(|cache| cache.usable(email, identity, now())))
}

fn remember_session(handle: &AppHandle, session: &CachedSession) {
    let result = (|| -> Result<(), AppError> {
        Entry::new("iloader", &session_key(&session.email))
            .map_err(|e| AppError::Keyring(e.to_string()))?
            .set_password(&serde_json::to_string(session).map_err(|e| AppError::Misc(e.to_string()))?)
            .map_err(|e| AppError::Keyring(e.to_string()))?;
        let store = handle.store("data.json").map_err(|e| AppError::Misc(e.to_string()))?;
        store.set("lastAccount", session.email.clone());
        store.save().map_err(|e| AppError::Misc(e.to_string()))?;
        Ok(())
    })();
    if result.is_err() { warn!("Could not persist the developer session in secure storage; the current login remains usable."); }
}

fn already_logged_in(state: &SideloaderMutex, email: &str) -> bool {
    state.lock().unwrap().as_ref().is_some_and(|session| {
        session.inner.get_email().eq_ignore_ascii_case(email.trim()) && session.expires_at > now().saturating_add(60)
    })
}

#[tauri::command]
pub async fn login_new(
    handle: AppHandle,
    window: Window,
    sideloader_state: State<'_, SideloaderMutex>,
    email: String,
    password: String,
    anisette_server: String,
    save_credentials: bool,
) -> Result<(), AppError> {
    let _operation = AccountOperation::acquire()?;
    let email = email.trim().to_lowercase();
    if email.is_empty() || password.is_empty() { return Err(AppError::Auth("Enter your Apple ID and password.".into())); }
    let session = if already_logged_in(&sideloader_state, &email) {
        None
    } else {
        let (account, session) = login(&handle, window, &email, Some(&password), anisette_server, false).await?
            .ok_or(AppError::NotLoggedIn)?;
        *sideloader_state.lock().unwrap() = Some(account);
        Some(session)
    };

    if save_credentials {
        let pass_entry = Entry::new("iloader", &email).map_err(|e| {
            AppError::KeyringWithMessage(
                "Failed to create entry for credentials".into(),
                e.to_string(),
            )
        })?;
        pass_entry.set_password(&password).map_err(|e| {
            AppError::KeyringWithMessage("Failed to save credentials".into(), e.to_string())
        })?;
        let store = handle
            .store("data.json")
            .map_err(|e| AppError::Misc(format!("Failed to get store: {:?}", e)))?;
        let mut existing_ids = store
            .get("ids")
            .unwrap_or_else(|| Value::Array(vec![]))
            .as_array()
            .cloned()
            .unwrap_or_else(std::vec::Vec::new);
        let value = Value::String(email.clone());
        if !existing_ids.contains(&value) {
            existing_ids.push(value);
        }
        store.set("ids", Value::Array(existing_ids));
        store.save().map_err(|e| AppError::Misc(format!("Failed to save accounts: {e}")))?;
        if let Some(session) = session { remember_session(&handle, &session); }
    }
    Ok(())
}

#[tauri::command]
pub async fn login_stored(
    handle: AppHandle,
    window: Window,
    email: String,
    anisette_server: String,
    sideloader_state: State<'_, SideloaderMutex>,
) -> Result<(), AppError> {
    let _operation = AccountOperation::acquire()?;
    if already_logged_in(&sideloader_state, &email) { return Ok(()); }
    let (account, session) = login(&handle, window, &email, None, anisette_server, false).await?
        .ok_or(AppError::NotLoggedIn)?;
    *sideloader_state.lock().unwrap() = Some(account);
    remember_session(&handle, &session);

    Ok(())
}

#[tauri::command]
pub async fn restore_session(
    handle: AppHandle, window: Window, anisette_server: String,
    sideloader_state: State<'_, SideloaderMutex>,
) -> Result<Option<String>, AppError> {
    let _operation = AccountOperation::acquire()?;
    if let Some(session) = sideloader_state.lock().unwrap().as_ref() {
        if session.expires_at > now().saturating_add(60) { return Ok(Some(session.inner.get_email().into())); }
    }
    let store = handle.store("data.json").map_err(|e| AppError::Misc(e.to_string()))?;
    let Some(email) = store.get("lastAccount").and_then(|v| v.as_str().map(str::to_owned)) else { return Ok(None); };
    let ids = store.get("ids").unwrap_or(Value::Null);
    let Some(saved_email) = ids.as_array().and_then(|ids| ids.iter().filter_map(Value::as_str).find(|id| id.eq_ignore_ascii_case(&email))) else { return Ok(None); };
    // Startup never retrieves a password or starts an interactive login.
    if let Some((account, _)) = login(&handle, window, saved_email, None, anisette_server, true).await? {
        let email = account.inner.get_email().to_string();
        *sideloader_state.lock().unwrap() = Some(account);
        return Ok(Some(email));
    }
    Ok(None)
}

#[tauri::command]
pub fn delete_account(handle: AppHandle, email: String) -> Result<(), AppError> {
    let _operation = AccountOperation::acquire()?;
    forget_session(&email)?;
    let store = handle
        .store("data.json")
        .map_err(|e| AppError::Misc(format!("Failed to get store: {:?}", e)))?;
    let mut existing_ids = store
        .get("ids")
        .unwrap_or_else(|| Value::Array(vec![]))
        .as_array()
        .cloned()
        .unwrap_or_else(std::vec::Vec::new);
    existing_ids.retain(|v| v.as_str().is_none_or(|s| s != email));
    store.set("ids", Value::Array(existing_ids));
    if store.get("lastAccount").and_then(|v| v.as_str().map(str::to_owned)).is_some_and(|id| id.eq_ignore_ascii_case(&email)) {
        store.delete("lastAccount");
    }
    store.save().map_err(|e| AppError::Misc(e.to_string()))?;
    let pass_entry = Entry::new("iloader", &email).map_err(|e| {
        AppError::KeyringWithMessage(
            "Failed to create keyring entry for credentials".into(),
            e.to_string(),
        )
    })?;
    match pass_entry.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => {},
        Err(e) => return Err(AppError::KeyringWithMessage("Failed to delete credentials".into(), e.to_string())),
    }
    Ok(())
}

#[tauri::command]
pub fn logged_in_as(sideloader_state: State<'_, SideloaderMutex>) -> Option<String> {
    let sideloader_guard = sideloader_state.lock().unwrap();
    sideloader_guard
        .as_ref()
        .filter(|account| account.expires_at > now().saturating_add(60))
        .map(|account| account.inner.get_email().to_string())
}

#[tauri::command]
pub fn invalidate_account(handle: AppHandle, sideloader_state: State<'_, SideloaderMutex>) -> Result<(), AppError> {
    let _operation = AccountOperation::acquire()?;
    let email = sideloader_state.lock().unwrap().as_ref().map(|account| account.inner.get_email().to_string());
    if let Some(email) = email { forget_session(&email)?; }
    let store = handle.store("data.json").map_err(|e| AppError::Misc(e.to_string()))?;
    store.delete("lastAccount");
    store.save().map_err(|e| AppError::Misc(e.to_string()))?;
    let mut sideloader_guard = sideloader_state.lock().unwrap();
    *sideloader_guard = None;
    Ok(())
}

#[tauri::command]
pub fn reset_anisette_state(handle: AppHandle, sideloader_state: State<'_, SideloaderMutex>) -> Result<bool, AppError> {
    let _operation = AccountOperation::acquire()?;
    let storage = create_sideloading_storage(&handle)?;
    let existed = storage.retrieve_data(ANISETTE_STATE_KEY)?.is_some_and(|data| !data.is_empty());
    storage.store_data(ANISETTE_STATE_KEY, &[])?;
    storage.delete("anisette_identity")?;
    storage.delete("anisette_generation")?;
    *sideloader_state.lock().unwrap() = None;
    Ok(existed)
}

async fn login(
    app: &AppHandle,
    window: Window,
    email: &str,
    password: Option<&str>,
    anisette_server: String,
    restore_only: bool,
) -> Result<Option<(AuthenticatedSideloader, CachedSession)>, AppError> {
    let credential_email = email;
    let email = email.trim().to_lowercase();
    let anisette_url = auth_session::normalize_server(&anisette_server)?;
    let storage = create_sideloading_storage(app)?;
    let identity = auth_session::prepare_anisette(storage.as_ref(), &anisette_url)?;
    let cache = cached_session(&email, &identity)?;
    if restore_only && cache.is_none() { return Ok(None); }
    let attempts = Arc::new(Mutex::new(VerificationAttempts::default()));
    let tfa_closure = {
        let window_clone = window.clone();
        move |params: TwoFactorCallbackParams| {
            let window_clone = window_clone.clone();
            let attempts = attempts.clone();

            async move {
                attempts.lock().unwrap_or_else(|e| e.into_inner()).next(&params)?;
                let request_id = uuid::Uuid::new_v4().to_string();
                let code: String = auth_session::request_reply(
                    &window_clone, "2fa-required", &format!("2fa-response-{request_id}"),
                    serde_json::json!({ "requestId": request_id, "params": params }), Duration::from_secs(120),
                ).await?;
                if code.len() != 6 || !code.bytes().all(|b| b.is_ascii_digit()) { bail!("Verification code must contain six digits"); }
                Ok(TwoFactorCallbackResponse::SubmitCode(code))
            }
            .boxed()
        }
    };

    let mut account = auth_session::bounded("Connecting to Apple", Duration::from_secs(45), AppleAccount::builder(&email)
        .anisette_provider(TimedAnisette(
            RemoteV3AnisetteProvider::default()?
                .set_serial_number("0".to_string())
                .set_storage(storage)
                .set_client_info_override(Some(crate::auth_session::client_info()))
                .set_url(&anisette_url),
        ))
        // isideload defaults to ten 429 retries, including authentication requests.
        .err_429_retries(None)
        .build()).await?;

    crate::apple_auth::configure_transport(&mut account)?;
    let mut restored = None;
    if let Some(cache) = cache {
        let mut candidate = DeveloperSession::new(cache.app_token(), cache.adsid.clone(), account.grandslam_client.clone(), account.anisette_generator.clone());
        match auth_session::bounded("Checking saved Apple session", Duration::from_secs(60), candidate.list_teams()).await {
            Ok(_) => { restored = Some((candidate, cache)); },
            Err(error) if session_rejected(&error) => { forget_session(&email)?; },
            // Do not convert network/Apple outages into another password or 2FA attempt.
            Err(error) => return Err(error.into()),
        }
    }
    let (dev_session, session) = if let Some(restored) = restored { restored } else {
        if restore_only { return Ok(None); }
        let stored_password;
        let password = match password {
            Some(password) => password,
            None => {
                let entry = Entry::new("iloader", credential_email).map_err(|e| AppError::Keyring(e.to_string()))?;
                stored_password = entry.get_password().map_err(|e| AppError::KeyringWithMessage("Failed to get credentials".into(), e.to_string()))?;
                &stored_password
            }
        };
        auth_session::bounded("Apple ID login", Duration::from_secs(300), account.login(password, Box::new(tfa_closure))).await?;
        debug!("Logged in");
        let token = auth_session::bounded("Creating Apple developer session", Duration::from_secs(180), account.get_app_token("xcode.auth")).await?;
        let adsid = account.spd.as_ref().and_then(|spd| spd.get("adsid")).and_then(|v| v.as_string())
            .ok_or_else(|| AppError::Auth("Apple did not return the account identifier".into()))?.to_string();
        let session = CachedSession { email: email.clone(), identity, token: token.token.clone(), adsid: adsid.clone(), expiry: token.expiry, duration: token.duration, saved_at: now() };
        (DeveloperSession::new(token, adsid, account.grandslam_client.clone(), account.anisette_generator.clone()), session)
    };

    debug!("Created developer session");

    let max_certs_callback: MaxCertsCallbackBox =
        Box::new(move |certs: Vec<DevelopmentCertificate>| {
            let window_clone = window.clone();
            Box::pin(async move {
                let cert_infos: Vec<CertificateInfo> = certs
                    .iter()
                    .map(|cert| CertificateInfo {
                        name: cert.name.clone(),
                        certificate_id: cert.certificate_id.clone(),
                        serial_number: cert.serial_number.clone(),
                        machine_name: cert.machine_name.clone(),
                        machine_id: cert.machine_id.clone(),
                    })
                    .collect();
                auth_session::request_reply::<Option<Vec<String>>>(
                    &window_clone, "max-certs-reached", "max-certs-response", cert_infos, Duration::from_secs(300),
                ).await
            })
        });

    // TODO: Team Selection

    let sideloader = SideloaderBuilder::new(dev_session, email.to_lowercase())
        .machine_name("iloader".into())
        .storage(create_sideloading_storage(app)?)
        .extensions_behavior(ExtensionsBehaviorSelection::Fixed(
            ExtensionsBehavior::ReuseMain,
        ))
        .max_certs_behavior(MaxCertsBehavior::Prompt(max_certs_callback))
        .build();

    debug!("Built sideloader");

    Ok(Some((AuthenticatedSideloader { inner: sideloader, expires_at: session.expires_at() }, session)))
}

fn session_rejected(error: &Report) -> bool {
    error.iter_reports().any(|cause| {
        if let Some(error) = cause.downcast_current_context::<reqwest::Error>() {
            return matches!(error.status().map(|s| s.as_u16()), Some(401 | 403));
        }
        matches!(cause.downcast_current_context::<isideload::SideloadError>(), Some(isideload::SideloadError::DeveloperError(1100, _)))
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CertificateInfo {
    pub name: Option<String>,
    pub certificate_id: Option<String>,
    pub serial_number: Option<String>,
    pub machine_name: Option<String>,
    pub machine_id: Option<String>,
}

#[tauri::command]
pub async fn get_certificates(
    sideloader_state: State<'_, SideloaderMutex>,
) -> Result<Vec<CertificateInfo>, AppError> {
    let mut sideloader = SideloaderGuard::take(&sideloader_state)?;

    let team = sideloader.get_mut().get_team().await?;
    let dev_session = sideloader.get_mut().get_dev_session();

    let certificates = dev_session.list_all_development_certs(&team, None).await?;

    Ok(certificates
        .into_iter()
        .map(|cert| CertificateInfo {
            name: cert.name,
            certificate_id: cert.certificate_id,
            serial_number: cert.serial_number,
            machine_name: cert.machine_name,
            machine_id: cert.machine_id,
        })
        .collect())
}

#[tauri::command]
pub async fn revoke_certificate(
    serial_number: String,
    sideloader_state: State<'_, SideloaderMutex>,
) -> Result<(), AppError> {
    let mut sideloader = SideloaderGuard::take(&sideloader_state)?;

    let team = sideloader.get_mut().get_team().await?;
    let dev_session = sideloader.get_mut().get_dev_session();

    dev_session
        .revoke_development_cert(&team, &serial_number, None)
        .await?;

    Ok(())
}

#[tauri::command]
pub async fn list_app_ids(
    sideloader_state: State<'_, SideloaderMutex>,
) -> Result<ListAppIdsResponse, AppError> {
    let mut sideloader = SideloaderGuard::take(&sideloader_state)?;

    let team = sideloader.get_mut().get_team().await?;
    let dev_session = sideloader.get_mut().get_dev_session();

    let response = dev_session.list_app_ids(&team, None).await?;

    Ok(response.clone())
}

#[tauri::command]
pub async fn delete_app_id(
    app_id_id: String,
    sideloader_state: State<'_, SideloaderMutex>,
) -> Result<(), AppError> {
    let mut sideloader = SideloaderGuard::take(&sideloader_state)?;

    let team = sideloader.get_mut().get_team().await?;
    let dev_session = sideloader.get_mut().get_dev_session();

    dev_session.delete_app_id(&team, &app_id_id, None).await?;

    Ok(())
}
