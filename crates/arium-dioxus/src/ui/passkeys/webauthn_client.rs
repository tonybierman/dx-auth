//! Browser bridge to `navigator.credentials` for the passkey ceremonies.
//!
//! WebAuthn is a browser Web API, so the real `create()` / `get()` calls only
//! exist on the wasm client. We reach them from Rust via `web-sys`; the
//! `webauthn-rs-proto` `wasm` feature supplies the `From` conversions between
//! the JSON the server speaks and the `web_sys` credential option/result types
//! (it handles the base64url ↔ `ArrayBuffer` marshalling internally, so we
//! never touch raw buffers). On the server/SSR build these are stubs that error
//! — the calls only ever fire from client-side event handlers.

/// Drive `navigator.credentials.create()` with the server's creation-options
/// JSON and return the attestation `RegisterPublicKeyCredential` as JSON.
#[cfg(all(target_arch = "wasm32", feature = "webauthn"))]
pub async fn create_credential(options_json: &str) -> Result<String, String> {
    use wasm_bindgen::JsCast;
    use wasm_bindgen_futures::JsFuture;
    use webauthn_rs_proto::{CreationChallengeResponse, RegisterPublicKeyCredential};

    let ccr: CreationChallengeResponse =
        serde_json::from_str(options_json).map_err(|e| format!("invalid creation options: {e}"))?;
    let options: web_sys::CredentialCreationOptions = ccr.into();

    let promise = credentials_container()?
        .create_with_options(&options)
        .map_err(js_error)?;
    let value = JsFuture::from(promise).await.map_err(js_error)?;
    let credential: web_sys::PublicKeyCredential = value
        .dyn_into()
        .map_err(|_| "browser did not return a PublicKeyCredential".to_string())?;

    let registration = RegisterPublicKeyCredential::from(credential);
    serde_json::to_string(&registration).map_err(|e| e.to_string())
}

/// Drive `navigator.credentials.get()` with the server's request-options JSON
/// and return the assertion `PublicKeyCredential` as JSON.
#[cfg(all(target_arch = "wasm32", feature = "webauthn"))]
pub async fn get_credential(options_json: &str) -> Result<String, String> {
    use wasm_bindgen::JsCast;
    use wasm_bindgen_futures::JsFuture;
    use webauthn_rs_proto::{PublicKeyCredential, RequestChallengeResponse};

    let rcr: RequestChallengeResponse =
        serde_json::from_str(options_json).map_err(|e| format!("invalid request options: {e}"))?;
    let options: web_sys::CredentialRequestOptions = rcr.into();

    let promise = credentials_container()?
        .get_with_options(&options)
        .map_err(js_error)?;
    let value = JsFuture::from(promise).await.map_err(js_error)?;
    let credential: web_sys::PublicKeyCredential = value
        .dyn_into()
        .map_err(|_| "browser did not return a PublicKeyCredential".to_string())?;

    let assertion = PublicKeyCredential::from(credential);
    serde_json::to_string(&assertion).map_err(|e| e.to_string())
}

#[cfg(all(target_arch = "wasm32", feature = "webauthn"))]
fn credentials_container() -> Result<web_sys::CredentialsContainer, String> {
    let window = web_sys::window().ok_or("no browser window")?;
    Ok(window.navigator().credentials())
}

/// A rejected WebAuthn promise (e.g. `NotAllowedError` when the user dismisses
/// the prompt) arrives as an opaque `JsValue`; render it readably.
#[cfg(all(target_arch = "wasm32", feature = "webauthn"))]
fn js_error(value: wasm_bindgen::JsValue) -> String {
    format!("{value:?}")
}

// ---- non-wasm stubs so the server/SSR build links ----

/// Server-build stub: the ceremony can only run in the browser.
#[cfg(all(not(target_arch = "wasm32"), feature = "webauthn"))]
pub async fn create_credential(_options_json: &str) -> Result<String, String> {
    Err("passkeys are only available in the browser".to_string())
}

/// Server-build stub: the ceremony can only run in the browser.
#[cfg(all(not(target_arch = "wasm32"), feature = "webauthn"))]
pub async fn get_credential(_options_json: &str) -> Result<String, String> {
    Err("passkeys are only available in the browser".to_string())
}
