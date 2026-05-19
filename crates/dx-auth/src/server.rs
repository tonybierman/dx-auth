//! All `dx-auth` server fns and the axum-level GitHub OAuth handlers.
//!
//! Consumers do `use dx_auth::server::*;` once at the top of their app so the
//! Dioxus `#[post(...)]` / `#[get(...)]` macro registrations link, then the
//! existing client-side call sites (`login_with_password(...).await`) just
//! work.

use dioxus::prelude::*;

use crate::wire::{LoginOutcome, MfaSetupView, MfaStatusView, ProviderId, UserProfile};

#[cfg(feature = "server")]
use crate::auth;

#[cfg(feature = "server")]
pub(crate) type DbExtension = axum::Extension<crate::pool::Pool>;

#[cfg(all(feature = "server", feature = "mail"))]
pub(crate) type MailExtension = axum::Extension<crate::mail::Mailer>;

#[cfg(feature = "server")]
pub(crate) type SessionStore = axum_session::Session<crate::pool::SessionPool>;

/// Session key under which we stash `(user_id, expires_at_unix, remember_me)`
/// between a successful password verification and the user submitting their
/// TOTP code.
#[cfg(all(feature = "server", feature = "mfa"))]
const MFA_PENDING_KEY: &str = "mfa_pending";

/// How long the pending challenge survives in the session.
#[cfg(all(feature = "server", feature = "mfa"))]
const MFA_PENDING_TTL_SECS: i64 = 5 * 60;

#[cfg(all(feature = "server", feature = "mfa"))]
fn unix_now_seconds() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

// ============================================================
// Account state / session
// ============================================================

/// Log out the current session.
#[post("/api/user/logout", auth: auth::Session)]
pub async fn logout() -> Result<()> {
    auth.logout_user();
    Ok(())
}

/// Returns the current user's public profile, including any third-party data
/// cached from an OAuth provider's user-info response. Returns an
/// authenticated=false default when the caller is anonymous.
#[get("/api/user/profile", auth: auth::Session)]
pub async fn get_current_user_profile() -> Result<UserProfile> {
    let user = auth.current_user.unwrap();
    Ok(UserProfile {
        is_authenticated: !user.anonymous,
        username: user.username,
        name: user.name,
        email: user.email,
        avatar_url: user.avatar_url,
        html_url: user.html_url,
    })
}

/// Which third-party providers the server has credentials configured for.
/// The UI uses this to decide which provider buttons to render.
#[get("/api/auth/providers")]
pub async fn available_providers() -> Result<Vec<ProviderId>> {
    let mut providers = Vec::new();
    let id_set = std::env::var("GITHUB_CLIENT_ID")
        .ok()
        .filter(|s| !s.is_empty())
        .is_some();
    let secret_set = std::env::var("GITHUB_CLIENT_SECRET")
        .ok()
        .filter(|s| !s.is_empty())
        .is_some();
    if id_set && secret_set {
        providers.push(ProviderId::Github);
    }
    Ok(providers)
}

// ============================================================
// Email / password
// ============================================================

/// Create a new email/password account. With `mail` enabled the user gets a
/// verification email and isn't logged in until they confirm; without `mail`
/// the new account is marked verified immediately (no email infrastructure
/// available) and the caller can sign in straight away.
#[cfg(feature = "mail")]
#[post("/api/user/register-password", db: DbExtension, mail: MailExtension)]
pub async fn register_with_password(email: String, password: String) -> Result<LoginOutcome> {
    let user_id = auth::create_password_user(&db.0, &email, &password).await?;
    send_verification_email(&db.0, &mail.0, user_id, &email).await;
    Ok(LoginOutcome::EmailUnverified)
}

#[cfg(not(feature = "mail"))]
#[post("/api/user/register-password", db: DbExtension)]
pub async fn register_with_password(email: String, password: String) -> Result<LoginOutcome> {
    let _user_id = auth::create_password_user(&db.0, &email, &password).await?;
    // No mailer wired in → skip the verification round-trip. (Caller's choice;
    // they opted out of the `mail` feature.)
    Ok(LoginOutcome::LoggedIn)
}

/// Log in with an existing email/password account. `remember_me` upgrades the
/// session to the long-term branch via `set_longterm(true)`; the default
/// short branch expires after the configured `lifetime`.
#[post("/api/user/login-password", auth: auth::Session, db: DbExtension, session: SessionStore)]
pub async fn login_with_password(
    email: String,
    password: String,
    remember_me: bool,
) -> Result<LoginOutcome> {
    match auth::verify_password_user(&db.0, &email, &password).await? {
        auth::VerifyOutcome::Verified(user_id) => {
            #[cfg(feature = "mfa")]
            {
                if auth::user_has_mfa(&db.0, user_id).await? {
                    let expires_at = unix_now_seconds() + MFA_PENDING_TTL_SECS;
                    session.set(MFA_PENDING_KEY, (user_id, expires_at, remember_me));
                    return Ok(LoginOutcome::MfaRequired);
                }
            }
            session.set_longterm(remember_me);
            auth.login_user(user_id);
            Ok(LoginOutcome::LoggedIn)
        }
        auth::VerifyOutcome::Unverified => Ok(LoginOutcome::EmailUnverified),
        auth::VerifyOutcome::Invalid => {
            Err(ServerFnError::new("Invalid email or password.").into())
        }
    }
}

// ============================================================
// Forgot-password reset
// ============================================================

/// Kick off the password reset flow. Always returns Ok regardless of whether
/// the email is registered, so the response can't be used to enumerate users.
#[cfg(feature = "mail")]
#[post("/api/user/request-password-reset", db: DbExtension, mail: MailExtension)]
pub async fn request_password_reset_email(email: String) -> Result<()> {
    if let Some(token) = auth::request_password_reset(&db.0, &email).await? {
        let link = format!("{}/auth/reset?token={token}", mail.0.base_url());
        let (subject, text, html) = crate::mail::templates::password_reset(&link);
        if let Err(err) = mail.0.send(&email, &subject, &text, html.as_deref()).await {
            eprintln!("[mail] WARN: failed to send password reset email: {err}");
        }
    }
    Ok(())
}

/// Complete the password reset using the token from the email link.
#[post("/api/user/reset-password", db: DbExtension)]
pub async fn reset_password(token: String, new_password: String) -> Result<()> {
    auth::consume_password_reset(&db.0, &token, &new_password).await?;
    Ok(())
}

// ============================================================
// Email verification
// ============================================================

/// Re-issue a verification email for an account that hasn't yet confirmed.
/// Always returns Ok so the response can't be used to enumerate which
/// addresses are registered and unverified.
#[cfg(feature = "mail")]
#[post("/api/user/resend-verification", db: DbExtension, mail: MailExtension)]
pub async fn resend_verification_email(email: String) -> Result<()> {
    if let Some(user_id) = auth::find_unverified_user_id(&db.0, &email).await? {
        send_verification_email(&db.0, &mail.0, user_id, &email).await;
    }
    Ok(())
}

/// Consume an email-verification token from the link in the user's inbox.
/// On success the account becomes verified and any subsequent sign-in is
/// allowed; the user still needs to enter credentials on the home page.
#[post("/api/user/verify-email", db: DbExtension)]
pub async fn verify_email(token: String) -> Result<bool> {
    Ok(auth::consume_verification_token(&db.0, &token).await?.is_some())
}

/// Internal helper: issue a token and send the verification email. Failures
/// are logged but never bubble up to the caller — we don't want a flaky SMTP
/// relay to fail the user-facing sign-up.
#[cfg(all(feature = "server", feature = "mail"))]
async fn send_verification_email(
    db: &crate::pool::Pool,
    mail: &crate::mail::Mailer,
    user_id: i64,
    to: &str,
) {
    match auth::issue_verification_token(db, user_id).await {
        Ok(token) => {
            let link = format!("{}/auth/verify?token={token}", mail.base_url());
            let (subject, text, html) = crate::mail::templates::verify_email(&link);
            if let Err(err) = mail.send(to, &subject, &text, html.as_deref()).await {
                eprintln!("[mail] WARN: failed to send verification email: {err}");
            }
        }
        Err(err) => eprintln!("[mail] WARN: failed to issue verification token: {err}"),
    }
}

// ============================================================
// MFA challenge (mid-login)
// ============================================================

/// Submit a TOTP (or recovery) code to finish the second-factor challenge
/// kicked off by a successful password login.
#[cfg(feature = "mfa")]
#[post("/api/user/verify-mfa", auth: auth::Session, db: DbExtension, session: SessionStore)]
pub async fn verify_login_mfa(code: String) -> Result<LoginOutcome> {
    let pending: Option<(i64, i64, bool)> = session.get(MFA_PENDING_KEY);
    let Some((user_id, expires_at, remember_me)) = pending else {
        return Err(ServerFnError::new(
            "Your second-factor challenge expired. Please sign in again.",
        )
        .into());
    };
    if unix_now_seconds() > expires_at {
        session.remove(MFA_PENDING_KEY);
        return Err(ServerFnError::new(
            "Your second-factor challenge expired. Please sign in again.",
        )
        .into());
    }

    if !auth::verify_mfa_challenge(&db.0, user_id, &code).await? {
        return Err(ServerFnError::new("Code didn't match. Try again.").into());
    }

    session.remove(MFA_PENDING_KEY);
    session.set_longterm(remember_me);
    auth.login_user(user_id);
    Ok(LoginOutcome::LoggedIn)
}

/// Cancel an in-flight MFA challenge so the user can restart sign-in.
#[cfg(feature = "mfa")]
#[post("/api/user/cancel-mfa", session: SessionStore)]
pub async fn cancel_mfa_challenge() -> Result<()> {
    session.remove(MFA_PENDING_KEY);
    Ok(())
}

// ============================================================
// MFA management (post-auth)
// ============================================================

/// Start MFA enrollment for the current user. Returns the secret + QR PNG +
/// the freshly-generated recovery codes (the only time the codes appear in
/// plaintext anywhere).
#[cfg(feature = "mfa")]
#[post("/api/user/mfa/setup", auth: auth::Session, db: DbExtension)]
pub async fn begin_mfa_setup() -> Result<MfaSetupView> {
    let user = auth
        .current_user
        .as_ref()
        .ok_or_else(|| ServerFnError::new("Not signed in."))?;
    if user.anonymous {
        return Err(ServerFnError::new("Not signed in.").into());
    }

    let label = user
        .email
        .clone()
        .unwrap_or_else(|| user.username.clone());

    let info = auth::setup_mfa_secret(&db.0, user.id as i64, &label).await?;
    Ok(MfaSetupView {
        secret_base32: info.secret_base32,
        qr_png_base64: info.qr_png_base64,
        recovery_codes: info.recovery_codes,
    })
}

/// Confirm enrollment by submitting a current TOTP code.
#[cfg(feature = "mfa")]
#[post("/api/user/mfa/confirm", auth: auth::Session, db: DbExtension)]
pub async fn confirm_mfa_setup(code: String) -> Result<()> {
    let user = auth
        .current_user
        .as_ref()
        .ok_or_else(|| ServerFnError::new("Not signed in."))?;
    if user.anonymous {
        return Err(ServerFnError::new("Not signed in.").into());
    }
    if auth::enable_mfa(&db.0, user.id as i64, &code).await? {
        Ok(())
    } else {
        Err(ServerFnError::new("That code didn't match. Try again.").into())
    }
}

/// Turn off MFA for the current user. Wipes the secret and all recovery codes.
#[cfg(feature = "mfa")]
#[post("/api/user/mfa/disable", auth: auth::Session, db: DbExtension)]
pub async fn disable_mfa_for_user() -> Result<()> {
    let user = auth
        .current_user
        .as_ref()
        .ok_or_else(|| ServerFnError::new("Not signed in."))?;
    if user.anonymous {
        return Err(ServerFnError::new("Not signed in.").into());
    }
    auth::disable_mfa(&db.0, user.id as i64).await?;
    Ok(())
}

/// Look up MFA enrollment state so the `/account/mfa` page can decide what
/// to render.
#[cfg(feature = "mfa")]
#[get("/api/user/mfa/status", auth: auth::Session, db: DbExtension)]
pub async fn get_mfa_status() -> Result<MfaStatusView> {
    let user = auth
        .current_user
        .as_ref()
        .ok_or_else(|| ServerFnError::new("Not signed in."))?;
    if user.anonymous {
        return Ok(MfaStatusView::Disabled);
    }
    Ok(match auth::mfa_status(&db.0, user.id as i64).await? {
        auth::MfaStatus::Disabled => MfaStatusView::Disabled,
        auth::MfaStatus::Pending => MfaStatusView::Pending,
        auth::MfaStatus::Enabled => MfaStatusView::Enabled,
    })
}

// ============================================================
// GitHub OAuth (axum handlers — not Dioxus server fns)
// ============================================================

#[cfg(all(feature = "server", feature = "oauth-github"))]
use crate::auth::OAuthClients;

#[cfg(all(feature = "server", feature = "oauth-github"))]
#[derive(serde::Deserialize)]
pub(crate) struct GithubCallbackParams {
    code: String,
    state: String,
}

#[cfg(all(feature = "server", feature = "oauth-github"))]
#[derive(serde::Deserialize)]
struct GithubUserInfo {
    id: u64,
    login: String,
    name: Option<String>,
    email: Option<String>,
    avatar_url: Option<String>,
    html_url: Option<String>,
}

#[cfg(all(feature = "server", feature = "oauth-github"))]
fn github_basic_client(
    clients: &OAuthClients,
) -> anyhow::Result<
    oauth2::basic::BasicClient<
        oauth2::EndpointSet,
        oauth2::EndpointNotSet,
        oauth2::EndpointNotSet,
        oauth2::EndpointNotSet,
        oauth2::EndpointSet,
    >,
> {
    use oauth2::basic::BasicClient;
    use oauth2::{AuthUrl, ClientId, ClientSecret, RedirectUrl, TokenUrl};

    Ok(
        BasicClient::new(ClientId::new(clients.github_client_id.clone()))
            .set_client_secret(ClientSecret::new(clients.github_client_secret.clone()))
            .set_auth_uri(AuthUrl::new(
                "https://github.com/login/oauth/authorize".to_string(),
            )?)
            .set_token_uri(TokenUrl::new(
                "https://github.com/login/oauth/access_token".to_string(),
            )?)
            .set_redirect_uri(RedirectUrl::new(clients.github_redirect_url.clone())?),
    )
}

#[cfg(all(feature = "server", feature = "oauth-github"))]
fn http_err<E: std::fmt::Display>(
    status: axum::http::StatusCode,
    e: E,
) -> (axum::http::StatusCode, String) {
    (status, e.to_string())
}

#[cfg(all(feature = "server", feature = "oauth-github"))]
pub(crate) async fn github_login(
    axum::extract::State(clients): axum::extract::State<OAuthClients>,
    session: SessionStore,
) -> Result<axum::response::Redirect, (axum::http::StatusCode, String)> {
    use oauth2::{CsrfToken, Scope};

    let client = github_basic_client(&clients)
        .map_err(|e| http_err(axum::http::StatusCode::INTERNAL_SERVER_ERROR, e))?;

    let (auth_url, csrf_state) = client
        .authorize_url(CsrfToken::new_random)
        .add_scope(Scope::new("read:user".to_string()))
        .add_scope(Scope::new("user:email".to_string()))
        .url();

    session.set("gh_oauth_state", csrf_state.secret().to_string());

    Ok(axum::response::Redirect::to(auth_url.as_ref()))
}

#[cfg(all(feature = "server", feature = "oauth-github"))]
pub(crate) async fn github_callback(
    axum::extract::State(clients): axum::extract::State<OAuthClients>,
    session: SessionStore,
    auth_session: auth::Session,
    axum::extract::Query(params): axum::extract::Query<GithubCallbackParams>,
) -> Result<axum::response::Redirect, (axum::http::StatusCode, String)> {
    use oauth2::{AuthorizationCode, TokenResponse};

    let expected_state: Option<String> = session.get("gh_oauth_state");
    session.remove("gh_oauth_state");

    let expected = expected_state.ok_or_else(|| {
        http_err(
            axum::http::StatusCode::BAD_REQUEST,
            "missing oauth state in session",
        )
    })?;

    if expected != params.state {
        return Err(http_err(
            axum::http::StatusCode::BAD_REQUEST,
            "oauth state mismatch",
        ));
    }

    let client = github_basic_client(&clients)
        .map_err(|e| http_err(axum::http::StatusCode::INTERNAL_SERVER_ERROR, e))?;

    let token = client
        .exchange_code(AuthorizationCode::new(params.code))
        .request_async(&clients.http)
        .await
        .map_err(|e| {
            http_err(
                axum::http::StatusCode::BAD_GATEWAY,
                format!("token exchange failed: {e}"),
            )
        })?;

    let info: GithubUserInfo = clients
        .http
        .get("https://api.github.com/user")
        .header("User-Agent", "dx-auth")
        .header("Accept", "application/vnd.github+json")
        .bearer_auth(token.access_token().secret())
        .send()
        .await
        .map_err(|e| {
            http_err(
                axum::http::StatusCode::BAD_GATEWAY,
                format!("github api request failed: {e}"),
            )
        })?
        .error_for_status()
        .map_err(|e| {
            http_err(
                axum::http::StatusCode::BAD_GATEWAY,
                format!("github api status: {e}"),
            )
        })?
        .json()
        .await
        .map_err(|e| {
            http_err(
                axum::http::StatusCode::BAD_GATEWAY,
                format!("github api parse: {e}"),
            )
        })?;

    let profile = auth::GithubProfile {
        id: info.id,
        login: &info.login,
        name: info.name.as_deref(),
        email: info.email.as_deref(),
        avatar_url: info.avatar_url.as_deref(),
        html_url: info.html_url.as_deref(),
    };

    let user_id = auth::upsert_github_user(&clients.db, profile)
        .await
        .map_err(|e| http_err(axum::http::StatusCode::INTERNAL_SERVER_ERROR, e))?;

    auth_session.login_user(user_id);

    Ok(axum::response::Redirect::to("/"))
}
