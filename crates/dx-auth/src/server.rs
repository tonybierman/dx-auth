//! All `dx-auth` server fns and the axum-level GitHub OAuth handlers.
//!
//! Consumers do `use dx_auth::server::*;` once at the top of their app so the
//! Dioxus `#[post(...)]` / `#[get(...)]` macro registrations link, then the
//! existing client-side call sites (`login_with_password(...).await`) just
//! work.

use dioxus::prelude::*;

use crate::wire::{LoginOutcome, ProviderId, UserProfile};
#[cfg(feature = "mfa")]
use crate::wire::{MfaSetupView, MfaStatusView};

#[cfg(feature = "server")]
use crate::auth;

#[cfg(feature = "server")]
pub(crate) type DbExtension = axum::Extension<crate::pool::Pool>;

#[cfg(all(feature = "server", feature = "mail"))]
pub(crate) type MailExtension = axum::Extension<crate::mail::Mailer>;

#[cfg(feature = "server")]
pub(crate) type SessionStore = axum_session::Session<crate::pool::SessionPool>;

/// Bundle of audit-relevant request info pulled out by the extractor
/// below. Server fns consume this and pass it through to
/// [`crate::auth::audit::record`].
#[cfg(feature = "server")]
#[derive(Debug, Clone, Default)]
pub struct AuditCtx {
    pub config: crate::config::AuditConfig,
    pub ip: Option<String>,
    pub user_agent: Option<String>,
}

#[cfg(feature = "server")]
impl AuditCtx {
    pub(crate) async fn record(
        &self,
        db: &crate::pool::Pool,
        event_type: &str,
        actor_id: Option<i64>,
        target_id: Option<i64>,
        details: Option<&str>,
    ) {
        crate::auth::audit::record_or_log(
            db,
            crate::auth::audit::RecordInput {
                event_type,
                actor_id,
                target_id,
                ip: self.ip.as_deref(),
                user_agent: self.user_agent.as_deref(),
                details,
            },
        )
        .await
    }
}

#[cfg(feature = "server")]
impl<S: Send + Sync> axum::extract::FromRequestParts<S> for AuditCtx {
    type Rejection = std::convert::Infallible;

    fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _state: &S,
    ) -> impl std::future::Future<Output = Result<Self, Self::Rejection>> + Send {
        let config = parts
            .extensions
            .get::<crate::config::AuditConfig>()
            .cloned()
            .unwrap_or_default();

        let ip = if config.capture_ip {
            parts
                .extensions
                .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
                .map(|ci| ci.0.ip().to_string())
                .or_else(|| {
                    parts
                        .headers
                        .get("x-forwarded-for")
                        .and_then(|v| v.to_str().ok())
                        .and_then(|s| s.split(',').next())
                        .map(|s| s.trim().to_string())
                })
                .or_else(|| {
                    parts
                        .headers
                        .get("x-real-ip")
                        .and_then(|v| v.to_str().ok())
                        .map(|s| s.to_string())
                })
        } else {
            None
        };

        let user_agent = if config.capture_user_agent {
            parts
                .headers
                .get(axum::http::header::USER_AGENT)
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string())
        } else {
            None
        };

        std::future::ready(Ok(AuditCtx {
            config,
            ip,
            user_agent,
        }))
    }
}

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
#[post("/api/user/logout", auth: auth::Session, db: DbExtension, audit: AuditCtx)]
pub async fn logout() -> Result<()> {
    let actor = auth.current_user.as_ref().and_then(|u| {
        if u.anonymous { None } else { Some(u.id as i64) }
    });
    auth.logout_user();
    if let Some(id) = actor {
        audit
            .record(&db.0, auth::audit::USER_LOGOUT, Some(id), Some(id), None)
            .await;
    }
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
#[post("/api/user/register-password", db: DbExtension, mail: MailExtension, audit: AuditCtx)]
pub async fn register_with_password(email: String, password: String) -> Result<LoginOutcome> {
    let user_id = auth::create_password_user(&db.0, &email, &password).await?;
    audit
        .record(
            &db.0,
            auth::audit::USER_SIGNUP,
            Some(user_id),
            Some(user_id),
            Some("{\"method\":\"password\"}"),
        )
        .await;
    send_verification_email(&db.0, &mail.0, user_id, &email).await;
    Ok(LoginOutcome::EmailUnverified)
}

#[cfg(not(feature = "mail"))]
#[post("/api/user/register-password", db: DbExtension, audit: AuditCtx)]
pub async fn register_with_password(email: String, password: String) -> Result<LoginOutcome> {
    let user_id = auth::create_password_user(&db.0, &email, &password).await?;
    audit
        .record(
            &db.0,
            auth::audit::USER_SIGNUP,
            Some(user_id),
            Some(user_id),
            Some("{\"method\":\"password\",\"auto_verified\":true}"),
        )
        .await;
    // No mailer wired in → skip the verification round-trip. (Caller's choice;
    // they opted out of the `mail` feature.)
    Ok(LoginOutcome::LoggedIn)
}

/// Log in with an existing email/password account. `remember_me` upgrades the
/// session to the long-term branch via `set_longterm(true)`; the default
/// short branch expires after the configured `lifetime`.
#[post(
    "/api/user/login-password",
    auth: auth::Session,
    db: DbExtension,
    session: SessionStore,
    audit: AuditCtx,
)]
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
            audit
                .record(
                    &db.0,
                    auth::audit::USER_LOGIN_SUCCESS,
                    Some(user_id),
                    Some(user_id),
                    Some(&format!(
                        "{{\"method\":\"password\",\"remember_me\":{remember_me}}}"
                    )),
                )
                .await;
            Ok(LoginOutcome::LoggedIn)
        }
        auth::VerifyOutcome::Unverified => {
            audit
                .record(
                    &db.0,
                    auth::audit::USER_LOGIN_FAILED,
                    None,
                    None,
                    Some("{\"method\":\"password\",\"reason\":\"unverified\"}"),
                )
                .await;
            Ok(LoginOutcome::EmailUnverified)
        }
        auth::VerifyOutcome::Invalid => {
            audit
                .record(
                    &db.0,
                    auth::audit::USER_LOGIN_FAILED,
                    None,
                    None,
                    Some("{\"method\":\"password\",\"reason\":\"invalid\"}"),
                )
                .await;
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
#[post(
    "/api/user/request-password-reset",
    db: DbExtension,
    mail: MailExtension,
    audit: AuditCtx,
)]
pub async fn request_password_reset_email(email: String) -> Result<()> {
    if let Some(token) = auth::request_password_reset(&db.0, &email).await? {
        // Look up the user id so we can attribute the event without
        // re-issuing the (now-burned) reset token to the API caller.
        let user_id: Option<i64> = sqlx::query_scalar(
            "SELECT user_id FROM password_reset_tokens WHERE token = $1 LIMIT 1",
        )
        .bind(&token)
        .fetch_optional(&db.0)
        .await
        .unwrap_or(None);
        audit
            .record(
                &db.0,
                auth::audit::USER_PWD_RESET_REQUESTED,
                user_id,
                user_id,
                None,
            )
            .await;
        let link = format!("{}/auth/reset?token={token}", mail.0.base_url());
        let (subject, text, html) = crate::mail::templates::password_reset(&link);
        if let Err(err) = mail.0.send(&email, &subject, &text, html.as_deref()).await {
            eprintln!("[mail] WARN: failed to send password reset email: {err}");
        }
    }
    Ok(())
}

/// Complete the password reset using the token from the email link.
#[post("/api/user/reset-password", db: DbExtension, audit: AuditCtx)]
pub async fn reset_password(token: String, new_password: String) -> Result<()> {
    let user_id = auth::consume_password_reset(&db.0, &token, &new_password).await?;
    audit
        .record(
            &db.0,
            auth::audit::USER_PWD_RESET_CONSUMED,
            Some(user_id),
            Some(user_id),
            None,
        )
        .await;
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
#[post("/api/user/verify-email", db: DbExtension, audit: AuditCtx)]
pub async fn verify_email(token: String) -> Result<bool> {
    let user_id = auth::consume_verification_token(&db.0, &token).await?;
    if let Some(id) = user_id {
        audit
            .record(
                &db.0,
                auth::audit::USER_EMAIL_VERIFIED,
                Some(id),
                Some(id),
                None,
            )
            .await;
    }
    Ok(user_id.is_some())
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
#[post(
    "/api/user/verify-mfa",
    auth: auth::Session,
    db: DbExtension,
    session: SessionStore,
    audit: AuditCtx,
)]
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
        audit
            .record(
                &db.0,
                auth::audit::USER_LOGIN_FAILED,
                Some(user_id),
                Some(user_id),
                Some("{\"method\":\"mfa\",\"reason\":\"invalid_code\"}"),
            )
            .await;
        return Err(ServerFnError::new("Code didn't match. Try again.").into());
    }

    session.remove(MFA_PENDING_KEY);
    session.set_longterm(remember_me);
    auth.login_user(user_id);
    audit
        .record(
            &db.0,
            auth::audit::USER_LOGIN_SUCCESS,
            Some(user_id),
            Some(user_id),
            Some(&format!(
                "{{\"method\":\"password+mfa\",\"remember_me\":{remember_me}}}"
            )),
        )
        .await;
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
#[post("/api/user/mfa/confirm", auth: auth::Session, db: DbExtension, audit: AuditCtx)]
pub async fn confirm_mfa_setup(code: String) -> Result<()> {
    let user = auth
        .current_user
        .as_ref()
        .ok_or_else(|| ServerFnError::new("Not signed in."))?;
    if user.anonymous {
        return Err(ServerFnError::new("Not signed in.").into());
    }
    let user_id = user.id as i64;
    if auth::enable_mfa(&db.0, user_id, &code).await? {
        audit
            .record(
                &db.0,
                auth::audit::USER_MFA_ENABLED,
                Some(user_id),
                Some(user_id),
                None,
            )
            .await;
        Ok(())
    } else {
        Err(ServerFnError::new("That code didn't match. Try again.").into())
    }
}

/// Turn off MFA for the current user. Wipes the secret and all recovery codes.
#[cfg(feature = "mfa")]
#[post("/api/user/mfa/disable", auth: auth::Session, db: DbExtension, audit: AuditCtx)]
pub async fn disable_mfa_for_user() -> Result<()> {
    let user = auth
        .current_user
        .as_ref()
        .ok_or_else(|| ServerFnError::new("Not signed in."))?;
    if user.anonymous {
        return Err(ServerFnError::new("Not signed in.").into());
    }
    let user_id = user.id as i64;
    auth::disable_mfa(&db.0, user_id).await?;
    audit
        .record(
            &db.0,
            auth::audit::USER_MFA_DISABLED,
            Some(user_id),
            Some(user_id),
            None,
        )
        .await;
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
    audit: AuditCtx,
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
    audit
        .record(
            &clients.db,
            auth::audit::USER_LOGIN_SUCCESS,
            Some(user_id),
            Some(user_id),
            Some("{\"method\":\"oauth\",\"provider\":\"github\"}"),
        )
        .await;

    Ok(axum::response::Redirect::to("/"))
}

// ============================================================
// Admin (Phase 11b)
// ============================================================

use crate::wire::{
    AccountView, AdminRoleDetail, AdminUserDetail, AdminUserSummary, AuditEventView, AuditQuery,
};

#[cfg(feature = "server")]
async fn require_admin_perm(
    auth_session: &auth::Session,
    db: &crate::pool::Pool,
    perm: &str,
) -> Result<i64> {
    use axum_session_auth::{Auth, Rights};
    let user = auth_session
        .current_user
        .as_ref()
        .ok_or_else(|| ServerFnError::new("Not signed in."))?;
    if user.anonymous {
        return Err(ServerFnError::new("Not signed in.").into());
    }
    Auth::<auth::User, i64, crate::pool::Pool>::build([axum::http::Method::GET], false)
        .requires(Rights::permission(perm.to_string()))
        .validate(user, &axum::http::Method::GET, Some(db))
        .await
        .then(|| user.id as i64)
        .ok_or_else(|| ServerFnError::new("You don't have permission for this action.").into())
}

#[cfg(feature = "server")]
async fn summarise_admin_user(
    db: &crate::pool::Pool,
    row: auth::AdminUserRow,
) -> anyhow::Result<AdminUserSummary> {
    let role_ids = auth::get_user_role_ids(db, row.id).await?;
    Ok(AdminUserSummary {
        id: row.id,
        username: row.username,
        display_name: row.display_name,
        email: row.email,
        email_verified: row.email_verified_at.is_some(),
        mfa_enabled: row.mfa_enabled_at.is_some(),
        anonymous: row.anonymous,
        deleted: row.deleted_at.is_some(),
        role_ids,
    })
}

/// List users for the admin browser. Capped at 500 per request.
#[get("/api/admin/users", auth: auth::Session, db: DbExtension)]
pub async fn admin_list_users(
    limit: i64,
    offset: i64,
) -> Result<Vec<AdminUserSummary>> {
    require_admin_perm(&auth, &db.0, "admin:users:read").await?;
    let rows = auth::list_users_for_admin(&db.0, limit, offset).await?;
    let mut summaries = Vec::with_capacity(rows.len());
    for row in rows {
        summaries.push(summarise_admin_user(&db.0, row).await?);
    }
    Ok(summaries)
}

/// Full detail for a single user (admin view).
#[get("/api/admin/users/get", auth: auth::Session, db: DbExtension)]
pub async fn admin_get_user(user_id: i64) -> Result<Option<AdminUserDetail>> {
    require_admin_perm(&auth, &db.0, "admin:users:read").await?;
    let Some(row) = auth::get_user_for_admin(&db.0, user_id).await? else {
        return Ok(None);
    };
    let permissions = auth::list_permissions_for_user(&db.0, user_id).await?;
    let name = row.name.clone();
    let avatar_url = row.avatar_url.clone();
    let html_url = row.html_url.clone();
    let summary = summarise_admin_user(&db.0, row).await?;
    Ok(Some(AdminUserDetail {
        summary,
        name,
        avatar_url,
        html_url,
        permissions,
    }))
}

/// Replace a user's full role list (admin).
#[post("/api/admin/users/roles", auth: auth::Session, db: DbExtension, audit: AuditCtx)]
pub async fn admin_set_user_roles(
    user_id: i64,
    role_ids: Vec<i64>,
) -> Result<()> {
    let actor_id = require_admin_perm(&auth, &db.0, "admin:users:write").await?;
    let before = auth::get_user_role_ids(&db.0, user_id).await.unwrap_or_default();
    auth::set_user_roles(&db.0, user_id, &role_ids).await?;
    let details = format!(
        "{{\"before\":{before:?},\"after\":{role_ids:?}}}"
    );
    audit
        .record(
            &db.0,
            auth::audit::ADMIN_ROLES_CHANGED,
            Some(actor_id),
            Some(user_id),
            Some(&details),
        )
        .await;
    Ok(())
}

/// Soft-delete a user (admin).
#[post("/api/admin/users/delete", auth: auth::Session, db: DbExtension, audit: AuditCtx)]
pub async fn admin_soft_delete_user(user_id: i64) -> Result<()> {
    let actor_id = require_admin_perm(&auth, &db.0, "admin:users:delete").await?;
    auth::soft_delete_user(&db.0, user_id).await?;
    audit
        .record(
            &db.0,
            auth::audit::ADMIN_USER_DELETED,
            Some(actor_id),
            Some(user_id),
            None,
        )
        .await;
    Ok(())
}

/// Query the audit log (admin). Filtering happens server-side; the UI just
/// posts whatever the user has typed.
#[post("/api/admin/audit/query", auth: auth::Session, db: DbExtension)]
pub async fn admin_query_audit_events(query: AuditQuery) -> Result<Vec<AuditEventView>> {
    require_admin_perm(&auth, &db.0, "admin:audit:read").await?;
    let events = auth::audit::query(&db.0, &query).await?;
    Ok(events)
}

/// List all roles + their permission tokens.
#[get("/api/admin/roles", auth: auth::Session, db: DbExtension)]
pub async fn admin_list_roles() -> Result<Vec<AdminRoleDetail>> {
    require_admin_perm(&auth, &db.0, "admin:roles:read").await?;
    let roles = auth::list_roles(&db.0).await?;
    let mut out = Vec::with_capacity(roles.len());
    for r in roles {
        let permissions = auth::list_permissions_for_role(&db.0, r.id).await?;
        out.push(AdminRoleDetail {
            id: r.id,
            name: r.name,
            description: r.description,
            is_system: r.is_system,
            permissions,
        });
    }
    Ok(out)
}

// ============================================================
// Account self-service (Phase 11c)
// ============================================================

/// What the AccountSettings UI renders against.
#[get("/api/account", auth: auth::Session, db: DbExtension)]
pub async fn get_account_view() -> Result<AccountView> {
    let user = auth
        .current_user
        .as_ref()
        .ok_or_else(|| ServerFnError::new("Not signed in."))?;
    if user.anonymous {
        return Err(ServerFnError::new("Not signed in.").into());
    }
    let id = user.id as i64;

    // We still need a couple of bits that aren't on the cached `User`:
    // whether a password is set, whether MFA is enabled, and which OAuth
    // providers are linked.
    let has_password = auth::get_password_hash(&db.0, id).await?.is_some();
    let providers = auth::linked_oauth_providers(&db.0, id).await?;

    #[cfg(feature = "mfa")]
    let mfa_enabled = auth::user_has_mfa(&db.0, id).await?;
    #[cfg(not(feature = "mfa"))]
    let mfa_enabled = false;

    Ok(AccountView {
        username: user.username.clone(),
        display_name: None, // populated below
        email: user.email.clone(),
        email_verified: true, // user is currently signed in, so they verified at some point
        mfa_enabled,
        has_password,
        linked_oauth_providers: providers,
    })
}

/// Set the current user's self-chosen display name.
#[post("/api/account/display-name", auth: auth::Session, db: DbExtension, audit: AuditCtx)]
pub async fn update_display_name(new_name: String) -> Result<()> {
    let user = auth
        .current_user
        .as_ref()
        .ok_or_else(|| ServerFnError::new("Not signed in."))?;
    if user.anonymous {
        return Err(ServerFnError::new("Not signed in.").into());
    }
    let id = user.id as i64;
    let trimmed = new_name.trim();
    let value = if trimmed.is_empty() { None } else { Some(trimmed) };
    auth::update_display_name(&db.0, id, value).await?;
    audit
        .record(
            &db.0,
            auth::audit::ACCOUNT_DISPLAY_NAME_CHANGED,
            Some(id),
            Some(id),
            None,
        )
        .await;
    Ok(())
}

/// Change the current user's password. Requires the current password
/// (which prevents session-hijack-and-rotate).
#[post("/api/account/password", auth: auth::Session, db: DbExtension, audit: AuditCtx)]
pub async fn change_password(current: String, new_password: String) -> Result<()> {
    let user = auth
        .current_user
        .as_ref()
        .ok_or_else(|| ServerFnError::new("Not signed in."))?;
    if user.anonymous {
        return Err(ServerFnError::new("Not signed in.").into());
    }
    let id = user.id as i64;
    let Some(stored) = auth::get_password_hash(&db.0, id).await? else {
        return Err(ServerFnError::new("This account doesn't use a password.").into());
    };
    if !auth::verify_password_against_hash(&stored, &current) {
        return Err(ServerFnError::new("Current password didn't match.").into());
    }
    auth::replace_password_hash(&db.0, id, &new_password).await?;
    audit
        .record(
            &db.0,
            auth::audit::ACCOUNT_PASSWORD_CHANGED,
            Some(id),
            Some(id),
            None,
        )
        .await;
    Ok(())
}

/// Self-service soft-delete.
#[post("/api/account/delete", auth: auth::Session, db: DbExtension, audit: AuditCtx)]
pub async fn delete_my_account() -> Result<()> {
    let user = auth
        .current_user
        .as_ref()
        .ok_or_else(|| ServerFnError::new("Not signed in."))?;
    if user.anonymous {
        return Err(ServerFnError::new("Not signed in.").into());
    }
    let id = user.id as i64;
    auth::soft_delete_user(&db.0, id).await?;
    // Record BEFORE logging out so the auth-session still has the user.
    audit
        .record(
            &db.0,
            auth::audit::ACCOUNT_SELF_DELETED,
            Some(id),
            Some(id),
            None,
        )
        .await;
    auth.logout_user();
    Ok(())
}
