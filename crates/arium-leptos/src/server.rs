//! All `arium-leptos` server fns.
//!
//! Consumers `use arium_leptos::server::*;` so the Leptos `#[server]`
//! registrations link, then call them like any async fn
//! (`login_with_password(...).await`) from client code.
//!
//! Unlike the Dioxus adapter (which names axum extractors in the `#[post]`
//! attribute), Leptos `#[server]` fns pull request context inside the body via
//! [`leptos_axum::extract`]. Everything the engine needs is already a request
//! extension after `arium::install` layers the router (`Pool`, `Mailer`, the
//! provider list as `axum::Extension`s; `auth::Session` / `SessionStore` /
//! `AuditCtx` as `FromRequestParts` extractors), so the bodies read almost
//! exactly like the Dioxus ones (`&db.0`, `&mail.0`, …).
//!
//! The axum-level OAuth handlers (not Leptos server fns) live in the engine's
//! `arium::oauth` module and are mounted by `arium::install`.

use leptos::prelude::*;

use arium_wire::{
    AccountView, AdminRoleDetail, AdminUserDetail, AdminUserSummary, AuditEventView, AuditQuery,
    LoginOutcome, ProviderInfo, ResourceRole, UserProfile,
};
#[cfg(feature = "tokens")]
use arium_wire::{ApiTokenView, CreateApiTokenResponse};
#[cfg(feature = "mfa")]
use arium_wire::{MfaSetupView, MfaStatusView};

#[cfg(feature = "ssr")]
use arium::auth;
#[cfg(feature = "ssr")]
use arium::extract::{AuditCtx, ResourceAuthorityExt, SessionStore};

// The axum extensions `arium::install` layers onto the router — extracted in
// each server-fn body so the body code (`&db.0`, `&mail.0`) mirrors the Dioxus
// adapter. Gated to `ssr` (the engine isn't present on the hydrate build, and
// these are only referenced from server-fn bodies, which are `ssr`-only).
#[cfg(feature = "ssr")]
type DbExtension = axum::Extension<arium::pool::Pool>;
#[cfg(all(feature = "ssr", feature = "mail"))]
type MailExtension = axum::Extension<arium::mail::Mailer>;
#[cfg(feature = "ssr")]
type ProvidersExtension = axum::Extension<std::sync::Arc<Vec<ProviderInfo>>>;

/// Map any server-side error into a `ServerFnError` with its message preserved.
/// Keeps `?` ergonomic across the engine's `anyhow` / `sqlx` error types, which
/// don't convert into `ServerFnError` on their own.
#[cfg(feature = "ssr")]
fn sfn<E: std::fmt::Display>(e: E) -> ServerFnError {
    ServerFnError::new(e.to_string())
}

/// Session key under which we stash `(user_id, expires_at_unix, remember_me)`
/// between a successful password verification and the user submitting their
/// TOTP code.
#[cfg(all(feature = "ssr", feature = "mfa"))]
const MFA_PENDING_KEY: &str = "mfa_pending";

/// How long the pending challenge survives in the session.
#[cfg(all(feature = "ssr", feature = "mfa"))]
const MFA_PENDING_TTL_SECS: i64 = 5 * 60;

#[cfg(all(feature = "ssr", feature = "mfa"))]
fn unix_now_seconds() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

// Single landing place for the post-credential session-setup contract:
// flip the session to long-term, then log the user in on the auth layer.
// Every login path (password signup, password login, MFA verify) goes through
// here so a future addition lands in one file instead of drifting across three.
#[cfg(feature = "ssr")]
fn complete_login(auth: &auth::Session, session: &SessionStore, user_id: i64, remember_me: bool) {
    session.set_longterm(remember_me);
    auth.login_user(user_id);
}

// ============================================================
// Account state / session
// ============================================================

/// Log out the current session.
#[server(endpoint = "user/logout")]
pub async fn logout() -> Result<(), ServerFnError> {
    let auth: auth::Session = leptos_axum::extract().await?;
    let db: DbExtension = leptos_axum::extract().await?;
    let audit: AuditCtx = leptos_axum::extract().await?;

    let actor = auth
        .current_user
        .as_ref()
        .and_then(|u| if u.anonymous { None } else { Some(u.id) });
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
#[server(endpoint = "user/profile")]
pub async fn get_current_user_profile() -> Result<UserProfile, ServerFnError> {
    let auth: auth::Session = leptos_axum::extract().await?;
    let db: DbExtension = leptos_axum::extract().await?;

    // `axum_session_auth` always populates `current_user` (anonymous users get
    // the guest row, not None) — but treat a missing value as an
    // unauthenticated request rather than panicking.
    let user = auth
        .current_user
        .ok_or_else(|| ServerFnError::new("Not signed in."))?;
    let permissions = if user.anonymous {
        Vec::new()
    } else {
        auth::list_permissions_for_user(&db.0, user.id)
            .await
            .map_err(sfn)?
    };
    Ok(UserProfile {
        is_authenticated: !user.anonymous,
        username: user.username,
        display_name: user.display_name,
        email: user.email,
        avatar_url: user.avatar_url,
        html_url: user.html_url,
        permissions,
    })
}

/// The caller's [`ResourceRole`](crate::ResourceRole) on `(kind, id)`, or `None` when they hold no
/// relationship to it (or aren't signed in). Drives the
/// [`ResourceGate`](crate::ui::resource_gate::ResourceGate) UI — a read for
/// rendering decisions, **not** the enforcement boundary. Resource-scoped
/// mutations must call [`require_resource_leptos`].
///
/// Requires the app to have registered a `ResourceAuthority` (via
/// `AuthConfigBuilder::resource_authority` or its own `Router::layer`).
#[server(endpoint = "resource/role")]
pub async fn get_resource_role(
    kind: String,
    id: i64,
) -> Result<Option<ResourceRole>, ServerFnError> {
    let auth: auth::Session = leptos_axum::extract().await?;
    let db: DbExtension = leptos_axum::extract().await?;
    let authority: ResourceAuthorityExt = leptos_axum::extract().await?;

    let Some(user) = auth.current_user else {
        return Ok(None);
    };
    if user.anonymous {
        return Ok(None);
    }
    authority
        .0
        .role_on(&db.0, user.id, arium::authz::ResourceRef::new(&kind, id))
        .await
        .map_err(sfn)
}

/// Which third-party providers the server has credentials configured for.
/// The UI uses this to decide which provider buttons to render. Order is
/// preserved from registration order on the `OAuthRegistry`.
#[server(endpoint = "auth/providers")]
pub async fn available_providers() -> Result<Vec<ProviderInfo>, ServerFnError> {
    let providers: ProvidersExtension = leptos_axum::extract().await?;
    Ok((*providers.0).clone())
}

// ============================================================
// Email / password
// ============================================================

/// Create a new email/password account. With `mail` enabled the user gets a
/// verification email and isn't logged in until they confirm; without `mail`
/// the new account is marked verified immediately and the caller can sign in.
///
/// Setting `DX_AUTH_SKIP_EMAIL_VERIFICATION=1` (also accepts `true`/`yes`/`on`)
/// short-circuits the round-trip even when `mail` is compiled in.
#[cfg(feature = "mail")]
#[server(endpoint = "user/register-password")]
pub async fn register_with_password(
    email: String,
    password: String,
) -> Result<LoginOutcome, ServerFnError> {
    let auth: auth::Session = leptos_axum::extract().await?;
    let db: DbExtension = leptos_axum::extract().await?;
    let mail: MailExtension = leptos_axum::extract().await?;
    let session: SessionStore = leptos_axum::extract().await?;
    let audit: AuditCtx = leptos_axum::extract().await?;

    let user_id = auth::create_password_user(&db.0, &email, &password)
        .await
        .map_err(sfn)?;

    if skip_email_verification() {
        auth::mark_email_verified(&db.0, user_id)
            .await
            .map_err(sfn)?;
        audit
            .record(
                &db.0,
                auth::audit::USER_SIGNUP,
                Some(user_id),
                Some(user_id),
                Some("{\"method\":\"password\",\"auto_verified\":true}"),
            )
            .await;
        complete_login(&auth, &session, user_id, false);
        return Ok(LoginOutcome::LoggedIn);
    }

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

/// Truthy-parse `DX_AUTH_SKIP_EMAIL_VERIFICATION`. Accepts `1`, `true`,
/// `yes`, `on` (case-insensitive); anything else (including unset) is false.
///
/// Its sole caller is the `mail`-gated `register_with_password`, so it carries
/// the same `ssr + mail` gate — otherwise an `ssr`-without-`mail` build (e.g.
/// examples/leptos-authz-example) flags it as dead code.
#[cfg(all(feature = "ssr", feature = "mail"))]
fn skip_email_verification() -> bool {
    match std::env::var("DX_AUTH_SKIP_EMAIL_VERIFICATION") {
        Ok(v) => matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        ),
        Err(_) => false,
    }
}

#[cfg(not(feature = "mail"))]
#[server(endpoint = "user/register-password")]
pub async fn register_with_password(
    email: String,
    password: String,
) -> Result<LoginOutcome, ServerFnError> {
    let auth: auth::Session = leptos_axum::extract().await?;
    let db: DbExtension = leptos_axum::extract().await?;
    let session: SessionStore = leptos_axum::extract().await?;
    let audit: AuditCtx = leptos_axum::extract().await?;

    let user_id = auth::create_password_user(&db.0, &email, &password)
        .await
        .map_err(sfn)?;
    // No mailer is wired in, so there is no verification round-trip to run:
    // mark the account verified at creation and log the user straight in — the
    // same end state the `mail` path reaches under DX_AUTH_SKIP_EMAIL_VERIFICATION.
    // Without this, the `LoggedIn` we return below would be a lie: the session
    // would stay anonymous (signup appears to do nothing) and a later sign-in
    // would fail as `Unverified`. The audit entry already claims `auto_verified`,
    // so this also makes the log truthful.
    auth::mark_email_verified(&db.0, user_id)
        .await
        .map_err(sfn)?;
    audit
        .record(
            &db.0,
            auth::audit::USER_SIGNUP,
            Some(user_id),
            Some(user_id),
            Some("{\"method\":\"password\",\"auto_verified\":true}"),
        )
        .await;
    complete_login(&auth, &session, user_id, false);
    Ok(LoginOutcome::LoggedIn)
}

/// Log in with an existing email/password account. `remember_me` upgrades the
/// session to the long-term branch via `set_longterm(true)`.
#[server(endpoint = "user/login-password")]
pub async fn login_with_password(
    email: String,
    password: String,
    remember_me: bool,
) -> Result<LoginOutcome, ServerFnError> {
    let auth: auth::Session = leptos_axum::extract().await?;
    let db: DbExtension = leptos_axum::extract().await?;
    let session: SessionStore = leptos_axum::extract().await?;
    let audit: AuditCtx = leptos_axum::extract().await?;

    match auth::verify_password_user(&db.0, &email, &password)
        .await
        .map_err(sfn)?
    {
        auth::VerifyOutcome::Verified(user_id) => {
            #[cfg(feature = "mfa")]
            {
                if auth::user_has_mfa(&db.0, user_id).await.map_err(sfn)? {
                    let expires_at = unix_now_seconds().saturating_add(MFA_PENDING_TTL_SECS);
                    session.set(MFA_PENDING_KEY, (user_id, expires_at, remember_me));
                    return Ok(LoginOutcome::MfaRequired);
                }
            }
            complete_login(&auth, &session, user_id, remember_me);
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
            Err(ServerFnError::new("Invalid email or password."))
        }
    }
}

// ============================================================
// Forgot-password reset
// ============================================================

/// Kick off the password reset flow. Always returns Ok regardless of whether
/// the email is registered, so the response can't be used to enumerate users.
#[cfg(feature = "mail")]
#[server(endpoint = "user/request-password-reset")]
pub async fn request_password_reset_email(email: String) -> Result<(), ServerFnError> {
    let db: DbExtension = leptos_axum::extract().await?;
    let mail: MailExtension = leptos_axum::extract().await?;
    let audit: AuditCtx = leptos_axum::extract().await?;

    if let Some(token) = auth::request_password_reset(&db.0, &email)
        .await
        .map_err(sfn)?
    {
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
        let (subject, text, html) = arium::mail::templates::password_reset(&link);
        if let Err(err) = mail.0.send(&email, &subject, &text, html.as_deref()).await {
            eprintln!("[mail] WARN: failed to send password reset email: {err}");
        }
    }
    Ok(())
}

/// Complete the password reset using the token from the email link.
#[server(endpoint = "user/reset-password")]
pub async fn reset_password(token: String, new_password: String) -> Result<(), ServerFnError> {
    let db: DbExtension = leptos_axum::extract().await?;
    let audit: AuditCtx = leptos_axum::extract().await?;

    let user_id = auth::consume_password_reset(&db.0, &token, &new_password)
        .await
        .map_err(sfn)?;
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
#[server(endpoint = "user/resend-verification")]
pub async fn resend_verification_email(email: String) -> Result<(), ServerFnError> {
    let db: DbExtension = leptos_axum::extract().await?;
    let mail: MailExtension = leptos_axum::extract().await?;

    if let Some(user_id) = auth::find_unverified_user_id(&db.0, &email)
        .await
        .map_err(sfn)?
    {
        send_verification_email(&db.0, &mail.0, user_id, &email).await;
    }
    Ok(())
}

/// Consume an email-verification token from the link in the user's inbox.
/// On success the account becomes verified and any subsequent sign-in is
/// allowed; the user still needs to enter credentials on the home page.
#[server(endpoint = "user/verify-email")]
pub async fn verify_email(token: String) -> Result<bool, ServerFnError> {
    let db: DbExtension = leptos_axum::extract().await?;
    let audit: AuditCtx = leptos_axum::extract().await?;

    let user_id = auth::consume_verification_token(&db.0, &token)
        .await
        .map_err(sfn)?;
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
#[cfg(all(feature = "ssr", feature = "mail"))]
async fn send_verification_email(
    db: &arium::pool::Pool,
    mail: &arium::mail::Mailer,
    user_id: i64,
    to: &str,
) {
    match auth::issue_verification_token(db, user_id).await {
        Ok(token) => {
            let link = format!("{}/auth/verify?token={token}", mail.base_url());
            let (subject, text, html) = arium::mail::templates::verify_email(&link);
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
#[server(endpoint = "user/verify-mfa")]
pub async fn verify_login_mfa(code: String) -> Result<LoginOutcome, ServerFnError> {
    let auth: auth::Session = leptos_axum::extract().await?;
    let db: DbExtension = leptos_axum::extract().await?;
    let session: SessionStore = leptos_axum::extract().await?;
    let audit: AuditCtx = leptos_axum::extract().await?;

    let pending: Option<(i64, i64, bool)> = session.get(MFA_PENDING_KEY);
    let Some((user_id, expires_at, remember_me)) = pending else {
        return Err(ServerFnError::new(
            "Your second-factor challenge expired. Please sign in again.",
        ));
    };
    if unix_now_seconds() > expires_at {
        session.remove(MFA_PENDING_KEY);
        return Err(ServerFnError::new(
            "Your second-factor challenge expired. Please sign in again.",
        ));
    }

    if !auth::verify_mfa_challenge(&db.0, user_id, &code)
        .await
        .map_err(sfn)?
    {
        audit
            .record(
                &db.0,
                auth::audit::USER_LOGIN_FAILED,
                Some(user_id),
                Some(user_id),
                Some("{\"method\":\"mfa\",\"reason\":\"invalid_code\"}"),
            )
            .await;
        return Err(ServerFnError::new("Code didn't match. Try again."));
    }

    session.remove(MFA_PENDING_KEY);
    complete_login(&auth, &session, user_id, remember_me);
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
#[server(endpoint = "user/cancel-mfa")]
pub async fn cancel_mfa_challenge() -> Result<(), ServerFnError> {
    let session: SessionStore = leptos_axum::extract().await?;
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
#[server(endpoint = "user/mfa/setup")]
pub async fn begin_mfa_setup() -> Result<MfaSetupView, ServerFnError> {
    let auth: auth::Session = leptos_axum::extract().await?;
    let db: DbExtension = leptos_axum::extract().await?;

    let user = auth
        .current_user
        .as_ref()
        .ok_or_else(|| ServerFnError::new("Not signed in."))?;
    if user.anonymous {
        return Err(ServerFnError::new("Not signed in."));
    }

    let label = user.email.clone().unwrap_or_else(|| user.username.clone());

    let info = auth::setup_mfa_secret(&db.0, user.id, &label)
        .await
        .map_err(sfn)?;
    Ok(MfaSetupView {
        secret_base32: info.secret_base32,
        qr_png_base64: info.qr_png_base64,
        recovery_codes: info.recovery_codes,
    })
}

/// Confirm enrollment by submitting a current TOTP code.
#[cfg(feature = "mfa")]
#[server(endpoint = "user/mfa/confirm")]
pub async fn confirm_mfa_setup(code: String) -> Result<(), ServerFnError> {
    let auth: auth::Session = leptos_axum::extract().await?;
    let db: DbExtension = leptos_axum::extract().await?;
    let audit: AuditCtx = leptos_axum::extract().await?;

    let user = auth
        .current_user
        .as_ref()
        .ok_or_else(|| ServerFnError::new("Not signed in."))?;
    if user.anonymous {
        return Err(ServerFnError::new("Not signed in."));
    }
    let user_id = user.id;
    if auth::enable_mfa(&db.0, user_id, &code).await.map_err(sfn)? {
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
        Err(ServerFnError::new("That code didn't match. Try again."))
    }
}

/// Turn off MFA for the current user. Wipes the secret and all recovery codes.
#[cfg(feature = "mfa")]
#[server(endpoint = "user/mfa/disable")]
pub async fn disable_mfa_for_user() -> Result<(), ServerFnError> {
    let auth: auth::Session = leptos_axum::extract().await?;
    let db: DbExtension = leptos_axum::extract().await?;
    let audit: AuditCtx = leptos_axum::extract().await?;

    let user = auth
        .current_user
        .as_ref()
        .ok_or_else(|| ServerFnError::new("Not signed in."))?;
    if user.anonymous {
        return Err(ServerFnError::new("Not signed in."));
    }
    let user_id = user.id;
    auth::disable_mfa(&db.0, user_id).await.map_err(sfn)?;
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
#[server(endpoint = "user/mfa/status")]
pub async fn get_mfa_status() -> Result<MfaStatusView, ServerFnError> {
    let auth: auth::Session = leptos_axum::extract().await?;
    let db: DbExtension = leptos_axum::extract().await?;

    let user = auth
        .current_user
        .as_ref()
        .ok_or_else(|| ServerFnError::new("Not signed in."))?;
    if user.anonymous {
        return Ok(MfaStatusView::Disabled);
    }
    Ok(match auth::mfa_status(&db.0, user.id).await.map_err(sfn)? {
        auth::MfaStatus::Disabled => MfaStatusView::Disabled,
        auth::MfaStatus::Pending => MfaStatusView::Pending,
        auth::MfaStatus::Enabled => MfaStatusView::Enabled,
    })
}

// ============================================================
// API tokens
// ============================================================

/// Create a new API token for the current user. The cleartext secret is
/// returned **once** in the response; only its prefix + SHA-256 hash are
/// persisted.
#[cfg(feature = "tokens")]
#[server(endpoint = "user/tokens/new")]
pub async fn create_api_token(name: String) -> Result<CreateApiTokenResponse, ServerFnError> {
    let auth: auth::Session = leptos_axum::extract().await?;
    let db: DbExtension = leptos_axum::extract().await?;
    let audit: AuditCtx = leptos_axum::extract().await?;

    let user = auth
        .current_user
        .as_ref()
        .ok_or_else(|| ServerFnError::new("Not signed in."))?;
    if user.anonymous {
        return Err(ServerFnError::new("Not signed in."));
    }
    let user_id = user.id;

    let (token, view) = auth::tokens::create_for_user(&db.0, user_id, &name)
        .await
        .map_err(sfn)?;

    let details = format!(
        "{{\"name\":{},\"prefix\":\"{}\"}}",
        json_string(&view.name),
        view.prefix
    );
    audit
        .record(
            &db.0,
            auth::audit::USER_API_TOKEN_CREATED,
            Some(user_id),
            Some(user_id),
            Some(&details),
        )
        .await;

    Ok(CreateApiTokenResponse { token, view })
}

/// List the current user's active (non-revoked) API tokens, newest first.
#[cfg(feature = "tokens")]
#[server(endpoint = "user/tokens")]
pub async fn list_api_tokens() -> Result<Vec<ApiTokenView>, ServerFnError> {
    let auth: auth::Session = leptos_axum::extract().await?;
    let db: DbExtension = leptos_axum::extract().await?;

    let user = auth
        .current_user
        .as_ref()
        .ok_or_else(|| ServerFnError::new("Not signed in."))?;
    if user.anonymous {
        return Err(ServerFnError::new("Not signed in."));
    }
    auth::tokens::list_for_user(&db.0, user.id)
        .await
        .map_err(sfn)
}

/// Soft-revoke an API token. Errors with `"Token not found."` if the token
/// doesn't exist, has already been revoked, or belongs to another user.
#[cfg(feature = "tokens")]
#[server(endpoint = "user/tokens/revoke")]
pub async fn revoke_api_token(token_id: i64) -> Result<(), ServerFnError> {
    let auth: auth::Session = leptos_axum::extract().await?;
    let db: DbExtension = leptos_axum::extract().await?;
    let audit: AuditCtx = leptos_axum::extract().await?;

    let user = auth
        .current_user
        .as_ref()
        .ok_or_else(|| ServerFnError::new("Not signed in."))?;
    if user.anonymous {
        return Err(ServerFnError::new("Not signed in."));
    }
    let user_id = user.id;

    let revoked = auth::tokens::revoke_for_user(&db.0, user_id, token_id)
        .await
        .map_err(sfn)?;
    if !revoked {
        return Err(ServerFnError::new("Token not found."));
    }

    let details = format!("{{\"token_id\":{token_id}}}");
    audit
        .record(
            &db.0,
            auth::audit::USER_API_TOKEN_REVOKED,
            Some(user_id),
            Some(user_id),
            Some(&details),
        )
        .await;
    Ok(())
}

/// Minimal JSON string encoder for audit detail payloads.
#[cfg(all(feature = "ssr", feature = "tokens"))]
fn json_string(raw: &str) -> String {
    json_escape(raw)
}

// ============================================================
// Admin
// ============================================================

#[cfg(feature = "ssr")]
async fn require_admin_perm(
    auth_session: &auth::Session,
    db: &arium::pool::Pool,
    perm: &str,
) -> Result<i64, ServerFnError> {
    use axum_session_auth::{Auth, Rights};
    let user = auth_session
        .current_user
        .as_ref()
        .ok_or_else(|| ServerFnError::new("Not signed in."))?;
    if user.anonymous {
        return Err(ServerFnError::new("Not signed in."));
    }
    Auth::<auth::User, i64, arium::pool::Pool>::build([axum::http::Method::GET], false)
        .requires(Rights::permission(perm.to_string()))
        .validate(user, &axum::http::Method::GET, Some(db))
        .await
        .then_some(user.id)
        .ok_or_else(|| ServerFnError::new("You don't have permission for this action."))
}

/// Resource-scoped enforcement for mutation server fns: verify the signed-in
/// caller holds at least `min_role` on `(kind, id)`, recording a denial in the
/// audit log. Returns the acting user id on success. This is the security
/// boundary — call it at the top of every resource-scoped mutation; the
/// [`ResourceGate`](crate::ui::resource_gate::ResourceGate) UI is cosmetic.
///
/// ```rust,ignore
/// #[server(endpoint = "board/rename")]
/// pub async fn rename_board(board_id: i64, name: String) -> Result<(), ServerFnError> {
///     let auth: auth::Session = leptos_axum::extract().await?;
///     let db: DbExtension = leptos_axum::extract().await?;
///     let authority: ResourceAuthorityExt = leptos_axum::extract().await?;
///     let audit: AuditCtx = leptos_axum::extract().await?;
///     let uid = require_resource_leptos(
///         &auth, &db.0, &authority, &audit, "board", board_id, ResourceRole::Editor,
///     ).await?;
///     // ... uid is authorized as at least an Editor of this board ...
/// }
/// ```
#[cfg(feature = "ssr")]
#[allow(clippy::too_many_arguments)]
pub async fn require_resource_leptos(
    auth_session: &auth::Session,
    db: &arium::pool::Pool,
    authority: &ResourceAuthorityExt,
    audit: &AuditCtx,
    kind: &str,
    id: i64,
    min_role: ResourceRole,
) -> Result<i64, ServerFnError> {
    let user = auth_session
        .current_user
        .as_ref()
        .ok_or_else(|| ServerFnError::new("Not signed in."))?;
    if user.anonymous {
        return Err(ServerFnError::new("Not signed in."));
    }
    let user_id = user.id;
    match arium::authz::require_resource(
        authority.0.as_ref(),
        db,
        user_id,
        arium::authz::ResourceRef::new(kind, id),
        min_role,
    )
    .await
    {
        Ok(id) => Ok(id),
        Err(arium::authz::ResourceAuthzError::Forbidden) => {
            let details = format!(
                "{{\"kind\":{},\"id\":{id},\"min_role\":\"{min_role:?}\"}}",
                json_escape(kind)
            );
            audit
                .record(
                    db,
                    auth::audit::RESOURCE_ACCESS_DENIED,
                    Some(user_id),
                    None,
                    Some(&details),
                )
                .await;
            Err(ServerFnError::new(
                "You don't have access to this resource.",
            ))
        }
        Err(arium::authz::ResourceAuthzError::Lookup(e)) => Err(ServerFnError::new(format!(
            "authorization check failed: {e}"
        ))),
    }
}

#[cfg(feature = "ssr")]
async fn summarise_admin_user(
    db: &arium::pool::Pool,
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
#[server(endpoint = "admin/users")]
pub async fn admin_list_users(
    limit: i64,
    offset: i64,
) -> Result<Vec<AdminUserSummary>, ServerFnError> {
    let auth: auth::Session = leptos_axum::extract().await?;
    let db: DbExtension = leptos_axum::extract().await?;

    require_admin_perm(&auth, &db.0, "admin:users:read").await?;
    let rows = auth::list_users_for_admin(&db.0, limit, offset)
        .await
        .map_err(sfn)?;
    let mut summaries = Vec::with_capacity(rows.len());
    for row in rows {
        summaries.push(summarise_admin_user(&db.0, row).await.map_err(sfn)?);
    }
    Ok(summaries)
}

/// Full detail for a single user (admin view).
#[server(endpoint = "admin/users/get")]
pub async fn admin_get_user(user_id: i64) -> Result<Option<AdminUserDetail>, ServerFnError> {
    let auth: auth::Session = leptos_axum::extract().await?;
    let db: DbExtension = leptos_axum::extract().await?;

    require_admin_perm(&auth, &db.0, "admin:users:read").await?;
    let Some(row) = auth::get_user_for_admin(&db.0, user_id)
        .await
        .map_err(sfn)?
    else {
        return Ok(None);
    };
    let permissions = auth::list_permissions_for_user(&db.0, user_id)
        .await
        .map_err(sfn)?;
    let avatar_url = row.avatar_url.clone();
    let html_url = row.html_url.clone();
    let summary = summarise_admin_user(&db.0, row).await.map_err(sfn)?;
    Ok(Some(AdminUserDetail {
        summary,
        avatar_url,
        html_url,
        permissions,
    }))
}

/// Replace a user's full role list (admin).
#[server(endpoint = "admin/users/roles")]
pub async fn admin_set_user_roles(user_id: i64, role_ids: Vec<i64>) -> Result<(), ServerFnError> {
    let auth: auth::Session = leptos_axum::extract().await?;
    let db: DbExtension = leptos_axum::extract().await?;
    let audit: AuditCtx = leptos_axum::extract().await?;

    let actor_id = require_admin_perm(&auth, &db.0, "admin:users:write").await?;
    let before = auth::get_user_role_ids(&db.0, user_id)
        .await
        .unwrap_or_default();
    auth::set_user_roles(&db.0, user_id, &role_ids)
        .await
        .map_err(sfn)?;
    let details = format!("{{\"before\":{before:?},\"after\":{role_ids:?}}}");
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
#[server(endpoint = "admin/users/delete")]
pub async fn admin_soft_delete_user(user_id: i64) -> Result<(), ServerFnError> {
    let auth: auth::Session = leptos_axum::extract().await?;
    let db: DbExtension = leptos_axum::extract().await?;
    let audit: AuditCtx = leptos_axum::extract().await?;

    let actor_id = require_admin_perm(&auth, &db.0, "admin:users:delete").await?;
    auth::soft_delete_user(&db.0, user_id).await.map_err(sfn)?;
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

/// Query the audit log (admin). Filtering happens server-side.
#[server(endpoint = "admin/audit/query")]
pub async fn admin_query_audit_events(
    query: AuditQuery,
) -> Result<Vec<AuditEventView>, ServerFnError> {
    let auth: auth::Session = leptos_axum::extract().await?;
    let db: DbExtension = leptos_axum::extract().await?;

    require_admin_perm(&auth, &db.0, "admin:audit:read").await?;
    let events = auth::audit::query(&db.0, &query).await.map_err(sfn)?;
    Ok(events)
}

/// List all roles + their permission tokens.
#[server(endpoint = "admin/roles")]
pub async fn admin_list_roles() -> Result<Vec<AdminRoleDetail>, ServerFnError> {
    let auth: auth::Session = leptos_axum::extract().await?;
    let db: DbExtension = leptos_axum::extract().await?;

    require_admin_perm(&auth, &db.0, "admin:roles:read").await?;
    let roles = auth::list_roles(&db.0).await.map_err(sfn)?;
    let mut out = Vec::with_capacity(roles.len());
    for r in roles {
        let permissions = auth::list_permissions_for_role(&db.0, r.id)
            .await
            .map_err(sfn)?;
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

/// Create a new (non-system) role.
#[server(endpoint = "admin/roles/create")]
pub async fn admin_create_role(
    name: String,
    description: Option<String>,
    permissions: Vec<String>,
) -> Result<i64, ServerFnError> {
    let auth: auth::Session = leptos_axum::extract().await?;
    let db: DbExtension = leptos_axum::extract().await?;
    let audit: AuditCtx = leptos_axum::extract().await?;

    let actor_id = require_admin_perm(&auth, &db.0, "admin:roles:write").await?;
    let role_id = auth::create_role(&db.0, &name, description.as_deref(), &permissions)
        .await
        .map_err(sfn)?;
    let details = format!(
        "{{\"name\":{},\"permissions\":{:?}}}",
        json_str(&name),
        permissions
    );
    audit
        .record(
            &db.0,
            auth::audit::ADMIN_ROLE_CREATED,
            Some(actor_id),
            Some(role_id),
            Some(&details),
        )
        .await;
    Ok(role_id)
}

/// Update a non-system role's metadata + permission token set.
#[server(endpoint = "admin/roles/update")]
pub async fn admin_update_role(
    role_id: i64,
    name: String,
    description: Option<String>,
    permissions: Vec<String>,
) -> Result<(), ServerFnError> {
    let auth: auth::Session = leptos_axum::extract().await?;
    let db: DbExtension = leptos_axum::extract().await?;
    let audit: AuditCtx = leptos_axum::extract().await?;

    let actor_id = require_admin_perm(&auth, &db.0, "admin:roles:write").await?;
    let before_tokens = auth::list_permissions_for_role(&db.0, role_id)
        .await
        .unwrap_or_default();
    auth::update_role(&db.0, role_id, &name, description.as_deref(), &permissions)
        .await
        .map_err(sfn)?;
    let details = format!(
        "{{\"name\":{},\"before\":{:?},\"after\":{:?}}}",
        json_str(&name),
        before_tokens,
        permissions
    );
    audit
        .record(
            &db.0,
            auth::audit::ADMIN_ROLE_UPDATED,
            Some(actor_id),
            Some(role_id),
            Some(&details),
        )
        .await;
    Ok(())
}

/// Delete a non-system role.
#[server(endpoint = "admin/roles/delete")]
pub async fn admin_delete_role(role_id: i64) -> Result<(), ServerFnError> {
    let auth: auth::Session = leptos_axum::extract().await?;
    let db: DbExtension = leptos_axum::extract().await?;
    let audit: AuditCtx = leptos_axum::extract().await?;

    let actor_id = require_admin_perm(&auth, &db.0, "admin:roles:write").await?;
    auth::delete_role(&db.0, role_id).await.map_err(sfn)?;
    audit
        .record(
            &db.0,
            auth::audit::ADMIN_ROLE_DELETED,
            Some(actor_id),
            Some(role_id),
            None,
        )
        .await;
    Ok(())
}

/// Minimal JSON string encoder shared by the audit detail payloads.
#[cfg(feature = "ssr")]
fn json_str(s: &str) -> String {
    json_escape(s)
}

/// Escape the characters that MUST be escaped inside a JSON string. Names with
/// control characters are rare enough that a heavier dep isn't worth pulling in.
#[cfg(feature = "ssr")]
fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len().saturating_add(2));
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

// ============================================================
// Account self-service
// ============================================================

/// What the AccountSettings UI renders against.
#[server(endpoint = "account")]
pub async fn get_account_view() -> Result<AccountView, ServerFnError> {
    let auth: auth::Session = leptos_axum::extract().await?;
    let db: DbExtension = leptos_axum::extract().await?;

    let user = auth
        .current_user
        .as_ref()
        .ok_or_else(|| ServerFnError::new("Not signed in."))?;
    if user.anonymous {
        return Err(ServerFnError::new("Not signed in."));
    }
    let id = user.id;

    // We still need a couple of bits that aren't on the cached `User`:
    // whether a password is set, whether MFA is enabled, and which OAuth
    // providers are linked.
    let has_password = auth::get_password_hash(&db.0, id)
        .await
        .map_err(sfn)?
        .is_some();
    let providers = auth::linked_oauth_providers(&db.0, id).await.map_err(sfn)?;

    #[cfg(feature = "mfa")]
    let mfa_enabled = auth::user_has_mfa(&db.0, id).await.map_err(sfn)?;
    #[cfg(not(feature = "mfa"))]
    let mfa_enabled = false;

    Ok(AccountView {
        username: user.username.clone(),
        display_name: user.display_name.clone(),
        email: user.email.clone(),
        email_verified: true, // user is currently signed in, so they verified at some point
        mfa_enabled,
        has_password,
        linked_oauth_providers: providers,
    })
}

/// Set the current user's self-chosen display name.
#[server(endpoint = "account/display-name")]
pub async fn update_display_name(new_name: String) -> Result<(), ServerFnError> {
    let auth: auth::Session = leptos_axum::extract().await?;
    let db: DbExtension = leptos_axum::extract().await?;
    let audit: AuditCtx = leptos_axum::extract().await?;

    let user = auth
        .current_user
        .as_ref()
        .ok_or_else(|| ServerFnError::new("Not signed in."))?;
    if user.anonymous {
        return Err(ServerFnError::new("Not signed in."));
    }
    let id = user.id;
    let trimmed = new_name.trim();
    let value = if trimmed.is_empty() {
        None
    } else {
        Some(trimmed)
    };
    auth::update_display_name(&db.0, id, value)
        .await
        .map_err(sfn)?;
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
#[server(endpoint = "account/password")]
pub async fn change_password(current: String, new_password: String) -> Result<(), ServerFnError> {
    let auth: auth::Session = leptos_axum::extract().await?;
    let db: DbExtension = leptos_axum::extract().await?;
    let audit: AuditCtx = leptos_axum::extract().await?;

    let user = auth
        .current_user
        .as_ref()
        .ok_or_else(|| ServerFnError::new("Not signed in."))?;
    if user.anonymous {
        return Err(ServerFnError::new("Not signed in."));
    }
    let id = user.id;
    let Some(stored) = auth::get_password_hash(&db.0, id).await.map_err(sfn)? else {
        return Err(ServerFnError::new("This account doesn't use a password."));
    };
    if !auth::verify_password_against_hash(&stored, &current) {
        return Err(ServerFnError::new("Current password didn't match."));
    }
    auth::replace_password_hash(&db.0, id, &new_password)
        .await
        .map_err(sfn)?;
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
#[server(endpoint = "account/delete")]
pub async fn delete_my_account() -> Result<(), ServerFnError> {
    let auth: auth::Session = leptos_axum::extract().await?;
    let db: DbExtension = leptos_axum::extract().await?;
    let audit: AuditCtx = leptos_axum::extract().await?;

    let user = auth
        .current_user
        .as_ref()
        .ok_or_else(|| ServerFnError::new("Not signed in."))?;
    if user.anonymous {
        return Err(ServerFnError::new("Not signed in."));
    }
    let id = user.id;
    auth::soft_delete_user(&db.0, id).await.map_err(sfn)?;
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
