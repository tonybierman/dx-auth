//! Outbound email infrastructure.
//!
//! The `Mailer` picks one of two backends at startup:
//!
//! - **SMTP** (when `SMTP_HOST` is set) — full STARTTLS connection via lettre.
//! - **File** (no SMTP env vars) — writes RFC-822-formatted `.eml` files to
//!   `./emails/<timestamp>.eml` so dev flows are testable without a provider.
//!
//! Templates live as plain functions in [`templates`] so we avoid adding a
//! template engine for two short messages.

use std::path::PathBuf;
use std::sync::Arc;

use lettre::{
    AsyncTransport, Message, Tokio1Executor,
    message::{Mailbox, MultiPart, SinglePart, header::ContentType},
    transport::smtp::{AsyncSmtpTransport, authentication::Credentials},
};

/// Default SMTP submission port used when `SMTP_PORT` is unset.
const DEFAULT_SMTP_PORT: u16 = 587;

/// Outbound email handle, cheaply cloneable so it can be stored in an
/// `axum::Extension` and shared across server functions.
#[derive(Clone)]
pub struct Mailer {
    inner: Arc<MailerInner>,
}

struct MailerInner {
    backend: Backend,
    from: Mailbox,
    base_url: String,
}

enum Backend {
    Smtp(AsyncSmtpTransport<Tokio1Executor>),
    File(PathBuf),
}

impl Mailer {
    /// Build the `Mailer` from env vars:
    ///
    /// - `SMTP_HOST` / `SMTP_PORT` (default 587) / `SMTP_USER` / `SMTP_PASSWORD`
    ///   — when `SMTP_HOST` is set we open a STARTTLS submission connection.
    /// - `FROM_EMAIL` (default `noreply@localhost`).
    /// - `PUBLIC_BASE_URL` (default `http://localhost:8080`) — used to build
    ///   absolute links inside email bodies.
    ///
    /// Without `SMTP_HOST` we fall back to a file backend at `./emails/`.
    pub fn from_env() -> anyhow::Result<Self> {
        let from: Mailbox = std::env::var("FROM_EMAIL")
            .unwrap_or_else(|_| "noreply@localhost".to_string())
            .parse()?;
        let base_url = std::env::var("PUBLIC_BASE_URL")
            .unwrap_or_else(|_| "http://localhost:8080".to_string());

        let backend = match std::env::var("SMTP_HOST") {
            Ok(host) if !host.is_empty() => {
                let port = std::env::var("SMTP_PORT")
                    .ok()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(DEFAULT_SMTP_PORT);
                let user = std::env::var("SMTP_USER").unwrap_or_default();
                let password = std::env::var("SMTP_PASSWORD").unwrap_or_default();

                let mut builder =
                    AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&host)?.port(port);
                if !user.is_empty() {
                    builder = builder.credentials(Credentials::new(user, password));
                }
                Backend::Smtp(builder.build())
            }
            _ => {
                let dir = PathBuf::from("./emails");
                std::fs::create_dir_all(&dir)?;
                Backend::File(dir)
            }
        };

        Ok(Self {
            inner: Arc::new(MailerInner {
                backend,
                from,
                base_url,
            }),
        })
    }

    /// Absolute base URL used to construct in-email links.
    pub fn base_url(&self) -> &str {
        &self.inner.base_url
    }

    /// One-line description of which backend is active; logged at startup.
    pub fn describe(&self) -> String {
        match &self.inner.backend {
            Backend::Smtp(_) => format!("smtp (from {})", self.inner.from),
            Backend::File(dir) => format!("file ({} — no SMTP_HOST set)", dir.display()),
        }
    }

    /// Send a message. `html` is optional; when present we send a
    /// multipart/alternative body so plain-text clients still render.
    pub async fn send(
        &self,
        to: &str,
        subject: &str,
        text: &str,
        html: Option<&str>,
    ) -> anyhow::Result<()> {
        let to: Mailbox = to.parse()?;

        let builder = Message::builder()
            .from(self.inner.from.clone())
            .to(to)
            .subject(subject);

        // Let lettre auto-pick the per-part Content-Transfer-Encoding. For the
        // plain-text body to stay clean (no quoted-printable `=3D` escapes or
        // mid-line soft wraps that mangle URLs) every line must be < 76 chars
        // — see `templates` and the 16-byte token length in `auth.rs`. The
        // HTML alternative is fine if it picks QP: real email clients decode
        // it back to working URLs.
        let message = match html {
            Some(html_body) => builder.multipart(
                MultiPart::alternative()
                    .singlepart(
                        SinglePart::builder()
                            .header(ContentType::TEXT_PLAIN)
                            .body(text.to_string()),
                    )
                    .singlepart(
                        SinglePart::builder()
                            .header(ContentType::TEXT_HTML)
                            .body(html_body.to_string()),
                    ),
            )?,
            None => builder
                .header(ContentType::TEXT_PLAIN)
                .body(text.to_string())?,
        };

        match &self.inner.backend {
            Backend::Smtp(t) => {
                t.send(message).await?;
            }
            Backend::File(dir) => {
                let ts = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_millis())
                    .unwrap_or(0);
                let path = dir.join(format!("{ts}.eml"));
                tokio::fs::write(&path, message.formatted()).await?;
                println!("[mail] wrote {}", path.display());
            }
        }

        Ok(())
    }
}

/// Email templates. Each returns `(subject, plain_text, html_optional)`.
pub mod templates {
    /// Body for the "click here to reset" email.
    ///
    /// IMPORTANT: keep every line of the plain-text body shorter than 76
    /// characters, so lettre picks 7bit transfer encoding and the URL stays
    /// intact when viewing the raw `.eml` file.
    pub fn password_reset(link: &str) -> (String, String, Option<String>) {
        let subject = "Reset your password".to_string();
        let text = format!(
            "Hi,\n\
             \n\
             We received a request to reset your password.\n\
             Click the link below to choose a new one:\n\
             \n\
             {link}\n\
             \n\
             This link expires in 1 hour.\n\
             If you didn't request a reset, ignore this email.\n"
        );
        let html = format!(
            "<p>Hi,</p>\
             <p>We received a request to reset your password. \
             <a href=\"{link}\">Click here to set a new one.</a></p>\
             <p>This link expires in 1 hour. If you didn't request a reset, ignore this email.</p>"
        );
        (subject, text, Some(html))
    }

    /// Body for the "verify your email" email sent on signup.
    pub fn verify_email(link: &str) -> (String, String, Option<String>) {
        let subject = "Verify your email".to_string();
        let text = format!(
            "Welcome!\n\
             \n\
             Please verify your email address by clicking the link below:\n\
             \n\
             {link}\n\
             \n\
             The link expires in 24 hours.\n"
        );
        let html = format!(
            "<p>Welcome!</p>\
             <p>Please verify your email address by clicking the link below:</p>\
             <p><a href=\"{link}\">{link}</a></p>\
             <p>The link expires in 24 hours.</p>"
        );
        (subject, text, Some(html))
    }
}
