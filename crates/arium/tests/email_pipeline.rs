//! End-to-end-ish exercise of the reset / verification mail pipeline using
//! the file backend (`./emails/<ts>.eml`). We do NOT pin down the subject
//! line or HTML body shape — those are copy. The contract under test is:
//!
//! - The mailer writes an `.eml` to the configured directory.
//! - The plain-text body contains the absolute link with the token.
//! - Extracting that token and feeding it back to the consume function
//!   succeeds — i.e. the end-to-end loop is intact.

#![cfg(feature = "mail")]

mod common;

use arium::auth;
use arium::mail::{Mailer, templates};
use regex::Regex;

/// RAII guard: change cwd for the duration of a test and restore at drop.
/// The mailer's file backend uses a relative `./emails` path resolved at
/// `send()` time, so we have to stay in the tempdir for the whole test.
struct CwdGuard {
    prev: std::path::PathBuf,
}

impl CwdGuard {
    fn into(dir: &std::path::Path) -> Self {
        let prev = std::env::current_dir().expect("cwd");
        std::env::set_current_dir(dir).expect("chdir");
        Self { prev }
    }
}

impl Drop for CwdGuard {
    fn drop(&mut self) {
        let _ = std::env::set_current_dir(&self.prev);
    }
}

/// Build a Mailer in file mode inside the tempdir. Caller must hold the
/// returned `(TempDir, CwdGuard)` for as long as the mailer is used so the
/// cwd stays put across `mailer.send()` calls.
fn temp_mailer() -> (tempfile::TempDir, CwdGuard, Mailer) {
    let dir = tempfile::tempdir().expect("tempdir");
    let _h1 = common::EnvGuard::unset("SMTP_HOST");
    let _h2 = common::EnvGuard::set("PUBLIC_BASE_URL", "http://test.invalid");
    let _h3 = common::EnvGuard::set("FROM_EMAIL", "noreply@test.invalid");

    let guard = CwdGuard::into(dir.path());
    let mailer = Mailer::from_env().expect("mailer build");
    (dir, guard, mailer)
}

fn newest_eml(dir: &std::path::Path) -> String {
    let emails_dir = dir.join("emails");
    let mut entries: Vec<_> = std::fs::read_dir(&emails_dir)
        .unwrap_or_else(|e| panic!("read_dir {}: {e}", emails_dir.display()))
        .filter_map(Result::ok)
        .map(|e| e.path())
        .collect();
    entries.sort();
    let path = entries.last().expect("at least one .eml");
    std::fs::read_to_string(path).expect("read eml")
}

#[tokio::test]
#[serial_test::serial] // chdir + env vars
async fn password_reset_email_carries_a_consumable_token() {
    let (dir, _cwd, mailer) = temp_mailer();
    let pool = common::pool().await;
    common::make_user(&pool, "alice@example.com", "hunter22!").await;

    let token = auth::request_password_reset(&pool, "alice@example.com")
        .await
        .unwrap()
        .unwrap();

    let link = format!("{}/auth/reset?token={token}", mailer.base_url());
    let (subject, text, html) = templates::password_reset(&link);
    assert!(!subject.is_empty());
    mailer
        .send("alice@example.com", &subject, &text, html.as_deref())
        .await
        .unwrap();

    let body = newest_eml(dir.path());
    let re = Regex::new(r"/auth/reset\?token=([a-f0-9]{32})").unwrap();
    let captured = re
        .captures(&body)
        .unwrap_or_else(|| panic!("token not found in email body:\n{body}"))
        .get(1)
        .unwrap()
        .as_str()
        .to_string();
    assert_eq!(captured, token, "email body must carry the token verbatim");

    // And feeding it back consummates the loop.
    auth::consume_password_reset(&pool, &captured, "new_password!")
        .await
        .unwrap();
}

#[tokio::test]
#[serial_test::serial]
async fn verification_email_carries_a_consumable_token() {
    let (dir, _cwd, mailer) = temp_mailer();
    let pool = common::pool().await;
    let uid = auth::create_password_user(&pool, "bob@example.com", "hunter22!")
        .await
        .unwrap();

    let token = auth::issue_verification_token(&pool, uid).await.unwrap();
    let link = format!("{}/auth/verify?token={token}", mailer.base_url());
    let (subject, text, html) = templates::verify_email(&link);
    mailer
        .send("bob@example.com", &subject, &text, html.as_deref())
        .await
        .unwrap();

    let body = newest_eml(dir.path());
    let re = Regex::new(r"/auth/verify\?token=([a-f0-9]{32})").unwrap();
    let captured = re
        .captures(&body)
        .unwrap_or_else(|| panic!("token not found:\n{body}"))
        .get(1)
        .unwrap()
        .as_str()
        .to_string();
    assert_eq!(captured, token);

    auth::consume_verification_token(&pool, &captured)
        .await
        .unwrap();
    // User is now verified.
    let outcome = auth::verify_password_user(&pool, "bob@example.com", "hunter22!")
        .await
        .unwrap();
    assert_eq!(outcome, auth::VerifyOutcome::Verified(uid));
}

#[test]
fn password_reset_template_keeps_plain_text_under_76_columns() {
    // Documented invariant in `mail.rs`: with every line < 76 chars, lettre
    // picks 7bit transfer encoding and the URL stays intact in raw `.eml`
    // views. Test a representative URL (32-hex-char token + the rest of the
    // path the templates assemble).
    let link = "http://localhost:8080/auth/reset?token=00112233445566778899aabbccddeeff";
    let (_subject, text, _html) = templates::password_reset(link);
    for (i, line) in text.lines().enumerate() {
        assert!(
            line.len() < 76,
            "password_reset line {i} is {} chars: {line:?}",
            line.len(),
        );
    }
}

#[test]
fn verify_email_template_keeps_plain_text_under_76_columns() {
    let link = "http://localhost:8080/auth/verify?token=00112233445566778899aabbccddeeff";
    let (_subject, text, _html) = templates::verify_email(link);
    for (i, line) in text.lines().enumerate() {
        assert!(
            line.len() < 76,
            "verify_email line {i} is {} chars: {line:?}",
            line.len(),
        );
    }
}
