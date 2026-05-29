//! `act-db users` — list / show / create / delete / verify /
//! reset-password / roles / disable-mfa. Every mutating verb routes
//! through `arium::auth::*` and emits one audit row on success.
//!
//! Password handling: `users create` and `users reset-password` accept
//! the target user's password via `--new-password` or prompt for it on
//! a TTY. Both are distinct from the operator's auth password (`-p`),
//! which the `arium-act` gate owns. Non-TTY runs without
//! `--new-password` fail fast rather than silently set an empty
//! password.

use std::io::IsTerminal;

use anyhow::Context;
use arium::auth;
use arium::auth::audit as ariumaudit;
use arium::pool::Pool;

use crate::UsersOp;
use crate::audit;
use crate::output::{Format, UserView, print_json};

pub async fn run(pool: &Pool, actor_id: i64, op: UsersOp, fmt: Format) -> anyhow::Result<()> {
    match op {
        UsersOp::List { limit, offset } => list(pool, limit, offset, fmt).await,
        UsersOp::Show { user_id } => show(pool, user_id, fmt).await,
        UsersOp::Create {
            email,
            new_password,
            verified,
        } => create(pool, actor_id, email, new_password, verified, fmt).await,
        UsersOp::Delete { user_id } => delete(pool, actor_id, user_id).await,
        UsersOp::Verify { user_id } => verify(pool, actor_id, user_id).await,
        UsersOp::ResetPassword {
            user_id,
            new_password,
        } => reset_password(pool, actor_id, user_id, new_password).await,
        UsersOp::Roles { user_id } => roles(pool, user_id, fmt).await,
        UsersOp::DisableMfa { user_id } => disable_mfa(pool, actor_id, user_id).await,
    }
}

async fn list(pool: &Pool, limit: i64, offset: i64, fmt: Format) -> anyhow::Result<()> {
    let rows = auth::list_users_for_admin(pool, limit, offset).await?;
    match fmt {
        Format::Json => {
            let views: Vec<UserView> = rows.iter().map(UserView::from).collect();
            print_json(&views)?;
        }
        Format::Human => {
            println!("{:>6}  {:<24}  {:<32}  verified", "id", "username", "email");
            for u in &rows {
                let email = u.email.as_deref().unwrap_or("-");
                let verified = u.email_verified_at.is_some();
                println!(
                    "{:>6}  {:<24}  {:<32}  {}",
                    u.id, u.username, email, verified
                );
            }
        }
    }
    Ok(())
}

async fn show(pool: &Pool, user_id: i64, fmt: Format) -> anyhow::Result<()> {
    let Some(u) = auth::get_user_for_admin(pool, user_id).await? else {
        anyhow::bail!("no user with id {user_id}");
    };
    let view = UserView::from(&u);
    match fmt {
        Format::Json => print_json(&view)?,
        Format::Human => {
            println!("id:                {}", view.id);
            println!("username:          {}", view.username);
            println!(
                "display_name:      {}",
                view.display_name.as_deref().unwrap_or("-")
            );
            println!(
                "email:             {}",
                view.email.as_deref().unwrap_or("-")
            );
            println!(
                "email_verified_at: {}",
                view.email_verified_at
                    .map(|t| t.to_string())
                    .unwrap_or_else(|| "-".to_string())
            );
            println!(
                "mfa_enabled_at:    {}",
                view.mfa_enabled_at
                    .map(|t| t.to_string())
                    .unwrap_or_else(|| "-".to_string())
            );
            println!("anonymous:         {}", view.anonymous);
        }
    }
    Ok(())
}

async fn create(
    pool: &Pool,
    actor_id: i64,
    email: String,
    password: Option<String>,
    verified: bool,
    fmt: Format,
) -> anyhow::Result<()> {
    let pw = match password {
        Some(p) => p,
        None => prompt_password()?,
    };
    let new_id = auth::create_password_user(pool, &email, &pw).await?;
    if verified {
        auth::mark_email_verified(pool, new_id).await?;
    }

    audit::record(
        pool,
        actor_id,
        audit::ACT_USER_CREATED,
        Some(new_id),
        serde_json::json!({
            "verb": "users.create",
            "email": email,
            "verified": verified,
        }),
    )
    .await;

    match fmt {
        Format::Json => print_json(&serde_json::json!({
            "id": new_id,
            "email": email,
            "verified": verified,
        }))?,
        Format::Human => println!("created user {new_id} ({email})"),
    }
    Ok(())
}

async fn delete(pool: &Pool, actor_id: i64, user_id: i64) -> anyhow::Result<()> {
    ensure_user(pool, user_id).await?;
    auth::soft_delete_user(pool, user_id).await?;
    audit::record(
        pool,
        actor_id,
        ariumaudit::ADMIN_USER_DELETED,
        Some(user_id),
        serde_json::json!({ "verb": "users.delete", "user_id": user_id }),
    )
    .await;
    println!("soft-deleted user {user_id}");
    Ok(())
}

async fn verify(pool: &Pool, actor_id: i64, user_id: i64) -> anyhow::Result<()> {
    ensure_user(pool, user_id).await?;
    auth::mark_email_verified(pool, user_id).await?;
    audit::record(
        pool,
        actor_id,
        ariumaudit::USER_EMAIL_VERIFIED,
        Some(user_id),
        serde_json::json!({ "verb": "users.verify", "user_id": user_id }),
    )
    .await;
    println!("verified user {user_id}");
    Ok(())
}

async fn reset_password(
    pool: &Pool,
    actor_id: i64,
    user_id: i64,
    password: Option<String>,
) -> anyhow::Result<()> {
    let Some(u) = auth::get_user_for_admin(pool, user_id).await? else {
        anyhow::bail!("no user with id {user_id}");
    };
    let email = u
        .email
        .clone()
        .context("user has no email on file; cannot reset password")?;

    let token = auth::request_password_reset(pool, &email)
        .await?
        .context("request_password_reset returned None (user not found?)")?;
    audit::record(
        pool,
        actor_id,
        ariumaudit::USER_PWD_RESET_REQUESTED,
        Some(user_id),
        serde_json::json!({ "verb": "users.reset_password", "user_id": user_id }),
    )
    .await;

    let pw = match password {
        Some(p) => p,
        None => prompt_password()?,
    };
    let _ = auth::consume_password_reset(pool, &token, &pw).await?;

    audit::record(
        pool,
        actor_id,
        ariumaudit::USER_PWD_RESET_CONSUMED,
        Some(user_id),
        serde_json::json!({ "verb": "users.reset_password", "user_id": user_id }),
    )
    .await;
    println!("password reset for user {user_id}");
    Ok(())
}

async fn roles(pool: &Pool, user_id: i64, fmt: Format) -> anyhow::Result<()> {
    let role_ids = auth::get_user_role_ids(pool, user_id).await?;
    let all = auth::list_roles(pool).await?;
    let mut rows: Vec<(i64, String)> = role_ids
        .into_iter()
        .filter_map(|rid| {
            all.iter()
                .find(|r| r.id == rid)
                .map(|r| (r.id, r.name.clone()))
        })
        .collect();
    rows.sort_by_key(|r| r.0);

    match fmt {
        Format::Json => print_json(
            &rows
                .iter()
                .map(|(id, name)| serde_json::json!({ "id": id, "name": name }))
                .collect::<Vec<_>>(),
        )?,
        Format::Human => {
            if rows.is_empty() {
                println!("(no roles)");
            } else {
                for (id, name) in &rows {
                    println!("{id}\t{name}");
                }
            }
        }
    }
    Ok(())
}

async fn disable_mfa(pool: &Pool, actor_id: i64, user_id: i64) -> anyhow::Result<()> {
    ensure_user(pool, user_id).await?;
    auth::disable_mfa(pool, user_id).await?;
    audit::record(
        pool,
        actor_id,
        ariumaudit::USER_MFA_DISABLED,
        Some(user_id),
        serde_json::json!({ "verb": "users.disable_mfa", "user_id": user_id }),
    )
    .await;
    println!("mfa disabled for user {user_id}");
    Ok(())
}

async fn ensure_user(pool: &Pool, user_id: i64) -> anyhow::Result<()> {
    if auth::get_user_for_admin(pool, user_id).await?.is_none() {
        anyhow::bail!("no user with id {user_id}");
    }
    Ok(())
}

fn prompt_password() -> anyhow::Result<String> {
    if !std::io::stdin().is_terminal() {
        anyhow::bail!(
            "no password supplied — pass --password or run on a TTY for an \
             interactive prompt"
        );
    }
    let one = rpassword::prompt_password("Password: ")?;
    let two = rpassword::prompt_password("Repeat: ")?;
    if one != two {
        anyhow::bail!("passwords do not match");
    }
    Ok(one)
}
