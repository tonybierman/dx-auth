//! `act-db tokens` — list / create / revoke per-user API tokens.
//!
//! `create` prints the cleartext token exactly once on stdout (with a
//! warning on stderr) and stores only the hash. There is no recovery
//! path after that — re-mint and revoke the old one. Matches
//! `arium::auth::tokens::create_for_user`'s contract.

use arium::auth::audit as ariumaudit;
use arium::auth::tokens;
use arium::pool::Pool;

use crate::TokensOp;
use crate::audit;
use crate::output::{Format, print_json};

pub async fn run(pool: &Pool, actor_id: i64, op: TokensOp, fmt: Format) -> anyhow::Result<()> {
    match op {
        TokensOp::List { user_id } => list(pool, user_id, fmt).await,
        TokensOp::Create { user_id, name } => create(pool, actor_id, user_id, name, fmt).await,
        TokensOp::Revoke { user_id, token_id } => revoke(pool, actor_id, user_id, token_id).await,
    }
}

async fn list(pool: &Pool, user_id: i64, fmt: Format) -> anyhow::Result<()> {
    let rows = tokens::list_for_user(pool, user_id).await?;
    match fmt {
        Format::Json => print_json(&rows)?,
        Format::Human => {
            println!("{:>4}  {:<24}  {:<14}  created", "id", "name", "prefix");
            for t in &rows {
                println!(
                    "{:>4}  {:<24}  {:<14}  {}",
                    t.id, t.name, t.prefix, t.created_at_iso
                );
            }
        }
    }
    Ok(())
}

async fn create(
    pool: &Pool,
    actor_id: i64,
    user_id: i64,
    name: String,
    fmt: Format,
) -> anyhow::Result<()> {
    let (cleartext, view) = tokens::create_for_user(pool, user_id, &name).await?;
    audit::record(
        pool,
        actor_id,
        ariumaudit::USER_API_TOKEN_CREATED,
        Some(user_id),
        serde_json::json!({
            "verb": "tokens.create",
            "user_id": user_id,
            "token_id": view.id,
            "name": view.name,
        }),
    )
    .await;

    match fmt {
        Format::Json => print_json(&serde_json::json!({
            "token": cleartext,
            "view": view,
        }))?,
        Format::Human => {
            eprintln!(
                "WARNING: this token is shown ONCE. Save it now; the DB only stores its hash."
            );
            println!("{cleartext}");
            eprintln!(
                "(id={}, name={}, prefix={})",
                view.id, view.name, view.prefix
            );
        }
    }
    Ok(())
}

async fn revoke(pool: &Pool, actor_id: i64, user_id: i64, token_id: i64) -> anyhow::Result<()> {
    let revoked = tokens::revoke_for_user(pool, user_id, token_id).await?;
    if !revoked {
        anyhow::bail!("no active token id={token_id} for user {user_id}");
    }
    audit::record(
        pool,
        actor_id,
        ariumaudit::USER_API_TOKEN_REVOKED,
        Some(user_id),
        serde_json::json!({
            "verb": "tokens.revoke",
            "user_id": user_id,
            "token_id": token_id,
        }),
    )
    .await;
    println!("revoked token {token_id} for user {user_id}");
    Ok(())
}
