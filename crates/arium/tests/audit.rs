//! Audit log: record, query, prune.
//!
//! We deliberately do NOT pin down the exact JSON shape of `details` —
//! that's the part most likely to evolve harmlessly, and locking it would
//! turn every refactor into a test rewrite. Instead we lock down:
//!
//! - One row written per `record` / `record_or_log` call.
//! - `query` filters by event_type (exact + `prefix.` form), actor, target,
//!   and time range.
//! - `query` sorts newest-first and respects limit.
//! - `prune` deletes rows older than the cutoff and only those rows.
//! - Failures inside `record_or_log` are swallowed (don't poison the caller).

mod common;

use arium::auth::audit;
use arium::wire::AuditQuery;

fn input<'a>(
    event_type: &'a str,
    actor: Option<i64>,
    target: Option<i64>,
) -> audit::RecordInput<'a> {
    audit::RecordInput {
        event_type,
        actor_id: actor,
        target_id: target,
        ip: None,
        user_agent: None,
        details: None,
    }
}

fn empty_query() -> AuditQuery {
    AuditQuery {
        event_type: String::new(),
        actor_id: None,
        target_id: None,
        since: None,
        until: None,
        limit: 50,
        offset: 0,
    }
}

#[tokio::test]
async fn record_inserts_exactly_one_row() {
    let pool = common::pool().await;
    audit::record(&pool, input(audit::USER_LOGIN_SUCCESS, Some(1), Some(1)))
        .await
        .unwrap();
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM audit_events")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 1);
}

#[tokio::test]
async fn query_exact_event_type_match() {
    let pool = common::pool().await;
    // FK constraints on `audit_events` require any non-NULL actor/target
    // to point at a real user row, so use the seeded Guest (id=1) where we
    // need one and `None` otherwise.
    audit::record(&pool, input(audit::USER_LOGIN_SUCCESS, None, None))
        .await
        .unwrap();
    audit::record(&pool, input(audit::USER_LOGOUT, None, None))
        .await
        .unwrap();
    audit::record(&pool, input(audit::USER_SIGNUP, None, None))
        .await
        .unwrap();

    let q = AuditQuery {
        event_type: audit::USER_LOGIN_SUCCESS.to_string(),
        ..empty_query()
    };
    let rows = audit::query(&pool, &q).await.unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].event_type, audit::USER_LOGIN_SUCCESS);
}

#[tokio::test]
async fn query_prefix_match() {
    let pool = common::pool().await;
    audit::record(&pool, input(audit::USER_LOGIN_SUCCESS, None, None))
        .await
        .unwrap();
    audit::record(&pool, input(audit::USER_LOGIN_FAILED, None, None))
        .await
        .unwrap();
    audit::record(&pool, input(audit::USER_LOGOUT, None, None))
        .await
        .unwrap();

    // Trailing dot turns it into LIKE 'user.login.%' — both successes and
    // failures match, logout does not.
    let q = AuditQuery {
        event_type: "user.login.".to_string(),
        ..empty_query()
    };
    let rows = audit::query(&pool, &q).await.unwrap();
    let types: Vec<&str> = rows.iter().map(|r| r.event_type.as_str()).collect();
    assert!(types.contains(&audit::USER_LOGIN_SUCCESS), "{types:?}");
    assert!(types.contains(&audit::USER_LOGIN_FAILED), "{types:?}");
    assert!(!types.contains(&audit::USER_LOGOUT), "{types:?}");
}

#[tokio::test]
async fn query_filters_by_actor_id() {
    let pool = common::pool().await;
    let alice = common::make_user(&pool, "alice@example.com", "hunter22!").await;
    let bob = common::make_user(&pool, "bob@example.com", "hunter22!").await;

    audit::record(&pool, input("evt.x", Some(alice), None))
        .await
        .unwrap();
    audit::record(&pool, input("evt.x", Some(bob), None))
        .await
        .unwrap();

    let q = AuditQuery {
        actor_id: Some(alice),
        ..empty_query()
    };
    let rows = audit::query(&pool, &q).await.unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].actor_id, Some(alice));
}

#[tokio::test]
async fn query_filters_by_target_id() {
    let pool = common::pool().await;
    let alice = common::make_user(&pool, "alice@example.com", "hunter22!").await;
    let bob = common::make_user(&pool, "bob@example.com", "hunter22!").await;

    audit::record(&pool, input("evt.x", Some(alice), Some(alice)))
        .await
        .unwrap();
    audit::record(&pool, input("evt.x", Some(alice), Some(bob)))
        .await
        .unwrap();

    let q = AuditQuery {
        target_id: Some(bob),
        ..empty_query()
    };
    let rows = audit::query(&pool, &q).await.unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].target_id, Some(bob));
}

#[tokio::test]
async fn query_filters_by_time_range() {
    let pool = common::pool().await;

    // Build rows at three different occurred_at stamps by writing the table
    // directly — `audit::record` always uses `now`, which we don't want here.
    let t0 = common::now_secs() - 100;
    let t1 = common::now_secs() - 50;
    let t2 = common::now_secs() - 10;
    for (i, ts) in [t0, t1, t2].iter().enumerate() {
        sqlx::query("INSERT INTO audit_events (occurred_at, event_type) VALUES ($1, $2)")
            .bind(ts)
            .bind(format!("evt.{i}"))
            .execute(&pool)
            .await
            .unwrap();
    }

    let q = AuditQuery {
        since: Some(t1),
        until: Some(t2),
        ..empty_query()
    };
    let rows = audit::query(&pool, &q).await.unwrap();
    // inclusive both ends → t1 and t2 match, t0 doesn't.
    assert_eq!(rows.len(), 2);
    assert!(
        rows.iter()
            .all(|r| r.occurred_at >= t1 && r.occurred_at <= t2)
    );
}

#[tokio::test]
async fn query_sorts_newest_first() {
    let pool = common::pool().await;
    let base = common::now_secs();
    for (offset, label) in [(0, "a"), (-10, "b"), (-5, "c")] {
        sqlx::query("INSERT INTO audit_events (occurred_at, event_type) VALUES ($1, $2)")
            .bind(base + offset)
            .bind(label)
            .execute(&pool)
            .await
            .unwrap();
    }
    let rows = audit::query(&pool, &empty_query()).await.unwrap();
    let types: Vec<_> = rows.iter().map(|r| r.event_type.as_str()).collect();
    assert_eq!(types, vec!["a", "c", "b"]);
}

#[tokio::test]
async fn query_clamps_limit_into_valid_range() {
    let pool = common::pool().await;
    for i in 0..5 {
        audit::record(&pool, input(&format!("evt.{i}"), None, None))
            .await
            .unwrap();
    }
    let q = AuditQuery {
        limit: 0, // clamped up to 1
        ..empty_query()
    };
    let rows = audit::query(&pool, &q).await.unwrap();
    assert_eq!(rows.len(), 1);
}

#[tokio::test]
async fn query_joins_actor_and_target_email_when_users_exist() {
    let pool = common::pool().await;
    let alice = common::make_user(&pool, "alice@example.com", "hunter22!").await;
    let bob = common::make_user(&pool, "bob@example.com", "hunter22!").await;

    audit::record(
        &pool,
        input(audit::ADMIN_USER_DELETED, Some(alice), Some(bob)),
    )
    .await
    .unwrap();

    let rows = audit::query(&pool, &empty_query()).await.unwrap();
    let row = rows
        .iter()
        .find(|r| r.event_type == audit::ADMIN_USER_DELETED)
        .unwrap();
    assert_eq!(row.actor_email.as_deref(), Some("alice@example.com"));
    assert_eq!(row.target_email.as_deref(), Some("bob@example.com"));
}

#[tokio::test]
async fn prune_zero_days_is_noop() {
    let pool = common::pool().await;
    audit::record(&pool, input("evt", None, None))
        .await
        .unwrap();
    let n = audit::prune(&pool, 0).await.unwrap();
    assert_eq!(n, 0);

    let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM audit_events")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(total, 1);
}

#[tokio::test]
async fn prune_deletes_only_rows_older_than_cutoff() {
    let pool = common::pool().await;
    let day = 86_400_i64;
    let now = common::now_secs();

    // 31 days old → pruned at 30-day retention.
    // 29 days old → kept.
    sqlx::query("INSERT INTO audit_events (occurred_at, event_type) VALUES ($1, 'old')")
        .bind(now - 31 * day)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO audit_events (occurred_at, event_type) VALUES ($1, 'young')")
        .bind(now - 29 * day)
        .execute(&pool)
        .await
        .unwrap();

    let deleted = audit::prune(&pool, 30).await.unwrap();
    assert_eq!(deleted, 1);

    let types: Vec<(String,)> =
        sqlx::query_as("SELECT event_type FROM audit_events ORDER BY event_type")
            .fetch_all(&pool)
            .await
            .unwrap();
    let types: Vec<String> = types.into_iter().map(|(t,)| t).collect();
    assert_eq!(types, vec!["young".to_string()]);
}

#[tokio::test]
async fn record_or_log_swallows_errors() {
    // Drop the table — subsequent `record_or_log` must NOT panic / propagate.
    let pool = common::pool().await;
    sqlx::query("DROP TABLE audit_events")
        .execute(&pool)
        .await
        .unwrap();
    // No panic, no return value — just needs to complete.
    audit::record_or_log(&pool, input("evt", None, None)).await;
}

#[tokio::test]
async fn record_propagates_errors_to_caller() {
    let pool = common::pool().await;
    sqlx::query("DROP TABLE audit_events")
        .execute(&pool)
        .await
        .unwrap();
    let err = audit::record(&pool, input("evt", None, None))
        .await
        .unwrap_err();
    // We don't care about the exact wording — only that it surfaced.
    let _ = err.to_string();
}

#[tokio::test]
async fn occurred_at_iso_is_a_human_readable_utc_string() {
    let pool = common::pool().await;
    audit::record(&pool, input("evt", None, None))
        .await
        .unwrap();
    let rows = audit::query(&pool, &empty_query()).await.unwrap();
    let iso = &rows[0].occurred_at_iso;
    assert!(iso.ends_with(" UTC"), "expected '<ts> UTC', got {iso:?}",);
    // Loose shape check: '2026-…' so a future timezone fix won't break this.
    assert!(iso.len() >= "2026-01-01 00:00:00 UTC".len(), "{iso:?}");
}
