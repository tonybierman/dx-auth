//! Batteries-included [`MembershipStore`] over the arium-owned
//! `arium_resource_members` table (migration `0009_resource_members`).
//!
//! Use this when you don't already have a membership table and want resource
//! authz to work out of the box:
//!
//! ```rust,ignore
//! let authority: arium::SharedResourceAuthority = std::sync::Arc::new(arium::SqlMembershipStore);
//! let cfg = AuthConfig::builder(pool, mailer).resource_authority(authority).build()?;
//! // grant / revoke / transfer via the arium::membership composites:
//! arium::grant_membership(&arium::SqlMembershipStore, &pool, actor, r, target, ResourceRole::Editor).await?;
//! ```
//!
//! Apps that already own a membership table implement [`MembershipStore`]
//! directly against it instead (see [`crate::membership`]); this type is just
//! the default backing store.

use crate::authz::{ResourceAuthority, ResourceRef};
use crate::membership::{Membership, MembershipStore, TxExec};
use crate::pool::Pool;
use crate::wire::ResourceRole;
use async_trait::async_trait;

/// A [`MembershipStore`] backed by arium's `arium_resource_members` table.
/// Stateless — construct with `SqlMembershipStore` wherever a store is needed.
pub struct SqlMembershipStore;

#[async_trait]
impl ResourceAuthority for SqlMembershipStore {
    async fn role_on(
        &self,
        db: &Pool,
        user_id: i64,
        r: ResourceRef<'_>,
    ) -> anyhow::Result<Option<ResourceRole>> {
        let role: Option<String> = sqlx::query_scalar(
            "SELECT role FROM arium_resource_members \
             WHERE kind = $1 AND resource_id = $2 AND user_id = $3",
        )
        .bind(r.kind)
        .bind(r.id)
        .bind(user_id)
        .fetch_optional(db)
        .await?;
        Ok(role.map(|s| ResourceRole::from_str_lossy(&s)))
    }
}

#[async_trait]
impl MembershipStore for SqlMembershipStore {
    async fn list_members(
        &self,
        db: &Pool,
        r: ResourceRef<'_>,
    ) -> anyhow::Result<Vec<Membership>> {
        let rows: Vec<(i64, String)> = sqlx::query_as(
            "SELECT user_id, role FROM arium_resource_members \
             WHERE kind = $1 AND resource_id = $2 ORDER BY user_id",
        )
        .bind(r.kind)
        .bind(r.id)
        .fetch_all(db)
        .await?;
        Ok(rows
            .into_iter()
            .map(|(user_id, role)| Membership {
                user_id,
                role: ResourceRole::from_str_lossy(&role),
            })
            .collect())
    }

    async fn list_resources_for_user(
        &self,
        db: &Pool,
        user_id: i64,
        kind: &str,
        min_role: ResourceRole,
    ) -> anyhow::Result<Vec<i64>> {
        let rows: Vec<(i64, String)> = sqlx::query_as(
            "SELECT resource_id, role FROM arium_resource_members \
             WHERE user_id = $1 AND kind = $2 ORDER BY resource_id",
        )
        .bind(user_id)
        .bind(kind)
        .fetch_all(db)
        .await?;
        Ok(rows
            .into_iter()
            .filter(|(_, role)| ResourceRole::from_str_lossy(role).at_least(min_role))
            .map(|(id, _)| id)
            .collect())
    }

    async fn role_on_tx(
        &self,
        tx: &mut TxExec<'_>,
        r: ResourceRef<'_>,
        user_id: i64,
    ) -> anyhow::Result<Option<ResourceRole>> {
        let role: Option<String> = sqlx::query_scalar(
            "SELECT role FROM arium_resource_members \
             WHERE kind = $1 AND resource_id = $2 AND user_id = $3",
        )
        .bind(r.kind)
        .bind(r.id)
        .bind(user_id)
        .fetch_optional(&mut **tx)
        .await?;
        Ok(role.map(|s| ResourceRole::from_str_lossy(&s)))
    }

    async fn count_holders_of_role(
        &self,
        tx: &mut TxExec<'_>,
        r: ResourceRef<'_>,
        role: ResourceRole,
    ) -> anyhow::Result<u64> {
        let n: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM arium_resource_members \
             WHERE kind = $1 AND resource_id = $2 AND role = $3",
        )
        .bind(r.kind)
        .bind(r.id)
        .bind(role.as_str())
        .fetch_one(&mut **tx)
        .await?;
        Ok(n as u64)
    }

    async fn upsert_role(
        &self,
        tx: &mut TxExec<'_>,
        r: ResourceRef<'_>,
        user_id: i64,
        role: ResourceRole,
    ) -> anyhow::Result<()> {
        sqlx::query(
            "INSERT INTO arium_resource_members (kind, resource_id, user_id, role) \
             VALUES ($1, $2, $3, $4) \
             ON CONFLICT (kind, resource_id, user_id) DO UPDATE SET role = excluded.role",
        )
        .bind(r.kind)
        .bind(r.id)
        .bind(user_id)
        .bind(role.as_str())
        .execute(&mut **tx)
        .await?;
        Ok(())
    }

    async fn remove_role(
        &self,
        tx: &mut TxExec<'_>,
        r: ResourceRef<'_>,
        user_id: i64,
    ) -> anyhow::Result<()> {
        sqlx::query(
            "DELETE FROM arium_resource_members \
             WHERE kind = $1 AND resource_id = $2 AND user_id = $3",
        )
        .bind(r.kind)
        .bind(r.id)
        .bind(user_id)
        .execute(&mut **tx)
        .await?;
        Ok(())
    }
}
