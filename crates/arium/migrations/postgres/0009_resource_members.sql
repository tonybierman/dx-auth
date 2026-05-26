-- Optional batteries-included storage for per-resource memberships, read/written
-- by `arium::SqlMembershipStore`. Apps that own their own membership table (and
-- implement `MembershipStore` over it) can ignore this table — it stays empty.
CREATE TABLE IF NOT EXISTS arium_resource_members (
    kind        TEXT NOT NULL,
    resource_id BIGINT NOT NULL,
    user_id     BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role        TEXT NOT NULL,
    PRIMARY KEY (kind, resource_id, user_id)
);

-- Supports the reverse query `list_resources_for_user` (which resources does
-- this user belong to?).
CREATE INDEX IF NOT EXISTS idx_arium_resource_members_user
    ON arium_resource_members (user_id, kind);
