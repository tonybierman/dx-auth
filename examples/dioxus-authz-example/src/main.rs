//! Smallest faithful demo of arium's **per-resource membership** authorization
//! in Dioxus.
//!
//! Three pieces, and only these three:
//!
//! 1. [`DemoAuthority`] — the app's [`ResourceAuthority`]: it answers "what role
//!    does this user hold on *this* document?" In a real app this reads a
//!    `doc_members` table; here it hands back a fixed role per document id so
//!    the lattice (Owner > Manager > Editor > Viewer) is visible at a glance.
//! 2. [`ResourceGate`] — a **cosmetic** UI gate. It shows the rename field only
//!    where the caller is at least an `Editor`. Hiding a control is not
//!    security.
//! 3. [`rename_doc`] — the mutation server fn. It calls
//!    `require_resource_dioxus` *first*: that fresh, per-request,
//!    default-deny check is the real boundary. The "Attempt edit anyway"
//!    button on view-only docs proves it — the request reaches the server and
//!    is rejected there, gate or no gate.
//!
//! Run with `dx serve` and register any account (signup logs you straight in —
//! no `mail` feature, so no verification round-trip); every signed-in user gets
//! the same demo roles below.

use dioxus::prelude::*;

use arium_dioxus::server::*;
use arium_dioxus::ui::components::button::{Button, ButtonVariant};
use arium_dioxus::ui::{
    LoginPanel, LoginSubmit, PermissionsProvider, ResourceGate, SubmitKind, use_permissions,
    use_resource_role,
};
use arium_dioxus::{LoginOutcome, ResourceRole, friendly_server_error};

const APP_CSS: Asset = asset!("/assets/app.css");

/// The demo documents. The role each carries is assigned by [`DemoAuthority`]
/// purely from its id, so one freshly-registered user can see every tier of the
/// lattice at once.
const DOCS: &[(i64, &str)] = &[
    (1, "Team roadmap"),     // Owner  — full control
    (2, "Design notes"),     // Editor — can edit
    (3, "Company handbook"), // Viewer — read-only
    (4, "Q3 board minutes"), // (none) — no relationship → denied
];

fn main() {
    #[cfg(not(feature = "server"))]
    dioxus::launch(app);

    #[cfg(feature = "server")]
    dioxus::serve(|| async {
        use std::sync::Arc;

        // Dev SQLite DB under the workspace `target/` dir (gitignored), unless
        // DATABASE_URL is set. arium owns this schema; the migrator creates it.
        let pool = {
            use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
            use std::str::FromStr;

            let connect_opts = match std::env::var("DATABASE_URL") {
                Ok(url) if !url.trim().is_empty() => SqliteConnectOptions::from_str(&url)?,
                _ => SqliteConnectOptions::new()
                    .filename(concat!(
                        env!("CARGO_MANIFEST_DIR"),
                        "/../../target/authz.db"
                    ))
                    .create_if_missing(true),
            };
            SqlitePoolOptions::new()
                .max_connections(20)
                .connect_with(connect_opts)
                .await?
        };
        arium_dioxus::migrator().run(&pool).await?;

        // The one line that wires per-resource authorization in: register the
        // app's `ResourceAuthority`. `install` layers it as an extension so the
        // `get_resource_role` / `require_resource_dioxus` extractors can reach
        // it. Without this the example's gate and boundary would 500.
        let authority: arium_dioxus::SharedResourceAuthority = Arc::new(DemoAuthority);
        let cfg = arium_dioxus::AuthConfig::builder(pool)
            .resource_authority(authority)
            .build()?;

        arium_dioxus::install(dioxus::server::router(app), cfg).await
    });
}

// ============================================================
// The app's ResourceAuthority (server-only)
// ============================================================

/// The app's plug-in to arium's per-resource enforcement. arium stores no
/// memberships itself — it calls this on every check.
///
/// A real app reads its own storage here (`SELECT role FROM doc_members WHERE
/// doc_id = $1 AND user_id = $2`) and keys on `user_id`. This demo ignores the
/// user and returns a fixed role per document so the whole lattice is on screen
/// for any signed-in account. `Ok(None)` is a hard deny, never an error.
#[cfg(feature = "server")]
struct DemoAuthority;

#[cfg(feature = "server")]
#[async_trait::async_trait]
impl arium_dioxus::ResourceAuthority for DemoAuthority {
    async fn role_on(
        &self,
        _db: &arium_dioxus::pool::Pool,
        _user_id: i64,
        r: arium_dioxus::ResourceRef<'_>,
    ) -> anyhow::Result<Option<ResourceRole>> {
        if r.kind != "doc" {
            return Ok(None);
        }
        Ok(match r.id {
            1 => Some(ResourceRole::Owner),
            2 => Some(ResourceRole::Editor),
            3 => Some(ResourceRole::Viewer),
            _ => None,
        })
    }
}

// ============================================================
// The membership-enforced mutation (the real boundary)
// ============================================================

#[cfg(feature = "server")]
type DbExt = axum::Extension<arium_dioxus::pool::Pool>;

/// Rename a document — a resource-scoped mutation, so it is gated by the
/// per-request `require_resource_dioxus` check (at least `Editor`). This is the
/// security boundary; the [`ResourceGate`] in the UI only decides whether the
/// field is *shown*. Nothing is persisted — the example just proves the check
/// passed (or, for the "Attempt edit anyway" button, that it was rejected).
#[post(
    "/api/doc/rename",
    auth: arium_dioxus::auth::Session,
    db: DbExt,
    authority: arium_dioxus::ResourceAuthorityExt,
    audit: arium_dioxus::AuditCtx,
)]
pub async fn rename_doc(doc_id: i64, new_title: String) -> Result<String> {
    require_resource_dioxus(
        &auth,
        &db.0,
        &authority,
        &audit,
        "doc",
        doc_id,
        ResourceRole::Editor,
    )
    .await?;
    Ok(format!(
        "✓ Server accepted the rename to “{new_title}” — you hold at least Editor on doc #{doc_id}."
    ))
}

// ============================================================
// UI
// ============================================================

fn app() -> Element {
    rsx! {
        // Catalog theme tokens straight from the adapter (no vendored copy).
        document::Stylesheet { href: arium_dioxus::DEFAULT_THEME_CSS }
        document::Stylesheet { href: APP_CSS }

        // PermissionsProvider gives a shared profile resource (`.profile()` /
        // `.is_authenticated()` / `.refresh()`) and pins the auth stylesheets
        // so the LoginPanel stays styled across sign-in/out re-mounts.
        PermissionsProvider {
            Home {}
        }
    }
}

#[component]
fn Home() -> Element {
    let perms = use_permissions();
    let mut auth_error = use_signal(String::new);

    let on_submit = move |submission: LoginSubmit| {
        auth_error.set(String::new());
        let LoginSubmit {
            kind,
            email,
            password,
            remember,
        } = submission;
        spawn(async move {
            let result = match kind {
                SubmitKind::SignIn => login_with_password(email, password, remember).await,
                SubmitKind::SignUp => register_with_password(email, password).await,
            };
            match result {
                Ok(LoginOutcome::LoggedIn) => perms.refresh(),
                Ok(_) => auth_error.set("Unexpected sign-in outcome.".to_string()),
                Err(e) => auth_error.set(friendly_server_error(e)),
            }
        });
    };

    rsx! {
        main { class: "app-shell",
            h1 { class: "title", "arium · per-resource membership" }

            if perms.is_loading() {
                p { class: "muted", "Loading…" }
            } else if perms.is_authenticated() {
                {
                    let name = perms
                        .profile()
                        .map(|p| p.display().to_string())
                        .unwrap_or_default();
                    rsx! {
                        p { class: "muted",
                            "Signed in as "
                            strong { "{name}" }
                            ". Your role on each document is decided server-side by a "
                            code { "ResourceAuthority" }
                            "."
                        }
                        for (id , title) in DOCS.iter().copied() {
                            DocCard { key: "{id}", id, title: title.to_string() }
                        }
                        div { class: "signout",
                            Button {
                                variant: ButtonVariant::Outline,
                                onclick: move |_| async move {
                                    let _ = logout().await;
                                    perms.refresh();
                                },
                                "Sign out"
                            }
                        }
                    }
                }
            } else {
                LoginPanel {
                    title: "Sign in",
                    description: "Register or sign in — any account works; roles are demo-assigned per document.",
                    error: {
                        let e = auth_error();
                        if e.is_empty() { None } else { Some(e) }
                    },
                    on_submit,
                }
            }
        }
    }
}

/// One document row: its title, the caller's role badge, and an edit affordance
/// gated by [`ResourceGate`]. Editors see a rename field; everyone else sees a
/// read-only note plus a button that calls the server fn anyway — to show the
/// boundary, not the gate, is what rejects it.
#[component]
fn DocCard(id: i64, title: String) -> Element {
    let role = use_resource_role("doc".to_string(), id);
    let role_label = match &*role.read() {
        Some(Ok(Some(r))) => r.as_str(),
        Some(Ok(None)) => "no access",
        Some(Err(_)) => "error",
        None => "…",
    };

    let mut draft = use_signal(|| title.clone());
    let mut result = use_signal(String::new);

    let save = move || {
        let new_title = draft();
        spawn(async move {
            match rename_doc(id, new_title).await {
                Ok(msg) => result.set(msg),
                Err(e) => result.set(friendly_server_error(e)),
            }
        });
    };

    rsx! {
        div { class: "doc-card",
            div { class: "doc-head",
                span { class: "doc-title", "{title}" }
                span { class: "doc-role", "{role_label}" }
            }

            ResourceGate {
                kind: "doc".to_string(),
                id,
                min_role: ResourceRole::Editor,
                // Shown when the caller is below Editor (or has no relationship).
                fallback: rsx! {
                    div { class: "doc-actions",
                        span { class: "doc-readonly", "🔒 View-only — no edit rights" }
                        Button {
                            variant: ButtonVariant::Outline,
                            onclick: move |_| save(),
                            "Attempt edit anyway"
                        }
                    }
                },
                // Shown when the caller is at least an Editor.
                div { class: "doc-actions",
                    input {
                        class: "rename-input",
                        value: "{draft}",
                        oninput: move |e| draft.set(e.value()),
                    }
                    Button { onclick: move |_| save(), "Save title" }
                }
            }

            if !result().is_empty() {
                p { class: "doc-result", "{result}" }
            }
        }
    }
}
