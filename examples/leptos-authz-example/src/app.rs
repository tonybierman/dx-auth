//! The membership demo: router, login wiring, the document list with its
//! per-resource gate, and the enforced rename server fn.
//!
//! Three pieces, mirroring the dioxus example:
//!
//! 1. `DemoAuthority` (in `main.rs`) implements arium's `ResourceAuthority` and
//!    is registered via `AuthConfigBuilder::resource_authority`. It decides the
//!    caller's role on each document.
//! 2. [`ResourceGate`] is a **cosmetic** UI gate — it only decides whether the
//!    rename field is shown.
//! 3. [`rename_doc`] is the resource-scoped mutation. It calls
//!    `require_resource_leptos` first — the fresh, per-request, default-deny
//!    check that is the real boundary. The "Attempt edit anyway" button on
//!    view-only docs proves the server rejects it, gate or no gate.

use arium_leptos::server::{login_with_password, logout, register_with_password};
use arium_leptos::ui::components::button::{Button, ButtonVariant};
use arium_leptos::ui::{
    LoginPanel, LoginSubmit, PermissionsProvider, ResourceGate, SubmitKind, use_permissions,
    use_resource_role,
};
use arium_leptos::{LoginOutcome, ResourceRole, friendly_server_error};
use leptos::prelude::*;
use leptos::task::spawn_local;
use leptos_meta::{Title, provide_meta_context};
use leptos_router::components::{Route, Router, Routes};
use leptos_router::path;

/// The demo documents. The role each carries is assigned by `DemoAuthority`
/// (in `main.rs`) purely from its id, so one signed-in user sees every tier of
/// the lattice at once.
const DOCS: &[(i64, &str)] = &[
    (1, "Team roadmap"),     // Owner  — full control
    (2, "Design notes"),     // Editor — can edit
    (3, "Company handbook"), // Viewer — read-only
    (4, "Q3 board minutes"), // (none) — no relationship → denied
];

/// A little app-shell + doc-card CSS. The dx-components theme (linked by the
/// adapter's auth stylesheets) supplies the color tokens used via `var(...)`.
const EXAMPLE_CSS: &str = r#"
html { --dark: initial; --light: ; color-scheme: dark; }
.app-shell { max-width: 34rem; margin: 3.5rem auto; padding: 0 1rem;
  display: flex; flex-direction: column; gap: 1.25rem;
  font-family: system-ui, sans-serif; color: var(--secondary-color-1); }
.title { font-size: 1.25rem; font-weight: 600; margin: 0; }
.muted { color: var(--secondary-color-7, #9aa0a6); font-size: 0.9rem; line-height: 1.4; margin: 0; }
.doc-card { border: 1px solid var(--secondary-color-4, #333); border-radius: 0.5rem;
  padding: 0.875rem 1rem; display: flex; flex-direction: column; gap: 0.625rem; }
.doc-head { display: flex; align-items: center; justify-content: space-between; gap: 0.75rem; }
.doc-title { font-weight: 600; }
.doc-role { font-size: 0.7rem; text-transform: uppercase; letter-spacing: 0.04em;
  padding: 0.15rem 0.5rem; border-radius: 999px; border: 1px solid var(--secondary-color-5, #444);
  color: var(--secondary-color-8, #c0c4c9); }
.doc-actions { display: flex; align-items: center; gap: 0.5rem; flex-wrap: wrap; }
.doc-readonly { font-size: 0.85rem; color: var(--secondary-color-7, #9aa0a6); }
.rename-input { flex: 1 1 12rem; padding: 0.4rem 0.6rem; border-radius: 0.375rem;
  border: 1px solid var(--secondary-color-5, #444); background: transparent; color: inherit; font: inherit; }
.doc-result { margin: 0; font-size: 0.85rem; color: var(--secondary-color-8, #c0c4c9); }
.signout { margin-top: 0.5rem; }
"#;

#[component]
pub fn App() -> impl IntoView {
    provide_meta_context();
    view! {
        <Title text="arium · per-resource membership (Leptos)" />
        <style inner_html=EXAMPLE_CSS></style>
        // PermissionsProvider gives a shared profile resource
        // (`.profile()` / `.is_authenticated()` / `.refresh()`) and pins the
        // auth stylesheets so the LoginPanel stays styled across re-mounts.
        <PermissionsProvider>
            <Router>
                <Routes fallback=|| view! { <p class="app-shell">"Not found."</p> }>
                    <Route path=path!("/") view=Home />
                </Routes>
            </Router>
        </PermissionsProvider>
    }
}

#[component]
fn Home() -> impl IntoView {
    let perms = use_permissions();
    let auth_error = RwSignal::new(String::new());

    let on_login = Callback::new(move |sub: LoginSubmit| {
        auth_error.set(String::new());
        let LoginSubmit {
            kind,
            email,
            password,
            remember,
        } = sub;
        spawn_local(async move {
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
    });

    let sign_out = Callback::new(move |_| {
        spawn_local(async move {
            let _ = logout().await;
            perms.refresh();
        });
    });

    view! {
        <main class="app-shell">
            <h1 class="title">"arium · per-resource membership"</h1>
            {move || {
                if perms.is_authenticated() {
                    let name = perms
                        .profile()
                        .map(|p| p.display().to_string())
                        .unwrap_or_default();
                    view! {
                        <p class="muted">
                            "Signed in as " <strong>{name}</strong>
                            ". Your role on each document is decided server-side by a "
                            <code>"ResourceAuthority"</code> "."
                        </p>
                        <For
                            each=|| DOCS.iter().copied()
                            key=|(id, _)| *id
                            children=|(id, title)| view! { <DocCard id=id title=title.to_string() /> }
                        />
                        <div class="signout">
                            <Button variant=ButtonVariant::Outline on_click=sign_out>
                                "Sign out"
                            </Button>
                        </div>
                    }
                        .into_any()
                } else {
                    view! {
                        <LoginPanel
                            title="Sign in"
                            description="Register or sign in — any account works; roles are demo-assigned per document."
                            error=Signal::derive(move || {
                                let e = auth_error.get();
                                if e.is_empty() { None } else { Some(e) }
                            })
                            on_submit=on_login
                        />
                    }
                        .into_any()
                }
            }}
        </main>
    }
}

/// One document row: its title, the caller's role badge, and an edit affordance
/// gated by [`ResourceGate`]. Editors see a rename field; everyone else sees a
/// read-only note plus a button that calls the server fn anyway — to show the
/// boundary, not the gate, is what rejects it.
#[component]
fn DocCard(id: i64, title: String) -> impl IntoView {
    let role = use_resource_role("doc".to_string(), id);
    let role_label = move || match role.get() {
        Some(Ok(Some(r))) => r.as_str().to_string(),
        Some(Ok(None)) => "no access".to_string(),
        Some(Err(_)) => "error".to_string(),
        None => "…".to_string(),
    };

    let draft = RwSignal::new(title.clone());
    let result = RwSignal::new(String::new());

    let save = Callback::new(move |_| {
        let new_title = draft.get();
        spawn_local(async move {
            match rename_doc(id, new_title).await {
                Ok(msg) => result.set(msg),
                Err(e) => result.set(friendly_server_error(e)),
            }
        });
    });

    let title_display = title.clone();
    view! {
        <div class="doc-card">
            <div class="doc-head">
                <span class="doc-title">{title_display}</span>
                <span class="doc-role">{role_label}</span>
            </div>
            <ResourceGate
                kind="doc"
                id=id
                min_role=ResourceRole::Editor
                // Shown when the caller is below Editor (or has no relationship).
                fallback=ViewFn::from(move || {
                    view! {
                        <div class="doc-actions">
                            <span class="doc-readonly">"🔒 View-only — no edit rights"</span>
                            <Button variant=ButtonVariant::Outline on_click=save>
                                "Attempt edit anyway"
                            </Button>
                        </div>
                    }
                })
            >
                // Shown when the caller is at least an Editor.
                <div class="doc-actions">
                    <input
                        class="rename-input"
                        prop:value=move || draft.get()
                        on:input=move |ev| draft.set(event_target_value(&ev))
                    />
                    <Button on_click=save>"Save title"</Button>
                </div>
            </ResourceGate>
            <Show when=move || !result.get().is_empty()>
                <p class="doc-result">{move || result.get()}</p>
            </Show>
        </div>
    }
}

/// Rename a document — a resource-scoped mutation, so it is gated by the
/// per-request `require_resource_leptos` check (at least `Editor`). This is the
/// security boundary; the [`ResourceGate`] in the UI only decides whether the
/// field is *shown*. Nothing is persisted — the example just proves the check
/// passed (or, for the "Attempt edit anyway" button, that it was rejected).
#[server(endpoint = "doc/rename")]
pub async fn rename_doc(doc_id: i64, new_title: String) -> Result<String, ServerFnError> {
    use arium_leptos::server::require_resource_leptos;
    let auth: arium_leptos::auth::Session = leptos_axum::extract().await?;
    let db: axum::Extension<arium_leptos::pool::Pool> = leptos_axum::extract().await?;
    let authority: arium_leptos::ResourceAuthorityExt = leptos_axum::extract().await?;
    let audit: arium_leptos::AuditCtx = leptos_axum::extract().await?;
    require_resource_leptos(
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
