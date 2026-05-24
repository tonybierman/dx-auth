//! The example application: router, pages, and login wiring. Everything
//! auth-related (server fns, screens, guards) comes from `arium_leptos`.

use arium_leptos::server::{
    login_with_password, logout, register_with_password, resend_verification_email,
};
use arium_leptos::ui::components::button::{Button, ButtonVariant};
use arium_leptos::ui::components::card::{Card, CardContent, CardDescription, CardHeader, CardTitle};
use arium_leptos::ui::components::tabs::{TabContent, TabList, TabTrigger, Tabs};
use arium_leptos::ui::{
    AccountSettings, AdminRoleEditor, AdminRoleList, AdminUserDetail, AdminUserList, ApiTokens,
    AuditLog, ForgotPassword, LoginPanel, LoginSubmit, MfaChallenge, MfaSetup, OAuthProvidersProvider,
    PermissionGate, PermissionsProvider, Policy, RequirePermission, ResetPassword, SubmitKind,
    VerifyEmail, use_oauth_providers, use_permissions,
};
use arium_leptos::wire::UserProfile;
use arium_leptos::{LoginOutcome, friendly_server_error};
use leptos::prelude::*;
use leptos::task::spawn_local;
use leptos_meta::{Title, provide_meta_context};
use leptos_router::components::{Route, Router, Routes};
use leptos_router::hooks::use_query_map;
use leptos_router::path;

const TOKEN_ADMIN_USERS: &str = "admin:users:read";
const TOKEN_ADMIN_AUDIT: &str = "admin:audit:read";
const TOKEN_ADMIN_ROLES: &str = "admin:roles:read";

/// Anyone with at least one admin-tab token may reach `/admin`; individual tabs
/// filter further by their specific token.
fn admin_policy() -> Policy {
    Policy::any_of([TOKEN_ADMIN_USERS, TOKEN_ADMIN_AUDIT, TOKEN_ADMIN_ROLES])
}

/// Small bit of example-only CSS for the app shell + the account screens'
/// app-level `auth-*` classes (the library leaves these to the consumer).
const EXAMPLE_CSS: &str = r#"
.app-shell { max-width: 40rem; margin: 3rem auto; padding: 0 1rem;
  font-family: system-ui, sans-serif; color: var(--secondary-color-1); }
.auth-form { display: flex; flex-direction: column; gap: 0.75rem; }
.auth-field { display: flex; flex-direction: column; gap: 0.375rem; }
.auth-label { font-size: 0.875rem; font-weight: 500; }
.auth-submit { margin-top: 0.5rem; }
.auth-error { color: var(--primary-error-color, #c0392b); font-size: 0.875rem; }
.auth-success { color: var(--secondary-color-4); font-size: 0.875rem; }
.profile-card { display: flex; gap: 1rem; align-items: center; padding: 1rem 0; }
.profile-card-name { font-weight: 600; }
.profile-card-handle { color: var(--secondary-color-4); font-size: 0.875rem; }
.app-actions-buttons { margin-top: 1.5rem; }
.app-admin-link { margin-top: 1rem; }
"#;

#[component]
pub fn App() -> impl IntoView {
    provide_meta_context();
    view! {
        <Title text="arium · Leptos example" />
        <style inner_html=EXAMPLE_CSS></style>
        <PermissionsProvider>
            <OAuthProvidersProvider>
                <Router>
                    <Routes fallback=|| view! { <p class="app-shell">"Not found."</p> }>
                        <Route path=path!("/") view=Home />
                        <Route path=path!("/auth/forgot") view=|| view! { <ForgotPassword /> } />
                        <Route path=path!("/auth/reset") view=ResetRoute />
                        <Route path=path!("/auth/verify") view=VerifyRoute />
                        <Route path=path!("/account/mfa") view=|| view! { <MfaSetup /> } />
                        <Route path=path!("/account/settings") view=AccountPage />
                        <Route path=path!("/admin") view=AdminPage />
                    </Routes>
                </Router>
            </OAuthProvidersProvider>
        </PermissionsProvider>
    }
}

#[component]
fn Home() -> impl IntoView {
    let perms = use_permissions();
    let providers = use_oauth_providers();
    let auth_error = RwSignal::new(String::new());
    let pending_email = RwSignal::new(None::<String>);
    let pending_mfa = RwSignal::new(false);

    let on_login = Callback::new(move |sub: LoginSubmit| {
        auth_error.set(String::new());
        let LoginSubmit { kind, email, password, remember } = sub;
        let email_pending = email.clone();
        spawn_local(async move {
            let result = match kind {
                SubmitKind::SignIn => login_with_password(email, password, remember).await,
                SubmitKind::SignUp => register_with_password(email, password).await,
            };
            match result {
                Ok(LoginOutcome::LoggedIn) => perms.refresh(),
                Ok(LoginOutcome::EmailUnverified) => pending_email.set(Some(email_pending)),
                Ok(LoginOutcome::MfaRequired) => pending_mfa.set(true),
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
            {move || {
                if perms.is_authenticated() {
                    let profile = perms.profile().unwrap_or_default();
                    view! {
                        <ProfileCard profile=profile />
                        <Tabs default_value="account">
                            <TabList>
                                <TabTrigger value="account">"Account"</TabTrigger>
                                <TabTrigger value="mfa">"Two-factor auth"</TabTrigger>
                                <TabTrigger value="tokens">"API tokens"</TabTrigger>
                            </TabList>
                            <TabContent value="account">
                                <AccountSettings />
                            </TabContent>
                            <TabContent value="mfa">
                                <MfaSetup />
                            </TabContent>
                            <TabContent value="tokens">
                                <ApiTokens />
                            </TabContent>
                        </Tabs>
                        <PermissionGate policy=admin_policy()>
                            <p class="app-admin-link">
                                <a href="/admin">"Open admin console →"</a>
                            </p>
                        </PermissionGate>
                        <div class="app-actions-buttons">
                            <Button variant=ButtonVariant::Outline on_click=sign_out>
                                "Sign out"
                            </Button>
                        </div>
                    }
                        .into_any()
                } else if pending_mfa.get() {
                    view! {
                        <MfaChallenge
                            on_logged_in=Callback::new(move |_| {
                                pending_mfa.set(false);
                                perms.refresh();
                            })
                            on_cancel=Callback::new(move |_| {
                                pending_mfa.set(false);
                                auth_error.set(String::new());
                                spawn_local(async move {
                                    let _ = arium_leptos::server::cancel_mfa_challenge().await;
                                });
                            })
                        />
                    }
                        .into_any()
                } else if let Some(email) = pending_email.get() {
                    view! {
                        <VerificationPending
                            email=email
                            on_back=Callback::new(move |_| {
                                pending_email.set(None);
                                auth_error.set(String::new());
                            })
                        />
                    }
                        .into_any()
                } else {
                    view! {
                        <LoginPanel
                            providers=providers
                            title="Welcome back"
                            description="Sign in to your workspace."
                            forgot_href="/auth/forgot"
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

#[component]
fn ProfileCard(profile: UserProfile) -> impl IntoView {
    let display_name = profile.display().to_string();
    let handle = profile.username.clone();
    let email = profile.email.clone();
    view! {
        <div class="profile-card">
            <div class="profile-card-text">
                <div class="profile-card-name">{display_name}</div>
                <div class="profile-card-handle">{format!("@{handle}")}</div>
                {email.map(|addr| view! { <div class="profile-card-email">{addr}</div> })}
            </div>
        </div>
    }
}

#[component]
fn VerificationPending(email: String, on_back: Callback<()>) -> impl IntoView {
    let resending = RwSignal::new(false);
    let resent = RwSignal::new(false);
    let email_resend = email.clone();
    view! {
        <Card class="login-panel">
            <CardHeader>
                <CardTitle>"Check your inbox"</CardTitle>
                <CardDescription>
                    "We sent a verification link to " <strong>{email}</strong>
                    ". Click it to finish signing in."
                </CardDescription>
            </CardHeader>
            <CardContent>
                <div class="auth-form">
                    <Show when=move || resent.get()>
                        <p class="auth-success">"Sent another link."</p>
                    </Show>
                    <Button
                        variant=ButtonVariant::Outline
                        on_click=Callback::new(move |_| {
                            let email = email_resend.clone();
                            resending.set(true);
                            spawn_local(async move {
                                let _ = resend_verification_email(email).await;
                                resending.set(false);
                                resent.set(true);
                            });
                        })
                    >
                        {move || if resending.get() { "Sending…" } else { "Resend verification email" }}
                    </Button>
                    <p class="auth-aux">
                        <a
                            href="#"
                            on:click=move |ev| {
                                ev.prevent_default();
                                on_back.run(());
                            }
                        >
                            "Back to sign in"
                        </a>
                    </p>
                </div>
            </CardContent>
        </Card>
    }
}

#[component]
fn ResetRoute() -> impl IntoView {
    let query = use_query_map();
    let token = query
        .read_untracked()
        .get("token")
        .unwrap_or_default();
    view! { <ResetPassword token=token /> }
}

#[component]
fn VerifyRoute() -> impl IntoView {
    let query = use_query_map();
    let token = query
        .read_untracked()
        .get("token")
        .unwrap_or_default();
    view! { <VerifyEmail token=token /> }
}

#[component]
fn AccountPage() -> impl IntoView {
    view! {
        <main class="app-shell">
            <AccountSettings />
            <p class="auth-aux">
                <a href="/">"← Back to home"</a>
            </p>
        </main>
    }
}

/// Admin console: gated behind `admin_policy`, with its own tabset. Each tab is
/// further pruned to the specific permission its surface needs.
#[component]
fn AdminPage() -> impl IntoView {
    let perms = use_permissions();
    let selected = RwSignal::new(None::<i64>);
    // Role pane: None = list, Some(None) = new, Some(Some(id)) = edit.
    let role_pane = RwSignal::new(None::<Option<i64>>);

    let default_tab = move || {
        if perms.has(TOKEN_ADMIN_USERS) {
            "users"
        } else if perms.has(TOKEN_ADMIN_AUDIT) {
            "audit"
        } else {
            "roles"
        }
    };

    view! {
        <RequirePermission policy=admin_policy() redirect_to="/">
            <main class="app-shell">
                {move || {
                    view! {
                        <Tabs default_value=default_tab()>
                            <TabList>
                                <PermissionGate token=TOKEN_ADMIN_USERS.to_string()>
                                    <TabTrigger value="users">"Users"</TabTrigger>
                                </PermissionGate>
                                <PermissionGate token=TOKEN_ADMIN_AUDIT.to_string()>
                                    <TabTrigger value="audit">"Audit log"</TabTrigger>
                                </PermissionGate>
                                <PermissionGate token=TOKEN_ADMIN_ROLES.to_string()>
                                    <TabTrigger value="roles">"Roles"</TabTrigger>
                                </PermissionGate>
                            </TabList>
                            <TabContent value="users">
                                {move || match selected.get() {
                                    Some(uid) => {
                                        view! {
                                            <AdminUserDetail
                                                user_id=uid
                                                on_back=Callback::new(move |_| selected.set(None))
                                            />
                                        }
                                            .into_any()
                                    }
                                    None => {
                                        view! {
                                            <AdminUserList on_select=Callback::new(move |id: i64| {
                                                selected.set(Some(id))
                                            }) />
                                        }
                                            .into_any()
                                    }
                                }}
                            </TabContent>
                            <TabContent value="audit">
                                <AuditLog />
                            </TabContent>
                            <TabContent value="roles">
                                {move || match role_pane.get() {
                                    Some(rid_opt) => {
                                        view! {
                                            <AdminRoleEditor
                                                role_id=rid_opt
                                                on_back=Callback::new(move |_| role_pane.set(None))
                                            />
                                        }
                                            .into_any()
                                    }
                                    None => {
                                        view! {
                                            <AdminRoleList
                                                on_select=Callback::new(move |id: i64| {
                                                    role_pane.set(Some(Some(id)))
                                                })
                                                on_new=Callback::new(move |_| role_pane.set(Some(None)))
                                            />
                                        }
                                            .into_any()
                                    }
                                }}
                            </TabContent>
                        </Tabs>
                    }
                }}
                <p class="auth-aux">
                    <a href="/">"← Back to home"</a>
                </p>
            </main>
        </RequirePermission>
    }
}
