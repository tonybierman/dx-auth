use crate::ui::components::button::{Button, ButtonVariant};
use crate::ui::components::card::{Card, CardDescription, CardHeader, CardTitle};
use crate::ui::components::input::Input;
use crate::ui::components::label::Label;
use leptos::prelude::*;

/// One third-party login provider entry.
///
/// `href` is the server-side route that starts the OAuth dance (e.g.
/// `/auth/github/login`). `icon_svg` is optional inline SVG markup.
#[derive(Clone, PartialEq)]
pub struct LoginProvider {
    /// Button label (e.g. `"GitHub"`).
    pub name: String,
    /// Server-side route that starts the OAuth dance.
    pub href: String,
    /// Optional inline SVG markup for the button icon.
    pub icon_svg: Option<String>,
}

impl From<crate::wire::ProviderInfo> for LoginProvider {
    fn from(info: crate::wire::ProviderInfo) -> Self {
        Self {
            name: info.display_name,
            href: info.login_url,
            icon_svg: info.icon_svg,
        }
    }
}

/// Which mode the email/password form is in.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum SubmitKind {
    /// Existing user signing in.
    #[default]
    SignIn,
    /// New user registering an account.
    SignUp,
}

/// Payload delivered to `LoginPanel`'s `on_submit`. `remember` is only
/// meaningful on `SignIn`.
#[derive(Clone, PartialEq, Debug, Default)]
pub struct LoginSubmit {
    /// Sign-in vs. sign-up form mode at submit time.
    pub kind: SubmitKind,
    /// Email the user typed.
    pub email: String,
    /// Password the user typed.
    pub password: String,
    /// "Remember me" checkbox state. Only meaningful when `kind == SignIn`.
    pub remember: bool,
}

/// A reusable "Sign in" card with an email + password form (toggleable into
/// sign-up mode) and an optional list of third-party providers below it.
#[component]
pub fn LoginPanel(
    #[prop(optional, into)] providers: Signal<Vec<LoginProvider>>,
    #[prop(default = "Welcome back")] title: &'static str,
    #[prop(default = "Sign in to your workspace.")] description: &'static str,
    #[prop(default = "Sign in")] submit_label: &'static str,
    #[prop(default = "Create your account")] signup_title: &'static str,
    #[prop(default = "Start a new workspace.")] signup_description: &'static str,
    #[prop(default = "Create account")] signup_submit_label: &'static str,
    #[prop(default = "you@example.com")] email_placeholder: &'static str,
    #[prop(default = "••••••••")] password_placeholder: &'static str,
    #[prop(optional)] forgot_href: Option<&'static str>,
    #[prop(default = true)] show_email_password: bool,
    #[prop(optional, into)] error: Signal<Option<String>>,
    #[prop(optional)] on_submit: Option<Callback<LoginSubmit>>,
) -> impl IntoView {
    let email = RwSignal::new(String::new());
    let password = RwSignal::new(String::new());
    let password_confirm = RwSignal::new(String::new());
    let mode = RwSignal::new(SubmitKind::SignIn);
    let remember = RwSignal::new(false);
    let local_error = RwSignal::new(String::new());

    let is_signup = move || mode.get() == SubmitKind::SignUp;

    let displayed_error = move || {
        let local = local_error.get();
        if !local.is_empty() {
            Some(local)
        } else {
            error.get().filter(|e| !e.is_empty())
        }
    };

    let on_form_submit = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
        let email_val = email.get_untracked();
        let password_val = password.get_untracked();
        let signup = mode.get_untracked() == SubmitKind::SignUp;

        if signup && password_val != password_confirm.get_untracked() {
            local_error.set("Passwords don't match.".to_string());
            return;
        }
        local_error.set(String::new());

        if let Some(handler) = on_submit {
            handler.run(LoginSubmit {
                kind: mode.get_untracked(),
                email: email_val,
                password: password_val,
                remember: remember.get_untracked() && !signup,
            });
        }

        // Wipe password fields after dispatching so a refused login doesn't
        // leave the password sitting in the DOM.
        password.set(String::new());
        password_confirm.set(String::new());
    };

    view! {
        <Card class="login-panel">
            <CardHeader>
                <CardTitle>{move || if is_signup() { signup_title } else { title }}</CardTitle>
                <CardDescription>
                    {move || if is_signup() { signup_description } else { description }}
                </CardDescription>
            </CardHeader>

            <Show when=move || show_email_password>
                <form class="login-form" on:submit=on_form_submit>
                    <div class="login-field">
                        <Label html_for="login-email" class="login-label">
                            "Email"
                        </Label>
                        <Input
                            id="login-email"
                            name="email"
                            input_type="email"
                            autocomplete="email"
                            placeholder=email_placeholder
                            value=email
                            on_input=Callback::new(move |v: String| email.set(v))
                        />
                    </div>

                    <div class="login-field">
                        <div class="login-label-row">
                            <Label html_for="login-password" class="login-label">
                                "Password"
                            </Label>
                            <Show when=move || !is_signup() && forgot_href.is_some()>
                                <a class="login-forgot" href=forgot_href.unwrap_or("#")>
                                    "Forgot?"
                                </a>
                            </Show>
                        </div>
                        <Input
                            id="login-password"
                            name="password"
                            input_type="password"
                            autocomplete="current-password"
                            placeholder=password_placeholder
                            value=password
                            on_input=Callback::new(move |v: String| password.set(v))
                        />
                    </div>

                    <Show
                        when=move || is_signup()
                        fallback=move || {
                            view! {
                                <label class="login-remember">
                                    <input
                                        type="checkbox"
                                        prop:checked=move || remember.get()
                                        on:change=move |ev| remember.set(event_target_checked(&ev))
                                    />
                                    <span>"Remember me on this device"</span>
                                </label>
                            }
                        }
                    >
                        <div class="login-field">
                            <Label html_for="login-password-confirm" class="login-label">
                                "Confirm password"
                            </Label>
                            <Input
                                id="login-password-confirm"
                                name="password_confirm"
                                input_type="password"
                                autocomplete="new-password"
                                placeholder=password_placeholder
                                value=password_confirm
                                on_input=Callback::new(move |v: String| password_confirm.set(v))
                            />
                        </div>
                    </Show>

                    <Show when=move || displayed_error().is_some()>
                        <div class="login-error" role="alert">
                            {move || displayed_error().unwrap_or_default()}
                        </div>
                    </Show>

                    <Button variant=ButtonVariant::Primary button_type="submit" class="login-submit">
                        {move || if is_signup() { signup_submit_label } else { submit_label }}
                    </Button>

                    <div class="login-toggle">
                        <span>
                            {move || {
                                if is_signup() {
                                    "Already have an account? "
                                } else {
                                    "Don't have an account? "
                                }
                            }}
                        </span>
                        <button
                            class="login-toggle-button"
                            type="button"
                            on:click=move |_| {
                                let next = if is_signup() {
                                    SubmitKind::SignIn
                                } else {
                                    SubmitKind::SignUp
                                };
                                mode.set(next);
                                local_error.set(String::new());
                                password.set(String::new());
                                password_confirm.set(String::new());
                            }
                        >
                            {move || if is_signup() { "Sign in" } else { "Sign up" }}
                        </button>
                    </div>
                </form>
            </Show>

            <Show when=move || !providers.get().is_empty()>
                <div class="login-providers">
                    {move || {
                        providers
                            .get()
                            .into_iter()
                            .map(|p| view! { <ProviderLink provider=p /> })
                            .collect_view()
                    }}
                </div>
            </Show>
        </Card>
    }
}

#[component]
fn ProviderLink(provider: LoginProvider) -> impl IntoView {
    let LoginProvider {
        name,
        href,
        icon_svg,
    } = provider;
    let label = format!("Continue with {name}");
    view! {
        <a class="login-provider-button" href=href>
            {icon_svg
                .map(|svg| view! { <span class="login-provider-icon" inner_html=svg></span> })}
            {label}
        </a>
    }
}
