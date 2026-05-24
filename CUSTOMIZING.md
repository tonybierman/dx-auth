# Customizing the UI

Everything `arium-dioxus` / `arium-leptos` render under the `ui` feature — the
`LoginPanel`, the MFA screens, the account and admin screens, and the catalog
widgets they're built from — is brandable along two axes:

1. **Copy** — titles, button labels, placeholders, the provider buttons — via
   **component props**. No CSS required.
2. **Appearance** — colors, light/dark, the whole palette — by **overriding the
   theme's CSS custom properties**.

Both axes work identically across the two adapters; only the prop *syntax*
(`#[props(...)]` vs `#[prop(...)]`, `Vec<T>` vs `Signal<Vec<T>>`) and the
mechanics of *loading* the stylesheet differ. Those adapter-specific bits — how
the theme is delivered and how the cascade is ordered — live in
[CONFIG_DIOXUS.md](CONFIG_DIOXUS.md#customizing-the-ui) and
[CONFIG_LEPTOS.md](CONFIG_LEPTOS.md#customizing-the-ui). This document covers the
shared surface.

## Branding the copy (props)

Pass props to the drop-in screen components to relabel them — no forking, no
CSS. Defaults are shown so you only override what you need.

### `LoginPanel`

| Prop | Default | What it sets |
| --- | --- | --- |
| `title` | `"Welcome back"` | Heading in sign-in mode. |
| `description` | `"Sign in to your workspace."` | Subheading in sign-in mode. |
| `submit_label` | `"Sign in"` | Submit-button text in sign-in mode. |
| `signup_title` | `"Create your account"` | Heading in sign-up mode. |
| `signup_description` | `"Start a new workspace."` | Subheading in sign-up mode. |
| `signup_submit_label` | `"Create account"` | Submit-button text in sign-up mode. |
| `email_placeholder` | `"you@example.com"` | Email field placeholder. |
| `password_placeholder` | `""` (empty) | Password field placeholder. Empty so an unfilled field doesn't look pre-filled; set it if you want a hint. |
| `forgot_href` | _(none)_ | When set, renders a "Forgot?" link below the password field pointing here. Omit it to hide the link. |
| `show_email_password` | `true` | Set `false` for an OAuth-only panel (hides the whole email/password form). |
| `providers` | _(empty)_ | OAuth buttons — see [Provider buttons](#provider-buttons-oauth). |
| `error` | _(none)_ | A server-supplied error to surface above the submit button. |
| `on_submit` | _(none)_ | Handler receiving `LoginSubmit { kind, email, password, remember }`. |

### `MfaSetup`

| Prop | Default | What it sets |
| --- | --- | --- |
| `title` | `"Two-factor authentication"` | Screen heading. |
| `back_href` | `"/"` | Where to send a visitor who isn't authenticated. |

### `MfaChallenge`

| Prop | Default | What it sets |
| --- | --- | --- |
| `title` | `"Two-factor authentication"` | Screen heading. |
| `on_logged_in` | _(required)_ | Fired after a valid TOTP / recovery code. |
| `on_cancel` | _(required)_ | Fired when the user backs out. |

> **No prop?** `AccountSettings`, the admin `AuditLog`, `VerifyEmail`,
> `ForgotPassword`, and `ResetPassword` render fixed copy. To change their
> wording, restyle with CSS or copy the component out of the crate and wire your
> own — they're thin shells over the same catalog widgets and server fns.

## Provider buttons (OAuth)

Each "Continue with …" button comes from a `LoginProvider` in the `providers`
list:

```rust
pub struct LoginProvider {
    pub name: String,            // button label → "Continue with {name}"
    pub href: String,            // server route that starts the OAuth flow
    pub icon_svg: Option<String>, // inline SVG markup for the leading icon
}
```

In practice you don't build these by hand: `OAuthProvidersProvider` fetches the
configured providers from the server and feeds the list into `LoginPanel` for
you, so the buttons reflect whichever OAuth features are compiled in and
configured (see the env-var sections in the CONFIG docs). `LoginProvider`
implements `From<ProviderInfo>`, so the display name, login URL, and icon all
flow from the server-side provider registry. To rebrand a button — a different
label or a custom logo — adjust the provider's display name / `icon_svg` at the
registry, or construct your own `Vec<LoginProvider>` and pass it to `providers`
directly.

## Theming the palette (CSS custom properties)

Every catalog widget and auth screen draws its colors from a small set of CSS
custom properties — never from hard-coded hex. Redefine those properties and the
entire UI re-skins at once. The default values are the **single source of
truth** in the theme asset (`assets/dx-components-theme.css` in either crate),
exposed in code as `DEFAULT_THEME_CSS`.

The token groups:

| Group | Tokens | Drives |
| --- | --- | --- |
| Primary | `--primary-color`, `--primary-color-1` … `--primary-color-7` | Surfaces / backgrounds / borders (light→dark ramp). |
| Secondary | `--secondary-color`, `--secondary-color-1` … `--secondary-color-6` | Text and foreground elements. |
| Focus | `--focused-border-color` | Focus-ring / focused-border color. |
| Semantic | `--primary-success-color`, `--secondary-success-color`, `--primary-warning-color`, `--secondary-warning-color`, `--primary-error-color`, `--secondary-error-color`, `--contrast-error-color`, `--primary-info-color`, `--secondary-info-color` | Success / warning / error / info states (badges, destructive buttons, alerts). |

### Light and dark

The defaults bake in both modes with a one-line-per-token trick:

```css
--primary-color: var(--dark, #000) var(--light, #fff);
```

`html[data-theme="dark"]` sets `--dark: initial; --light: ;` (and vice-versa),
so exactly one of the two values survives — `#000` in dark mode, `#fff` in
light. With no `data-theme` attribute, `:root` falls back to the OS
`prefers-color-scheme`. So you get system-follows-OS for free, and your app can
force a mode by setting `data-theme` on `<html>`.

### Overriding tokens

Define the same property names in your own stylesheet and make sure it lands
**after** the default theme in the cascade (the per-adapter sections explain how
the ordering works for each). You only need the tokens you're actually changing:

```css
/* brand.css — pin your palette regardless of light/dark */
:root {
  --secondary-color-2: #6d28d9;     /* primary button fill / brand accent */
  --focused-border-color: #6d28d9;  /* matching focus ring */
}
```

To keep light/dark behavior, reuse the same `var(--dark, …) var(--light, …)`
pattern in your overrides instead of a flat value. To re-skin wholesale, define
the full set rather than vendoring (and drifting from) a copy of the default
file.

## Catalog widgets and variants

The screens are assembled from a catalog of primitives (`Button`, `Input`,
`Card`, `Checkbox`, `Select`, `Badge`, `Avatar`, `AlertDialog`, `Tabs`,
`Pagination`, `Separator`, `Skeleton`, …) under `arium_{dioxus,leptos}::ui`. They
expose appearance via typed props rather than free-form classes — e.g.
`Button` takes `ButtonVariant` (`Primary`, `Secondary`, `Destructive`,
`Outline`, `Ghost`, `Link`) and `ButtonSize` (`Xs`, `Sm`, `Default`, `Lg`, and
the `Icon*` sizes). Each variant reads the palette tokens above, so overriding a
token re-skins every variant consistently — you rarely need to touch a widget's
own CSS.

> **Restyling by class name is adapter-specific.** The Dioxus catalog scopes its
> class names (a `#[css_module]` hashes `dx-button` etc.), so an external
> stylesheet *cannot* target `.dx-button` — override tokens instead. The Leptos
> catalog uses plain global class names, so you *can* also target them directly.
> The mechanics and consequences are spelled out in each CONFIG doc.
