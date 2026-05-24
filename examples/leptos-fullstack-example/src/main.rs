//! SSR server for the example. Wires the arium engine (`arium::install`) onto
//! the axum router that also serves the Leptos app + server-fn endpoints.

#[cfg(feature = "ssr")]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    use axum::Router;
    use axum::routing::post;
    use leptos::config::get_configuration;
    use leptos::prelude::*;
    use leptos_axum::{
        LeptosRoutes, file_and_error_handler, generate_route_list, handle_server_fns,
    };
    use leptos_fullstack_example::app::App;
    use leptos_fullstack_example::shell;
    use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
    use std::str::FromStr;

    // DB location: `DATABASE_URL` when set (e.g. the Docker image passes
    // `sqlite:///app/data/auth-leptos.db?mode=rwc`), otherwise a dev default
    // under the workspace `target/` dir (gitignored), not the example's cwd.
    let connect_opts = match std::env::var("DATABASE_URL") {
        Ok(url) if !url.trim().is_empty() => SqliteConnectOptions::from_str(&url)?,
        _ => SqliteConnectOptions::new()
            .filename(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../target/auth-leptos.db"
            ))
            .create_if_missing(true),
    };
    let pool = SqlitePoolOptions::new()
        .max_connections(20)
        .connect_with(connect_opts)
        .await?;
    arium_leptos::migrator().run(&pool).await?;

    let mailer = arium_leptos::Mailer::from_env()?;
    println!("[startup] mailer backend: {}", mailer.describe());

    let builder = arium_leptos::AuthConfig::builder(pool.clone(), mailer.clone());
    let builder = match arium_leptos::oauth::github::GithubProvider::from_env()? {
        Some(gh) => {
            println!("[startup] GitHub OAuth: enabled");
            builder.oauth_provider(gh)?
        }
        None => {
            println!("[startup] GitHub OAuth: disabled");
            builder
        }
    };
    // Google sign-in via the OIDC engine (build with `--features oauth-google`).
    // `from_env` is async — it runs OIDC discovery against accounts.google.com.
    #[cfg(feature = "oauth-google")]
    let builder = match arium_leptos::oauth::google::GoogleProvider::from_env().await? {
        Some(google) => {
            println!("[startup] Google OAuth: enabled");
            builder.oauth_provider(google)?
        }
        None => {
            println!("[startup] Google OAuth: disabled");
            builder
        }
    };
    let cfg = builder.build()?;

    let conf = get_configuration(None)?;
    let leptos_options = conf.leptos_options;
    let routes = generate_route_list(App);

    // Server fns extract their request context (auth session, db pool, mailer,
    // …) from the axum extensions `install` layers on below — no extra
    // `provide_context` needed.
    let app = Router::new()
        .route("/api/{*fn_name}", post(handle_server_fns))
        .leptos_routes(&leptos_options, routes, {
            let opts = leptos_options.clone();
            move || shell(opts.clone())
        })
        .fallback(file_and_error_handler::<LeptosOptions, _>(shell))
        .with_state(leptos_options.clone());

    // `install` layers AuthSessionLayer + SessionLayer (+ OAuth routes, rate
    // limiter, Pool/Mailer/Providers extensions) over the whole router.
    let app = arium_leptos::install(app, cfg).await?;

    let addr = leptos_options.site_addr;
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    println!("[startup] listening on http://{addr}");
    axum::serve(listener, app.into_make_service()).await?;
    Ok(())
}

#[cfg(not(feature = "ssr"))]
fn main() {}
