//! SSR server for the Leptos membership demo. Wires the arium engine
//! (`arium_leptos::install`) onto the axum router that serves the Leptos app +
//! server-fn endpoints, and registers the app's [`DemoAuthority`] so the
//! per-resource gate and boundary can reach it.

#[cfg(feature = "ssr")]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    use std::sync::Arc;

    use axum::Router;
    use axum::routing::post;
    use leptos::config::get_configuration;
    use leptos::prelude::*;
    use leptos_axum::{
        LeptosRoutes, file_and_error_handler, generate_route_list, handle_server_fns,
    };
    use leptos_authz_example::app::App;
    use leptos_authz_example::shell;

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
                    "/../../target/authz-leptos.db"
                ))
                .create_if_missing(true),
        };
        SqlitePoolOptions::new()
            .max_connections(20)
            .connect_with(connect_opts)
            .await?
    };
    arium_leptos::migrator().run(&pool).await?;

    // The one line that wires per-resource authorization in: register the app's
    // `ResourceAuthority`. `install` layers it as an extension so the
    // `get_resource_role` / `require_resource_leptos` extractors can reach it.
    let authority: arium_leptos::SharedResourceAuthority = Arc::new(DemoAuthority);
    let cfg = arium_leptos::AuthConfig::builder(pool)
        .resource_authority(authority)
        .build()?;

    let conf = get_configuration(None)?;
    let leptos_options = conf.leptos_options;
    let routes = generate_route_list(App);

    let app = Router::new()
        .route("/api/{*fn_name}", post(handle_server_fns))
        .leptos_routes(&leptos_options, routes, {
            let opts = leptos_options.clone();
            move || shell(opts.clone())
        })
        .fallback(file_and_error_handler::<LeptosOptions, _>(shell))
        .with_state(leptos_options.clone());

    // `install` layers AuthSessionLayer + SessionLayer (+ the Pool / Providers /
    // ResourceAuthority extensions) over the whole router.
    let app = arium_leptos::install(app, cfg).await?;

    let addr = leptos_options.site_addr;
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    println!("[startup] listening on http://{addr}");
    axum::serve(listener, app.into_make_service()).await?;
    Ok(())
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
#[cfg(feature = "ssr")]
struct DemoAuthority;

#[cfg(feature = "ssr")]
#[async_trait::async_trait]
impl arium_leptos::ResourceAuthority for DemoAuthority {
    async fn role_on(
        &self,
        _db: &arium_leptos::pool::Pool,
        _user_id: i64,
        r: arium_leptos::ResourceRef<'_>,
    ) -> anyhow::Result<Option<arium_leptos::ResourceRole>> {
        use arium_leptos::ResourceRole;
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

#[cfg(not(feature = "ssr"))]
fn main() {}
