# leptos-authz-example

The Leptos parallel of [dioxus-authz-example](../dioxus-authz-example): the
smallest faithful demo of arium's **per-resource membership** authorization in
[`arium-leptos`](../../crates/arium-leptos) — the second authorization axis (a
user's role on *one* resource), kept apart from everything else so the
membership story stands alone.

For the everything-on tour (OAuth, MFA, mail, API tokens, admin console) see
[leptos-fullstack-example](../leptos-fullstack-example).

## Run

```bash
cargo leptos serve -p leptos-authz-example
```

Open <http://127.0.0.1:3100> and register any account — signup logs you straight
in (no email round-trip; this example builds the adapter without `mail`). The
dev SQLite DB is `target/authz-leptos.db` (`rm` it to start fresh). Needs
[`cargo-leptos`](https://book.leptos.dev/ssr/21_cargo_leptos.html).

## What it shows

Every signed-in user is given a fixed role on four demo documents, so the whole
role lattice is on one screen:

| Document          | Role     | Rename field? | Server fn (`require ≥ Editor`) |
|-------------------|----------|---------------|--------------------------------|
| Team roadmap      | `Owner`  | shown         | accepted                       |
| Design notes      | `Editor` | shown         | accepted                       |
| Company handbook  | `Viewer` | hidden        | **rejected**                   |
| Q3 board minutes  | (none)   | hidden        | **rejected**                   |

Three pieces, and only these three:

1. **`DemoAuthority`** (in `main.rs`) implements arium's
   `ResourceAuthority::role_on` — the one method an app writes to plug its own
   membership storage into arium. arium stores no memberships itself; it calls
   this on every check. A real app reads a `doc_members` table keyed on the
   user; this demo returns a fixed role per document id. Registered once via
   `AuthConfigBuilder::resource_authority(...)`.

2. **`ResourceGate`** is a *cosmetic* UI gate — it only decides whether the
   rename field is shown. Hiding a control is not a security boundary.

3. **`rename_doc`** is the resource-scoped mutation. It calls
   `require_resource_leptos(.., ResourceRole::Editor)` first — a fresh,
   per-request, default-deny check, and the *real* boundary. The "Attempt edit
   anyway" button on the view-only documents proves the point: the request
   reaches the server and is rejected there, gate or no gate.

The two layers map to the engine's `arium::authz` module — see its docs for the
global-RBAC vs. per-resource distinction.
