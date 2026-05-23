//! Drop-in API token management UI.
//!
//! Gated on `feature = "tokens"`. Mount on a route like `/account/tokens`
//! (or inside an account-settings tab) after the user is signed in.
//!
//! Drives [`crate::server::create_api_token`],
//! [`crate::server::list_api_tokens`], and
//! [`crate::server::revoke_api_token`].

mod component;

pub use component::ApiTokens;
