//! The rmcp `ServerHandler` for the demo, plus two trivial tools (`ping`,
//! `echo`). The tools themselves are unremarkable — the point of the example is
//! that the *endpoint* is gated by arium's bearer-token auth (see `main.rs`),
//! so neither tool is reachable without a valid `dxsk_` token.
//!
//! Standard rmcp 1.7 tool wiring: a `ToolRouter` field set in the constructor,
//! `#[tool_router]` on the tool impl, and `#[tool_handler]` on the
//! `ServerHandler` impl.

use rmcp::{
    ErrorData as McpError, ServerHandler,
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::*,
    tool, tool_handler, tool_router,
};

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct EchoParams {
    /// The text to echo back to the caller.
    pub message: String,
}

#[derive(Clone)]
pub struct DemoMcp {
    #[allow(dead_code)]
    tool_router: ToolRouter<DemoMcp>,
}

#[tool_router]
impl DemoMcp {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            tool_router: Self::tool_router(),
        }
    }

    #[tool(
        description = "Health check — returns 'pong'. Reachable only with a valid arium bearer token."
    )]
    async fn ping(&self) -> Result<CallToolResult, McpError> {
        Ok(CallToolResult::success(vec![Content::text("pong")]))
    }

    #[tool(
        description = "Echo the supplied message back. Demonstrates a parameterized tool behind arium auth."
    )]
    async fn echo(
        &self,
        Parameters(EchoParams { message }): Parameters<EchoParams>,
    ) -> Result<CallToolResult, McpError> {
        Ok(CallToolResult::success(vec![Content::text(message)]))
    }
}

#[tool_handler]
impl ServerHandler for DemoMcp {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::from_build_env())
            .with_instructions(
                "arium-protected demo MCP server. Every request to this endpoint must carry a \
                 valid arium API token (`Authorization: Bearer dxsk_…`); unauthenticated calls \
                 get 401 with a `WWW-Authenticate` challenge pointing at the Protected Resource \
                 Metadata document. Tools: `ping` (returns 'pong') and `echo { message }`."
                    .to_string(),
            )
    }
}
