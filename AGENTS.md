# AGENTS.md

This file provides guidance to agents when working with code in this repository.

## Commands

```bash
# Run all tests (use tests/ subdir — root-level test_*.py files are integration tests that require a live ODM server)
uv run pytest tests/

# Run a single test
uv run pytest tests/test_mcp_server.py::test_server_initialization

# Run the MCP server
uv run ibm-odm-management-mcp-server --url http://localhost:9060/decisioncenter-api
```

## Critical: pytest asyncio is STRICT mode

Async tests **must** be decorated with `@pytest.mark.asyncio` — they will silently not run as coroutines otherwise. Configured via `pyproject.toml` (`configfile` is picked up automatically by pytest).

## `mcp_types` is a separate package from `mcp`

`Tool`, `Resource`, `CallToolResult`, `TextContent` etc. are imported from `mcp_types`, **not** from `mcp`. The `mcp` SDK (v2 beta, `mcp>=2.0.0b1`) exports `MCPServer` as `mcp.server.MCPServer`. Always import MCP data types from `mcp_types`.

## Tool repositories are split by role

`MCPServer` maintains four separate `dict[str, DecisionCenterEndpoint]` repositories:
- `repository_dc` / `repository_dc_admin` — Decision Center tools, the admin version includes privileged endpoints
- `repository_res_monitor` / `repository_res_deployer` — RES console tools

At runtime, `list_tools()` selects the appropriate pair based on `credentials.isDcAdmin` and `credentials.isResDeployer`. Tests must set both halves of the pair.

## Tool filtering uses lowercase

`tags`, `tools`, and `no_tools` lists are normalized to **lowercase** inside `init()`. Pass already-lowercased values when constructing `MCPServer` directly in tests.

## `call_tool` looks up from admin/deployer repositories only

`call_tool` resolves tools against `repository_dc_admin` and `repository_res_deployer`, not the unprivileged sets. Mock/populate those repos in tests, not `repository_dc`.

## `Credentials` requires at least one URL

`Credentials.__init__` raises `ValueError` if both `odm_url` and `odm_res_url` are `None`. At minimum supply `odm_url`.

## SSL verification: string `"True"` / `"False"` from CLI, bool internally

`parse_arguments()` returns `verifyssl` as the **string** `"True"` or `"False"`. `create_credentials()` converts it: `verifyssl = args.verifyssl != "False"`. When constructing `Credentials` directly, pass a `bool`.

## `test_tools_generation.py` (root level) is a live-server integration test

It calls `MCPServer.init()` against a real ODM instance and will fail collection without one. Run only against a live server; it is excluded from normal CI (`uv run pytest tests/`).

## Trace storage defaults to `~/.ibm-odm-management-mcp-server/traces`

`DiskTraceStorage` creates the directory automatically. Trace filenames follow `{tool_name}-{http_code}-{timestamp_hex}.json`. The special file `parsing.json` stores tool configuration and is excluded from execution listings.

---

## SDK v2 migration notes

Reference: https://github.com/modelcontextprotocol/python-sdk/blob/main/docs/migration.md

This codebase is on branch `upgrade-sdk-v2`. The items below are the SDK v2 breaking changes that are most likely to affect this project.

### `mcp_types` package — already done ✅

`Tool`, `Resource`, `CallToolResult`, `TextContent` etc. must come from `mcp_types`, not `mcp.types` (removed). This is already correct throughout the codebase.

### snake_case field names — verify everywhere

All Pydantic model fields are now **snake_case** for Python attribute access; the JSON wire format is unchanged. Watch for:

| v1 (camelCase) | v2 (snake_case) |
|---|---|
| `inputSchema` | `input_schema` |
| `isError` | `is_error` |
| `nextCursor` | `next_cursor` |
| `mimeType` | `mime_type` |
| `structuredContent` | `structured_content` |

Constructor kwargs still accept both spellings (e.g. `Tool(inputSchema={...})` still works), but **attribute access** must use snake_case. `model_dump()` now emits snake_case — use `model_dump(by_alias=True, mode="json")` to get wire-format camelCase.

### Lowlevel `Server`: decorator-based handlers replaced with `on_*` constructor params

The current code uses direct attribute assignment (`self.server.list_tools = self.list_tools`) which is neither the v1 decorator style nor the v2 `on_*` constructor style. The v2 canonical form is:

```python
server = SDK_MCPServer(
    "ibm-odm-management-mcp-server",
    on_list_tools=self.list_tools,
    on_call_tool=self.call_tool,
    on_list_resources=self.list_resources,
    on_read_resource=self.read_resource,
)
```

Handler signatures in v2 are `async def handler(ctx: ServerRequestContext, params: XxxRequestParams) -> XxxResult`. The current `list_tools` and `call_tool` signatures may need updating.

### `call_tool` handler signature changed

v2 lowlevel handlers receive `(ctx: ServerRequestContext, params: CallToolRequestParams)` and must return a full `CallToolResult`. The current signature `call_tool(self, name, arguments, context)` needs to be updated to accept and destructure a `CallToolRequestParams` object.

### `read_resource` URI type changed from `AnyUrl` to `str`

The current code strips the `file://` prefix with `uri.encoded_string()[len('file://'):]`. In v2, `uri` is a plain `str`, so call `str(uri)` or access it directly — `.encoded_string()` no longer exists.

### Transport parameters moved off the `MCPServer` constructor

`host`, `port`, and `streamable_http_path` are no longer constructor arguments — they are passed to `run()` instead:

```python
# v2
server.run(transport="streamable-http", host=self.host, port=self.port, streamable_http_path=self.path)
```

The current `SDK_MCPServer.__init__` call already does **not** pass these; they are passed to `server.run()` — this is correct for v2.

### `MCPError` (was `McpError`) and `ToolError`

`McpError` → `MCPError`. `ToolError` is still imported from `mcp.server.mcpserver.exceptions` — correct.

### `get_access_token()` context var

`get_access_token()` from `mcp.server.auth.middleware.auth_context` is used to retrieve the bearer token for the current request. This replaces the defunct v1 `get_context().request_context.request.headers` approach and is the correct v2 pattern.
