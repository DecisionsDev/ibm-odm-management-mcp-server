# User authentication in remote mode

When the MCP server runs remotely, the challenge is to let the MCP server impersonate the user who runs a tool. In other words, have the MCP server use the credentials of that user when logging in to ODM.

This ensures that:
- each user only has access to the data in Decision Center it is supposed to see and be able to modify
- that any changes in Decision Center are recorded in history against the user who made the changes
- that the user only has access to the tools that his role gives access to

This page explains how to configure the Management MCP server so that it uses the users credentials in remote mode.



https://github.com/user-attachments/assets/2a7dcf8b-bc40-4290-8361-718663afe523



## 1. Requirements

> [!IMPORTANT]
> The Management MCP server can use the users credentials in remote mode only if the following conditions are met:
> - ODM needs to be configured to use OpenID Connect
> - The OpenID Connect Client needs to be secured with a Client Secret

## 2. Configuration

### 2.1 MCP server configuration

- The MCP server must be started with some additional mandatory parameters specific to this usage:

    | CLI Argument | Environment Variable | Description |
    |--------------|----------------------|-------------|
    | `--mcp-ext-url` | `MCP_EXT_URL` | MCP server external URL |
    | `--issuer-url` | `ISSUER_URL` | OpenID Connect issuer URL |
    | `--jwks-url` | `JWKS_URL` | **Option 1**:  OpenID Connect JWKS URI. When provided, bearer tokens are verified locally against the IdP public keys instead of calling the introspection or userinfo endpoint on every request. Signing keys are cached by `kid` (up to 10 entries). |
    | `--jwt-algorithms` | `JWT_ALGORITHMS` | **Option 1**:  Optional space-separated list of accepted JWT signing algorithms. Only used when `--jwks-url` is set. Default: `RS256 RS384 RS512 ES256 ES384 ES512 PS256`. |
    | `--introspection-url` | `INTROSPECTION_URL` | **Option 2**: OpenID Connect introspection URL. Either this or `--userinfo-url` is required. |
    | `--userinfo-url` | `USERINFO_URL` | **Option 3**: OpenID Connect userinfo URL. Alternative to `--introspection-url` for providers (e.g. Amazon Cognito) that do not support token introspection. |

    - The MCP external URL is the URL that is configured in the AI assistant to access the MCP server (with or without the path `/mcp` appended, eg. `https://my-mcp-server.com`). This URL MUST match the URL configured in the AI assistant (see [2.3 AI Assistant configuration](#23-ai-assistant-configuration)).
    - The issuer URL can be found in the `issuer` field of the `.well-known/openid-configuration` document of the OpenID Connect server.
    - the other parameters are needed to validate tokens:
        - Use `--jwks-url` (the `jwks_uri` field in the discovery document) along with `--jwt-algorithms` to verify tokens locally (after downloading the key) without a network round-trip on every request
        - or use `--introspection-url` if your provider exposes an introspection endpoint (`introspection_endpoint` in the discovery document),
        - or use `--userinfo-url` if it exposes a userinfo endpoint instead (`userinfo_endpoint` in the discovery document, e.g. Amazon Cognito).

> [!NOTE]
> - At least one means of validation must be configured.
> - If several are configured, each means is used in order, until enables to validate the token.
> - The default order is: JWKS, introspection, userinfo
> - The order can be redefined by setting the environment variable TOKEN_VALIDATION_ORDER, to "introspection, jwks" for instance if userinfo should not be used and introspection should be used in priority.

- The MCP server also needs the following parameters to validate the users tokens:

    | CLI Argument | Environment Variable | Description |
    |--------------|----------------------|-------------|
    | `--client-id`     | `CLIENT_ID`     | OpenID Connect client ID |
    | `--client-secret` | `CLIENT_SECRET` | OpenID Connect client Secret |

- Last the MCP server can optionally be configured with credentials of its own:

    - In which case the MCP server generates the list of all the tools during startup, which speeds up the connection of the AI assistant to the MCP server.
        - those credentials must grant at least the `resMonitor` role.
    - Otherwise the MCP server:
        - generates the list of Decision Center tools during startup (as not authentication is required).
        - generates the list of RES console tools when a user who has the `resMonitor` role connects (using the user's credentials).

    You can either use:
    - the client credentials grant if it is available, in which case you must provide the following parameters as well:

        | CLI Argument | Environment Variable | Description |
        |--------------|----------------------|-------------|
        | `--token-url`     | `TOKEN_URL`     | OpenID Connect token URL |
        | `--scope`         | `SCOPE`         | OpenID Connect scope used when requesting an access token with the client_credentials grant (`openid` by default)  |

    - or the password grant using a service account, in which case you must provide the following parameters:

        | CLI Argument | Environment Variable | Description |
        |--------------|----------------------|-------------|
        | `--token-url`     | `TOKEN_URL`     | OpenID Connect token URL |
        | `--scope`         | `SCOPE`         | OpenID Connect scope used when requesting an access token with the password grant (`openid` by default)  |
        | `--username`      | `ODM_USERNAME`  | Username of a service account defined in the OpenId Connect Provider |
        | `--password`      | `ODM_PASSWORD`  | Password of a service account defined in the OpenId Connect Provider |

- Example:
    - with Keycloak as OpenID Connect Provider
    - and using the client_credentials grant

    ```bash
    uv run ibm-odm-management-mcp-server \
        --transport         streamable-http \
        --url               https://my-business-console-server.com/decisioncenter-api \
        --res-url           https://my-res-console-server.com/res \
        --token-url         https://my-keycloak-server.com/auth/realms/myrealm/protocol/openid-connect/token \
        --introspection-url https://my-keycloak-server.com/auth/realms/myrealm/protocol/openid-connect/token/introspect \
        --issuer-url        https://my-keycloak-server.com/auth/realms/myrealm \
        --mcp-ext-url       https://my-mcp-server.com \
        --ssl-cert-path     /path/to/certificate_filename.pem \
        --client-id         <OPENID_CLIENT_ID> \
        --client-secret     <OPENID_CLIENT_SECRET> \
        --trace             EXECUTIONS_WITH_CONTENT CONFIGURATION \
        --log-level         INFO
    ```

### 2.2 OpenID Connect Client configuration

A URI needs to be configured in the OpenID Connect client as a valid redirect URI. 
- This URI is used by the client-side `mcp-remote` command line tool when authenticating the user.
- This URI is `http://localhost:34206/oauth/callback` if you configure `mcp-remote` as suggested in the next chapter [2.3 AI Assistant configuration](#23-ai-assistant-configuration).

You can get more background in [3.1 How Things work](#31-how-things-work).

### 2.3 AI Assistant configuration

1. Create a JSON file named `oauth_client_info.json` with the content below and replace `OPENID_CLIENT_ID` and `OPENID_CLIENT_SECRET` with the values of your OpenID Connect client:
    ```json
    {
        "client_id":     "OPENID_CLIENT_ID",
        "client_secret": "OPENID_CLIENT_SECRET"
    }
    ```

1. Find the configuration file of your AI assistant.
    - check our READMEs for [Claude](./Claude-desktop-integration-guide.md) and [IBM Bob](./IBM-Bob-integration-guide.md) to get instructions
    - if you use IBM Bob and keep several windows opened, then it is best to use the local configuration file **Project MCPs** (rather than the **Global MCPs** configuration file)
        - otherwise, all the IBM Bob windows would try to authenticate the user at the same time and might fail.

1. Edit the configuration file of your AI assistant with the content below:
    - replace `https://my-mcp-server.com/mcp` with the URL of your MCP server
    - replace `/path/to/oauth_client_info.json` with the path to the `oauth_client_info.json` file you created in the previous step
    - replace `/path/to/ca.pem` with the path to the CA certificate used to sign the MCP server certificate (or the MCP server certificate file)

    ```json
    {
        "mcpServers": {
            "ibm-odm-management-mcp-server": {
                "command": "npx",
                "args": [
                    "mcp-remote",
                    "https://my-mcp-server.com/mcp",
                    "34206", "--host", "localhost",
                    "--static-oauth-client-info", "@/path/to/oauth_client_info.json"
                ],
                "env": {
                    "NODE_EXTRA_CA_CERTS": "/path/to/ca.pem"
                }
            }
        }
    }
    ```
    - optionally:
        - add the `--silent` option if you use IBM Bob to get rid of messages that IBM Bob displays as errors even if they are not
        - or add the `--debug` option instead for troubleshooting
        - add the `--allow-http` option if the MCP server uses HTTP
        - add the `NODE_TLS_REJECT_UNAUTHORIZED` environment variable and set it to `"0"` if the MCP server uses a self-signed certificate

    - read more about the options that the `mcp-remote` command can take in https://www.npmjs.com/package/mcp-remote#flags

> [!NOTE]
> - Alternatively Claude Desktop can be configured without using `mcp-remote`.
> - See [Get started with custom connectors using remote MCP](https://support.claude.com/en/articles/11175166-get-started-with-custom-connectors-using-remote-mcp)
> - This solution is not available in the free plan though


## 3. Troubleshooting

### 3.1 How things work

The AI assistant does not connect to the MCP server directly but uses the `mcp-remote` tool instead (see [2.3 AI Assistant configuration](#23-ai-assistant-configuration)).

The `mcp-remote` tool authenticates the user to obtain an access token and then use it to connect to the MCP server. 
To do that, `mcp-remote` follows the Authorization Code flow:
1. `mcp-remote` opens a page in the web browser and navigates to the OpenID Connect authorization endpoint which displays a login page
1. once the user logged in, the login page redirects an authorization code to the redirect URI specified in the request
1. `mcp-remote` listens to that redirect URI and trades the authorization code for an access token by sending a request to the OpenID Connect token endpoint
1. `mcp-remote` connects to the MCP server with the access token in the authorization header

When a user runs a tool, the MCP server retrieves the user's access token and connects to ODM RES console or Decision Center with it.

The `mcp-remote` tool keeps the access token in memory (or in a file in debug mode) and only re-authenticate the user when the access token (and refresh token) are expired. 

If you wish to authenticate yourself with different credentials, you may need to:
- either wait for some time for the token to expire
- or 
    - configure `mcp-remote` with the `--debug` option and delete the tokens manually. In debug mode, the tokens are stored in a file named `<ID>_tokens.json` located in the `~/.mcp-auth/mcp-remote-<VERSION>` directory (eg. `~/.mcp-auth/mcp-remote-0.1.37/17b244e3d408a03337239f65a72c293c_tokens.json`).
    - close the browser and restart it
    - close the AI Assistant completely and restart it

As a further reading, Anthropic’s official [MCP documentation](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/authorization) provides a detailed step by step description of MCP OAuth 2.1 Flow.

### 3.2 How to get more information

The various logs you can check are:
1. the AI Assistant log
    - Claude Desktop records log messages in a file named `mcp-server-<SERVERNAME>.log` (eg. `mcp-server-ibm-odm-management-mcp-server.log`) located in `~/Library/Log/Claude` directory on Mac and `%APPDATA%\Claude\logs` on Windows
    - IBM Bob displays the log messages in the UI (in the settings of the MCP server)
1. the `mcp-remote` log
    - `mcp-remote` sends log messages to the AI Assistant (unless it is configured with the `--silent` option). Those log messages are recorded in the AI Assistant log.
    - `mcp-remote` may record debug log messages as well if you can configure it  with the `--debug` option
    - `mcp-remote` debug log file is named `<ID>_debug.log` (eg. `17b244e3d408a03337239f65a72c293c_debug.log`) and is located in the `~/.mcp-auth/mcp-remote-<VERSION>` directory (eg. `~/.mcp-auth/mcp-remote-0.1.37/`)
1. the MCP server log
1. the OpenID Connect provider log
1. the ODM RES console and/or Decision Center logs

### 3.3 Frequent issues

#### 3.3.1 Invalid Grant
- Symptoms:
    - the credentials are accepted, but the connection to the MCP server is in error (no tools)
    - IBM Bob displays the errors:
        ```
        [2026-06-21T09:20:19.657Z][17558] Authorization error: {"name":"InvalidGrantError"}
        [2026-06-21T09:20:19.660Z][17558] Authorization error during finishAuth {"errorMessage":"Code not valid","stack":"InvalidGrantError: Code not valid\n ...
        ```
- Possible Causes and solutions:
    1. Several instances of IBM Bob all try to authenticate the user at the same time
        - In that case, another symptom is that several login page gets displayed in the web browser
        - The solution is either to keep only one IBM Bob window, or enable the MCP server in only one window by configuring the MCP server in the "Project MCPs" (rather than "Global MCPs") configuration file.

    1. The OIDC Provider refused the MCP client request for a token
        - This can happen if the resource specified in the MCP client request is not registered in the OIDC Provider as a legit resource server.
        - The MCP client sets this resource with the value of the field `resource` found in the response to the URL `<MCP_SERVER_URL>/.well-known/oauth-protected-resource`. This field is set with the value passed to the `--mcp-ext-url` flag (or from the value of the `MCP_EXT_URL` environment variable). This is the URL of the Management MCP server (generally without the `/mcp` path).
        - Solutions:
            - if you use `mcp-remote`, you can either specify an alternative resource that the OIDC Provider accepts using the `--resource <legit-resource>` flag or not send the resource using the `--disable-resource-parameter` flag
            - or configure the OIDC Provider so that it accepts to generate to token for that resource:
                - in AWS Cognito, define a "resource server" with the URL of the Management MCP server,
                - in Azure Entra ID, select "Expose an API", click "Add", set the URL of the Management MCP server, and click "Save". 

#### 3.3.2 Invalid parameter: redirect_uri
- Symptoms:
    - a login page gets displayed in the web browser
    - the credentials are accepted, but page displays a message such as `Invalid parameter: redirect_uri`

- Cause:
    - the redirect URI used is not declared as valid in the OpenID Connect Client

- Solution:
    - find what the redirect URI is
        - either based on the `mcp-remote` command line parameters
        - or in the URL to the authentication endpoint (as a query parameter)
        - or in the OpenID Connect Provider log
    - add this URI to the list of the valid redirect URI for the OpenID Connect Client

#### 3.3.3 The login page is not displayed
- Symptoms:
    - the login page does not get displayed in the web browser

- Troubleshooting:
    - add the `--debug` option to the `mcp-remote` command line
    - close and reopen the AI Assistant
    - check `mcp-remote` debug log file (see [3.2 How to get more information](#32-how-to-get-more-information))

- Possible Causes:
    - `mcp-remote` might be unable to establish a TLS connection to the MCP server, in which case
        - either disable all checks if the MCP server certificate is self-signed 
        - or specify the MCP server certificate in `mcp-remote` command line using the `NODE_EXTRA_CA_CERTS` environment variable (see [2.3 AI Assistant configuration](#23-ai-assistant-configuration))

    - `mcp-remote` might be unable to determine the OpenId authorization endpoint, in which case
        - navigate to `https://<MY_MCP_SERVER>/.well-known/oauth-protected-resource` after replacing `<MY_MCP_SERVER>` by the ROOT URL of your MCP server (without `/mcp`)
            - if this page does not respond, the MCP server might not be using the users credentials
            - you can check if there is a message `MCP Server running in remote mode, using users credentials` in the MCP server log
            - check that all the required MCP server parameters are set (see [2.1 MCP server configuration](#21-mcp-server-configuration))
        - check that the response contains a field "authorization_servers"
        - navigate to this URL followed by `.well-known/openid-configuration` eg. `https://<MY_AUTHORIZATION_SERVER>/.well-known/openid-configuration`
        - check that the response contains a field "authorization_endpoint"

#### 3.3.4 Invalid Scope
- Symptoms:
    - the OIDC provider rejects the token request with an "invalid scope" error,
    - or the MCP server rejects the token with an error "Unable to decode the token: Signature verification failed".

- Cause:
    - the MCP client may not be using the suitable scope(s).
    - the MCP client uses the scope(s) advertised by the MCP server in the field `scopes_supported` at the URL `<MCP_SERVER_URL>/.well-known/oauth-protected-resource`, but this scope(s) might be only suitable for the MCP server to connect using the client_credentials grant, and the MCP client may need a different scope for the Authorization Code flow.

- Solution:
    - Specify the scope to use for the Authorization Code flow using the flag `--static-oauth-client-metadata { "scope": "scope_for_authorization_code_flow"}`

## 4. mcp-remote parameters

Check [mcp-remote home page project](https://www.npmjs.com/package/mcp-remote) to find the full list of parameters.

The main parameters are:

| Parameter | Description | Documented in |
|-----------|-------------|---------------|
| `<url>` (positional) | URL of the MCP server (e.g. `https://my-mcp-server.com/mcp`) | [2.3 AI Assistant configuration](#23-ai-assistant-configuration) |
| `<port>` (positional) | Local port for the OAuth callback listener (e.g. `34206`) | [2.3 AI Assistant configuration](#23-ai-assistant-configuration) |
| `--host` | Hostname for the OAuth callback listener (e.g. `localhost`) | [2.3 AI Assistant configuration](#23-ai-assistant-configuration) |
| `--static-oauth-client-info` | JSON object (or `@/path/to/file`) providing the `client_id` and `client_secret` used by `mcp-remote` to authenticate to the OIDC provider. Example: `{ "client_id": "32a0f2d3-...", "client_secret": "fsG8Q~..." }` | [2.3 AI Assistant configuration](#23-ai-assistant-configuration) |
| `--static-oauth-client-metadata` | JSON object supplying additional OAuth client metadata, such as the `scope` to request. Example: `{ "scope": "32a0f2d3-.../.default" }` | [3.3.1 Invalid Grant](#334-invalid-scope) |
| `--disable-resource-parameter` | Do not send the `resource` parameter in token requests. Useful when the OIDC provider does not accept or recognise the MCP server URL as a resource. | [3.3.1 Invalid Grant](#331-invalid-grant) |
| `--resource` | Override the `resource` parameter sent in token requests with an alternative value accepted by the OIDC provider. | [3.3.1 Invalid Grant](#331-invalid-grant) |
| `--allow-http` | Allow connections to MCP servers over plain HTTP (disabled by default for security). | [2.3 AI Assistant configuration](#23-ai-assistant-configuration) |
| `--silent` | Suppress `mcp-remote` log messages forwarded to the AI assistant. | [2.3 AI Assistant configuration](#23-ai-assistant-configuration) |
| `--debug` | Enable verbose debug logging; tokens are persisted to `~/.mcp-auth/mcp-remote-<VERSION>/` for inspection. | [2.3 AI Assistant configuration](#23-ai-assistant-configuration), [3.1 How things work](#31-how-things-work) |


The main environment variables are:

| Environment Variable | Description | Documented in |
|----------------------|-------------|---------------|
| `NODE_EXTRA_CA_CERTS` | Path to a PEM file containing additional CA certificates that Node.js should trust. Use this to allow `mcp-remote` to connect to an MCP server whose TLS certificate is signed by a private CA. | [2.3 AI Assistant configuration](#23-ai-assistant-configuration) |
| `NODE_TLS_REJECT_UNAUTHORIZED` | Set to `"0"` to disable all TLS certificate verification. Use only for testing with self-signed certificates. | [2.3 AI Assistant configuration](#23-ai-assistant-configuration) |


