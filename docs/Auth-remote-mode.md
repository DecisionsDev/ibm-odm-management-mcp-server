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
    | `--introspection-url` | `INTROSPECTION_URL` | OpenID Connect introspection URL |

    - The MCP external URL is the URL that is configured in the AI assistant to access the MCP server (with or without the path `/mcp` appended, eg. `https://my-mcp-server.com`). This URL MUST match the URL configured in the AI assistant (see [2.3 AI Assistant configuration](#23-ai-assistant-configuration)).
    - The issuer and introspection URL can be found when navigating to the `.well-known/openid-configuration` URL of the OpenID Connect server. The response contains the fields `issuer` and `introspection_endpoint`.

- The MCP server also needs the following parameters to introspect the users tokens:

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

The AI assistant do not connect to the MCP server directly but use the `mcp-remote` tool instead (see [2.3 AI Assistant configuration](#23-ai-assistant-configuration)).

The `mcp-remote` tool authenticates the user to obtain an access token and then use it to connect to the MCP server. 
To do that, `mcp-remote` follows the Authorization Code flow:
1. `mcp-remote` opens a page in the web browser and navigates to the OpenID Connect authorization endpoint which displays a login page
1. once the user logged in, the login page redirects an authorization code to the redirect URI specified in the request
1. `mcp-remote` listens to that redirect URI and trades the authorization code for an access token by sending a request to the OpenID Connect token endpoint
1. `mcp-remote` connects to the MCP server with the access token in the authorization header

The MCP server keeps the access token of each user in memory and when a user runs a tool, the MCP server uses the user's access token to connect to ODM RES console or Decision Center.

The `mcp-remote` tool keeps the access token in memory (or in a file in debug mode) and only re-authenticate the user when the access token (and refresh token) are expired. 

If you wish to authenticate yourself with different credentials, you may need to:
- either wait for some time for the token to expire
- or 
    - configure `mcp-remote` with the `--debug` option and delete the tokens manually. In debug mode, the tokens are stored in a file named `<ID>_tokens.json` located in the `~/.mcp-auth/mcp-remote-<VERSION>` directory (eg. `~/.mcp-auth/mcp-remote-0.1.37/17b244e3d408a03337239f65a72c293c_tokens.json`).
    - close the browser and restart it
    - close the AI Assistant completely and restart it

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

#### 3.3.1 InvalidGrantError using IBM Bob
- Symptoms:
    - several login page gets displayed in the web browser
    - the credentials are accepted, but the connection to the MCP server is in error (no tools)
    - IBM Bob displays the errors:
        ```
        [2026-06-21T09:20:19.657Z][17558] Authorization error: {"name":"InvalidGrantError"}
        [2026-06-21T09:20:19.660Z][17558] Authorization error during finishAuth {"errorMessage":"Code not valid","stack":"InvalidGrantError: Code not valid\n ...
        ```
- Cause:
    - This error occurs when several instances of IBM Bob all try to authenticate the user at the same time

- Solution:
    - either keep only one IBM Bob window, or enable the MCP server in only one window by configuring the MCP server in the "Project MCPs" (rather than "Global MCPs") configuration file.

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

#### 3.3.2 The login page is not displayed
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
        - navigate to https://<MY_MCP_SERVER>/.well-known/oauth-protected-resource after replacing `<MY_MCP_SERVER>` by the URL of your MCP server
            - if this page does not respond, the MCP server might not be using the users credentials
            - you can check if there is a message `MCP Server running in remote mode, using users credentials` in the MCP server log
            - check that all the required MCP server parameters are set (see [2.1 MCP server configuration](#21-mcp-server-configuration))
        - check that the response contains a field "authorization_servers"
        - navigate to this URL followed by `.well-known/openid-configuration` eg. https://<MY_AUTHORIZATION_SERVER>/.well-known/openid-configuration
        - check that the response contains a field "authorization_endpoint"
