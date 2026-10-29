# IBM ODM Management MCP Server Documentation
## Overview

The IBM ODM Management MCP Server bridges IBM ODM Management REST APIs with modern AI assistants and orchestration platforms.
It enables you to:
- Expose as tools for AI assistants
  - Decision Center REST API
  - Decision Server REST API (aka RES console)
- Integrate easily with Watson Orchestrate, Claude Desktop, IBM Bob, ...

## Features

- **Tool Integration:** Expose ODM Decision Center and Decision Server Console REST API endpoints as tools
- **Authentication:** Zen API Key, Basic Auth, and OpenID Connect
- **Multi-Platform:** Works with Watson Orchestrate, Claude Desktop, ...

## Quickstart

Check the [Claude Desktop Integration Guide](/docs/Claude-desktop-integration-guide.md) for detailed instructions on setting up and using the Management MCP Server in **Claude Desktop**.

Or check the [IBM Bob Integration Guide](/docs/IBM-Bob-integration-guide.md) for detailed instructions on setting up and using the Management MCP Server in **IBM Bob**.

### Demo Video

Watch our demo video to see Claude Desktop integration in action:

https://github.com/user-attachments/assets/26c038a2-d650-47c5-a09e-4c1da62c578e


## Prerequisites & Installation

- **Python 3.13 or higher** - This MCP server is written in Python and requires Python 3.13 or higher
- **uv** - A fast Python package installer and resolver
- **Git** - open source distributed version control system

Please find the instructions to install the prerequisites in [Claude Desktop Integration Guide - (Step 1)](/docs/Claude-desktop-integration-guide.md#step-1-install-git-python-and-uv).

## Configuration

### 1. ODM Container Environments & Authentication

Depending on your IBM ODM deployment, use the appropriate authentication/authorization method:

#### 1.1. **ODM on Cloud Pak for Business Automation**
- **Environment:** Cloud Pak for Business Automation (CP4BA)
- **Authentication:** username and Zen API Key

  | description   | command line argument            | Environment variable      |
  |---------------|----------------------------------|---------------------------|
  | user name     | `--username <username>`          | `ODM_USERNAME=<username>` |
  | Zen API key   | `--zenapikey <your-zen-api-key>` | `ZENAPIKEY=<zen-api-key>` |

#### 1.2. **ODM on Kubernetes**
- **Environment:** IBM ODM deployed on Kubernetes (including OpenShift)
- **Authentication:** 3 possibilities
  1. **Basic Authentication:**  

        | description   | command line argument   | Environment variable      |
        |---------------|-------------------------|---------------------------|
        | user name     | `--username <username>` | `ODM_USERNAME=<username>` |
        | password      | `--password <password>` | `ODM_PASSWORD=<password>` |

  1. **OpenID Connect (using Client Secret):**

        | description                     | command line argument     | Environment variable      |
        |---------------------------------|---------------------------|---------------------------|
        | OpenID Connect URL to get tokens| `--token-url <TOKEN_URL>` | `TOKEN_URL=<TOKEN_URL>`   |
        | OpenID Connect CLIENT ID        | `--client-id <CLIENT_ID>` | `CLIENT_ID=<CLIENT_ID>`   |
        | OpenID Connect CLIENT SECRET    | `--client-secret <CLIENT_SECRET>` | `CLIENT_SECRET=<CLIENT_SECRET>` |
        | OpenID Connect scope (optional - default is `openid`) | `--scope <scope>`         | `SCOPE=<scope>`           |

  1. **OpenID Connect (using Private Key JWT):**

        | description                     | command line argument     | Environment variable      |
        |---------------------------------|---------------------------|---------------------------|
        | OpenID Connect URL to get tokens| `--token-url <TOKEN_URL>` | `TOKEN_URL=<TOKEN_URL>`   |
        | OpenID Connect CLIENT ID        | `--client-id <CLIENT_ID>` | `CLIENT_ID=<CLIENT_ID>`   |
        | Path to the certificate used for PKJWT authentication | `--pkjwt-cert-path <CERT_PATH>` | `PKJWT_CERT_PATH=<CERT_PATH>` |
        | Path to the Private Key used for PKJWT authentication | `--pkjwt-key-path <PRIVATE_KEY_PATH>` | `PKJWT_KEY_PATH=<PRIVATE_KEY_PATH>` |
        | Password of the Private Key used for PKJWT authentication (optional: only needed if the private key is password-protected) | `--pkjwt-key-password <PASSWORD>` | `PKJWT_KEY_PASSWORD=<PASSWORD>` |
        | OpenID Connect scope (optional - default is `openid`) | `--scope <scope>`         | `SCOPE=<scope>`           |


#### 1.3. **ODM for Developers (Docker/Local)**
- **Environment:** Local Docker or Developer Edition
- **Authentication:** Basic Auth

    | description   | command line argument   | Environment variable      |
    |---------------|-------------------------|---------------------------|
    | user name     | `--username <username>` | `ODM_USERNAME=<username>` |
    | password      | `--password <password>` | `ODM_PASSWORD=<password>` |

### 2. Authorization

#### 2.1. ODM on Cloud Pak for Business Automation

If ODM is deployed in IBM Cloud Pak for Business Automation, the user/service account used must have a role assigned that grants one of the Zen permissions below:

  | Zen permissions | Equivalent ODM Liberty roles | Description |
  |-----------------|------------------------------|-------------|
  | ODM - Administer Decision Center                                 | rtsAdministrator | Gives access to all the Decision Center tools |
  | ODM - Administer database for Decision Center                    | rtsInstaller     | Gives access to all the Decision Center tools |
  | ODM - Manage decision services and deployment in Decision Center | rtsConfigManager | Gives access to only some Decision Center tools |
  | ODM - Manage decision services in Decision Center                | rtsUser          | Gives access to only some Decision Center tools |

  | Zen permissions | Equivalent ODM Liberty roles | Description |
  |-----------------|------------------------------|-------------|
  | ODM - Monitor and deploy decision services in Decision Server	   | resDeployer      | Gives access to all the Decision server console tools |
  | ODM - Monitor decision services in Decision Server               | resMonitor       | Gives access to only some Decision server console tools |

Read more in [Managing user permissions](https://www.ibm.com/docs/en/cloud-paks/cp-biz-automation/26.0.0?topic=access-managing-user-permissions).

#### 2.2. ODM on Kubernetes

If ODM is deployed on Kubernetes, the user/service account used must have at least one of the roles below:

  | ODM roles           | Description |
  |---------------------|-------------|
  | rtsAdministrator    | Gives access to all the Decision Center tools |
  | rtsAdministrator    | Gives access to all the Decision Center tools |
  | rtsConfigManager    | Gives access to only some Decision Center tools |
  | rtsUser             | Gives access to only some Decision Center tools |

  | ODM roles      | Description |
  |----------------|-------------|
  | resDeployer    | Gives access to all the Decision Server console tools |
  | resMonitor     | Gives access to only some Decision Server console tools |

#### 2.3. ODM on Cloud

If ODM is deployed in the managed offering ODM on Cloud, the user/service account used must have at least one of the roles below assigned (for the suitable environment (Development / Test / Production)):

  | Decision Center Role | Description |
  |----------------------|-------------|
  | Administrator        | Gives access to all the Decision Center tools |
  | Configuration Manager| Gives access to all the Decision Center tools |
  | User                 | Gives access to only some Decision Center tools |

  | Decision Server Role | Description |
  |----------------------|-------------|
  | Deployer             | Gives access to all the Decision Server console tools |
  | Monitor              | Gives access to only some Decision Server console tools |

Read more in [Creating and managing service accounts](https://www.ibm.com/docs/en/dbaoc?topic=access-creating-managing-service-accounts).

### 3. Secure connection

#### 3.1. Server certificate checks

When establishing a SSL/TLS secure connection, the Management MCP server can perform two checks:
1. verify that the server certificate is valid and trusted
    - this check is enabled by default
    - and can be disabled in dev/test environments by setting
      - **CLI:** `--verifyssl "False"`
      - **Env:** `VERIFY_SSL="False"`
    - this check requires that:
      - either the server certificate was signed with a public CA certificate available in the system trusted certificates
      - or this signing certificate is provided to the MCP server using:
        - **CLI:** `--ssl-cert-path <certificate_path_list>`
        - **Env:** `SSL_CERT_PATH=<certificate_path_list>`
      - use this latter option to solve the error `certificate verify failed: self-signed certificate in certificate chain`
      - if several certificates need to be trusted:
        - either concatenate all the certificates in the same file,
        - or specify a list of paths separated by a semi-colon or a comma,
          - each path being either a certificate file
          - or a directory in which case, all the files with the extension *.pem or *.crt are taken into account

1. verify that the MCP server connects to the intended server and not a malicious interceptor by checking that the Common Name (CN) or Subject Alternative Name (SAN) fields in the server certificate matches the domain name in the requested URL
    - this check is disabled by default (for compatibility)
    - and can be enabled by setting
      - **CLI:** `--verifyssl-hostname "True"`
      - **Env:** `VERIFY_SSL_HOSTNAME="True"`

#### 3.2. mTLS (mutual TLS)

ODM can be configured to check the authenticity of the clients that try to establish a secure connection.

In that case, the Management MCP server (which acts as a client), must be configured with both a private key and its related certificate (and the server must be configured to trust the clients presenting that certificate when establishing a secure connection).

The parameters below can be specified:
  - **CLI:** `--mtls-key-path <PRIVATE_KEY_PATH> --mtls-cert-path <CERT_PATH>` and optionally `--mtls-key-password <PASSWORD>` if the private key is password-protected.
  - **Env:** `MTLS_KEY_PATH=<private_key_path> MTLS_CERT_PATH=<cert_path>` and optionally `MTLS_KEY_PASSWORD=<password>` if the private key is password-protected.

#### 3.3. HTTPS for remote MCP clients

The sections above secure the connection from the Management MCP server to ODM. When the Management MCP server runs in remote mode (`--transport streamable-http` or `sse`), it can also serve its own endpoint over HTTPS, so that remote MCP clients connect to it securely.

Provide the certificate and the private key (PEM format) of the Management MCP server:
  - **CLI:** `--https-cert-path <CERT_PATH> --https-key-path <PRIVATE_KEY_PATH>` and optionally `--https-key-password <PASSWORD>` if the private key is password-protected.
  - **Env:** `HTTPS_CERT_PATH=<cert_path> HTTPS_KEY_PATH=<private_key_path>` and optionally `HTTPS_KEY_PASSWORD=<password>` if the private key is password-protected.

If the certificate is signed by an intermediate CA, the certificate file should contain the full chain (server certificate first). When these options are not specified, the Management MCP server serves plain HTTP. They are ignored with the `stdio` transport.

For example, to test locally with a self-signed certificate:
```bash
openssl req -x509 -newkey rsa:2048 -nodes -keyout key.pem -out cert.pem -days 365 -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
uvx --from git+https://github.com/DecisionsDev/ibm-odm-management-mcp-server ibm-odm-management-mcp-server \
    --url http://localhost:9060/decisioncenter-api --username odmAdmin --password odmAdmin \
    --transport streamable-http --https-cert-path cert.pem --https-key-path key.pem
```
MCP clients then connect to `https://localhost:3000/mcp`. With a self-signed certificate, the MCP client must be configured to trust it.

> [!TIP]
> On Kubernetes or OpenShift, TLS can instead be terminated by an Ingress or a Route in front of the Management MCP server, which then keeps serving plain HTTP inside the cluster.


## Configuration Parameters Table

| CLI Argument      | Environment Variable | Description                                                                                            | Default                                 |
|-------------------|---------------------|---------------------------------------------------------------------------------------------------------|-----------------------------------------|
| `--url`           | `ODM_URL`           | URL of the Decision Center REST API                      |              |
| `--res-url`       | `ODM_RES_URL`       | URL of the Decision Server Console (aka RES Console)     |              |
| `--username`      | `ODM_USERNAME`      | Username (Basic Auth, Zen authentication or OpenId Connect)                                                           | `odmAdmin`                              |
| `--password`      | `ODM_PASSWORD`      | Password (Basic Auth or OpenId Connect)                                                                                | `odmAdmin`                              |
| `--zenapikey`     | `ZENAPIKEY`         | Zen API Key for authentication with Cloud Pak for Business Automation                                   |                                         |
| `--client-id`     | `CLIENT_ID`         | OpenID Connect client ID for authentication                                                             |                                         |
| `--client-secret` | `CLIENT_SECRET`     | OpenID Connect client secret for authentication                                                         |                                         |
| `--pkjwt-cert-path` | `PKJWT_CERT_PATH` | Path to the certificate for PKJWT authentication (mandatory for PKJWT)                                  |                                         |
| `--pkjwt-key-path` | `PKJWT_KEY_PATH`   | Path to the private key certificate for PKJWT authentication (mandatory for PKJWT)                      |                                         |
| `--pkjwt-key-password` | `PKJWT_KEY_PASSWORD` | Password to decrypt the private key for PKJWT authentication. Only needed if the key is password-protected. |                               |
| `--token-url`     | `TOKEN_URL`         | OpenID Connect token endpoint URL for authentication                                                    |                                         |
| `--scope`         | `SCOPE`             | OpenID Connect scope used when requesting an access token   | `openid`                                |
| `--verifyssl`     | `VERIFY_SSL`        | Whether to verify SSL certificates are valid and trusted (`True` or `False`)                          | `True`                                  |
| `--verifyssl-hostname` | `VERIFY_SSL_HOSTNAME` | Whether to verify that the MCP server is connecting to the intended server by checking that the Common Name (CN) or Subject Alternative Name (SAN) fields of the server certificate matches the domain name in the requested URL  (`True` or `False`) | `False`                                  |
| `--ssl-cert-path` | `SSL_CERT_PATH`     | Semi-colon or comma-separated list of paths (files or directories) containing trusted SSL certificates. When a directory is specified, only the files with *.pem or *.crt extension are taken into account. If not provided, defaults to the system certificates. |                                         |
| `--mtls-cert-path`| `MTLS_CERT_PATH`    | Path to the SSL certificate file of the client for mutual TLS authentication (mandatory for mTLS)       |                                         |
| `--mtls-key-path` | `MTLS_KEY_PATH`     | Path to the SSL private key file of the client for mutual TLS authentication (mandatory for mTLS)       |                                         |
| `--mtls-key-password` | `MTLS_KEY_PASSWORD` | Password to decrypt the private key of the client for mutual TLS authentication. Only needed if the key is password-protected. |              |

> Parameters to monitor the MCP server
>| CLI Argument | Environment Variable | Description | Default |
>|--------------|----------------------|-------------|---------|
>| `--log-level`      | `LOG_LEVEL`      | Set the logging level (`DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`) | `INFO` |
>| `--traces-dir`     | `TRACES_DIR`     | Directory to store tools execution traces | `~/.ibm-odm-management-mcp-server/traces` |
>| `--trace`          | `TRACE`          | Specifies what to trace (`EXECUTIONS`, `EXECUTIONS_WITH_CONTENT`, `CONFIGURATION`) |
>| `--traces-maxsize` | `TRACES_MAXSIZE` | Maximum number of traces to store before removing oldest traces | `200` |

> Parameters to filter out the tools published
>| CLI Argument | Environment Variable | Description | Default |
>|--------------|----------------------|-------------|---------|
>| `--tools`    | `TOOLS`              | List of tools to publish (eg. decisionServices releases createRelease). This option takes precedence over the options --no-tools, --tool-profile and --tags. With `--tool-profile ESSENTIAL`, these tools are added to the essential tools; with `--tool-profile ALL`, only these tools are published | |
>| `--no-tools` | `NO_TOOLS`           | List of tools to ignore  (eg. launchCleanup wipe executeSqlScript). This option takes precedence over the options --tool-profile and --tags | |
>| `--tool-profile` | `TOOL_PROFILE`   | Set of tools published: `ESSENTIAL` (a curated subset of the most useful Decision Center and Decision Server console tools, see [Essential tools](./docs/Essential-tools.md)) or `ALL` (all the tools). Case-insensitive. Can be combined with --tools, --no-tools and --tags | `ESSENTIAL` |
>| `--tags`     | `TAGS`               | List of tags (eg. About Explore Build). Publish only the tools that belong to the tags listed. | |

> Parameters to start the MCP server in remote mode (allowing connections from remote MCP clients) 
>| CLI Argument | Environment Variable | Description | Default |
>|--------------|----------------------|-------------|---------|
>| `--transport`| `TRANSPORT`          | `stdio`, `streamable-http` or `sse` : Means of communication of the Management MCP server: local (`stdio`) or remote (`streamable-http` or `sse`)) | `stdio` |
>| `--host`     | `HOST`               | IP or hostname that the MCP server listens to in remote mode. | `0.0.0.0` |
>| `--port`     | `PORT`               | Port that the MCP server listens to in remote mode. | `3000` |
>| `--mount-path`| `MOUNT_PATH`        | Path that the MCP server listens to in remote mode. | `/mcp` |
>| `--https-cert-path`| `HTTPS_CERT_PATH` | Path to the certificate (PEM) of the MCP server to serve HTTPS in remote mode. If not provided, the MCP server serves plain HTTP. See [HTTPS for remote MCP clients](#33-https-for-remote-mcp-clients) | |
>| `--https-key-path` | `HTTPS_KEY_PATH`  | Path to the private key (PEM) of the MCP server certificate (mandatory for HTTPS) | |
>| `--https-key-password` | `HTTPS_KEY_PASSWORD` | Password to decrypt the private key of the MCP server certificate. Only needed if the key is password-protected. | |

> Additional parameters to start the MCP server in remote mode using users credentials.
>   - Read more about this mode in the page [User authentication in remote mode](./docs/Auth-remote-mode.md).
>
> | CLI Argument | Environment Variable | Description | Default |
> |--------------|----------------------|-------------|---------|
> | `--mcp-ext-url` | `MCP_EXT_URL` | MCP server external URL | |
> | `--issuer-url` | `ISSUER_URL` | OpenID Connect issuer URL | |
> | `--introspection-url` | `INTROSPECTION_URL` | OpenID Connect introspection URL. Either this or `--userinfo-url` is required. | |
> | `--userinfo-url` | `USERINFO_URL` | OpenID Connect userinfo URL. Alternative to `--introspection-url` for providers (e.g. Amazon Cognito) that do not support token introspection. | |
> | `--jwks-url` | `JWKS_URL` | OpenID Connect JWKS URI. When provided, incoming bearer tokens are verified locally using the IdP public keys (no introspection round-trip). Signing keys are cached by `kid` (up to 10 entries). | |
> | `--jwt-algorithms` | `JWT_ALGORITHMS` | Space-separated list of accepted JWT signing algorithms. | `RS256 RS384 RS512 ES256 ES384 ES512 PS256` |

## MCP Server Configuration File          

You can configure the MCP server for clients like Claude Desktop using a JSON configuration file, which can contain both environment variables and command-line arguments.

**Tips:**
- Use CLI arguments for quick overrides or non-sensitive parameters.
- Use environment variables for secrets.
- You can mix both methods if needed. CLI arguments override environment variables.
- By default only the most useful tools are published as not all tools are needed most of the time, and a smaller number of tools helps the AI agent to pick the right one. See [Essential tools](./docs/Essential-tools.md) for the list of the tools published. Add `--tool-profile ALL` to publish all the tools.

Here are some examples for different types of deployment (dev/test or production), environments (CloudPak, ...) and use cases:
- [Example 1: Basic Auth](#example-1-basic-auth)
- [Example 2: Basic Auth for ODM for Developers](#example-2-basic-auth-for-odm-for-developers)
- [Example 3: For Cloud Pak (Zen API Key)](#example-3-for-cloud-pak-zen-api-key)
- [Example 4: OpenID Connect](#example-4-openid-connect)
- [Example 5: mTLS (Mutual TLS) Authentication](#example-5-mtls-mutual-tls-authentication)
- [Example 6: Tool filtering](#example-6-tool-filtering)
- [Example 7: Role-based tool filtering](#example-7-role-based-tool-filtering)
- [Example 8: Remote tool filtering](#example-8-remote-tool-filtering)
- [Example 9: Monitoring enabled](#example-9-monitoring-enabled)

### Example 1: Basic Auth

The example below shows a typical use-case where the sensitive information (here the password) is passed as an environment variable (so that it does not show in the arguments of the process), and the other parameters are passed as CLI arguments:

```json
{
  "mcpServers": {
    "ibm-odm-management-mcp-server": {
      "command": "uvx",
      "args": [
        "--from", "git+https://github.com/DecisionsDev/ibm-odm-management-mcp-server",
        "ibm-odm-management-mcp-server",
        "--url",     "https://decisioncenter-api-url",
        "--res-url", "https://res-console-url",
        "--verifyssl-hostname", "True",
        "--ssl-cert-path", "odm-certificate-file;openid-provider-certificate-file",
        "--username", "username"
      ],
      "env": {
        "ODM_PASSWORD": "password"
      }
    }
  }
}
```

### Example 2: Basic Auth for ODM for Developers

For local development and testing, use the Basic Auth.

```json
"args": [
  "--from", "git+https://github.com/DecisionsDev/ibm-odm-management-mcp-server",
  "ibm-odm-management-mcp-server",
  "--url",      "http://localhost:9060/decisioncenter-api",
  "--res-url",  "http://localhost:9060/res",
  "--username", "odmAdmin"
],
"env": {
  "ODM_PASSWORD": "odmAdmin"
}
```

### Example 3: For Cloud Pak (Zen API Key)

For production deployments on the Cloud Pak, use the Zen API Key.

```json
"args": [
  "--from", "git+https://github.com/DecisionsDev/ibm-odm-management-mcp-server",
  "ibm-odm-management-mcp-server",
  "--url",           "https://decisioncenter-api-url",
  "--res-url",       "https://res-console-url",
  "--verifyssl-hostname", "True",
  "--ssl-cert-path", "odm-certificate-file;openid-provider-certificate-file",
  "--username",      "USERNAME"
],
"env": {
  "ZENAPIKEY": "ZEN_API_KEY"
}
```

### Example 4: OpenID Connect

For production deployments on other environments than the Cloud Pak, you may use OpenID Connect if ODM is configured to use it.

The Management MCP Server supports the options below to authenticate to the token endpoint and to ODM:

- Client authentication to the token endpoint:
  - using a **Client Secret** or 
  - using **Private Key JWT**

- User authentication to ODM
  - using the credentials of a user (username and password) (Password grant), or
  - using the Client service account (Client Credentials grant)

The Decision Center API is best used by authenticating with the credentials of the user so that:
- the user has only access to the content they are allowed to see and modify,
- and the user's role is enforced.

The Decision Server API can make use of the Client service account. Please notice that the user might have more privilege that way if the Client service account is granted a role (eg. `resDeployer`) that the user does not have.

1) Example using a Client Secret and the user's credentials
```json
"args": [
  "--from", "git+https://github.com/DecisionsDev/ibm-odm-management-mcp-server",
  "ibm-odm-management-mcp-server",
  "--url",           "https://decisioncenter-api-url",
  "--res-url",       "https://res-console-url",
  "--verifyssl-hostname", "True",
  "--ssl-cert-path", "odm-certificate-file;openid-provider-certificate-file",
  "--token-url",     "https://your-openid-connect_provider-token-endpoint-url",
  "--scope",         "the_scope_to_be_used_if_different_from_default_value_openid"
],
"env": {
  "CLIENT_ID":      "YOUR_CLIENT_ID",
  "CLIENT_SECRET":  "YOUR_CLIENT_SECRET",
  "ODM_USERNAME":   "YOUR_USERNAME",
  "ODM_PASSWORD":   "YOUR_PASSWORD"
}
```

2) Example using a Private Key (PKJWT) and authenticating to the Decision Server API with Client Credentials
```json
"args": [
  "--from", "git+https://github.com/DecisionsDev/ibm-odm-management-mcp-server",
  "ibm-odm-management-mcp-server",
  "--res-url",       "https://res-console-url",
  "--verifyssl-hostname", "True",
  "--ssl-cert-path", "odm-certificate-file;openid-provider-certificate-file",
  "--token-url",     "https://your-openid-connect_provider-token-endpoint-url",
  "--scope",         "the_scope_to_be_used_for_client_credentials"
],
"env": {
  "CLIENT_ID":       "YOUR_CLIENT_ID",
  "PKJWT_KEY_PATH":  "PKJWT_PRIVATE_KEY_FILENAME",
  "PKJWT_CERT_PATH": "PKJWT_CERTIFICATE_FILENAME"
}
```

### Example 5: mTLS (Mutual TLS) Authentication

The Management MCP Server also supports mTLS (mutual TLS) authentication, which secure the SSL connection further.

mTLS must be complemented with another means of authentication/authorization for authorization purpose (to assess the right to access to the Decision Center), for instance with basic auth in the example below:

```json
"args": [
  "--from", "git+https://github.com/DecisionsDev/ibm-odm-management-mcp-server",
  "ibm-odm-management-mcp-server",
  "--url",           "https://decisioncenter-api-url",
  "--res-url",       "https://res-console-url",
  "--verifyssl-hostname", "True",
  "--ssl-cert-path", "odm-certificate-file;openid-provider-certificate-file",
  "--username",      "USERNAME_OR_SERVICE_ACCOUNT"
],
"env": {
  "ODM_PASSWORD":   "USERNAME_OR_SERVICE_ACCOUNT_PASSWORD",
  "MTLS_KEY_PATH":  "MTLS_PRIVATE_KEY_FILENAME",
  "MTLS_CERT_PATH": "MTLS_CERTIFICATE_FILENAME"
}
```

### Example 6: Tool filtering

By default only the essential tools are published as not all tools are needed most of the time, and a smaller number of tools helps the AI agent to pick the right one.
See [Essential tools](./docs/Essential-tools.md) for the list of the essential and non-essential tools.

You may want to add more tools, or have a different set of tools published.

The four options below enable to adjust the list of tools published.
They can be used separately or together and in the latter case, are processed in the following order of precedence:

1. First, you can specify the tools to publish explicitly

    For instance, you can specify to publish only the tools `decisionServices` (to list decision services), `decisionService` (to get a decision service by its ID), `testSuites` (list of test suites), `run` (to run a test suite), `testreports` and `decisionServicesImport`:
    ```json
    "args": [
      "--tool-profile", "ALL",
      "--tools", "decisionServices", "decisionService", "testSuites", "run", "testreports", "decisionServicesImport"
    ]
    ```
    Without `--tool-profile ALL`, these tools are added to the essential tools.
    This option takes precedence over the other two below: if a tool is specified with the `--tools` option, it is published no matter the values of the other options.
    
1. You can also specify the tools that should not be published 

    For instance, you can have all the tools published but `wipe`, `executeSQLScript` and `launchCleanup`
    ```json
    "args": [
      "--tool-profile", "ALL",
      "--no-tools", "wipe", "executeSQLScript", "launchCleanup"
    ]
    ```
    This option takes precedence over the next options: if a tool is specified with the `--no-tools` option, it is not published no matter the value of the `--tool-profile` and `--tags` options.

1. You can also choose the set of tools published

    The `--tool-profile` option takes the value `ESSENTIAL` (default) or `ALL` (case-insensitive). `ESSENTIAL` restricts the published tools to a curated subset of the most commonly used tools (see [Essential tools](./docs/Essential-tools.md) for the list), while `ALL` publishes all the tools.
    ```json
    "args": [
      "--tool-profile", "ALL"
    ]
    ```

    With `ESSENTIAL`, it can be combined with the other options to adjust that subset:
    - `--tools` adds tools to it: the tools listed are published even if they are not essential.
    - `--no-tools` removes tools from it: the tools listed are not published even if they are essential.
    - `--tags` restricts it further to the tools that belong to the tags/categories listed.

    For instance, with the configuration below, the essential tools are published, plus `addServer` and `updateServer`, but not `deploy`:
    ```json
    "args": [
      "--tool-profile", "ESSENTIAL",
      "--tools",    "addServer", "updateServer",
      "--no-tools", "deploy"
    ]
    ```

1. Last, you can specify the tag(s) of the tools that should be published

    When using the `--tags` option, the tools that do not belong to tags/categories listed are not published.

    For instance with the configuration below, the Decision Center tools that belong to the tag/category `Admin` or `DBAdmin` will not be published: 
    ```json
    "args": [
      "--tags", "About", "Explore", "Manage", "Govern", "Build", "Model"
    ]
    ```

In the `--tools` and `--no-tools` options, tools are identified by their `operationId`.

You can check the list of the tools with their `operationId` and tag/category in [Remote Tool Filtering](/docs/remote-tool-filtering.md).
This list is based on ODM 9.6.0.0 and some tools may be missing in earlier releases.

### Example 7: Role-based tool filtering

Some tools are restricted to users with specific roles. Those tools are automatically filtered out when the management MCP server uses credentials that do not grant the required role(s).
Please refer to the 'role' column in the table above to see the role required by each tool.

In the example below (suitable for ODM for Developer), two MCP servers are defined, each using different credentials.
- the first MCP server publishes the subset of Decision Center tools accessible to users with the `rtsUser` role
- the second MCP server publishes the subset of Decision Server console tools accessible to users with the `resMonitor` role

```json
{
  "mcpServers": {
    "ibm-odm-dc-management-mcp-server": {
      "command": "uvx",
      "args": [
        "--from", "git+https://github.com/DecisionsDev/ibm-odm-management-mcp-server",
        "ibm-odm-management-mcp-server",
        "--url",     "http://localhost:9060/decisioncenter-api",
        "--username", "rtsUser1"
      ],
      "env": {
        "ODM_PASSWORD": "rtsUser1"
      }
    },
    "ibm-odm-res-management-mcp-server": {
      "command": "uvx",
      "args": [
        "--from", "git+https://github.com/DecisionsDev/ibm-odm-management-mcp-server",
        "ibm-odm-management-mcp-server",
        "--res-url",  "http://localhost:9060/res",
        "--username", "resMonitor"
      ],
      "env": {
        "ODM_PASSWORD": "resMonitor"
      }
    }
  }
}
```

### Example 8: Remote tool filtering

When the MCP server runs remotely, each user can configure the MCP client to retrieve their own list of tools.

See [Remote Tool Filtering](/docs/remote-tool-filtering.md).

### Example 9: Monitoring enabled

With the configuration below, the MCP server records a file named `<tool_name>-<HTTP-response-code>-<timestamp>.json` in the `~/.mcp-server-traces` directory each time a tool is ran. This file is empty. Alternatively it can store the input and output of the tool execution by replacing `EXECUTIONS` with `EXECUTIONS_WITH_CONTENT`.

```json
"args": [
  "--from", "git+https://github.com/DecisionsDev/ibm-odm-management-mcp-server",
  "ibm-odm-management-mcp-server",
  "--url",      "https://decisioncenter-api-url",
  "--res-url",  "https://res-console-url",
  "--username", "odmAdmin",
  "--trace",    "EXECUTIONS",
  "--traces-dir", "~/.mcp-server-traces"
],
"env": {
  "ODM_PASSWORD": "odmAdmin"
}
```

With this configuration, an additional tool named `getToolExecutions` is available to return the tool executions. By default the MCP server only keeps 200 executions (configurable). When this limit is reached the oldest executions are deleted.

This tool can query the executions of a specific tool or with a specific HTTP response code. It can optionally retrieve the inputs used to call the tools and outputs returned provided those information are stored (requires the argument `EXECUTIONS_WITH_CONTENT`).

You can ask the AI agent questions such as:
  ```
  Which tools have been executed the most?
  ```
  ```
  Have users been added or deleted? If so, which ?
  ```
  ```
  Which executions failed and for which reason ?
  ```



> Note: You can also have the MCP server record a file named `parsing.json` containing the list of tools as returned to the AI agent (for debug) by adding the `CONFIGURATION` argument: `"--trace", "EXECUTIONS", "CONFIGURATION",`.

## Docker image

The repository features a [Dockerfile](/Dockerfile) so that you can build a Docker image running the IBM ODM Management MCP server, which can be useful to run the MCP server remotely.

You can find instructions in the [Build-Docker-image](/docs/Build-Docker-image.md) readme.

## Compatibility

The Management MCP server is compatible with ODM versions: 9.6, 9.5, 9.0.

## Additional information

- For IBM Operational Decision Manager (ODM), see [IBM Documentation](https://www.ibm.com/docs/en/odm).
- For IBM Watsonx Orchestrate, see [Getting Started](https://www.ibm.com/docs/en/watsonx/watson-orchestrate/base?topic=getting-started-watsonx-orchestrate).
- For Claude Desktop, see [Claude Documentation](https://support.claude.com/en/collections/16163169-claude-desktop).
