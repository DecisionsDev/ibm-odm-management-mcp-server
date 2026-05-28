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

Read more in [Managing user permissions](https://www.ibm.com/docs/en/cloud-paks/cp-biz-automation/25.0.0?topic=access-managing-user-permissions).

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

#### 3.1. Server certificate

To establish a SSL/TLS secure connection to the server, the Management MCP server must have access to the certificate used to sign the server certificate.

If a public CA certificate was used to sign the server certificate, the Management MCP server can find it among the system trusted certificates.

If this is a self-signed certificate, it can be specified :
  - **CLI:** `--ssl-cert-path <certificate_filename>`
  - **Env:** `SSL_CERT_PATH=<certificate_filename>`

Alternatively, in dev/test environments, the authenticity of the server can be ignored:
  - **CLI:** `--verifyssl "False"`
  - **Env:** `VERIFY_SSL="False"`

#### 3.2. mTLS (mutual TLS)

ODM can be configured to check the authenticity of the clients that try to establish a secure connection.

In that case, the Management MCP server (which acts as a client), must be configured with both a private key and its related certificate (and the server must be configured to trust the clients presenting that certificate when establishing a secure connection).

The parameters below can be specified:
  - **CLI:** `--mtls-key-path <PRIVATE_KEY_PATH> --mtls-cert-path <CERT_PATH>` and optionally `--mtls-key-password <PASSWORD>` if the private key is password-protected.
  - **Env:** `MTLS_KEY_PATH=<private_key_path> MTLS_CERT_PATH=<cert_path>` and optionally `MTLS_KEY_PASSWORD=<password>` if the private key is password-protected.


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
| `--verifyssl`     | `VERIFY_SSL`        | Whether to verify SSL certificates (`True` or `False`)                                                  | `True`                                  |
| `--ssl-cert-path` | `SSL_CERT_PATH`     | Path to the SSL certificate file. If not provided, defaults to system certificates.                     |                                         |
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
>| `--tools`    | `TOOLS`              | List of tools to publish (eg. decisionServices releases createRelease). This option takes precedence over the options --no-tools and --tags | |
>| `--no-tools` | `NO_TOOLS`           | List of tools to ignore  (eg. launchCleanup wipe executeSqlScript). This option takes precedence over the option --tags | |
>| `--tags`     | `TAGS`               | List of tags (eg. About Explore Build). Publish only the tools that belong to the tags listed. | |

> Parameters to start the MCP server in remote mode (allowing connections from remote MCP clients) 
>| CLI Argument | Environment Variable | Description | Default |
>|--------------|----------------------|-------------|---------|
>| `--transport`| `TRANSPORT`          | `stdio`, `streamable-http` or `sse` : Means of communication of the Management MCP server: local (`stdio`) or remote (`streamable-http` or `sse`)) | `stdio` |
>| `--host`     | `HOST`               | IP or hostname that the MCP server listens to in remote mode. | `0.0.0.0` |
>| `--port`     | `PORT`               | Port that the MCP server listens to in remote mode. | `3000` |
>| `--mount-path`| `MOUNT_PATH`        | Path that the MCP server listens to in remote mode. | `/mcp` |

## MCP Server Configuration File          

You can configure the MCP server for clients like Claude Desktop using a JSON configuration file, which can contain both environment variables and command-line arguments.

**Tips:**
- Use CLI arguments for quick overrides or non-sensitive parameters.
- Use environment variables for secrets.
- You can mix both methods if needed. CLI arguments override environment variables.

Here are some examples for different types of deployment (dev/test or production), environments (CloudPak, ...) and use cases:
- [Example 1: Basic Auth](#example-1-basic-auth)
- [Example 2: Basic Auth for ODM for Developers](#example-2-basic-auth-for-odm-for-developers)
- [Example 3: For Cloud Pak (Zen API Key)](#example-3-for-cloud-pak-zen-api-key)
- [Example 4: OpenID Connect](#example-4-openid-connect)
- [Example 5: mTLS (Mutual TLS) Authentication](#example-5-mtls-mutual-tls-authentication)
- [Example 6: Tool filtering](#example-6-tool-filtering)
- [Example 7: Role-based tool filtering](#example-7-role-based-tool-filtering)
- [Example 8: Monitoring enabled](#example-8-monitoring-enabled)

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
        "--ssl-cert-path", "certificate-file",
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
  "--ssl-cert-path", "certificate-file",
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
  "--ssl-cert-path", "certificate-file",
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
  "--ssl-cert-path", "certificate-file",
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
  "--ssl-cert-path", "certificate-file",
  "--username",      "USERNAME_OR_SERVICE_ACCOUNT"
],
"env": {
  "PASSWORD":       "USERNAME_OR_SERVICE_ACCOUNT_PASSWORD",
  "MTLS_KEY_PATH":  "MTLS_PRIVATE_KEY_FILENAME",
  "MTLS_CERT_PATH": "MTLS_CERTIFICATE_FILENAME"
}
```

### Example 6: Tool filtering

You may want to have only a subset of tools published.
The three options below enable to achieve this.
They can be used separately or together and in the latter case, are processed in the following order of precedence:

1. First, you can specify the tools to publish explicitly

    For instance, you can specify to publish only the tools `decisionServices` (to list decision services), `decisionService` (to get a decision service by its ID), `testSuites` (list of test suites), `run` (to run a test suite), `testreports` and `decisionServicesImport`: 
    ```json
    "args": [
      "--tools", "decisionServices", "decisionService", "testSuites", "run", "testreports", "decisionServicesImport"
    ]
    ```
    This option takes precedence over the other two below: if a tool is specified with the `--tools` option, it is published no matter the values of the other options.
    
1. You can also specify the tools that should not be published 

    For instance, you can have all the tools published but `wipe`, `executeSQLScript` and `launchCleanup`
    ```json
    "args": [
      "--no-tools", "wipe", "executeSQLScript", "launchCleanup"
    ]
    ```
    This option takes precedence over the next option: if a tool is specified with the `--no-tools` option, it is not published no matter the value of the `--tags` option.

1. Last, you can specify the tag(s) of the tools that should be published

    When using the `--tags` option, the tools that do not belong to tags/categories listed are not published.

    For instance with the configuration below, the Decision Center tools that belong to the tag/category `Admin` or `DBAdmin` will not be published: 
    ```json
    "args": [
      "--tags", "About", "Explore", "Manage", "Govern", "Build", "Interchange"
    ]
    ```

In the `--tools` and `--no-tools` options, tools are identified by their `operationId`.

Here is the list of the tools with their `operationId` and tag in ODM 9.6.0.0:

1. Decision Center tools:

    | `operationId`                 | tool                                                                                                                            | tag         | role             |
    |-------------------------------|---------------------------------------------------------------------------------------------------------------------------------|-------------|------------------|
    | about                         | Get system, product, and database information                                                                                   | About       |                  |
    | unlockAllUserArtifacts        | Unlock all artifacts owned by a user                                                                                            | Admin       |                  |
    | addUser                       | Add or update a user                                                                                                            | Admin       | rtsAdministrator |
    | getUsersRolesRegistry         | Retrieve the last configuration file that was uploaded                                                                          | Admin       | rtsAdministrator |
    | setUsersRolesRegistry         | Set the configuration for users, groups and roles                                                                               | Admin       | rtsAdministrator |
    | ldapSync                      | Synchronize the repository with any associated LDAP server                                                                      | Admin       | rtsAdministrator |
    | importTabPermissions          | Import tab permissions                                                                                                          | Admin       | rtsAdministrator |
    | importPermissions             | Import permissions                                                                                                              | Admin       |                  |
    | importCommandPermissions      | Import command permissions                                                                                                      | Admin       | rtsAdministrator |
    | addGroup                      | Add or update a group.                                                                                                          | Admin       | rtsAdministrator |
    | updateDynamicDomains          | Update dynamic domains                                                                                                          | Admin       |                  |
    | branchImport                  | Import a decision service on top of an existing branch                                                                          | Admin       |                  |
    | decisionServicesImport        | Import a decision service into the repository                                                                                   | Admin       |                  |
    | branchSecurity                | Security configuration of a branch                                                                                              | Admin       | rtsAdministrator |
    | branchSecurity_1              | Enforce the security on a branch                                                                                                | Admin       | rtsAdministrator |
    | users                         | List of the users that are defined in Decision Center                                                                           | Admin       | rtsAdministrator |
    | eraseAllUsers                 | Remove all users                                                                                                                | Admin       | rtsAdministrator |
    | user                          | Details of the user                                                                                                             | Admin       | rtsAdministrator |
    | deleteUser                    | Remove a user                                                                                                                   | Admin       | rtsAdministrator |
    | metrics                       | Get repository metrics                                                                                                          | Admin       | rtsAdministrator |
    | exportTabPermissions          | Export the tab permissions to JSON                                                                                              | Admin       | rtsAdministrator |
    | exportPermissions             | Export the permissions that are defined for a group to JSON                                                                     | Admin       | rtsAdministrator |
    | effectivePermissions          | Retrieve the effective permissions for one or more groups to JSON                                                               | Admin       |                  |
    | exportCommandPermissions      | Export the command permissions to JSON                                                                                          | Admin       | rtsAdministrator |
    | groups                        | List of the groups that are defined in Decision Center                                                                          | Admin       | rtsAdministrator |
    | eraseAllGroups                | Remove all groups                                                                                                               | Admin       | rtsAdministrator |
    | group                         | Details of the group                                                                                                            | Admin       | rtsAdministrator |
    | deleteGroup                   | Remove a group                                                                                                                  | Admin       | rtsAdministrator |
    | listDynamicDomains            | Get the list of dynamic domains                                                                                                 | Admin       |                  |
    | deleteDecisionService         | Delete a decision service                                                                                                       | Admin       | rtsAdministrator |
    | decisionServiceExport         | Export a decision service to a compressed file                                                                                  | Admin       |                  |
    | branch_1                      | Details of the branch from which the security configuration is inherited from                                                   | Admin       | rtsAdministrator |
    | branchGroups                  | Comma-separated list of the groups that are set on a branch                                                                     | Admin       | rtsAdministrator |
    | run                           | Run a test suite                                                                                                                | Build       |                  |
    | deploy                        | Deploy a RuleApp to an execution server (Rule Execution Server)                                                                 | Build       |                  |
    | build                         | Build a RuleApp for the deployment configuration                                                                                | Build       |                  |
    | snapshot_1                    | Create a snapshot of a branch in the decision service                                                                           | Build       |                  |
    | deleteTestReport              | Delete a test report                                                                                                            | Build       |                  |
    | download                      | Download the RuleApp archive for the deployment configuration                                                                   | Build       |                  |
    | setPersistenceLocale          | Set persistence locale                                                                                                          | DBAdmin     | rtsAdministrator |
    | wipe                          | Wipe element version content                                                                                                    | DBAdmin     |                  |
    | uploadMessagesFile            | Persist localized messages file                                                                                                 | DBAdmin     | rtsAdministrator |
    | uploadExtensionModelFiles     | Persist model extension files .brmx and .brdx                                                                                   | DBAdmin     | rtsAdministrator |
    | executeSQLScript              | Run SQL script                                                                                                                  | DBAdmin     | rtsAdministrator |
    | generate                      | Launch DC database diagnostics generation                                                                                       | DBAdmin     | rtsAdministrator |
    | generateExtensionModelScript  | Generate an SQL script for model extensions                                                                                     | DBAdmin     | rtsAdministrator |
    | stopCleanup                   | Stop cleanup operation                                                                                                          | DBAdmin     | rtsAdministrator |
    | launchCleanup                 | Launch cleanup of the repository                                                                                                | DBAdmin     | rtsAdministrator |
    | getExecutionStatus            | Get the run status of the SQL script                                                                                            | DBAdmin     |                  |
    | getModelExtensionFiles        | Retrieve model extension files as file archive                                                                                  | DBAdmin     | rtsAdministrator |
    | generateMigrationRole         | Generate a migration role                                                                                                       | DBAdmin     | rtsAdministrator |
    | generateMigrationScript       | Generate migration script                                                                                                       | DBAdmin     | rtsAdministrator |
    | results                       | Get DC database diagnostics results                                                                                             | DBAdmin     | rtsAdministrator |
    | isCleanupRunning              | Check cleanup execution                                                                                                         | DBAdmin     |                  |
    | cleanupReport                 | Export report for last cleanup operation to JSON                                                                                | DBAdmin     |                  |
    | cleanupOldReports             | Export old cleanup reports to JSON                                                                                              | DBAdmin     |                  |
    | snapshots                     | List of the snapshots that are associated with the decision service                                                             | Explore     |                  |
    | releases                      | List of the releases in the decision service                                                                                    | Explore     |                  |
    | branches                      | List of the branches in the decision service                                                                                    | Explore     |                  |
    | server                        | Details of the server                                                                                                           | Explore     |                  |
    | release                       | Details of the release                                                                                                          | Explore     |                  |
    | ruleflows                     | List of ruleflows in a project                                                                                                  | Explore     |                  |
    | folders                       | List of folders of a project                                                                                                    | Explore     |                  |
    | activity                      | Details of the activity                                                                                                         | Explore     |                  |
    | testSuite                     | Details of the test suite                                                                                                       | Explore     |                  |
    | testReport                    | Details of the test report                                                                                                      | Explore     |                  |
    | snapshot_2                    | Details of the snapshot                                                                                                         | Explore     |                  |
    | servers                       | List of the servers that are defined in Decision Center                                                                         | Explore     |                  |
    | project                       | Get the project with the ID                                                                                                     | Explore     |                  |
    | variablesets                  | List of variableSet in a project                                                                                                | Explore     |                  |
    | technicalrules                | List of technical rules in a project                                                                                            | Explore     |                  |
    | rules                         | List of rules in a project                                                                                                      | Explore     |                  |
    | generateReport                | Generate a report for the project                                                                                               | Explore     |                  |
    | queries                       | List of queries in a project                                                                                                    | Explore     |                  |
    | queryRun                      | List of elements returned by a query                                                                                            | Explore     |                  |
    | queryReport                   | Generate a report with the elements returned by a query                                                                         | Explore     |                  |
    | operations                    | List of operations in a project                                                                                                 | Explore     |                  |
    | functions                     | List of functions in a project                                                                                                  | Explore     |                  |
    | deploymentConfiguration       | Details of the deployment configuration                                                                                         | Explore     |                  |
    | DeploymentReport              | Details of the deployment report                                                                                                | Explore     |                  |
    | decisionServices              | Get the list of decision services                                                                                               | Explore     |                  |
    | decisionService               | Get a decision service by its ID                                                                                                | Explore     |                  |
    | testSuites                    | List of the test suites for the decision service                                                                                | Explore     |                  |
    | testReports                   | List of the test reports for the decision service                                                                               | Explore     |                  |
    | projects                      | List of the projects that form the decision service, and the decision service itself                                            | Explore     |                  |
    | deploymentConfigurations      | List of the deployment configurations for the decision service                                                                  | Explore     |                  |
    | DeploymentReports             | List of the deployment reports for the decision service                                                                         | Explore     |                  |
    | activities                    | List of the activities in the decision service                                                                                  | Explore     |                  |
    | branch                        | Details of the branch                                                                                                           | Explore     |                  |
    | createValidationActivity      | Create a validation activity in an open release                                                                                 | Govern      |                  |
    | createChangeActivity          | Create a change activity in an open release                                                                                     | Govern      |                  |
    | createRelease                 | Create a new release in a decision service                                                                                      | Govern      |                  |
    | updateRelease                 | Update an open release of a decision service                                                                                    | Govern      |                  |
    | deleteRelease                 | Delete an open release in a decision service                                                                                    | Govern      |                  |
    | reopenRelease                 | Reopen a release that is canceled or rejected in a decision service                                                             | Govern      |                  |
    | removeReleaseApprover         | Remove an approver from an open release of a decision service                                                                   | Govern      |                  |
    | rejectRelease                 | Reject the open release of a decision service                                                                                   | Govern      |                  |
    | changeReleaseOwner            | Change the owner of an open release of a decision service                                                                       | Govern      |                  |
    | cancelRelease                 | Cancel an open release in a decision service                                                                                    | Govern      |                  |
    | approveRelease                | Approve an open release of a decision service                                                                                   | Govern      |                  |
    | allowReleaseApproval          | Allow the approval of an open release of a decision service                                                                     | Govern      |                  |
    | addReleaseApprover            | Add an approver to an open release of a decision service                                                                        | Govern      |                  |
    | updateActivity                | Update an activity in an open release                                                                                           | Govern      |                  |
    | deleteActivity                | Delete an activity in an open release                                                                                           | Govern      |                  |
    | resumeWorkInActivity          | Resume work in an activity in an open release                                                                                   | Govern      |                  |
    | reopenActivity                | Reopen an activity in an open release                                                                                           | Govern      |                  |
    | removeActivityAuthor          | Remove an author from an activity in an open release                                                                            | Govern      |                  |
    | removeActivityApprover        | Remove an approver from an activity in an open release                                                                          | Govern      |                  |
    | rejectChangesInActivity       | Reject changes of an activity in an open release                                                                                | Govern      |                  |
    | finishWorkInActivity          | Finish work on an activity in an open release                                                                                   | Govern      |                  |
    | changeActivityOwner           | Change the owner of an activity in an open release                                                                              | Govern      |                  |
    | cancelActivity                | Cancel an activity in an open release                                                                                           | Govern      |                  |
    | approveChangesInActivity      | Approve changes of an activity in an open release                                                                               | Govern      |                  |
    | allowActivityApproval         | Allow approval for an activity in an open release                                                                               | Govern      |                  |
    | addActivityAuthor             | Add an author to an activity in an open release                                                                                 | Govern      |                  |
    | addActivityApprover           | Add an approver to an activity in an open release                                                                               | Govern      |                  |
    | applyAsset                    | Import a decision service defined from a JSON description                                                                       | Interchange |                  |
    | registerWebhook               | Register a webhook to notify other applications of events that are coming from Decision Center                                  | Manage      | rtsAdministrator |
    | renameSnapshot                | Rename a snapshot from a decision service                                                                                       | Manage      |                  |
    | addServer                     | Add a target server to use for deployments, simulations, and tests                                                              | Manage      | rtsAdministrator |
    | snapshot                      | Create a snapshot of a branch in the decision service                                                                           | Manage      |                  |
    | createDSBranch                | Create a new branch in a decision service                                                                                       | Manage      |                  |
    | renameBranch                  | Rename a branch from a decision service                                                                                         | Manage      |                  |
    | copyBranch                    | Create a new branch from an existing one, and set its parent to the main branch, or the initial release in the case of releases | Manage      |                  |
    | registerWebhook_1             | Update a webhook to notify other applications of events that are coming from Decision Center                                    | Manage      | rtsAdministrator |
    | deleteWebhook                 | Unregister a webhook                                                                                                            | Manage      | rtsAdministrator |
    | updateServer                  | Update a target server to use for deployments, simulations, and tests                                                           | Manage      | rtsAdministrator |
    | deleteServer                  | Remove a target server to use for deployments, simulations, and tests                                                           | Manage      | rtsAdministrator |
    | importDT                      | Import an Excel file into an existing decision table                                                                            | Manage      |                  |
    | webhooks                      | Get a list of the webhooks that are bound to this instance of Decision Center                                                   | Manage      | rtsAdministrator |
    | deleteSnapshot                | Delete a snapshot from a decision service                                                                                       | Manage      |                  |
    | exportDT                      | Export an Excel file from an existing decision table                                                                            | Manage      |                  |
    | deleteBranch                  | Delete a branch from a decision service                                                                                         | Manage      |                  |
    | discardBuildState             | Discard all the built states of branches, releases, activities, and snapshots                                                   | Manage      | rtsAdministrator |
    | updateRuleflow                | Update an existing ruleflow                                                                                                     | Model       |                  |
    | moveRuleflow                  | Move a ruleflow                                                                                                                 | Model       |                  |
    | updateTransition              | Update an existing transition                                                                                                   | Model       |                  |
    | updateRuleTask                | Update an existing rule task                                                                                                    | Model       |                  |
    | renameFolder                  | Rename a folder                                                                                                                 | Model       |                  |
    | moveFolder                    | Move a folder                                                                                                                   | Model       |                  |
    | updateDecisionTable           | Update an existing decision table                                                                                               | Model       |                  |
    | moveDecisionTable             | Move a decision table                                                                                                           | Model       |                  |
    | updateActionRule              | Update an existing action rule                                                                                                  | Model       |                  |
    | moveActionRule                | Move an action rule                                                                                                             | Model       |                  |
    | createTransition              | Create a new transition                                                                                                         | Model       |                  |
    | createRuleTask                | Create a new rule task                                                                                                          | Model       |                  |
    | createRuleflow                | Create a new ruleflow                                                                                                           | Model       |                  |
    | createFolder                  | Create a new folder                                                                                                             | Model       |                  |
    | createDecisionTable           | Create a new decision table                                                                                                     | Model       |                  |
    | createActionRule              | Create a new action rule                                                                                                        | Model       |                  |

1. Decision Server / RES console tools:

    | OperationId                          | Tool                                                                                 | tag            | role        |
    |--------------------------------------|--------------------------------------------------------------------------------------|----------------|-------------|
    | getRuleApps                          | Returns all the RuleApps contained in the repository.                                | Ruleapps       | resMonitor  |
    | getCountOfRuleApps                   | Get count of ruleapps                                                                | Ruleapps       | resMonitor  |
    | getRuleAppsByName                    | Returns all the RuleApps with the specified name                                     | Ruleapps       | resMonitor  |
    | getCountOfRuleAppsByName             | Get count of ruleapps by name                                                        | Ruleapps       | resMonitor  |
    | getRuleAppWithHighestNumber          | Returns the highest version of a RuleApp, identified by its name                     | Ruleapps       | resMonitor  |
    | getRuleAppWithHighestNumberArchive   | Returns the archive of the highest version of the RuleApp                            | Ruleapps       | resMonitor  |
    | getRuleApp                           | Returns the RuleApp identified by its name and version number                        | Ruleapps       | resMonitor  |
    | getRulesets                          | Returns all the rulesets contained in the RuleApp                                    | Ruleapps       | resMonitor  |
    | getCountOfRulesets                   | Get count of rulesets                                                                | Ruleapps       | resMonitor  |
    | addRuleset                           | Adds a new ruleset in a RuleApp, identified by its name and version number, in the repository| Ruleapps       | resDeployer |
    | getRuleAppArchive                    | Returns the archive of the RuleApp                                                   | Ruleapps       | resMonitor  |
    | notifyRuleAppChanges                 | Notifies to reload all the rulesets contained in the RuleApp                         | Ruleapps       | resMonitor  |
    | getRuleAppProperties                 | Returns all the properties associated with a RuleApp                                 | Ruleapps       | resMonitor  |
    | getCountOfRuleAppProperties          | Get count of ruleapp properties                                                      | Ruleapps       | resMonitor  |
    | addRuleAppProperty                   | Adds a new, named property to a RuleApp, identified by its name and version number   | Ruleapps       | resDeployer |
    | updateRuleAppProperty                | Updates an existing property of a RuleApp identified by its name and version number  | Ruleapps       | resDeployer |
    | deleteRuleAppProperty                | Removes a named property of a RuleApp identified by its name and version number      | Ruleapps       | resDeployer |
    | getRulesetsByName                    | Returns all the rulesets with that name contained in a RuleApp                       | Ruleapps       | resMonitor  |
    | getCountOfRulesetsByName             | Get count of rulesets by name                                                        | Ruleapps       | resMonitor  |
    | getRulesetWithHighestNumber          | Returns the highest version of the ruleset, identified by its name, contained in a RuleApp identified by its name and version number| Ruleapps       | resMonitor  |
    | getRulesetWithHighestNumberArchive   | Returns the archive of the highest version of a ruleset identified by its name and by the name and the highest version of its RuleApp| Ruleapps       | resMonitor  |
    | getRulesetWithHighestNumberArchive2  | Returns the archive of the highest version of a ruleset identified by its name and by the name and version number of its RuleApp| Ruleapps       | resMonitor  |
    | getRuleset                           | Returns the ruleset, identified by its name and version number, contained in a RuleApp| Ruleapps       | resMonitor  |
    | getRulesetXOMs                       | Returns the XOMs referenced by a ruleset contained in a RuleApp                      | Ruleapps       | resMonitor  |
    | getRulesetSignature                  | Returns the signature of a ruleset, identified by its name and version number and by the name and version number of its RuleApp| Ruleapps       | resMonitor  |
    | getRulesetArchive                    | Returns the archive of a ruleset identified by its name and version number and by the name and version number of its RuleApp| Ruleapps       | resMonitor  |
    | notifyRulesetChanges                 | Notifies to reload the ruleset, identified by its name and version number and by the name and version number of its RuleApp| Ruleapps       | resMonitor  |
    | getRulesetProperties                 | Returns all the properties associated with a ruleset, identified by its name and version number and by the name and version number of its RuleApp| Ruleapps       | resMonitor  |
    | getCountOfRulesetProperties          | Get count of ruleset properties                                                      | Ruleapps       | resMonitor  |
    | addRulesetProperty                   | Adds a new, named property to a ruleset, identified by its name and version number, contained in a RuleApp identified by its name and version number| Ruleapps       | resDeployer |
    | updateRulesetArchive                 | Replaces an existing ruleset archive by another ruleset archive                      | Ruleapps       | resDeployer |
    | updateRulesetProperty                | Updates an existing property of a ruleset, identified by its name and version number and by the name and version number of the RuleApp| Ruleapps       | resDeployer |
    | deleteRulesetProperty                | Removes a named property of a ruleset identified by its name and version number, contained in a RuleApp identified by its name and version number| Ruleapps       | resDeployer |
    | deployRulesetArchive                 | Deploys a ruleset archive at the specified location in the repository                | Ruleapps       | resDeployer |
    | updateRuleset                        | Updates an existing ruleset in a RuleApp, identified by their names and version numbers, in the repository| Ruleapps       | resDeployer |
    | deleteRuleset                        | Removes a ruleset, identified by its name and version number, contained in a RuleApp, identified by its name and version number| Ruleapps       | resDeployer |
    | updateRuleApp                        | Updates an existing RuleApp in the repository                                        | Ruleapps       | resDeployer |
    | deleteRuleApp                        | Removes a RuleApp, identified by its name and version number, from the repository    | Ruleapps       | resDeployer |
    | deployRuleAppArchive                 | Deploys a RuleApp archive in the repository, based on the merging and versioning policies passed as parameters| Ruleapps       | resDeployer |
    | addRuleApp                           | Adds a new RuleApp in the repository                                                 | Ruleapps       | resDeployer |
    | getAllRulesets                       | Returns all the rulesets of the repository.                                          | Rulesets       | resMonitor  |
    | getCountOfAllRulesets                | Get count of all rulesets                                                            | Rulesets       | resMonitor  |
    | getLibraries                         | Returns all the managed XOM libraries contained in the repository.                   | Libraries      | resMonitor  |
    | getCountOfLibraries                  | Get count of libraries                                                               | Libraries      | resMonitor  |
    | getLibrariesByName                   | Returns all the managed XOM libraries, identified by their name                      | Libraries      | resMonitor  |
    | getCountOfLibrariesByName            | Get count of libraries by name                                                       | Libraries      | resMonitor  |
    | getLibraryWithHighestNumber          | Returns the highest version of a managed XOM library, identified by its name         | Libraries      | resMonitor  |
    | getLibrary                           | Returns the description of a managed XOM library                                     | Libraries      | resMonitor  |
    | addLibrary                           | Adds a new managed XOM library in the repository.                                    | Libraries      | resDeployer |
    | updateLibrary                        | Updates the resources and libraries referenced by an existing managed XOM library    | Libraries      | resDeployer |
    | deleteLibrary                        | Removes a named library from the repository                                          | Libraries      | resDeployer |
    | deleteUnusedLibraries                | Removes libraries that are unused and/or in error from the repository                | Libraries      | resDeployer |
    | getResources                         | Returns all the managed XOMs contained in the repository.                            | Xoms           | resMonitor  |
    | getCountOfResources                  | Get count of resources                                                               | Xoms           | resMonitor  |
    | getResourcesByName                   | Returns all the managed XOMs with the specified name                                 | Xoms           | resMonitor  |
    | getCountOfResourcesByName            | Get count of resources by name                                                       | Xoms           | resMonitor  |
    | getByteCodeOfHighestResource         | Returns the byte code of the highest version of the managed XOM                      | Xoms           | resMonitor  |
    | getResourceWithHighestNumber         | Returns the highest version of a managed XOM identified by its name                  | Xoms           | resMonitor  |
    | getResource                          | Returns the description of a managed XOM                                             | Xoms           | resMonitor  |
    | getByteCodeOfResource                | Returns the byte code of a managed XOM identified by its name and version number     | Xoms           | resMonitor  |
    | deleteResource                       | Removes a managed XOM from the repository                                            | Xoms           | resDeployer |
    | deployResource                       | Deploys a managed XOM in the repository                                              | Xoms           | resDeployer |
    | deleteUnusedXomResources             | Removes XOM resources that are unused and/or in error from the repository            | Xoms           | resDeployer |
    | getDecisionTraces                    | Returns all the Decision Warehouse traces that match the optional selection filters from the repository.| Decisiontraces | resMonitor  |
    | getCountOfDecisionTraces             | Get count of decision traces                                                         | Decisiontraces | resMonitor  |
    | getDecisionTrace                     | Returns the Decision Warehouse trace with the specified execution identifier         | Decisiontraces | resMonitor  |
    | deleteDecisionTrace                  | Removes the trace with the specified execution identifier from the repository        | Decisiontraces | resDeployer |
    | deleteDecisionTracesByIds            | Removes all the Decision Warehouse traces when their execution identifier is included in the request body| Decisiontraces | resDeployer |
    | deleteDecisionTraces                 | Removes all the Decision Warehouse traces that match the optional selection filters. | Decisiontraces | resDeployer |
    | getExecutionUnits                    | Returns information about all execution units.                                       | Executionunits | resMonitor  |
    | getCountOfExecutionUnits             | Get count of execution units                                                         | Executionunits | resMonitor  |
    | getRulesetStatistics                 | Returns execution statistics about a ruleset                                         | Executionunits | resMonitor  |
    | resetRulesetStatistics               | Resets the execution statistics about a ruleset.                                     | Executionunits | resDeployer |
    | getRulesetStatisticsForExecutionUnit | Returns execution statistics about a ruleset                                         | Executionunits | resMonitor  |
    | getConsoleInfo                       | Returns the Rule Execution Server console initialization information.                | Utilities      | resMonitor  |
    | getDiagnostics                       | Returns the Rule Execution Server diagnostic information.                            | Utilities      | resMonitor  |
    | getDiagnosticById                    | Returns the diagnostics for a specified element ID.                                  | Utilities      | resMonitor  |
    | getVersion                           | Returns the Rule Execution Server version information.                               | Utilities      | resMonitor  |

### Example 7: Role-based tool filtering

Some tools are restricted to users with specific roles. Those tools are automatically filtered out when the management MCP server uses credentials that do not grant the required role(s).
Please refer to the 'role' column in the table above to see the role required by each tool.

In the example below (suitable for ODM for Developer), two MCP servers are defined, each using different credentials.
- the first MCP server publishes the subset of Decision Center tools accessible to users with the `rtsUser` role
- the second MCP server publishes the subset of Decision Server console tools accessible to users with the `rtsMonitor` role

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

### Example 8: Monitoring enabled

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

## Additional information

- For IBM Operational Decision Manager (ODM), see [IBM Documentation](https://www.ibm.com/docs/en/odm).
- For IBM Watsonx Orchestrate, see [Getting Started](https://www.ibm.com/docs/en/watsonx/watson-orchestrate/base?topic=getting-started-watsonx-orchestrate).
- For Claude Desktop, see [Claude Documentation](https://support.claude.com/en/collections/16163169-claude-desktop).
