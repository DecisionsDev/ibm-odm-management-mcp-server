# IBM ODM Management MCP Server Documentation (BETA)

## Overview

The IBM ODM Management MCP Server bridges IBM ODM Decision Center with modern AI assistants and orchestration platforms.
It enables you to:
- Expose Decision Center REST API endpoints as tools for AI assistants
- Integrate easily with Watson Orchestrate, Claude Desktop, and Cursor AI

## Features

- **Tool Integration:** Expose ODM Decision Center REST API endpoints as tools
- **Authentication:** Zen API Key, Basic Auth, and OpenID Connect
- **Multi-Platform:** Works with Watson Orchestrate, Claude Desktop, Cursor AI, ...

## Quickstart: Claude Desktop Integration

For detailed instructions on setting up and using Claude Desktop with the Management MCP Server, see the [Claude Desktop Integration Guide](/docs/Claude-desktop-integration-guide.md).

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

  | Zen permissions |
  |-----------------|
  | ODM - Administer Decision Center |
  | ODM - Administer database for Decision Center |
  | ODM - Manage decision services and deployment in Decision Center |
  | ODM - Manage decision services in Decision Center |

> Note: The `ODM - Administer Decision Center` role is required for some tools.

Read more in [Managing user permissions](https://www.ibm.com/docs/en/cloud-paks/cp-biz-automation/25.0.0?topic=access-managing-user-permissions).

#### 2.2. ODM on Kubernetes

If ODM is deployed on Kubernetes, the user/service account used must have at least one of the roles below:

  | ODM roles           |
  |---------------------|
  | rtsAdministrators   |
  | rtsUsers            |

> Note: The `Administator` role is required for some tools.

#### 2.3. ODM on Cloud

If ODM is deployed in the managed offering ODM on Cloud, the user/service account used must have at least one of the roles below assigned (for the suitable environment (Development / Test / Production)):

  | Decision Center Role |
  |----------------------|
  | Administrator        |
  | Configuration Manager|
  | User                 |

> Note: The `Administator` role is required for some tools.

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

The ODM Decision Center server can be configured to check the authenticity of the clients that try to establish a secure connection.

In that case, the Management MCP server (which acts as a client), must be configured with both a private key and its related certificate (and the server must be configured to trust the clients presenting that certificate when establishing a secure connection).

The parameters below can be specified:
  - **CLI:** `--mtls-key-path <PRIVATE_KEY_PATH> --mtls-cert-path <CERT_PATH>` and optionally `--mtls-key-password <PASSWORD>` if the private key is password-protected.
  - **Env:** `MTLS_KEY_PATH=<private_key_path> MTLS_CERT_PATH=<cert_path>` and optionally `MTLS_KEY_PASSWORD=<password>` if the private key is password-protected.


## Configuration Parameters Table

| CLI Argument      | Environment Variable | Description                                                                                            | Default                                 |
|-------------------|---------------------|---------------------------------------------------------------------------------------------------------|-----------------------------------------|
| `--url`           | `ODM_URL`           | URL of the Decision Center REST API                      |              |
| `--res-url`       | `ODM_RES_URL`       | URL of the Decision Server Console (aka RES Console)     |              |
| `--username`      | `ODM_USERNAME`      | Username for Basic Auth or Zen authentication                                                           | `odmAdmin`                              |
| `--password`      | `ODM_PASSWORD`      | Password for Basic Auth                                                                                 | `odmAdmin`                              |
| `--zenapikey`     | `ZENAPIKEY`         | Zen API Key for authentication with Cloud Pak for Business Automation                                   |                                         |
| `--client-id`     | `CLIENT_ID`         | OpenID Connect client ID for authentication                                                             |                                         |
| `--client-secret` | `CLIENT_SECRET`     | OpenID Connect client secret for authentication                                                         |                                         |
| `--pkjwt-cert-path` | `PKJWT_CERT_PATH` | Path to the certificate for PKJWT authentication (mandatory for PKJWT)                                  |                                         |
| `--pkjwt-key-path` | `PKJWT_KEY_PATH`   | Path to the private key certificate for PKJWT authentication (mandatory for PKJWT)                      |                                         |
| `--pkjwt-key-password` | `PKJWT_KEY_PASSWORD` | Password to decrypt the private key for PKJWT authentication. Only needed if the key is password-protected. |                               |
| `--token-url`     | `TOKEN_URL`         | OpenID Connect token endpoint URL for authentication                                                    |                                         |
| `--scope`         | `SCOPE`             | OpenID Connect scope used when requesting an access token using Client Credentials for authentication   | `openid`                                |
| `--verifyssl`     | `VERIFY_SSL`        | Whether to verify SSL certificates (`True` or `False`)                                                  | `True`                                  |
| `--ssl-cert-path` | `SSL_CERT_PATH`     | Path to the SSL certificate file. If not provided, defaults to system certificates.                     |                                         |
| `--mtls-cert-path`| `MTLS_CERT_PATH`    | Path to the SSL certificate file of the client for mutual TLS authentication (mandatory for mTLS)       |                                         |
| `--mtls-key-path` | `MTLS_KEY_PATH`     | Path to the SSL private key file of the client for mutual TLS authentication (mandatory for mTLS)       |                                         |
| `--mtls-key-password` | `MTLS_KEY_PASSWORD` | Password to decrypt the private key of the client for mutual TLS authentication. Only needed if the key is password-protected. |              |
| `--log-level`     | `LOG_LEVEL`         | Set the logging level (`DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`)                                 | `INFO`                                  |
| `--traces-dir`    | `TRACES_DIR`        | Directory to store execution traces                                                                     | `~/.ibm-odm-management-mcp-server/traces`                  |
| `--trace`         | `TRACE`           | Specifies what to trace (`EXECUTIONS`, `EXECUTIONS_WITH_CONTENT`, `CONFIGURATION`)                             |
| `--traces-maxsize` | `TRACES_MAXSIZE`  | Maximum number of traces to store before removing oldest traces                                          | `200`                                    |

> Parameters specific to Decision Center REST API
>| CLI Argument | Environment Variable | Description | Default |
>|--------------|----------------------|-------------|---------|
>| `--tags`     | `TAGS`               | List of tags (eg. About Explore Build). Useful to keep only the tools whose tag is in the list. If this option is not specified, all the tools are published by the MCP server. | |
>| `--tools`    | `TOOLS`              | List of tools to publish (eg. decisionServices releases createRelease). This option can be used along with --tags but it takes precedence over the option --no-tools | |
>| `--no-tools` | `NO_TOOLS`           | List of tools to ignore  (eg. launchCleanup wipe executeSqlScript). This option can be used along with --tags but is ignored if the option --tools is specified. | |

> Parameters to start the MCP server in remote mode (allowing connections from remote MCP clients) 
>| CLI Argument | Environment Variable | Description | Default |
>|--------------|----------------------|-------------|---------|
>| `--transport`| `TRANSPORT`          | `stdio`, `streamable-http` or `sse` : Means of communication of the Management MCP server: local (`stdio`) or remote (`streamable-http` or `sse`)) | `stdio` |
>| `--host`     | `HOST`               | IP or hostname that the MCP server listens to in remote mode. | `0.0.0.0` |
>| `--port`     | `PORT`               | Port that the MCP server listens to in remote mode. | `3000` |
>| `--mount-path`| `MOUNT_PATH`        | Path that the MCP server listens to in remote mode. | `/mcp` |

## MCP Server Configuration File          

You can configure the MCP server for clients like Claude Desktop or Cursor AI using a JSON configuration file, which can contain both environment variables and command-line arguments.

**Tips:**
- Use CLI arguments for quick overrides or non-sensitive parameters.
- Use environment variables for secrets.
- You can mix both methods if needed. CLI arguments override environment variables.

The example below shows a typical use-case where the sensitive information (here the password) is passed as an environment variable (so that it does not show in the arguments of the process), and the other parameters are passed as CLI arguments:

```json
{
  "mcpServers": {
    "ibm-odm-management-mcp-server": {
      "command": "uvx",
      "args": [
        "--from", "git+https://github.com/DecisionsDev/ibm-odm-management-mcp-server",
        "ibm-odm-management-mcp-server",
        "--url", "https://odm-decisioncenter-api-url",
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

The examples below demonstrate various use cases depending on the type of deployment (dev/test or production), and environments (CloudPak, ...).

### Example 1: Basic Auth for Local Development

For local development and testing, use the Basic Auth.

```json
"args": [
  "--from", "git+https://github.com/DecisionsDev/ibm-odm-management-mcp-server",
  "ibm-odm-management-mcp-server",
  "--url", "http://localhost:9060/decisioncenter-api",
  "--username", "odmAdmin"
],
"env": {
  "ODM_PASSWORD": "odmAdmin"
}
```

### Example 2: For Cloud Pak (Zen API Key)

For production deployments on the Cloud Pak, use the Zen API Key.

```json
"args": [
  "--from", "git+https://github.com/DecisionsDev/ibm-odm-management-mcp-server",
  "ibm-odm-management-mcp-server",
  "--url",           "https://odm-decisioncenter-api-url",
  "--ssl-cert-path", "certificate-file",
  "--username",      "USERNAME"
],
"env": {
  "ZENAPIKEY": "ZEN_API_KEY"
}
```

### Example 3: OpenID Connect

For production deployments on other environments than the Cloud Pak, you may use OpenID Connect if ODM is configured to use it.

The Management MCP Server can authenticate to ODM configured with OpenID Connect, using the Client Credentials flow.

Two authentication variants are possible:

1) Using a Client Secret
```json
"args": [
  "--from", "git+https://github.com/DecisionsDev/ibm-odm-management-mcp-server",
  "ibm-odm-management-mcp-server",
  "--url",           "https://odm-decisioncenter-api-url",
  "--ssl-cert-path", "certificate-file",
  "--token-url",     "https://your-openid-connect_provider-token-endpoint-url",
  "--scope",         "the_scope_to_be_used_for_client_credentials"
],
"env": {
  "CLIENT_ID":      "YOUR_CLIENT_ID",
  "CLIENT_SECRET":  "YOUR_CLIENT_SECRET"
}
```

2) Using a Private Key (PKJWT)
```json
"args": [
  "--from", "git+https://github.com/DecisionsDev/ibm-odm-management-mcp-server",
  "ibm-odm-management-mcp-server",
  "--url",           "https://odm-decisioncenter-api-url",
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

### Example 4: mTLS (Mutual TLS) Authentication

The Management MCP Server also supports mTLS (mutual TLS) authentication, which secure the SSL connection further.

mTLS must be complemented with another means of authentication/authorization for authorization purpose (to assess the right to access to the Decision Center), for instance with basic auth in the example below:

```json
"args": [
  "--from", "git+https://github.com/DecisionsDev/ibm-odm-management-mcp-server",
  "ibm-odm-management-mcp-server",
  "--url",           "https://odm-decisioncenter-api-url",
  "--ssl-cert-path", "certificate-file",
  "--username",      "USERNAME_OR_SERVICE_ACCOUNT"
],
"env": {
  "PASSWORD":       "USERNAME_OR_SERVICE_ACCOUNT_PASSWORD",
  "MTLS_KEY_PATH":  "MTLS_PRIVATE_KEY_FILENAME",
  "MTLS_CERT_PATH": "MTLS_CERTIFICATE_FILENAME"
}
```

### Example 5: Tool filtering

You may want to have only a subset of tools published.
You can achieve that is various ways:
1. You can specify the tag(s) of the tools that should be published

    For instance, you can specify all the tags but `Admin` and `DBAdmin` to filter out the tools from those two categories: 
    ```json
    "args": [
    ...
    "--tags", "About", "Explore", "Manage", "Govern", "Build", "Interchange"
    ...
    ```
1. You can specify the tools to publish

    For instance, you can specify to publish only the tools `decisionServices` (to list decision services), `decisionService` (to get a decision service by its ID), `testSuites` (list of test suites), `run` (to run a test suite), `testreports` and `decisionServicesImport`: 
    ```json
    "args": [
    ...
    "--tools", "decisionServices", "decisionService", "testSuites", "run", "testreports", "decisionServicesImport"
    ...
    ```
    
1. You can specify the tools that should not be published 

    For instance, you can have all the tools published but `wipe`, `executeSQLScript` and `launchCleanup`
    ```json
    "args": [
    ...
    "--tags", "About", "Explore", "Manage", "Govern", "Build", "Admin", "DBAdmin",
    "--no-tools", "wipe", "executeSQLScript", "launchCleanup"
    ...
    ```

    > Note 1: The `--no-tools` option is ignored if the option `--tools` is specified.

    > Note 2: the `--tags` option can be used along (in the example above, the tag `interchange` is not specified so all the tools from that category are filtered out as well).

Tools are identified by their `operationId` in the `--tools` and `--no-tools` options.

Here is the list of the tools with their `operationId` and tag in ODM 9.5.0.1:

  | `operationId` | tool      | tag     | role    |
  |---------------|-----------|---------|---------|
  | registerWebhook | Register a webhook to notify other applications of events that are coming from Decision Center | Manage | admin |
  | renameSnapshot | Rename a snapshot from a decision service | Manage | |
  | addServer | Add a target server to use for deployments, simulations, and tests | Manage | admin |
  | createValidationActivity | Create a validation activity in an open release | Govern | |
  | createChangeActivity | Create a change activity in an open release | Govern | |
  | snapshots | List of the snapshots that are associated with the decision service | Explore | |
  | snapshot | Create a snapshot of a branch in the decision service | Manage | |
  | releases | List of the releases in the decision service | Explore | |
  | createRelease | Create a new release in a decision service | Govern | |
  | branches | List of the branches in the decision service | Explore | |
  | createDSBranch | Create a new branch in a decision service | Manage | |
  | renameBranch | Rename a branch from a decision service | Manage | |
  | copyBranch | Create a new branch from an existing one, and set its parent to the main branch, or the initial release in the case of releases | Manage | |
  | setPersistenceLocale | Set persistence locale | DBAdmin | admin |
  | registerWebhook_1 | Update a webhook to notify other applications of events that are coming from Decision Center | Manage | admin |
  | deleteWebhook | Unregister a webhook | Manage | admin |
  | addUser | Add or update a user | Admin | admin |
  | run | Run a test suite | Build | |
  | server | Details of the server | Explore | |
  | updateServer | Update a target server to use for deployments, simulations, and tests | Manage | admin |
  | deleteServer | Remove a target server to use for deployments, simulations, and tests | Manage | admin |
  | getUsersRolesRegistry | Retrieve the last configuration file that was uploaded | Admin | admin |
  | setUsersRolesRegistry | Set the configuration for users, groups and roles | Admin | admin |
  | ldapSync | Synchronize the repository with any associated LDAP server | Admin | admin |
  | release | Details of the release | Explore | |
  | updateRelease | Update an open release of a decision service | Govern | |
  | deleteRelease | Delete an open release in a decision service | Govern | |
  | reopenRelease | Reopen a release that is canceled or rejected in a decision service | Govern | |
  | removeReleaseApprover | Remove an approver from an open release of a decision service | Govern | |
  | rejectRelease | Reject the open release of a decision service | Govern | |
  | changeReleaseOwner | Change the owner of an open release of a decision service | Govern | |
  | cancelRelease | Cancel an open release in a decision service | Govern | |
  | approveRelease | Approve an open release of a decision service | Govern | |
  | allowReleaseApproval | Allow the approval of an open release of a decision service | Govern | |
  | addReleaseApprover | Add an approver to an open release of a decision service | Govern | |
  | importTabPermissions | Import tab permissions | Admin | admin |
  | importPermissions | Import permissions | Admin | |
  | importCommandPermissions | Import command permissions | Admin | admin |
  | addGroup | Add or update a group | Admin | admin |
  | updateDynamicDomains | Update dynamic domains | Admin | |
  | deploy | Deploy a RuleApp to an execution server (Rule Execution Server) | Build | |
  | build | Build a RuleApp for the deployment configuration | Build | |
  | snapshot_1 | Create a snapshot of a branch in the decision service | Build | |
  | branchImport | Import a decision service on top of an existing branch | Admin | |
  | importDT | Import an Excel file into an existing decision table | Manage | |
  | decisionServicesImport | Import a decision service into the repository | Admin | |
  | branchSecurity | Security configuration of a branch | Admin | admin |
  | branchSecurity_1 | Enforce the security on a branch | Admin | admin |
  | applyAsset | None | Interchange | |
  | activity | Details of the activity | Explore | |
  | updateActivity | Update an activity in an open release | Govern | |
  | deleteActivity | Delete an activity in an open release | Govern | |
  | resumeWorkInActivity | Resume work in an activity in an open release | Govern | |
  | reopenActivity | Reopen an activity in an open release | Govern | |
  | removeActivityAuthor | Remove an author from an activity in an open release | Govern | |
  | removeActivityApprover | Remove an approver from an activity in an open release | Govern |
  | rejectChangesInActivity | Reject changes of an activity in an open release | Govern | |
  | finishWorkInActivity | Finish work on an activity in an open release | Govern | |
  | changeActivityOwner | Change the owner of an activity in an open release | Govern | |
  | cancelActivity | Cancel an activity in an open release | Govern | |
  | approveChangesInActivity | Approve changes of an activity in an open release | Govern | |
  | allowActivityApproval | Allow approval for an activity in an open release | Govern | |
  | addActivityAuthor | Add an author to an activity in an open release | Govern | |
  | addActivityApprover | Add an approver to an activity in an open release | Govern | |
  | wipe | Wipe element version content | DBAdmin | |
  | uploadMessagesFile | Persist localized messages file | DBAdmin | admin |
  | uploadExtensionModelFiles | Persist model extension files .brmx and .brdx | DBAdmin | admin |
  | executeSQLScript | Run SQL script | DBAdmin | admin |
  | generate | Launch DC database diagnostics generation | DBAdmin | admin |
  | generateExtensionModelScript | Generate an SQL script for model extensions | DBAdmin | admin |
  | stopCleanup | Stop cleanup operation | DBAdmin | admin |
  | launchCleanup | Launch cleanup of the repository | DBAdmin | admin |
  | webhooks | Get a list of the webhooks that are bound to this instance of Decision Center | Manage | admin |
  | users | List of the users that are defined in Decision Center | Admin | admin |
  | eraseAllUsers | Remove all users | Admin | admin |
  | user | Details of the user | Admin | admin |
  | deleteUser | Remove a user | Admin | admin |
  | testSuite | Details of the test suite | Explore | |
  | testReport | Details of the test report | Explore | |
  | deleteTestReport | Delete a test report | Build | |
  | snapshot_2 | Details of the snapshot | Explore | |
  | deleteSnapshot | Delete a snapshot from a decision service | Manage | |
  | servers | List of the servers that are defined in Decision Center | Explore | |
  | metrics | Get repository metrics | Admin | admin |
  | project | Get the project with the ID | Explore | |
  | variablesets | List of variableSet in a project | Explore | |
  | technicalrules | List of technical rules in a project | Explore | |
  | rules | List of rules in a project | Explore | |
  | ruleflows | List of ruleflows in a project | Explore | |
  | generateReport | Generate a report for the project | Explore | |
  | queries | List of queries in a project | Explore | |
  | queryRun | List of elements returned by a query | Explore | |
  | queryReport | Generate a report with the elements returned by a query | Explore | |
  | operations | List of operations in a project | Explore | |
  | functions | List of functions in a project | Explore | |
  | folders | List of folders of a project | Explore | |
  | exportTabPermissions | Export the tab permissions to JSON | Admin | admin |
  | exportPermissions | Export the permissions that are defined for a group to JSON | Admin | admin |
  | effectivePermissions | Retrieve the effective permissions for one or more groups to JSON | Admin | |
  | exportCommandPermissions | Export the command permissions to JSON | Admin | admin |
  | groups | List of the groups that are defined in Decision Center | Admin | admin |
  | eraseAllGroups | Remove all groups | Admin | admin |
  | group | Details of the group | Admin | admin |
  | deleteGroup | Remove a group | Admin | admin |
  | listDynamicDomains | Get the list of dynamic domains | Admin | |
  | deploymentConfiguration | Details of the deployment configuration | Explore | |
  | download | Download the RuleApp archive for the deployment configuration | Build | |
  | DeploymentReport | Details of the deployment report | Explore | |
  | decisionServices | Get the list of decision services | Explore | |
  | decisionService | Get a decision service by its ID | Explore | |
  | deleteDecisionService | Delete a decision service | Admin | admin |
  | testSuites | List of the test suites for the decision service | Explore | |
  | testReports | List of the test reports for the decision service | Explore | |
  | projects | List of the projects that form the decision service, and the decision service itself | Explore | |
  | decisionServiceExport | Export a decision service to a compressed file | Admin | |
  | deploymentConfigurations | List of the deployment configurations for the decision service | Explore | |
  | DeploymentReports | List of the deployment reports for the decision service | Explore | |
  | exportDT | Export an Excel file from an existing decision table | Manage | |
  | activities | List of the activities in the decision service | Explore | |
  | branch | Details of the branch | Explore | |
  | deleteBranch | Delete a branch from a decision service | Manage | |
  | branch_1 | Details of the branch from which the security configuration is inherited from | Admin | admin |
  | branchGroups | Comma-separated list of the groups that are set on a branch | Admin | admin |
  | about | Get system, product, and database information | About | |
  | getExecutionStatus | Get the run status of the SQL script | DBAdmin | |
  | getModelExtensionFiles | Retrieve model extension files as file archive | DBAdmin | admin |
  | generateMigrationRole | Generate a migration role | DBAdmin | admin |
  | generateMigrationScript | Generate migration script | DBAdmin | admin |
  | results | Get DC database diagnostics results | DBAdmin | admin |
  | isCleanupRunning | Check cleanup execution | DBAdmin | |
  | cleanupReport | Export report for last cleanup operation to JSON | DBAdmin | |
  | cleanupOldReports | Export old cleanup reports to JSON | DBAdmin | |
  | discardBuildState | Discard all the built states of branches, releases, activities, and snapshots | Manage | admin |

### Example 6: Role-based tool filtering

The tools restricted to users with the 'admin' role are implicitly filtered out when the credentials used to configure the management MCP server do not grant this role.
Please refer to the 'role' column in the table above to see which tools require the 'admin' role.

## Additional information

- For IBM Operational Decision Manager (ODM), see [IBM Documentation](https://www.ibm.com/docs/en/odm).
- For IBM Watsonx Orchestrate, see [Getting Started](https://www.ibm.com/docs/en/watsonx/watson-orchestrate/base?topic=getting-started-watsonx-orchestrate).
- For Claude Desktop, see [Claude Documentation](https://support.claude.com/en/collections/16163169-claude-desktop).
