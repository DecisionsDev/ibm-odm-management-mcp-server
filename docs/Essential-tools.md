# Essential and non-essential tools

The IBM ODM Management MCP server publishes 228 tools in total (150 for Decision Center and 78 for the Decision Server console).
Many MCP clients and LLMs work better with a smaller number of tools. By default, the server publishes only a curated subset of the most useful ones: **68 essential tools** instead of 228.

## Choosing the set of tools published (`--tool-profile`)

| CLI Argument | Environment Variable | Description | Default |
|--------------|----------------------|-------------|---------|
| `--tool-profile` | `TOOL_PROFILE` | Set of tools published: `ESSENTIAL` (only the essential tools) or `ALL` (all the tools). | `ESSENTIAL` |

The value is case-insensitive. Any other value is rejected at startup.
At startup, the server logs the profile in use, for instance `Tool profile: ESSENTIAL. By default, only the essential tools are published`.

```json
"args": [
  "--tool-profile", "ALL"
]
```

Tools are identified by their `operationId`, as in the `--tools` and `--no-tools` options. The comparison is not case-sensitive.

## Tuning the list using it with `--tools`, `--no-tools` and `--tags`

The four options can be combined. They are applied in the following order of precedence:

1. `--tools`: a tool listed is always published, even if it is not essential.
1. `--no-tools`: a tool listed is never published, even if it is essential (unless it is also listed in `--tools`).
1. `--tool-profile ESSENTIAL`: a tool that is not essential is not published.
1. `--tags`: a tool that does not belong to one of the tags/categories listed is not published.

| Option combined with `--tool-profile ESSENTIAL` | Effect |
|-------------------------------------------------|--------|
| `--tools t1 t2`   | **Adds** `t1` and `t2` to the essential tools. With `--tool-profile ALL`, `--tools` publishes *only* the tools listed. |
| `--no-tools t1 t2`| **Removes** `t1` and `t2` from the essential tools. |
| `--tags c1 c2`    | **Restricts** the essential tools to those whose tag/category is `c1` or `c2`. |

### Examples

Publish the essential tools only (default, no argument needed):

```json
"args": ["--tool-profile", "ESSENTIAL"]
```

Publish all the tools:

```json
"args": ["--tool-profile", "ALL"]
```

Publish the essential tools, plus `addServer` and `updateServer`, but not `deploy`:

```json
"args": [
  "--tools",    "addServer", "updateServer",
  "--no-tools", "deploy"
]
```

Publish only the essential tools of the `Explore` and `Build` categories:

```json
"args": [
  "--tags", "Explore", "Build"
]
```

> [!NOTE]
> Tools that require a role the credentials do not grant (see the `Role` column below) are filtered out anyway, whatever the options.

## Essential tools

These tools are published when `--tool-profile` is `ESSENTIAL` (default).

### Decision Center tools (50)

| Category | Tool (`operationId`) | Description | Role |
|----------|----------------------|-------------|------|
| About | `about` | Get system, product, and database information |  |
| Admin | `decisionServiceExport` | Export a decision service to a compressed file |  |
| Admin | `decisionServicesImport` | Import a decision service into the repository |  |
| Build | `deploy` | Deploy a RuleApp to an execution server (Rule Execution Server) |  |
| Build | `run` | Run a test suite |  |
| Explore | `branch` | Details of the branch |  |
| Explore | `branches` | List of the branches in the decision service |  |
| Explore | `decisionService` | Get a decision service by its ID |  |
| Explore | `decisionServices` | Get the list of decision services |  |
| Explore | `deploymentConfiguration` | Details of the deployment configuration |  |
| Explore | `deploymentConfigurations` | List of the deployment configurations for the decision service |  |
| Explore | `folders` | List of folders of a project |  |
| Explore | `functions` | List of functions in a project |  |
| Explore | `operations` | List of operations in a project |  |
| Explore | `project` | Get the project with the ID |  |
| Explore | `projects` | List of the projects that form the decision service, and the decision service itself |  |
| Explore | `queries` | List of queries in a project |  |
| Explore | `queryRun` | List of elements returned by a query |  |
| Explore | `release` | Details of the release |  |
| Explore | `releases` | List of the releases in the decision service |  |
| Explore | `ruleflows` | List of ruleflows in a project |  |
| Explore | `rules` | List of rules in a project |  |
| Explore | `snapshots` | List of the snapshots that are associated with the decision service |  |
| Explore | `technicalrules` | List of technical rules in a project |  |
| Explore | `testReport` | Details of the test report |  |
| Explore | `testReports` | List of the test reports for the decision service |  |
| Explore | `testSuite` | Details of the test suite |  |
| Explore | `testSuites` | List of the test suites for the decision service |  |
| Explore | `variablesets` | List of variableSet in a project |  |
| Manage | `createDSBranch` | Create a new branch in a decision service |  |
| Manage | `deleteBranch` | Delete a branch from a decision service |  |
| Manage | `exportDT` | Export an Excel file from an existing decision table |  |
| Manage | `importDT` | Import an Excel file into an existing decision table |  |
| Manage | `renameBranch` | Rename a branch from a decision service |  |
| Model | `createActionRule` | Create a new action rule |  |
| Model | `createDecisionTable` | Create a new decision table |  |
| Model | `createFolder` | Create a new folder |  |
| Model | `createRuleflow` | Create a new ruleflow |  |
| Model | `createRuleTask` | Create a new rule task |  |
| Model | `createTransition` | Create a new transition |  |
| Model | `moveActionRule` | Move an action rule |  |
| Model | `moveDecisionTable` | Move a decision table |  |
| Model | `moveFolder` | Move a folder |  |
| Model | `moveRuleflow` | Move a ruleflow |  |
| Model | `renameFolder` | Rename a folder |  |
| Model | `updateActionRule` | Update an existing action rule |  |
| Model | `updateDecisionTable` | Update an existing decision table |  |
| Model | `updateRuleflow` | Update an existing ruleflow |  |
| Model | `updateRuleTask` | Update an existing rule task |  |
| Model | `updateTransition` | Update an existing transition |  |

### Decision Server console tools (18)

| Category | Tool (`operationId`) | Description | Role |
|----------|----------------------|-------------|------|
| Decisiontraces | `getDecisionTrace` | Returns the Decision Warehouse trace with the specified execution identifier | resMonitor |
| Decisiontraces | `getDecisionTraces` | Returns all the Decision Warehouse traces that match the optional selection filters from the repository. | resMonitor |
| Executionunits | `getExecutionUnits` | Returns information about all execution units. | resMonitor |
| Executionunits | `getRulesetStatistics` | Returns execution statistics about a ruleset | resMonitor |
| Ruleapps | `addRulesetProperty` | Adds a new, named property to a ruleset, identified by its name and version number, contained in a RuleApp identified by its name and version number | resDeployer |
| Ruleapps | `deleteRuleApp` | Removes a RuleApp, identified by its name and version number, from the repository | resDeployer |
| Ruleapps | `deleteRulesetProperty` | Removes a named property of a ruleset identified by its name and version number, contained in a RuleApp identified by its name and version number | resDeployer |
| Ruleapps | `deployRuleAppArchive` | Deploys a RuleApp archive in the repository, based on the merging and versioning policies passed as parameters | resDeployer |
| Ruleapps | `getRuleApp` | Returns the RuleApp identified by its name and version number | resMonitor |
| Ruleapps | `getRuleApps` | Returns all the RuleApps contained in the repository. | resMonitor |
| Ruleapps | `getRuleset` | Returns the ruleset, identified by its name and version number, contained in a RuleApp | resMonitor |
| Ruleapps | `getRulesetProperties` | Returns all the properties associated with a ruleset, identified by its name and version number and by the name and version number of its RuleApp | resMonitor |
| Ruleapps | `getRulesets` | Returns all the rulesets contained in the RuleApp | resMonitor |
| Ruleapps | `getRulesetSignature` | Returns the signature of a ruleset, identified by its name and version number and by the name and version number of its RuleApp | resMonitor |
| Ruleapps | `updateRulesetProperty` | Updates an existing property of a ruleset, identified by its name and version number and by the name and version number of the RuleApp | resDeployer |
| Utilities | `getConsoleInfo` | Returns the Rule Execution Server console initialization information. | resMonitor |
| Utilities | `getDiagnostics` | Returns the Rule Execution Server diagnostic information. | resMonitor |
| Utilities | `getVersion` | Returns the Rule Execution Server version information. | resMonitor |

## Non-essential tools

These tools are *not* published when `--tool-profile` is `ESSENTIAL` (default). Use `--tool-profile ALL` to publish them all, or `--tools` to add some of them back.

### Decision Center tools (100)

| Category | Tool (`operationId`) | Description | Role |
|----------|----------------------|-------------|------|
| Admin | `addGroup` | Add or update a group. | rtsAdministrator |
| Admin | `addUser` | Add or update a user | rtsAdministrator |
| Admin | `branch_1` | Details of the branch from which the security configuration is inherited from | rtsAdministrator |
| Admin | `branchGroups` | Comma-separated list of the groups that are set on a branch | rtsAdministrator |
| Admin | `branchImport` | Import a decision service on top of an existing branch |  |
| Admin | `branchSecurity` | Security configuration of a branch | rtsAdministrator |
| Admin | `branchSecurity_1` | Enforce the security on a branch | rtsAdministrator |
| Admin | `deleteDecisionService` | Delete a decision service | rtsAdministrator |
| Admin | `deleteGroup` | Remove a group | rtsAdministrator |
| Admin | `deleteUser` | Remove a user | rtsAdministrator |
| Admin | `effectivePermissions` | Retrieve the effective permissions for one or more groups to JSON |  |
| Admin | `eraseAllGroups` | Remove all groups | rtsAdministrator |
| Admin | `eraseAllUsers` | Remove all users | rtsAdministrator |
| Admin | `exportCommandPermissions` | Export the command permissions to JSON | rtsAdministrator |
| Admin | `exportPermissions` | Export the permissions that are defined for a group to JSON | rtsAdministrator |
| Admin | `exportTabPermissions` | Export the tab permissions to JSON | rtsAdministrator |
| Admin | `getUsersRolesRegistry` | Retrieve the last configuration file that was uploaded | rtsAdministrator |
| Admin | `group` | Details of the group | rtsAdministrator |
| Admin | `groups` | List of the groups that are defined in Decision Center | rtsAdministrator |
| Admin | `importCommandPermissions` | Import command permissions | rtsAdministrator |
| Admin | `importPermissions` | Import permissions |  |
| Admin | `importTabPermissions` | Import tab permissions | rtsAdministrator |
| Admin | `ldapSync` | Synchronize the repository with any associated LDAP server | rtsAdministrator |
| Admin | `listDynamicDomains` | Get the list of dynamic domains |  |
| Admin | `metrics` | Get repository metrics | rtsAdministrator |
| Admin | `setUsersRolesRegistry` | Set the configuration for users, groups and roles | rtsAdministrator |
| Admin | `unlockAllUserArtifacts` | Unlock all artifacts owned by a user |  |
| Admin | `updateDynamicDomains` | Update dynamic domains |  |
| Admin | `user` | Details of the user | rtsAdministrator |
| Admin | `users` | List of the users that are defined in Decision Center | rtsAdministrator |
| Build | `build` | Build a RuleApp for the deployment configuration |  |
| Build | `deleteTestReport` | Delete a test report |  |
| Build | `download` | Download the RuleApp archive for the deployment configuration |  |
| Build | `snapshot_1` | Create a snapshot of a branch in the decision service |  |
| DBAdmin | `cleanupOldReports` | Export old cleanup reports to JSON |  |
| DBAdmin | `cleanupReport` | Export report for last cleanup operation to JSON |  |
| DBAdmin | `executeSQLScript` | Run SQL script | rtsAdministrator |
| DBAdmin | `generate` | Launch DC database diagnostics generation | rtsAdministrator |
| DBAdmin | `generateExtensionModelScript` | Generate an SQL script for model extensions | rtsAdministrator |
| DBAdmin | `generateMigrationRole` | Generate a migration role | rtsAdministrator |
| DBAdmin | `generateMigrationScript` | Generate migration script | rtsAdministrator |
| DBAdmin | `getExecutionStatus` | Get the run status of the SQL script |  |
| DBAdmin | `getModelExtensionFiles` | Retrieve model extension files as file archive | rtsAdministrator |
| DBAdmin | `isCleanupRunning` | Check cleanup execution |  |
| DBAdmin | `launchCleanup` | Launch cleanup of the repository | rtsAdministrator |
| DBAdmin | `results` | Get DC database diagnostics results | rtsAdministrator |
| DBAdmin | `setPersistenceLocale` | Set persistence locale | rtsAdministrator |
| DBAdmin | `stopCleanup` | Stop cleanup operation | rtsAdministrator |
| DBAdmin | `uploadExtensionModelFiles` | Persist model extension files .brmx and .brdx | rtsAdministrator |
| DBAdmin | `uploadMessagesFile` | Persist localized messages file | rtsAdministrator |
| DBAdmin | `wipe` | Wipe element version content |  |
| Explore | `activities` | List of the activities in the decision service |  |
| Explore | `activity` | Details of the activity |  |
| Explore | `DeploymentReport` | Details of the deployment report |  |
| Explore | `DeploymentReports` | List of the deployment reports for the decision service |  |
| Explore | `generateReport` | Generate a report for the project |  |
| Explore | `queryReport` | Generate a report with the elements returned by a query |  |
| Explore | `server` | Details of the server |  |
| Explore | `servers` | List of the servers that are defined in Decision Center |  |
| Explore | `snapshot_2` | Details of the snapshot |  |
| Govern | `addActivityApprover` | Add an approver to an activity in an open release |  |
| Govern | `addActivityAuthor` | Add an author to an activity in an open release |  |
| Govern | `addReleaseApprover` | Add an approver to an open release of a decision service |  |
| Govern | `allowActivityApproval` | Allow approval for an activity in an open release |  |
| Govern | `allowReleaseApproval` | Allow the approval of an open release of a decision service |  |
| Govern | `approveChangesInActivity` | Approve changes of an activity in an open release |  |
| Govern | `approveRelease` | Approve an open release of a decision service |  |
| Govern | `cancelActivity` | Cancel an activity in an open release |  |
| Govern | `cancelRelease` | Cancel an open release in a decision service |  |
| Govern | `changeActivityOwner` | Change the owner of an activity in an open release |  |
| Govern | `changeReleaseOwner` | Change the owner of an open release of a decision service |  |
| Govern | `createChangeActivity` | Create a change activity in an open release |  |
| Govern | `createRelease` | Create a new release in a decision service |  |
| Govern | `createValidationActivity` | Create a validation activity in an open release |  |
| Govern | `deleteActivity` | Delete an activity in an open release |  |
| Govern | `deleteRelease` | Delete an open release in a decision service |  |
| Govern | `finishWorkInActivity` | Finish work on an activity in an open release |  |
| Govern | `rejectChangesInActivity` | Reject changes of an activity in an open release |  |
| Govern | `rejectRelease` | Reject the open release of a decision service |  |
| Govern | `removeActivityApprover` | Remove an approver from an activity in an open release |  |
| Govern | `removeActivityAuthor` | Remove an author from an activity in an open release |  |
| Govern | `removeReleaseApprover` | Remove an approver from an open release of a decision service |  |
| Govern | `reopenActivity` | Reopen an activity in an open release |  |
| Govern | `reopenRelease` | Reopen a release that is canceled or rejected in a decision service |  |
| Govern | `resumeWorkInActivity` | Resume work in an activity in an open release |  |
| Govern | `updateActivity` | Update an activity in an open release |  |
| Govern | `updateRelease` | Update an open release of a decision service |  |
| Interchange | `applyAsset` | Import a decision service defined from a JSON description |  |
| Manage | `addServer` | Add a target server to use for deployments, simulations, and tests | rtsAdministrator |
| Manage | `copyBranch` | Create a new branch from an existing one, and set its parent to the main branch, or the initial release in the case of releases |  |
| Manage | `deleteServer` | Remove a target server to use for deployments, simulations, and tests | rtsAdministrator |
| Manage | `deleteSnapshot` | Delete a snapshot from a decision service |  |
| Manage | `deleteWebhook` | Unregister a webhook | rtsAdministrator |
| Manage | `discardBuildState` | Discard all the built states of branches, releases, activities, and snapshots | rtsAdministrator |
| Manage | `registerWebhook` | Register a webhook to notify other applications of events that are coming from Decision Center | rtsAdministrator |
| Manage | `registerWebhook_1` | Update a webhook to notify other applications of events that are coming from Decision Center | rtsAdministrator |
| Manage | `renameSnapshot` | Rename a snapshot from a decision service |  |
| Manage | `snapshot` | Create a snapshot of a branch in the decision service |  |
| Manage | `updateServer` | Update a target server to use for deployments, simulations, and tests | rtsAdministrator |
| Manage | `webhooks` | Get a list of the webhooks that are bound to this instance of Decision Center | rtsAdministrator |

### Decision Server console tools (60)

| Category | Tool (`operationId`) | Description | Role |
|----------|----------------------|-------------|------|
| Decisiontraces | `deleteDecisionTrace` | Removes the trace with the specified execution identifier from the repository | resDeployer |
| Decisiontraces | `deleteDecisionTraces` | Removes all the Decision Warehouse traces that match the optional selection filters. | resDeployer |
| Decisiontraces | `deleteDecisionTracesByIds` | Removes all the Decision Warehouse traces when their execution identifier is included in the request body | resDeployer |
| Decisiontraces | `getCountOfDecisionTraces` | Get count of decision traces | resMonitor |
| Executionunits | `getCountOfExecutionUnits` | Get count of execution units | resMonitor |
| Executionunits | `getRulesetStatisticsForExecutionUnit` | Returns execution statistics about a ruleset | resMonitor |
| Executionunits | `resetRulesetStatistics` | Resets the execution statistics about a ruleset. | resDeployer |
| Libraries | `addLibrary` | Adds a new managed XOM library in the repository. | resDeployer |
| Libraries | `deleteLibrary` | Removes a named library from the repository | resDeployer |
| Libraries | `deleteUnusedLibraries` | Removes libraries that are unused and/or in error from the repository | resDeployer |
| Libraries | `getCountOfLibraries` | Get count of libraries | resMonitor |
| Libraries | `getCountOfLibrariesByName` | Get count of libraries by name | resMonitor |
| Libraries | `getLibraries` | Returns all the managed XOM libraries contained in the repository. | resMonitor |
| Libraries | `getLibrariesByName` | Returns all the managed XOM libraries, identified by their name | resMonitor |
| Libraries | `getLibrary` | Returns the description of a managed XOM library | resMonitor |
| Libraries | `getLibraryWithHighestNumber` | Returns the highest version of a managed XOM library, identified by its name | resMonitor |
| Libraries | `updateLibrary` | Updates the resources and libraries referenced by an existing managed XOM library | resDeployer |
| Ruleapps | `addRuleApp` | Adds a new RuleApp in the repository | resDeployer |
| Ruleapps | `addRuleAppProperty` | Adds a new, named property to a RuleApp, identified by its name and version number | resDeployer |
| Ruleapps | `addRuleset` | Adds a new ruleset in a RuleApp, identified by its name and version number, in the repository | resDeployer |
| Ruleapps | `deleteRuleAppProperty` | Removes a named property of a RuleApp identified by its name and version number | resDeployer |
| Ruleapps | `deleteRuleset` | Removes a ruleset, identified by its name and version number, contained in a RuleApp, identified by its name and version number | resDeployer |
| Ruleapps | `deployRulesetArchive` | Deploys a ruleset archive at the specified location in the repository | resDeployer |
| Ruleapps | `getCountOfRuleAppProperties` | Get count of ruleapp properties | resMonitor |
| Ruleapps | `getCountOfRuleApps` | Get count of ruleapps | resMonitor |
| Ruleapps | `getCountOfRuleAppsByName` | Get count of ruleapps by name | resMonitor |
| Ruleapps | `getCountOfRulesetProperties` | Get count of ruleset properties | resMonitor |
| Ruleapps | `getCountOfRulesets` | Get count of rulesets | resMonitor |
| Ruleapps | `getCountOfRulesetsByName` | Get count of rulesets by name | resMonitor |
| Ruleapps | `getRuleAppArchive` | Returns the archive of the RuleApp | resMonitor |
| Ruleapps | `getRuleAppProperties` | Returns all the properties associated with a RuleApp | resMonitor |
| Ruleapps | `getRuleAppsByName` | Returns all the RuleApps with the specified name | resMonitor |
| Ruleapps | `getRuleAppWithHighestNumber` | Returns the highest version of a RuleApp, identified by its name | resMonitor |
| Ruleapps | `getRuleAppWithHighestNumberArchive` | Returns the archive of the highest version of the RuleApp | resMonitor |
| Ruleapps | `getRulesetArchive` | Returns the archive of a ruleset identified by its name and version number and by the name and version number of its RuleApp | resMonitor |
| Ruleapps | `getRulesetsByName` | Returns all the rulesets with that name contained in a RuleApp | resMonitor |
| Ruleapps | `getRulesetWithHighestNumber` | Returns the highest version of the ruleset, identified by its name, contained in a RuleApp identified by its name and version number | resMonitor |
| Ruleapps | `getRulesetWithHighestNumberArchive` | Returns the archive of the highest version of a ruleset identified by its name and by the name and the highest version of its RuleApp | resMonitor |
| Ruleapps | `getRulesetWithHighestNumberArchive2` | Returns the archive of the highest version of a ruleset identified by its name and by the name and version number of its RuleApp | resMonitor |
| Ruleapps | `getRulesetXOMs` | Returns the XOMs referenced by a ruleset contained in a RuleApp | resMonitor |
| Ruleapps | `notifyRuleAppChanges` | Notifies to reload all the rulesets contained in the RuleApp | resMonitor |
| Ruleapps | `notifyRulesetChanges` | Notifies to reload the ruleset, identified by its name and version number and by the name and version number of its RuleApp | resMonitor |
| Ruleapps | `updateRuleApp` | Updates an existing RuleApp in the repository | resDeployer |
| Ruleapps | `updateRuleAppProperty` | Updates an existing property of a RuleApp identified by its name and version number | resDeployer |
| Ruleapps | `updateRuleset` | Updates an existing ruleset in a RuleApp, identified by their names and version numbers, in the repository | resDeployer |
| Ruleapps | `updateRulesetArchive` | Replaces an existing ruleset archive by another ruleset archive | resDeployer |
| Rulesets | `getAllRulesets` | Returns all the rulesets of the repository. | resMonitor |
| Rulesets | `getCountOfAllRulesets` | Get count of all rulesets | resMonitor |
| Utilities | `getDiagnosticById` | Returns the diagnostics for a specified element ID. | resMonitor |
| Xoms | `deleteResource` | Removes a managed XOM from the repository | resDeployer |
| Xoms | `deleteUnusedXomResources` | Removes XOM resources that are unused and/or in error from the repository | resDeployer |
| Xoms | `deployResource` | Deploys a managed XOM in the repository | resDeployer |
| Xoms | `getByteCodeOfHighestResource` | Returns the byte code of the highest version of the managed XOM | resMonitor |
| Xoms | `getByteCodeOfResource` | Returns the byte code of a managed XOM identified by its name and version number | resMonitor |
| Xoms | `getCountOfResources` | Get count of resources | resMonitor |
| Xoms | `getCountOfResourcesByName` | Get count of resources by name | resMonitor |
| Xoms | `getResource` | Returns the description of a managed XOM | resMonitor |
| Xoms | `getResources` | Returns all the managed XOMs contained in the repository. | resMonitor |
| Xoms | `getResourcesByName` | Returns all the managed XOMs with the specified name | resMonitor |
| Xoms | `getResourceWithHighestNumber` | Returns the highest version of a managed XOM identified by its name | resMonitor |

> The list of the tools is the one of ODM 9.6.0.0. The list of non-essential tools is defined by `DecisionCenterManager.non_essential_tools` in [`DecisionCenterManager.py`](../src/decisioncenter_mcp_server/DecisionCenterManager.py): a tool that is not in that list is considered as essential.
