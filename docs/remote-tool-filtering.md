# Remote Tool Filtering

When the MCP server runs remotely, different clients often need different subsets of tools. Rather than running multiple server instances, you can adjust which tools are published **per connection** by sending filtering options in the HTTP request — either as a query parameter or as custom headers.

This page shows two examples:
1. [Basic: select a profile with a query parameter](#1-basic-select-a-profile-with-a-query-parameter)
2. [Custom: fine-grained filtering with headers](#2-custom-fine-grained-filtering-with-headers)

Each example shows the configuration for **mcp-remote**, **IBM Bob**, and **Claude Desktop**.

> [!NOTE]
> IBM Bob and Claude Desktop can also connect to the server directly **without** `mcp-remote`, by running the server locally via `uvx`. In that case filtering is configured through the CLI arguments `--tool-profile`, `--tools`, `--no-tools`, and `--tags` — see [Essential tools](Essential-tools.md). The HTTP-level filtering described on this page applies only when the server runs remotely and the client connects through `mcp-remote`.

---

## Filtering options reference

The server reads these overrides from every incoming HTTP request. They take precedence over the server-level defaults set on the command line.

### Query parameters

| Query parameter | Value | Effect |
|-----------------|-------|--------|
| `tools=essential` | `essential` (`essentials` is also accepted) | Publish only the [essential tools](Essential-tools.md) (override server-level `--tool-profile ALL`) |
| `tools=all` | `all` | Publish all tools (override server-level `--tool-profile ESSENTIAL`) |

Values are case-insensitive.

### Headers

| Header | Value | Effect |
|--------|-------|--------|
| `X-Tool-Profile` | `essential` (or `essentials`) / `all` | Same as the `tools` query parameter |
| `X-Tools` | Comma/space-separated tool names | Publish only the listed tools (equivalent to `--tools`) |
| `X-No-Tools` | Comma/space-separated tool names | Remove the listed tools (equivalent to `--no-tools`) |
| `X-Tags` | Comma/space-separated category names | Publish only tools whose category is listed (equivalent to `--tags`) |

The options combine in the same way as the command-line flags; see [Essential tools](Essential-tools.md) for the precedence rules.

---

## 1. Basic: select a profile with a query parameter

The simplest way to switch between *all tools* and *essential tools* is to append `?tools=essential` (or `?tools=all`) to the MCP server URL. No extra headers are required. Without it, the server-level `--tool-profile` applies (`ESSENTIAL` by default).

> **Use case:** a developer workstation that always wants the full tool set vs. a team-shared assistant that should only see the curated subset.

Append the query parameter directly to the URL:

```json
{
  "mcpServers": {
    "ibm-odm-management-mcp-server": {
      "command": "npx",
      "args": [
        "mcp-remote",
        "https://my-mcp-server.com/mcp?tools=essential"
      ]
    }
  }
}
```
---

## 2. Custom: fine-grained filtering with headers

For more control you can send custom headers telling which specific tools you need.
You can use this approach alone, or in combination with the query parameter described in the previous section.

> **Use cases:** 
> 1. you need only the essential tools plus a few more tools.
> 1. you want to ignore some tools deemed dangerous, such as `eraseAllUsers`
> 1. you want to select tools that belong to a list of categories


### 2.1 Configuration in mcp-remote

#### 2.1.1 Using a Header file

`mcp-remote` supports loading headers from a file using the `--header-file` flag, which avoid long lists out of the configuration file.

Create a plain text file (e.g. `/path/to/headers.txt`) with one `Name: Value` entry per line:

```
X-Tool-Profile: essentials
X-Tools: addServer, updateServer, deleteServer
```

Or, to remove specific tools from whatever the server default is:

```
X-No-Tools: addGroup, deleteGroup, eraseAllUsers
```

Or, to restrict to a specific category:

```
X-Tags: Build, Deploy
```

Pass the header file using `--header-file`:

```json
{
  "mcpServers": {
    "ibm-odm-management-mcp-server": {
      "command": "npx",
      "args": [
        "mcp-remote",
        "https://my-mcp-server.com/mcp",
        "--header-file",
        "/path/to/headers.txt"
      ]
    }
  }
}
```

See the [mcp-remote documentation](https://www.npmjs.com/package/mcp-remote) for the full list of flags.

#### 2.1.2 Using Headers

`mcp-remote` also supports specifying headers using the `--header` flag.

Pass the header file using `--header-file`:

```json
{
  "mcpServers": {
    "ibm-odm-management-mcp-server": {
      "command": "npx",
      "args": [
        "mcp-remote",
        "https://my-mcp-server.com/mcp",
        "--header",
        "X-Tool-Profile: essentials",
        "--header",
        "X-Tools: addServer, updateServer, deleteServer"
      ]
    }
  }
}
```

### 2.2 Configuration in IBM Bob without mcp-remote

IBM Bob can connect to a remote MCP server with or without mcp-remote.
If you do not use mcp-remote, IBM Bob enables to specify headers too:

```json
{
  "mcpServers": {
    "ibm-odm-management-mcp-server": {
      "type": "streamable-http",
      "url": "https://my-mcp-server.com/mcp",
      "headers": {
        "X-Tool-Profile": "essentials",
        "X-Tools": "addServer, updateServer, deleteServer"
      },
      "alwaysAllow": ["addServer", "updateServer"],
      "disabled": false
    }
  }
}
```

> [!TIP]
> When you use IBM Bob with several windows open, use the **Project MCPs** configuration file (`.bob/mcp.json` in the project root) instead of the global one, so that each project can carry its own header file with the tools it needs.
