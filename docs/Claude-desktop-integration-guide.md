# Claude Desktop Integration Guide

## Part 1: Installation & Configuration

### Prerequisites

- Claude Desktop ([Download](https://claude.ai/download))


### Step 1: Install Git, Python and uv

- [Install Git](https://git-scm.com/install/windows) (you can keep the default options)
- Install Python 3.13 or later
- Install uv:
  - on macOS: 
    ```shell
    brew install uv
    ```
  - on Windows: 
    1. in Powershell, run the command described in [installing uv](https://docs.astral.sh/uv/getting-started/installation/)
    1. once `uv` is installed, open a new Powershell tab, and run the command below:
        ```powershell
        uv tool install git+https://github.com/DecisionsDev/ibm-odm-management-mcp-server
        ```
    1. run the command below in Powershell:
        ```powershell
        New-Item -ItemType SymbolicLink -Path "$(Split-Path (Get-Command git).Source -Parent)\git" -Target (Get-Command git).Source
        ```
        > Note:
        > This command creates a symbolic link named `git` to `git.exe` to prevent the errors below (from happening whenever the GitHub repository was updated and uvx calls git to fetch the changes): 
        > ```
        > 2025-12-31T10:29:46.477Z [ibm-odm-management-mcp-server] [info] Message from client: {"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"claude-ai","version":"0.1.0"}},"jsonrpc":"2.0","id":0} { metadata: undefined }
        >    Updating https://github.com/DecisionsDev/ibm-odm-management-mcp-server (HEAD)
        >   × Failed to download and build `decisioncenter-mcp-server @
        >   │ git+https://github.com/DecisionsDev/ibm-odm-management-mcp-server@bbb8a86091410aa1f8a9fa458c43a6fba38596f3`
        >   ├─▶ Git operation failed
        >   ╰─▶ Git executable not found. Ensure that Git is installed and available.
        > ```

- Verify your Python and `uv` installation:

    **For macOS/Linux (in Terminal):**
    ```bash
    uv python list
    ```

    **For Windows (in PowerShell):**
    ```powershell
    uv python list
    ```

### Step 2: Install Docker or Rancher Desktop (Optional)

If you don't have Docker installed yet, we recommend using Rancher Desktop which provides Docker and Kubernetes in a single application.

#### For Windows:

1. **Install WSL 2 (Windows Subsystem for Linux)**:
   - Open PowerShell as Administrator and run:
     ```powershell
     wsl --install
     ```
   - Restart your computer when prompted
   - Open PowerShell as Administrator and run:
     ```powershell
     wsl --install
     ```
   - After restart, a Linux distribution (usually Ubuntu) will be installed automatically
   - Set up your Linux username and password when prompted (ex: admin/admin)
     

2. **Install Rancher Desktop**:
   - Download the installer from [Rancher Desktop website](https://rancherdesktop.io/)
   - Run the installer and follow the on-screen instructions
   - Run Rancher Desktop
     - Disable Enable Kubernetes (Not needed for this demonstration)
     - Wait until the initialization was finished.
     - Ensure WSL integration is enabled
     - Select "dockerd" as the container runtime (not "containerd")
   - After installation, Rancher Desktop will start automatically

3. **Verify Installation**:
   - Open a new PowerShell windows
   - Run the following commands:
     ```powershell
     docker --version
     docker compose --version
     ```
   - These commands should display the installed versions, confirming that Docker and Docker Compose are properly installed

#### For macOS:

1. **Install Rancher Desktop**:
   - Download the installer from [Rancher Desktop website](https://rancherdesktop.io/)
   - Open the downloaded .dmg file and drag Rancher Desktop to your Applications folder
   - Launch Rancher Desktop from your Applications folder
   - Select "dockerd" as the container runtime (not "containerd")

2. **Verify Installation**:
   - Open Terminal
   - Run the following commands:
     ```bash
     docker --version
     docker compose --version
     ```
   - These commands should display the installed versions, confirming that Docker and Docker Compose are properly installed

### Step 3: Run ODM Locally (Optional)

If you want to use a local ODM instance for development or testing, 

- clone this repository,
```bash
  git clone https://github.com/DecisionsDev/ibm-odm-management-mcp-server.git
  cd ibm-odm-management-mcp-server
 ```
- and run:

    **For macOS/Linux (in Terminal):**
    ```bash
    docker compose up
    ```
    
    **For Windows (in PowerShell):**
    ```powershell
    docker compose up
    ```
    
  If the command is successful, you should see:
    ```
   [+] Running 1/1
    ✅ Container odm Running
    ```

- Once the containers are running, the ODM web consoles are available at [http://localhost:9060](http://localhost:9060) using the default credentials:

  - **Username:** `odmAdmin`
  - **Password:** `odmAdmin`

This ODM instance will be available for the MCP Server, pre-populated with sample data for testing and development purposes.

### Step 4: Configure Claude Desktop
1. Open Claude Desktop Settings:
   - On macOS, click the Claude menu in the top menu bar and select **Settings**.
   - On Windows, access **Settings** from the Claude application.

1. Navigate to the **Developer** tab and click **Edit Config**

1. This opens a window allowing you to open the configuration file:
   - macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
   - Windows: `%APPDATA%\Claude\claude_desktop_config.json`

1. Edit the configuration file and add the following configuration:
   ```json
   {
     "mcpServers": {
       "ibm-odm-management-mcp-server": {
         "command": "uvx",
         "args": [
           "--from", "git+https://github.com/DecisionsDev/ibm-odm-management-mcp-server", "ibm-odm-management-mcp-server",
           "--url",      "http://localhost:9060/decisioncenter-api",
           "--username", "odmAdmin"
         ],
         "env": {
           "PASSWORD": "odmAdmin"
         }
       }
     }
   }
   ```
1. Restart Claude Desktop:

    Simply closing the window is not enough, Claude Desktop must be stopped and restarted:
    - on macOS: Claude > Quit
    - on Windows: File > Exit

Refer to the [Configuration Parameters Table](../README.md#configuration-parameters-table) for a list of supported environment variables and CLI arguments.

## Part 2: Demo Walkthrough

This walkthrough demonstrates how Claude Desktop can interact with IBM ODM Developer Edition through the Authoring MCP Server. The sample database contains two decision services:

1. **Loan Validation Service** – Assess loan requests.
2. **Miniloan Service** – Assess loan requests (simplified version).

### Step-by-Step Scenario

#### 1. Claude Connects to ODM

Once Claude Desktop is configured with the MCP Server, it automatically connects to the ODM Developer Edition. The MCP Server retrieves and exposes the available decision center REST API endpoints as Claude tools.

To see all the tools listed in Claude Desktop, proceed as follows:
- Click the ➕ icon, then click `Connectors` and finally `Manage connectors`:
![Screenshot showing Claude tools](images/claude-mcp-tools.png)

- then click the `Configure` button to the right of `ibm-odm-management-mcp-server`, and you should see:
![Screenshot showing Claude tools](images/claude-mcp-tools-details.png)

> Note: The connector may take some time to get displayed.

#### 2. The user starts a Conversation

The user initiates a conversation in Claude with request in natural language such as:

- **User:** "Let me know which version of ODM Decision Center is running"

- **Claude** recognizes this intent and activates the `about` tool.

  ![Invoking the about tool](images/claude-about-tool-invocation.png)

#### 3. Next Conversation: creating a group of users

- **User:** "Create a group named 'Miniloan Users' with rtsUser1 and rtsUser2 as members and with full authoring permissions"

- **Claude** runs the `addGroup` tool with the parameters
  ```
  {
    'name': 'Miniloan Users',
    'users': [
      'rtsUser1',
      'rtsUser2'
    ],
    'securityProfile': 'FULLACCESS'
  }
  ```

- After completion **Claude** adds: Perfect! I've successfully created the group 'Miniloan Users' with the following configuration:
    - Group Name: Miniloan Users
    - Members: rtsUser1, rtsUser2
    - Security Profile: FULLACCESS (full authoring permissions)
    - Role: rtsUser

#### 4. Next Conversation: Enforcing the security of a branch to users of the newly created group

- **User:** "Configure all the branches of the decision service Miniloan Service so that only members of this new group can modify this branch"

- **Claude** replies "I'll configure the main branch of the Miniloan Service decision service to restrict modifications to only members of the 'Miniloan Users' group. First, let me find the decision service" and runs the `decisionServices` tool with the parameters below
  ```
  {
    'q': 'name:Miniloan Service'
  }
  ```

- then **Claude** explains "Now let me get all the branches for this decision service" and runs the `branches` tool with the parameters below
  ```
  {
    'decisionServiceId': 'f4440cab-4dca-471c-8a9e-ec05ede7c031'
  }
  ```

- then **Claude** explains "Now I'll configure the security on the only branch to restrict modifications to only the 'Miniloan Users' group" and runs the `branchSecurity_1` tool with the parameters below and adds "Great! The security has been configured".
  ```
  {
    'groups': 'Miniloan Users',
    'branchId': '1653c443-b1e7-468c-85dd-0a7213b078f2',
    'securityEnforced': 'true'
  }
  ```

### Demo Notes

- This scenario demonstrates how Claude can interact with ODM Decision Center through the REST API endpoints exposed as tools.
- The tools are exposed automatically by the MCP Server based on the ODM configuration.
- You can tune this setup to restrict the REST API endpoints exposed or integrate it into broader workflows using Watson Orchestrate.
