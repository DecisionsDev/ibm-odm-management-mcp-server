# Copyright contributors to the IBM ODM MCP Server project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from typing import Optional
from mcp_types import Tool, Resource, CallToolResult, TextContent
from mcp.server.mcpserver.context import Context
from mcp.server.mcpserver.exceptions import ToolError
from mcp.server import MCPServer as SDK_MCPServer
from mcp.server.auth.settings import AuthSettings
from mcp.server.auth.provider import AccessToken, TokenVerifier
from mcp.server.auth.routes import build_resource_metadata_url
from mcp.server.auth.middleware.auth_context import get_access_token
import mcp.server.auth.middleware.bearer_auth as bearer_auth
from starlette.authentication import AuthCredentials
from starlette.requests import HTTPConnection
from pydantic import AnyUrl
import logging
import json
import argparse
import os
import sys
import time

from .Credentials import Credentials
from .DecisionCenterManager import DecisionCenterManager
from .DecisionCenterEndpoint import DecisionCenterEndpoint
from .ToolTrace import DiskTraceStorage

INSTRUCTIONS = """
IBM ODM Decision Center MCP server
This server provides access to decision center REST API for IBM Operational Decision Manager.
You can invoke REST API endpoints using the provided tools.
For more information, please refer to the documentation.
"""

class MCPServer:

    get_tools_executions_toolname = "getToolExecutions"
    max_trace_files = 200

    tools_executions_tool = Tool(
            name=get_tools_executions_toolname,
            title="Get tool executions",
            description=f"Get the tool executions with or without content. Useful to keep track of the tools that have been executed, their arguments and results. Only the most recent executions are kept. The number of executions that are kept is defined by the MCP server option --traces-maxsize ({max_trace_files} by default).",
            inputSchema={'type': 'object', 'required': [], 
                         'properties': {
                            'filter': {'type': 'string', 'description': 'Filter to apply on the tool executions. Only the executions of tools whose name matches the filter will be included in the result. The filter supports partial match.'},
                            'with_content': {'type': 'boolean', 'description': 'Whether to include the content of the tool execution (arguments and results) in the trace. If false, only metadata such as timestamps, tool name and execution status will be included.'}
                            }
                        }
            )

    def __init__(self, credentials: Credentials,
                 tags: list[str] = [], tools: list[str] = [], no_tools: list[str] = [],
                 trace: list[str] = [], traces_dir: str = None, traces_maxsize: int = max_trace_files,
                 transport: Optional[str] = 'stdio', host: Optional[str] = '0.0.0.0', port: Optional[int] = 3000, path: Optional[str] = '/mcp', mcp_ext_url: Optional[str] = None, issuer_url: Optional[str] = None, introspection_url: Optional[str] = None,
                ):
        # Get logger for this class
        self.logger = logging.getLogger(__name__)
        self.credentials = credentials
        self.tags: list[str] = tags
        self.tools: list[str] = tools       # explicit list of tools to publish
        self.no_tools: list[str] = no_tools # explicit list of tools to discard
        self.trace          = trace
        self.traces_dir     = traces_dir
        self.traces_maxsize = traces_maxsize
        self.transport = transport
        self.host      = host
        self.port      = port
        self.path      = path
        self.issuer_url= issuer_url
        self.introspection_url= introspection_url
        self.mcp_ext_url = mcp_ext_url

        self.repository_dc              : dict[str, DecisionCenterEndpoint] = {}
        self.repository_dc_admin        : dict[str, DecisionCenterEndpoint] = {}
        self.repository_res_monitor     : dict[str, DecisionCenterEndpoint] = {}
        self.repository_res_deployer    : dict[str, DecisionCenterEndpoint] = {}

        self.user_credentials           : dict[str, Credentials] = {} # key = token,          value: Credentials = user_credentials
        self.mcp_tokens                 : dict[str, AccessToken] = {} # key = token,          value: AccessToken = mcp token

        # Set up trace storage with configured parameters if tracing is enabled
        # If traces_dir is None, DiskTraceStorage will use the default path in user's home directory
        self.trace_recorder = DiskTraceStorage(trace_executions    = "EXECUTIONS_WITH_CONTENT" in self.trace or "EXECUTIONS" in self.trace,
                                               verbose             = "EXECUTIONS_WITH_CONTENT" in self.trace,
                                               trace_configuration = "CONFIGURATION"           in self.trace,
                                               storage_dir = self.traces_dir, 
                                               max_traces = self.traces_maxsize)

        self.manager = DecisionCenterManager(credentials, self.trace_recorder)

    def introspect_token(self, token):
        """Verify token via introspection endpoint."""
        # client_id = self.credentials.client_id
        # client_secret = self.credentials.client_secret)
        import requests

        # headers={"Content-Type": "application/x-www-form-urlencoded"},
        request_body = {
                'token':         token,
                'client_id':     self.credentials.client_id,
                'client_secret': self.credentials.client_secret
            }

        if self.credentials.verify_ssl:
            response = requests.post(url=self.introspection_url, data=request_body, verify=self.credentials.cacert)
        else:
            response = requests.post(url=self.introspection_url, data=request_body, verify=False)

        try:
            response.raise_for_status() # raise an HTTPError if the request failed
        except Exception as e:
            self.logger.debug(f"Token introspection failed. {str(e)}")
            return None

        response_body = response.json()

        if not response_body.get("active", False):
            # the token is expired
            return None

        return AccessToken(
                    token     = token,
                    client_id = response_body.get("client_id", "unknown"),
                    scopes    = response_body.get("scope", "").split() if response_body.get("scope") else [],
                    expires_at= response_body.get("exp", 0),
                    resource  = response_body.get("aud"),  # Include resource in token
                )

    def get_mcp_token(self, token:str):
        if token is None:
            return None
        if token in self.mcp_tokens:
            mcp_token : AccessToken | None = self.mcp_tokens.get(token)
        else:
            mcp_token = self.introspect_token(token)
            if mcp_token:
                self.mcp_tokens[token] = mcp_token

        if mcp_token and self.logger.isEnabledFor(logging.DEBUG):
            validity = mcp_token.expires_at - int(time.time())
            self.logger.debug("token %s", f"expiring in {validity} seconds" if validity > 0 else "expired")

        return mcp_token

    def token_overview(self, token):
        return token[:5] + '...' + token[-5:]

    def get_current_token(self) -> str:
        """Return the bearer token for the current request via the SDK contextvar.

        Replaces the defunct get_context().request_context.request.headers approach.
        get_access_token() is set by AuthContextMiddleware for every HTTP request
        that carries a valid Bearer token.
        """
        access_token = get_access_token()
        if access_token is None:
            raise Exception("No access token found for the current request")
        return access_token.token

    def get_user_credentials(self):
        token = self.get_current_token()

        credentials = self.user_credentials.get(token)
        if credentials is None:
            credentials = Credentials(
                                        odm_url=self.credentials.odm_url,
                                        odm_res_url=self.credentials.odm_res_url,
                                        token_url=self.credentials.token_url,
                                        scope=self.credentials.scope,
                                        client_id=self.credentials.client_id,
                                        mtls_cert_path=self.credentials.mtls_cert_path, mtls_key_path=self.credentials.mtls_key_path, mtls_key_password=self.credentials.mtls_key_password,
                                        ssl_cert_path=self.credentials.ssl_cert_path,
                                        verify_ssl=self.credentials.verify_ssl,
                                        token = token,
                                        )
            self.user_credentials[token] = credentials

            # check if the user credentials grant the rtsAdministrator/rtsInstaller role
            credentials.isDcAdmin = self.manager.isDcAdmin(credentials.odm_url, credentials.get_session())

            # check if the user credentials grant the resMonitor and resDeployer roles
            self.manager.check_res_roles(credentials)

        self.logger.debug(f"Using user credentials. user token: '{self.token_overview(credentials.token)}'")
        return credentials

    def use_user_credentials(self) -> bool:
        return self.transport != "stdio" \
           and self.credentials.client_id is not None \
           and self.credentials.client_secret is not None \
           and self.issuer_url is not None \
           and self.introspection_url is not None \
           and self.mcp_ext_url is not None
        

    def update_repository(self, credentials = None):
        if credentials is None:
            credentials = self.credentials

        # generate the MCP tools for Decision Center REST API
        if len(self.repository_dc) == 0 and credentials.odm_url:
            self.repository_dc, self.repository_dc_admin = self.manager.generate_tools_format(self.manager.fetch_endpoints(credentials), self.tags, self.tools, self.no_tools)

        # generate the MCP tools for Decision Server console REST API (aka RES console)
        if len(self.repository_res_monitor) == 0 and credentials.odm_res_url:
            self.repository_res_monitor, self.repository_res_deployer = self.manager.generate_res_tools(self.manager.fetch_res_api_endpoints(credentials), self.tags, self.tools, self.no_tools)

        # save traces of all the tools
        if credentials == self.credentials:
            self.trace_recorder.save(dict(self.repository_dc_admin, **self.repository_res_deployer))

    async def list_tools(self) -> list[Tool]:
        """
        List available tools.
        Each tool specifies its arguments using JSON Schema validation.
        """
        if self.use_user_credentials():
            credentials = self.get_user_credentials()

            # update the list of tools (unless it was already generated during startup)
            self.update_repository(credentials)
        else:
            credentials = self.credentials

        # select the list of tools based on the roles granted to the credentials used
        if   credentials.isDcAdmin:     dc_repository = self.repository_dc_admin
        else:                           dc_repository = self.repository_dc

        if   credentials.isResDeployer: res_repository = self.repository_res_deployer
        elif credentials.isResMonitor:  res_repository = self.repository_res_monitor
        else:                           res_repository = {}

        tools = [MCPServer.tools_executions_tool] if self.trace_recorder.trace_executions else []
        for tool_name, endpoint in dc_repository.items():
            tools.append(endpoint.tool)
        for tool_name, endpoint in res_repository.items():
            tools.append(endpoint.tool)

        self.logger.info(f"list_tools returned {len(dc_repository)} DC tools + {len(res_repository)} RES tools" + " + 1 tool to query tool executions" if self.trace_recorder.trace_executions else "")
        return tools

    async def call_tool(self, name: str, arguments: dict | None, context: Context) -> CallToolResult:
        """
        Handle tool execution requests.
        """
        def get_tools_executions(arguments):
            filter = arguments.get('filter') if arguments else None
            with_content = arguments.get('with_content', False) if arguments else False
            return self.trace_recorder.get_executions(filter=filter, with_content=with_content)

        if self.logger.isEnabledFor(logging.DEBUG): self.logger.debug("Calling tool '%s' with arguments: %s", name, arguments)
        else:                                             self.logger.info ("Calling tool '%s'", name)

        if self.use_user_credentials(): credentials = self.get_user_credentials()
        else:                           credentials = self.credentials

        if name == MCPServer.get_tools_executions_toolname:
            executions = get_tools_executions(arguments)
            result = { "executions": executions }
            is_error = False
        else:
            endpoint : DecisionCenterEndpoint = self.repository_dc_admin.get(name)
            if endpoint is None:
                endpoint = self.repository_res_deployer.get(name)
            if endpoint is None:
                raise ToolError(f"Unknown tool: {name}")

            try:
                result = self.manager.invokeDecisionCenterApi(endpoint, arguments, self.transport == 'stdio', credentials)
                is_error = False
            except Exception as e:
                result = str(e)
                is_error = True

        # Handle dictionary response
        if isinstance(result, dict):
            response_text = json.dumps(result, indent=2, ensure_ascii=False)
        else:
            # Handle non-dict response (string, etc)
            response_text = str(result)

        return CallToolResult(
                    content=[
                        TextContent(
                            type="text", 
                            text=response_text,
                        )
                    ],
                    is_error=is_error,
                )

    async def list_resources(self) -> list[Resource]:
        """
        List available resources.
        """
        resources = [Resource(name=os.path.basename(trace_file), uri=f'file://{trace_file}') for trace_file in self.trace_recorder.trace_files]
        self.logger.info(f"{len(resources)} resources available")
        return resources

    async def read_resource(self, uri: AnyUrl) -> str:
        """
        Read a resource by its URI.
        """
        self.logger.info(f"Reading resource from URI: {uri.encoded_string()}")
        try:
            filepathname = uri.encoded_string()[len('file://'):]    # remove the 'file://' prefix to get the local file path
            with open(filepathname, 'r') as f:
                return f.read()
        except FileNotFoundError:
            raise ValueError(f"resource not found")

    def start(self):

        if self.use_user_credentials():
            token_verifier: AccessTokenVerifier | None = AccessTokenVerifier(mcpserver = self)
            auth: AuthSettings | None = AuthSettings(issuer_url          = self.issuer_url,
                                                     required_scopes     =[self.credentials.scope],
                                                     resource_server_url = self.mcp_ext_url)

            self.logger.info       (f"MCP Server running in remote mode, using users credentials. Resource metadata URL: {build_resource_metadata_url(resource_server_url = self.mcp_ext_url)}")
        else: 
            if self.transport != "stdio": 
                self.logger.warning("MCP Server running in remote mode, but NOT using users credentials\n" + HOWTO_USE_USERS_CREDENTIALS_MSG)
            token_verifier = None
            auth = None

        self.server = SDK_MCPServer(name="ibm-odm-management-mcp-server",
                              instructions=INSTRUCTIONS,
                              token_verifier=token_verifier,
                              auth=auth,
                              debug=self.logger.isEnabledFor(logging.DEBUG),
                             )
        # Register handlers
        self.server.list_resources = self.list_resources
        self.server.read_resource  = self.read_resource
        self.server.list_tools = self.list_tools
        self.server.call_tool  = self.call_tool

                        # sse_path=self.path,
        self.server.run(transport=self.transport,
                        host=self.host,
                        port=self.port,
                        streamable_http_path=self.path,
        )

def init_logging(level_name):
    level=getattr(logging, level_name, logging.INFO)
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    logging.info(f"Running Python {sys.version_info}. Logging level set to: {logging.getLevelName(level)}")

def create_credentials(args):
    verifyssl = args.verifyssl != "False"

    if args.zenapikey:    # If zenapikey is provided, use it for authentication
        return Credentials(
            odm_url=args.url,
            odm_res_url=args.res_url,
            username=args.username,
            zenapikey=args.zenapikey,
            mtls_cert_path=args.mtls_cert_path, mtls_key_path=args.mtls_key_path, mtls_key_password=args.mtls_key_password,
            ssl_cert_path=args.ssl_cert_path,
            verify_ssl=verifyssl
        )
    elif args.client_secret:  # OpenID Client Secret provided
        return Credentials(
            odm_url=args.url,
            odm_res_url=args.res_url,
            token_url=args.token_url,
            scope=args.scope,
            client_id=args.client_id,
            client_secret=args.client_secret,
            username=args.username,
            password=args.password,
            mtls_cert_path=args.mtls_cert_path, mtls_key_path=args.mtls_key_path, mtls_key_password=args.mtls_key_password,
            ssl_cert_path=args.ssl_cert_path,
            verify_ssl=verifyssl
        )
    elif args.pkjwt_key_path:  # OpenID PKJWT
        return Credentials(
            odm_url=args.url,
            odm_res_url=args.res_url,
            token_url=args.token_url,
            scope=args.scope,
            client_id=args.client_id,
            username=args.username,
            password=args.password,
            pkjwt_cert_path=args.pkjwt_cert_path, pkjwt_key_path=args.pkjwt_key_path, pkjwt_key_password=args.pkjwt_key_password,
            mtls_cert_path=args.mtls_cert_path, mtls_key_path=args.mtls_key_path, mtls_key_password=args.mtls_key_password,
            ssl_cert_path=args.ssl_cert_path,
            verify_ssl=verifyssl
        )
    else:  # Default to basic authentication
        return Credentials(
            odm_url=args.url,
            odm_res_url=args.res_url,
            username=args.username if args.username else "odmAdmin",
            password=args.password if args.password else "odmAdmin",
            mtls_cert_path=args.mtls_cert_path, mtls_key_path=args.mtls_key_path, mtls_key_password=args.mtls_key_password,
            ssl_cert_path=args.ssl_cert_path,
            verify_ssl=verifyssl
        )

def init(args):
    init_logging(args.log_level)
    credentials = create_credentials(args)
    server = MCPServer(
        credentials     = credentials,
        tags            = [tag.lower()  for tag  in args.tags]     if args.tags else [],
        tools           = [tool.lower() for tool in args.tools]    if args.tools else [],
        no_tools        = [tool.lower() for tool in args.no_tools] if args.no_tools else [],
        trace           = args.trace if args.trace is not None else [],
        traces_dir      = args.traces_dir, 
        traces_maxsize  = args.traces_maxsize,
        transport       = args.transport,
        host            = args.host,
        port            = args.port,
        path            = args.mount_path,
        mcp_ext_url     = args.mcp_ext_url,
        issuer_url      = args.issuer_url,
        introspection_url = args.introspection_url,
    )
    if server.use_user_credentials:
        # the MCP server credentials are optional is this case
        credentials.ignoreAuthErrors = True
    server.update_repository()
    return server

def parse_arguments():
    parser = argparse.ArgumentParser(description="Decision MCP Server")
    parser.add_argument("--url",               type=str, default=os.getenv("ODM_URL"), help="ODM Decision Center REST API URL")
    parser.add_argument("--res-url",           type=str, default=os.getenv("ODM_RES_URL"), help="ODM Decision Server Console URL (aka RES Console)")
    parser.add_argument("--username",          type=str, default=os.getenv("ODM_USERNAME"), help="ODM username (optional)")
    parser.add_argument("--password",          type=str, default=os.getenv("ODM_PASSWORD"), help="ODM password (optional)")
    parser.add_argument("--zenapikey",         type=str, default=os.getenv("ZENAPIKEY"), help="Zen API Key (optional)")
    parser.add_argument("--client-id",         type=str, default=os.getenv("CLIENT_ID"), help="OpenID Client ID (optional)")
    parser.add_argument("--client-secret",     type=str, default=os.getenv("CLIENT_SECRET"), help="OpenID Client Secret (optional)")
    parser.add_argument("--token-url",         type=str, default=os.getenv("TOKEN_URL"), help="OpenID Connect token endpoint URL")
    parser.add_argument("--scope",             type=str, default=os.getenv("SCOPE", "openid"), help="OpenID Connect scope using when requesting an access token using Client Credentials (optional)")
    parser.add_argument("--verifyssl",         type=str, default=os.getenv("VERIFY_SSL", "True"), choices=["True", "False"], help="Disable SSL check. Default is True (SSL verification enabled).")
    parser.add_argument("--ssl-cert-path",     type=str, default=os.getenv("SSL_CERT_PATH"), help="Path to the SSL certificate file. If not provided, defaults to system certificates.")
    parser.add_argument("--pkjwt-cert-path",   type=str, default=os.getenv("PKJWT_CERT_PATH"), help="Path to the certificate for PKJWT authentication (mandatory for PKJWT).")
    parser.add_argument("--pkjwt-key-path",    type=str, default=os.getenv("PKJWT_KEY_PATH"),  help="Path to the private key for PKJWT authentication (mandatory for PKJWT).")
    parser.add_argument("--pkjwt-key-password",type=str, default=os.getenv("PKJWT_KEY_PASSWORD"), help="Password to decrypt the private key for PKJWT authentication. Only needed if the key is password-protected.")
    parser.add_argument("--mtls-cert-path",    type=str, default=os.getenv("MTLS_CERT_PATH"), help="Path to the certificate of the client for mutual TLS authentication (mandatory for mTLS).")
    parser.add_argument("--mtls-key-path",     type=str, default=os.getenv("MTLS_KEY_PATH"),  help="Path to the private key of the client for mutual TLS authentication (mandatory for mTLS).")
    parser.add_argument("--mtls-key-password", type=str, default=os.getenv("MTLS_KEY_PASSWORD"), help="Password to decrypt the private key of the client for mutual TLS authentication. Only needed if the key is password-protected.")

    # arguments useful when running the MCP server in remote mode
    parser.add_argument("--transport",         type=str, default=os.getenv("TRANSPORT", "stdio"), choices=["stdio", "streamable-http", "sse"], help="Means of communication of the Decision MCP server: local (stdio) or remote.")
    parser.add_argument("--host",              type=str, default=os.getenv("HOST", "0.0.0.0"), help="IP or hostname that the MCP server listens to in remote mode.")
    parser.add_argument("--port",              type=int, default=os.getenv("PORT", 3000), help="Port that the MCP server listens to in remote mode.")
    parser.add_argument("--mount-path",        type=str, default=os.getenv("MOUNT_PATH", "/mcp"), help="Path that the MCP server listens to in remote mode.")

    # additional arguments useful when running the MCP server in remote mode using users credentials
    parser.add_argument("--mcp-ext-url",       type=str, default=os.getenv("MCP_EXT_URL"), help="MCP server external URL. Needed in remote mode to authenticate with users credentials.")
    parser.add_argument("--issuer-url",        type=str, default=os.getenv("ISSUER_URL"), help="OpenID Connect issuer URL. Needed in remote mode to authenticate with users credentials.")
    parser.add_argument("--introspection-url", type=str, default=os.getenv("INTROSPECTION_URL"), help="OpenID Connect introspection URL. Needed in remote mode to authenticate with users credentials.")
    
    # Logging-related arguments
    parser.add_argument("--log-level",         type=str, default=os.getenv("LOG_LEVEL", "INFO"),
                        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
                        help="Set the logging level (default: INFO)")

    # Decision Center REST API specific arguments
    parser.add_argument("--tags",              type=str, default=os.getenv("TAGS"),     nargs='+', help="List of Tags (eg. About Explore Build). Useful to keep only the tools whose tag is in the list. If this option is not specified, all the tools are published by the MCP server.")
    parser.add_argument("--tools",             type=str, default=os.getenv("TOOLS"),    nargs='+', help="Explicit list of tools to publish. All the other tools are filtered out. If this option is not specified, all the tools are published by the MCP server.")
    parser.add_argument("--no-tools",          type=str, default=os.getenv("NO_TOOLS"), nargs='+', help="Explicit list of tools to discard. All the other tools are published. Option ignored if the option --tools is provided. If this option is not specified, all the tools are published by the MCP server.")

    # Trace-related arguments
    parser.add_argument("--trace",             type=str, default=os.getenv("TRACE"),    nargs='+', choices=["EXECUTIONS", "EXECUTIONS_WITH_CONTENT", "CONFIGURATION"], help="Specifies what to trace.")
    parser.add_argument("--traces-dir",        type=str, default=os.getenv("TRACES_DIR"), help="Directory to store traces files (optional). If not provided, traces will be stored in the directory '~/.ibm-odm-management-mcp-server/traces'")
    parser.add_argument("--traces-maxsize",    type=int, default=int(os.getenv("TRACES_MAXSIZE", f"{MCPServer.max_trace_files}")), help=f"Maximum number of traces to store (default: {MCPServer.max_trace_files}). When the limit is reached, the oldest trace file will be deleted when a new trace is saved.  ")

    return parser.parse_args()

def main():
    args = parse_arguments()
    server = init(args)
    server.start()

HOWTO_USE_USERS_CREDENTIALS_MSG = """When MCP Server runs in remote mode, it authenticates to ODM with users credentials if all the conditions below are met:
    1. OpenID is used with a client secret
    3. the openID issuer and introspection URLs are set
    4. the MCP server external URL is set"""

class AccessTokenVerifier(TokenVerifier):
    def __init__(self, mcpserver: MCPServer):
        self.mcpserver = mcpserver

    async def verify_token(self, token: str) -> AccessToken | None:
        return self.mcpserver.get_mcp_token(token)
