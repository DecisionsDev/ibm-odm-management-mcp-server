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
from mcp.server.models import InitializationOptions
import mcp.types as types
from mcp.server.fastmcp import FastMCP
from pydantic import AnyUrl
import mcp.server.stdio
import logging
import json
import argparse
import os
import sys

from .Credentials import Credentials
from .DecisionCenterManager import DecisionCenterManager
from .DecisionCenterEndpoint import DecisionCenterEndpoint

INSTRUCTIONS = """
IBM ODM Decision Center MCP server
This server provides access to decision center REST API for IBM Operational Decision Manager.
You can invoke REST API endpoints using the provided tools.
For more information, please refer to the documentation.
"""

class MCPServer:

    def __init__(self, credentials: Credentials,
                 tags: list[str] = [], tools: list[str] = [], no_tools: list[str] = [],
                 transport: Optional[str] = 'stdio', host: Optional[str] = '0.0.0.0', port: Optional[int] = 3000, path: Optional[str] = '/mcp'):
        # Get logger for this class
        self.logger = logging.getLogger(__name__)
        self.credentials = credentials
        self.tags: list[str] = tags
        self.tools: list[str] = tools       # explicit list of tools to publish
        self.no_tools: list[str] = no_tools # explicit list of tools to discard
        self.transport = transport
        self.host      = host
        self.port      = port
        self.path      = path
        self.repository: dict[str, DecisionCenterEndpoint] = {}
        self.manager = DecisionCenterManager(credentials=credentials)

    def update_repository(self):

        if os.environ.get('TRACE_FILE'):
            try: os.remove(os.environ.get('TRACE_FILE'))
            except FileNotFoundError: pass # ignore

        # generate the MCP tools for Decision Center REST API
        if self.credentials.odm_url:
            endpoints       = self.manager.fetch_endpoints()
            self.repository = self.manager.generate_tools_format(endpoints, self.tags, self.tools, self.no_tools, self.credentials.isAdmin)

        # generate the MCP tools for Decision Server console REST API (aka RES console)
        if self.credentials.odm_res_url:
            self.repository = self.manager.generate_res_tools(self.manager.fetch_res_api_endpoints(), self.repository)

        if os.environ.get('TRACE_FILE'):
            import pprint
            try:
                with open(os.environ.get('TRACE_FILE'), 'a') as f:
                    for endpoint in self.repository.values():
                        pprint.pp(endpoint.tool, f)
            except FileNotFoundError: pass # ignore


    async def list_tools(self) -> list[types.Tool]:
        """
        List available tools.
        Each tool specifies its arguments using JSON Schema validation.
        """
        tools = []
        for tool_name, endpoint in self.repository.items():
            tools.append(endpoint.tool)
        return tools

    async def call_tool(self,
        name: str, arguments: dict | None
    ) -> list[types.TextContent | types.ImageContent | types.EmbeddedResource]:
        """
        Handle tool execution requests.
        """
        self.logger.info("Invoking tool: %s with arguments: %s", name, arguments)

        endpoint : DecisionCenterEndpoint = self.repository.get(name)
        if endpoint is None:
            raise ValueError(f"Unknown tool: {name}")

        # this call may throw an exception, handled by Server.call_tool.handler
        result = self.manager.invokeDecisionCenterApi(endpoint, arguments, self.transport == 'stdio')

        # Handle dictionary response
        if isinstance(result, dict):
            response_text = json.dumps(result, indent=2, ensure_ascii=False)
        else:
            # Handle non-dict response (string, etc)
            response_text = str(result)

        return [
            types.TextContent(
                type="text",
                text=response_text,
            )
        ]

    async def list_resources(self) -> list[types.Resource]:
        """
        List available resources.
        """
        return []

    async def read_resource(self, uri: AnyUrl) -> str:
        """
        Read a resource by its URI.
        """
        raise ValueError(f"resource not found")

    def start(self):
        self.server = FastMCP(name="ibm-odm-management-mcp-server",
                              instructions=INSTRUCTIONS,
                              host=self.host,
                              port=self.port,
                              sse_path=self.path,
                              streamable_http_path=self.path,
                             )
        # Register handlers
        self.server._mcp_server.list_resources()(self.list_resources)
        self.server._mcp_server.read_resource()(self.read_resource)
        self.server._mcp_server.list_tools()(self.list_tools)
        self.server._mcp_server.call_tool()(self.call_tool)

        self.server.run(transport=self.transport)

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
            pkjwt_cert_path=args.pkjwt_cert_path, pkjwt_key_path=args.pkjwt_key_path, pkjwt_key_password=args.pkjwt_key_password,
            mtls_cert_path=args.mtls_cert_path, mtls_key_path=args.mtls_key_path, mtls_key_password=args.mtls_key_password,
            ssl_cert_path=args.ssl_cert_path,
            verify_ssl=verifyssl
        )
    else:  # Default to basic authentication
        if not args.username or not args.password:
            raise ValueError("Username and password must be provided for basic authentication.")
        return Credentials(
            odm_url=args.url,
            odm_res_url=args.res_url,
            username=args.username,
            password=args.password,
            mtls_cert_path=args.mtls_cert_path, mtls_key_path=args.mtls_key_path, mtls_key_password=args.mtls_key_password,
            ssl_cert_path=args.ssl_cert_path,
            verify_ssl=verifyssl
        )

def init(args):
    init_logging(args.log_level)
    credentials = create_credentials(args)
    server = MCPServer(
        credentials=credentials,
        tags    =[tag.lower()  for tag  in args.tags]     if args.tags else [],
        tools   =[tool.lower() for tool in args.tools]    if args.tools else [],
        no_tools=[tool.lower() for tool in args.no_tools] if args.no_tools else [],
        transport=args.transport, host=args.host, port=args.port, path=args.mount_path,
    )
    server.update_repository()
    return server

def parse_arguments():
    parser = argparse.ArgumentParser(description="Decision MCP Server")
    parser.add_argument("--url",               type=str, default=os.getenv("ODM_URL"), help="ODM Decision Center REST API URL")
    parser.add_argument("--res-url",           type=str, default=os.getenv("ODM_RES_URL"), help="ODM Decision Server Console URL (aka RES Console)")
    parser.add_argument("--username",          type=str, default=os.getenv("ODM_USERNAME", "odmAdmin"), help="ODM username (optional)")
    parser.add_argument("--password",          type=str, default=os.getenv("ODM_PASSWORD", "odmAdmin"), help="ODM password (optional)")
    parser.add_argument("--zenapikey",         type=str, default=os.getenv("ZENAPIKEY"), help="Zen API Key (optional)")
    parser.add_argument("--client-id",         type=str, default=os.getenv("CLIENT_ID"), help="OpenID Client ID (optional)")
    parser.add_argument("--client-secret",     type=str, default=os.getenv("CLIENT_SECRET"), help="OpenID Client Secret (optional)")
    parser.add_argument("--token-url",         type=str, default=os.getenv("TOKEN_URL"), help="OpenID Connect token endpoint URL (optional)")
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
    
    # Logging-related arguments
    parser.add_argument("--log-level",         type=str, default=os.getenv("LOG_LEVEL", "INFO"),
                        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
                        help="Set the logging level (default: INFO)")

    # Decision Center REST API specific arguments
    parser.add_argument("--tags",              type=str, default=os.getenv("TAGS"),     nargs='+', help="List of Tags (eg. About Explore Build). Useful to keep only the tools whose tag is in the list. If this option is not specified, all the tools are published by the MCP server.")
    parser.add_argument("--tools",             type=str, default=os.getenv("TOOLS"),    nargs='+', help="Explicit list of tools to publish. All the other tools are filtered out. If this option is not specified, all the tools are published by the MCP server.")
    parser.add_argument("--no-tools",          type=str, default=os.getenv("NO_TOOLS"), nargs='+', help="Explicit list of tools to discard. All the other tools are published. Option ignored if the option --tools is provided. If this option is not specified, all the tools are published by the MCP server.")
        
    return parser.parse_args()

def main():
    args = parse_arguments()
    server = init(args)
    server.start()