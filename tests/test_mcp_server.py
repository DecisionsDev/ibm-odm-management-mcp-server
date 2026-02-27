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

import pytest
from unittest.mock import Mock, patch
import os
import argparse
import mcp.types as types
from mcp.server.fastmcp import FastMCP
import json
from decisioncenter_mcp_server.MCPServer import MCPServer, parse_arguments, create_credentials, init, INSTRUCTIONS
from decisioncenter_mcp_server.Credentials import Credentials

# Test fixtures
@pytest.fixture
def mock_credentials():
    return Credentials(
        odm_url="http://test:9060/decisioncenter-api",
        username="test_user",
        password="test_pass"
    )

@pytest.fixture
def mock_server():
    return Mock(spec=FastMCP)

@pytest.fixture
def mcp_server(mock_credentials, mock_server):
    mcp_server = MCPServer(credentials=mock_credentials)
    mcp_server.server = mock_server
    mcp_server.manager = Mock()
    mcp_server.repository = {}
    return mcp_server

# Test DecisionMCPServer initialization
def test_server_initialization(mcp_server):
    assert isinstance(mcp_server.repository, dict)
    assert mcp_server.server is not None
    assert mcp_server.credentials is not None

# Test argument parsing
@pytest.mark.parametrize("args, expected", [
    (
        ["--url", "http://test-odm:9060/decisioncenter-api"],
          {"url": "http://test-odm:9060/decisioncenter-api"}
    ),
    (
        ["--username", "testuser", "--password", "testpass"],
          {"username": "testuser",   "password": "testpass"}
    ),
    (
        ["--zenapikey", "test-key"],
          {"zenapikey": "test-key"}
    ),
    (
        ["--client-id", "test-client", "--client-secret", "test-secret", "--token-url", "http://op/token", "--scope", "openid"],
          {"client_id": "test-client",   "client_secret": "test-secret",   "token_url": "http://op/token",   "scope": "openid"}
    ),
    (
        ["--pkjwt-cert-path", "/custom/cert/file", "--pkjwt-key-path", "/custom/key/file", "--pkjwt-key-password", "xyz-password"],
          {"pkjwt_cert_path": "/custom/cert/file",   "pkjwt_key_path": "/custom/key/file",   "pkjwt_key_password": "xyz-password"}
    ),
    (
        ["--mtls-cert-path", "/custom/cert/file", "--mtls-key-path", "/custom/key/file", "--mtls-key-password", "xyz-password"],
          {"mtls_cert_path": "/custom/cert/file",   "mtls_key_path": "/custom/key/file",   "mtls_key_password": "xyz-password"}
    ),
    (
        ["--verifyssl", "False"],
          {"verifyssl": "False"}
    ),
    (
        ["--ssl-cert-path", "/custom/cert/file"],
          {"ssl_cert_path": "/custom/cert/file"}
    ),
    (
        ["--log-level", "DEBUG"],
          {"log_level": "DEBUG"}  # Test log level argument
    ),
    (
        ["--trace",  "EXECUTIONS", "CONFIGURATION", "--traces-dir", "/custom/trace/dir", "--traces-maxsize", "10000"],
          {"trace": ["EXECUTIONS", "CONFIGURATION"],  "traces_dir": "/custom/trace/dir",   "traces_maxsize":  10000}
    ),
    (
        ["--transport", "streamable-http", "--host", "127.0.0.1", "--port", "3001", "--mount-path", "/decision-mcp"],
          {"transport": "streamable-http",   "host": "127.0.0.1",   "port":  3001,    "mount_path": "/decision-mcp"}  # Test remote arguments
    ),
    (
        ["--transport", "streamable-http"],
          {"transport": "streamable-http", "host": "0.0.0.0", "port": 3000, "mount_path": "/mcp"}  # Test remote arguments with default values
    ),
    (
        ["--tags",  "Manage", "--tools",  "Tool1", "--no-tools",  "Tool2"],
          {"tags": ["Manage"],  "tools": ["Tool1"],  "no_tools": ["Tool2"]}
    ),
    (
        [],  # No arguments
        {"scope": "openid", "verifyssl": "True", "log_level": "INFO", "transport":"stdio"}  # Default values
    ),
])
def test_parse_arguments(args, expected):  # Added 'expected' parameter
    with patch('sys.argv', ['script'] + args):
        parsed_args = parse_arguments()
        for key, value in expected.items():
            assert getattr(parsed_args, key) == value

# Test credentials creation
def test_create_credentials_basic_auth():
    args = argparse.Namespace(
        url="http://test:9060/decisioncenter-api",
        res_url=None,
        username="test_user",
        password="test_pass",
        zenapikey=None,
        client_id=None,
        client_secret=None,
        token_url=None,
        scope="openid",
        verifyssl="True",
        ssl_cert_path=None,
        pkjwt_cert_path=None,
        pkjwt_key_path=None,
        pkjwt_key_password=None,
        mtls_cert_path=None,
        mtls_key_path=None,
        mtls_key_password=None,
        console_auth_type=None,
        runtime_auth_type=None,
        log_level="INFO",
        trace = None, traces_dir = None, traces_maxsize = 200,
    )
    credentials = create_credentials(args)
    assert credentials.odm_url == "http://test:9060/decisioncenter-api"
    assert credentials.username == "test_user"
    assert credentials.password == "test_pass"

# Test SSL verification
@pytest.mark.parametrize("verify_ssl, expected", [
    ("True",  True),
    ("False", False)
])
def test_ssl_verification(verify_ssl, expected):
    args = argparse.Namespace(
        url="http://test:9060/decisioncenter-api",
        res_url=None,
        username="test_user",
        password="test_pass",
        zenapikey=None,
        client_id=None,
        client_secret=None,
        token_url=None,
        scope="openid",
        verifyssl=verify_ssl,
        ssl_cert_path=None,
        pkjwt_cert_path=None,
        pkjwt_key_path=None,
        pkjwt_key_password=None,
        mtls_cert_path=None,
        mtls_key_path=None,
        mtls_key_password=None,
        console_auth_type=None,
        runtime_auth_type=None,
        log_level="INFO",
        trace = None, traces_dir = None, traces_maxsize = 200,
    )
    credentials = create_credentials(args)
    assert credentials.verify_ssl == expected

# Test tags,tool,no-tools verification
@pytest.mark.parametrize("tags, expected_tags", [
    (["Admin", "Build", "DBAdmin"], ["admin", "build", "dbadmin"]),
    (["Explore"],                   ["explore"])
])
@pytest.mark.parametrize("tools, expected_tools", [
    (["Tool1", "Tool2", "TOOL3"], ["tool1", "tool2", "tool3"]),
    (["tool4"],                   ["tool4"])
])
@pytest.mark.parametrize("notools, expected_notools", [
    (["Tool1", "Tool2", "TOOL3"], ["tool1", "tool2", "tool3"]),
    (["tool4"],                   ["tool4"])
])
def test_tags_verification(tags, expected_tags, tools, expected_tools, notools, expected_notools):
    args = argparse.Namespace(
        url="http://test:9060/decisioncenter-api",
        res_url=None,
        username="test_user",
        password="test_pass",
        zenapikey=None,
        client_id=None,
        client_secret=None,
        token_url=None,
        scope="openid",
        verifyssl="True",
        ssl_cert_path=None,
        pkjwt_cert_path=None,
        pkjwt_key_path=None,
        pkjwt_key_password=None,
        mtls_cert_path=None,
        mtls_key_path=None,
        mtls_key_password=None,
        console_auth_type=None,
        runtime_auth_type=None,
        log_level="INFO",
        trace = None, traces_dir = None, traces_maxsize = 200,
        tags=tags,
        tools=tools,
        no_tools=notools,
        transport=None,
        host=None,
        port=None,
        mount_path=None,
    )
    MCPServer.update_repository = Mock(return_value = {})
    server = init(args)
    assert server.tags == expected_tags
    assert server.tools == expected_tools
    assert server.no_tools == expected_notools

# Test environment variables
def test_environment_variables():
    with patch.dict(os.environ, {
        'ODM_URL': 'http://env-test:9060/decisioncenter-api',
        'ODM_USERNAME': 'env_user',
        'ODM_PASSWORD': 'env_pass',
        'LOG_LEVEL': 'DEBUG'
    }), patch('sys.argv', ['script']):  # Added sys.argv patch
        args = parse_arguments()
        assert args.url == 'http://env-test:9060/decisioncenter-api'
        assert args.username == 'env_user'
        assert args.password == 'env_pass'
        assert args.log_level == 'DEBUG'

class DummyTool:
    def __init__(self, name, description, input_schema):
        self.name = name
        self.description = description
        self.inputSchema = input_schema

# Mock the types module
@pytest.fixture
def mock_types():
    mock = Mock()
    mock.Tool = DummyTool
    return mock

@pytest.fixture
def mock_manager():
    manager = Mock()
    # Setup mock rulesets
    manager.fetch_endpoints.return_value = [
        {"url": "/v1/endpoint1",
         "operations": {
            "method":       {"name": "GET"},
            "operation_id": "endpoint1",
            "summary":      "summary1",
            "parameters": [
                {"name": "param1.1", "schema": {"type": {"value": "number"}}, "description": "description1", "required": True},
                {"name": "param1.2"}]
            }
        },
        {"url": "/v1/endpoint2",
         "operations": {
            "method":       {"name":"POST"},
            "operation_id": "endpoint2",
            "summary":      "summary2",
            "description":  "description2",
            "request_body": {
                "content": {
                    "type": {"value": "application/json"},
                    "schema": {
                        "properties": [
                            {"name": "param2.1", "schema": {"type": {"value": "number"}}, "description": "description1"},
                            {"name": "param2.2"}],
                        "required": ["param2.1"]
                        }
                    }
                }
            }
        }
    ]
    # Setup mock tools
    manager.generate_tools_format.return_value = {
        "endpoint1": Mock(
            method="GET",
            url="http://test:9060/decisioncenter-api/v1/endpoint1",
            parameters={
                "param1": {"in": "query"},
                "param2": {"in": "query"}
            },
            tool=types.Tool(
                name="endpoint1",
                title="summary1",
                description="summary1",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "param1.1": {
                            "type":        "number",
                            "description": "description1.1"
                        },
                        "param1.2": {
                            "type": "string"
                        }
                    },
                    "required": ["param1.1"]
                }
            )
        ),
        "endpoint2": Mock(
            method="GET",
            url="http://test:9060/decisioncenter-api/v1/endpoint2",
            parameters={
                "param1": {"in": "body/json"},
                "param2": {"in": "body/json"}
            },
            tool=types.Tool(
                name="endpoint2",
                title="summary2",
                description="description2",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "param2.1": {
                            "type":        "number",
                            "description": "description2.1"
                        },
                        "param2.2": {
                            "type": "string"
                        }
                    },
                    "required": ["param2.2"]
                }
            )
        )
    }
    return manager

@pytest.fixture
def server(mock_manager):
    credentials = Credentials(
        odm_url="http://test:9060/decisioncenter-api",
        username="test",
        password="test"
    )
    server = MCPServer(credentials=credentials)
    server.manager = mock_manager
    server.repository = mock_manager.generate_tools_format()
    return server

@pytest.mark.asyncio
async def test_list_tools(server, mock_manager):
    # Execute
    tools = await server.list_tools()

    # Verify
    assert len(tools) == 2
    # assert mock_manager.fetch_endpoints.called
    # assert mock_manager.generate_tools_format.called
    
    # Verify tool properties
    assert tools[0].name == "endpoint1", f"{repr(tools[0])}"
    assert tools[0].title == "summary1"
    assert tools[0].description == "summary1"
    
    assert tools[1].name == "endpoint2", f"{repr(tools[1])}"
    assert tools[1].title == "summary2"
    assert tools[1].description == "description2"

    # Verify repository updates
    assert len(server.repository) == 2
    assert "endpoint1" in server.repository
    assert "endpoint2" in server.repository


@pytest.mark.asyncio
async def test_list_tools_empty(server, mock_manager):
    # Setup empty response
    mock_manager.fetch_endpoints.return_value = []
    mock_manager.generate_tools_format.return_value = {}
    server.repository = mock_manager.generate_tools_format()

    # Execute
    tools = await server.list_tools()

    # Verify
    assert len(tools) == 0
    assert len(server.repository) == 0

@pytest.mark.asyncio
async def test_call_tool_success(server, mock_manager):
    # Setup mock response
    mock_manager.invokeDecisionCenterApi.return_value = {
        "result": "endpoint_result"
    }

    # Setup test data
    tool_name = "endpoint1"
    arguments = {"input": "test_value"}
    
    # Add tool to repository
    server.repository[tool_name] = Mock(name="endpoint1")

    # Execute
    result = await server.call_tool(tool_name, arguments)

    # Verify
    assert mock_manager.invokeDecisionCenterApi.called

    # Verify response format
    assert len(result) == 1
    assert isinstance(result[0], types.TextContent)
    assert result[0].type == "text"
    
    # Verify response content
    response_data = json.loads(result[0].text)
    assert response_data["result"] == "endpoint_result"

@pytest.mark.asyncio
async def test_call_tool_unknown_tool(server):
    # Try to call non-existent tool
    with pytest.raises(ValueError) as exc_info:
        await server.call_tool("unknown_tool", {})
    assert str(exc_info.value) == "Unknown tool: unknown_tool"

@pytest.mark.asyncio
async def test_call_tool_non_dict_response(server, mock_manager):
    # Setup mock response as string
    mock_manager.invokeDecisionCenterApi.return_value = "string_response"
    tool_name = "tool1"
    server.repository[tool_name] = Mock()

    # Execute
    result = await server.call_tool(tool_name, {})

    # Verify string handling
    assert len(result) == 1
    assert isinstance(result[0], types.TextContent)
    assert result[0].text == "string_response"

# Test transport configuration
def test_server_initialization_with_streamable_http_transport():
    """Test MCPServer initialization with streamable-http transport."""
    credentials = Credentials(
        odm_url="http://test:9060/decisioncenter-api",
        username="test",
        password="test"
    )
    
    # Create server with streamable-http transport
    server = MCPServer(
        credentials=credentials,
        transport="streamable-http",
        host="127.0.0.1",
        port=3001,
        path="/decision-mcp"
    )
    
    # Verify transport configuration
    assert server.transport == "streamable-http"
    assert server.host == "127.0.0.1"
    assert server.port == 3001
    assert server.path == "/decision-mcp"

def test_server_initialization_with_default_transport():
    """Test MCPServer initialization with default stdio transport."""
    credentials = Credentials(
        odm_url="http://test:9060/decisioncenter-api",
        username="test",
        password="test"
    )
    
    # Create server with default transport
    server = MCPServer(
        credentials=credentials,
    )
    
    # Verify default transport configuration
    assert server.transport == "stdio"
    assert server.host == "0.0.0.0"
    assert server.port == 3000
    assert server.path == "/mcp"

def test_server_start_with_streamable_http_transport():
    """Test that server.start() correctly configures FastMCP with streamable-http transport."""
    credentials = Credentials(
        odm_url="http://test:9060/decisioncenter-api",
        username="test",
        password="test"
    )
    
    # Create server with streamable-http transport
    server = MCPServer(
        credentials=credentials,
        transport="streamable-http",
        host="127.0.0.1",
        port=3001,
        path="/custom-path"
    )
    
    # Mock the FastMCP and its run method
    with patch('decisioncenter_mcp_server.MCPServer.FastMCP') as mock_fastmcp_class, \
         patch('decisioncenter_mcp_server.MCPServer.DecisionCenterManager') as mock_manager_class:
        
        # Setup mocks
        mock_fastmcp = mock_fastmcp_class.return_value
        mock_fastmcp._mcp_server = Mock()
        mock_fastmcp._mcp_server.list_resources = Mock()
        mock_fastmcp._mcp_server.read_resource = Mock()
        mock_fastmcp._mcp_server.list_tools = Mock()
        mock_fastmcp._mcp_server.call_tool = Mock()
        mock_fastmcp.run = Mock()
        
        mock_manager = mock_manager_class.return_value
        
        # Call start
        server.start()
        
        # Verify FastMCP was initialized with correct parameters
        mock_fastmcp_class.assert_called_once_with(
            name="ibm-odm-management-mcp-server",
            instructions=INSTRUCTIONS,
            host="127.0.0.1",
            port=3001,
            sse_path="/custom-path",
            streamable_http_path="/custom-path"
        )
        
        # Verify run was called with streamable-http transport
        mock_fastmcp.run.assert_called_once_with(transport="streamable-http")
        
        # Verify manager was initialized
        assert server.manager is not None

def test_server_initialization_with_default_transport():
    """Test MCPServer initialization with default stdio transport."""
    credentials = Credentials(
        odm_url="http://test:9060/decisioncenter-api",
        username="test",
        password="test"
    )
    
    # Create server with default transport
    server = MCPServer(
        credentials=credentials,
    )
    
    # Verify default transport configuration
    assert server.transport == "stdio"
    assert server.host == "0.0.0.0"
    assert server.port == 3000
    assert server.path == "/mcp"

def test_server_start_with_sse_transport():
    """Test that server.start() correctly configures FastMCP with sse transport."""
    credentials = Credentials(
        odm_url="http://test:9060/decisioncenter-api",
        username="test",
        password="test"
    )
    
    # Create server with streamable-http transport
    server = MCPServer(
        credentials=credentials,
        transport="sse",
        host="127.0.0.1",
        port=3001,
        path="/custom-path"
    )
    
    # Mock the FastMCP and its run method
    with patch('decisioncenter_mcp_server.MCPServer.FastMCP') as mock_fastmcp_class, \
         patch('decisioncenter_mcp_server.MCPServer.DecisionCenterManager') as mock_manager_class:
        
        # Setup mocks
        mock_fastmcp = mock_fastmcp_class.return_value
        mock_fastmcp._mcp_server = Mock()
        mock_fastmcp._mcp_server.list_resources = Mock()
        mock_fastmcp._mcp_server.read_resource = Mock()
        mock_fastmcp._mcp_server.list_tools = Mock()
        mock_fastmcp._mcp_server.call_tool = Mock()
        mock_fastmcp.run = Mock()
        
        mock_manager = mock_manager_class.return_value
        
        # Call start
        server.start()
        
        # Verify FastMCP was initialized with correct parameters
        mock_fastmcp_class.assert_called_once_with(
            name="ibm-odm-management-mcp-server",
            instructions=INSTRUCTIONS,
            host="127.0.0.1",
            port=3001,
            sse_path="/custom-path",
            streamable_http_path="/custom-path"
        )
        
        # Verify run was called with streamable-http transport
        mock_fastmcp.run.assert_called_once_with(transport="sse")
        
        # Verify manager was initialized
        assert server.manager is not None
