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
from mcp_types import Tool, TextContent
from mcp.server import MCPServer as SDK_MCPServer
from mcp.server.mcpserver.exceptions import ToolError
import json
from decisioncenter_mcp_server.MCPServer   import MCPServer, parse_arguments, create_credentials, init, init_logging
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
    return Mock(spec=SDK_MCPServer)

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
        ["--client-id", "test-client", "--client-secret", "test-secret", "--issuer-url", "http://op", "--introspection-url", "http://op/token/introspect",  "--token-url", "http://op/token", "--scope", "openid"],
          {"client_id": "test-client",   "client_secret": "test-secret",   "issuer_url": "http://op",   "introspection_url": "http://op/token/introspect",    "token_url": "http://op/token",   "scope": "openid"}
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
    with patch('sys.argv', ['script'] + args), \
         patch.dict('os.environ', {}, clear=False) as env:
        env.pop('PORT', None)
        env.pop('HOST', None)
        env.pop('TRANSPORT', None)
        env.pop('MOUNT_PATH', None)
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
        issuer_url=None,
        introspection_url=None,
        token_url=None,
        mcp_ext_url=None,
        scope="openid",
        verifyssl="True",
        verifyssl_hostname="True",
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
        issuer_url=None,
        introspection_url=None,
        token_url=None,
        mcp_ext_url=None,
        scope="openid",
        verifyssl=verify_ssl,
        verifyssl_hostname="True",
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
        issuer_url=None,
        introspection_url=None,
        token_url=None,
        mcp_ext_url=None,
        scope="openid",
        verifyssl="True",
        verifyssl_hostname="True",
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
    repo = {
        "endpoint1": Mock(
            method="GET",
            url="http://test:9060/decisioncenter-api/v1/endpoint1",
            parameters={
                "param1": {"in": "query"},
                "param2": {"in": "query"}
            },
            tool=Tool(
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
            tool=Tool(
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
    manager.generate_tools_format.return_value = repo, repo
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
    server.repository_dc, server.repository_dc_admin = mock_manager.generate_tools_format()
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
    assert len(server.repository_dc) == 2
    assert "endpoint1" in server.repository_dc
    assert "endpoint2" in server.repository_dc


@pytest.mark.asyncio
async def test_list_tools_empty(server, mock_manager):
    # Setup empty response
    mock_manager.fetch_endpoints.return_value = []
    mock_manager.generate_tools_format.return_value = {}, {}
    server.repository_dc, server.repository_dc_admin = mock_manager.generate_tools_format()

    # Execute
    tools = await server.list_tools()

    # Verify
    assert len(tools) == 0
    assert len(server.repository_dc) == 0

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
    server.repository_dc[tool_name] = Mock(name="endpoint1")

    # Execute
    result = await server.call_tool(tool_name, arguments, {})

    # Verify
    assert mock_manager.invokeDecisionCenterApi.called

    # Verify response format
    assert len(result.content) == 1
    assert isinstance(result.content[0], TextContent)
    assert result.content[0].type == "text"
    
    # Verify response content
    response_data = json.loads(result.content[0].text)
    assert response_data["result"] == "endpoint_result"

@pytest.mark.asyncio
async def test_call_tool_unknown_tool(server):
    # Try to call non-existent tool
    with pytest.raises(ToolError) as exc_info:
        await server.call_tool("unknown_tool", {}, {})
    assert str(exc_info.value) == "Unknown tool: unknown_tool"

@pytest.mark.asyncio
async def test_call_tool_non_dict_response(server, mock_manager):
    # Setup mock response as string
    mock_manager.invokeDecisionCenterApi.return_value = "string_response"
    tool_name = "tool1"
    server.repository_dc[tool_name] = Mock()

    # Execute
    result = await server.call_tool(tool_name, {}, {})

    # Verify string handling
    assert len(result.content) == 1
    assert isinstance(result.content[0], TextContent)
    assert result.content[0].text == "string_response"

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
    """Test that server.start() correctly configures SDK_MCPServer with streamable-http transport."""
    credentials = Credentials(
        odm_url="http://test:9060/decisioncenter-api",
        username="test",
        password="test",
        client_id="clientid",
    )
    
    # Create server with streamable-http transport
    server = MCPServer(
        credentials=credentials,
        transport="streamable-http",
        host="127.0.0.1",
        port=3001,
        path="/custom-path",
        issuer_url="https://openid-provider",
    )
    
    # Mock the SDK_MCPServer and its run method
    with patch('decisioncenter_mcp_server.MCPServer.SDK_MCPServer') as mock_fastmcp_class, \
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
        
        # Verify run was called with streamable-http transport
        mock_fastmcp.run.assert_called_once_with(transport="streamable-http", host='127.0.0.1', port=3001, streamable_http_path='/custom-path')
        
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
        issuer_url="https://openid-provider",
    )
    
    # Verify default transport configuration
    assert server.transport == "stdio"
    assert server.host == "0.0.0.0"
    assert server.port == 3000
    assert server.path == "/mcp"

def test_server_start_with_sse_transport():
    """Test that server.start() correctly configures SDK_MCPServer with sse transport."""
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
        path="/custom-path",
        issuer_url="https://openid-provider",
    )
    
    # Mock the SDK_MCPServer and its run method
    with patch('decisioncenter_mcp_server.MCPServer.SDK_MCPServer') as mock_fastmcp_class, \
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
        
        # Verify run was called with streamable-http transport
        mock_fastmcp.run.assert_called_once_with(transport="sse", host='127.0.0.1', port=3001, streamable_http_path='/custom-path')
        
        # Verify manager was initialized
        assert server.manager is not None


# ---------------------------------------------------------------------------
# Tests for the access-log suppression filter used when probes are enabled
# ---------------------------------------------------------------------------

import logging as _logging
from decisioncenter_mcp_server.MCPServer import _SuppressAccessLogForProbes


def _make_record(client_addr: str, method: str = "GET", path: str = "/", status_code: int = 200) -> _logging.LogRecord:
    """Build a uvicorn-style access log record matching the real 5-element args tuple.

    Uvicorn emits: logger.info('%s - "%s %s HTTP/%s" %d', client_addr, method, path, http_version, status_code)
    so record.args is (client_addr, method, path, http_version, status_code).
    """
    record = _logging.LogRecord(
        "uvicorn.access", _logging.INFO, "", 0,
        '%s - "%s %s HTTP/%s" %d',
        (),
        None,
    )
    record.args = (client_addr, method, path, "1.1", status_code)
    return record


def test_probes_enabled_same_host_is_suppressed():
    """A request from the local IP must be filtered out (filter returns False)."""
    local_ip = "10.0.0.1"
    f = _SuppressAccessLogForProbes(local_ip)
    assert f.filter(_make_record("10.0.0.1:12345")) is False


def test_probes_enabled_different_host_is_not_suppressed():
    """A request from a different IP must pass through (filter returns True)."""
    local_ip = "10.0.0.1"
    f = _SuppressAccessLogForProbes(local_ip)
    assert f.filter(_make_record("10.0.0.2:12345")) is True


def test_probes_enabled_logging_filter_passes_when_not_suppressed():
    """A record with no args tuple passes through (non-access-log record)."""
    f = _SuppressAccessLogForProbes("10.0.0.1")
    record = _logging.LogRecord("uvicorn.access", _logging.INFO, "", 0, "plain message", (), None)
    assert f.filter(record) is True


def test_probes_enabled_logging_filter_drops_when_suppressed():
    """IP prefix match is exact: 10.0.0.10 must not match local_ip 10.0.0.1."""
    f = _SuppressAccessLogForProbes("10.0.0.1")
    # 10.0.0.10 starts with "10.0.0.1" but not "10.0.0.1:" — must NOT be suppressed
    assert f.filter(_make_record("10.0.0.10:12345")) is True


def test_probes_enabled_401_post_from_same_pod_ip_is_suppressed():
    """A 401 POST /mcp from the pod's own IP (probe auth failure) must be suppressed."""
    local_ip = "10.0.0.1"
    f = _SuppressAccessLogForProbes(local_ip)
    assert f.filter(_make_record("10.0.0.1:41008", method="POST", path="/mcp", status_code=401)) is False


def test_probes_enabled_401_post_from_loopback_is_suppressed():
    """A 401 POST /mcp arriving via 127.0.0.1 must be suppressed even when the
    resolved pod IP is different — loopback is always treated as local."""
    local_ip = "10.0.0.1"
    f = _SuppressAccessLogForProbes(local_ip)
    assert f.filter(_make_record("127.0.0.1:41008", method="POST", path="/mcp", status_code=401)) is False


def test_probes_enabled_401_post_from_different_host_is_not_suppressed():
    """A 401 POST /mcp from a different IP must still pass through."""
    local_ip = "10.0.0.1"
    f = _SuppressAccessLogForProbes(local_ip)
    assert f.filter(_make_record("192.168.1.1:41008", method="POST", path="/mcp", status_code=401)) is True


def test_probes_enabled_filter_on_root_handler_suppresses_propagated_record():
    """When the filter is attached to a root handler (to intercept propagated records),
    it must still suppress uvicorn.access records from the local IP."""
    local_ip = "10.0.0.1"
    f = _SuppressAccessLogForProbes(local_ip)
    record = _make_record("10.0.0.1:41008", method="POST", path="/mcp", status_code=401)
    # Simulate propagation: the record arrives at a root handler with logger name still "uvicorn.access"
    assert f.filter(record) is False


def test_probes_enabled_filter_on_root_handler_suppresses_loopback_propagated_record():
    """Filter on a root handler must also suppress loopback records propagated from uvicorn.access."""
    local_ip = "10.0.0.1"
    f = _SuppressAccessLogForProbes(local_ip)
    record = _make_record("127.0.0.1:41008", method="POST", path="/mcp", status_code=401)
    assert f.filter(record) is False


def test_probes_enabled_filter_on_root_handler_passes_non_uvicorn_records():
    """When the filter is attached to a root handler, records from other loggers
    (e.g. application code) must never be suppressed, even if their args happen
    to start with the local IP."""
    local_ip = "10.0.0.1"
    f = _SuppressAccessLogForProbes(local_ip)
    # A record from a different logger — must always pass through
    record = _logging.LogRecord("myapp", _logging.INFO, "", 0, "some message", (), None)
    record.args = ("10.0.0.1:9999", "extra", "data")
    assert f.filter(record) is True


def test_probes_enabled_configure_logging_is_patched_on_start():
    """When STARTUP_RETRY_IF_FAILURE=True and transport is streamable-http, start() must
    patch uvicorn.Config.configure_logging so the access-log filter survives dictConfig."""
    import uvicorn.config as _uvicorn_config

    credentials = Credentials(
        odm_url="http://test:9060/decisioncenter-api",
        username="test",
        password="test",
    )
    server = MCPServer(
        credentials=credentials,
        transport="streamable-http",
        host="127.0.0.1",
        port=3001,
        path="/mcp",
    )

    original_configure_logging = _uvicorn_config.Config.configure_logging

    with patch('decisioncenter_mcp_server.MCPServer.SDK_MCPServer') as mock_cls, \
         patch('decisioncenter_mcp_server.MCPServer.DecisionCenterManager'), \
         patch.dict(os.environ, {"STARTUP_RETRY_IF_FAILURE": "True"}), \
         patch('socket.gethostbyname', return_value="10.0.0.1"):

        mock_fastmcp = mock_cls.return_value
        mock_fastmcp.run = Mock()

        init_logging("INFO", "streamable-http")
        server.start()

        # configure_logging must have been replaced with the wrapper
        assert _uvicorn_config.Config.configure_logging is not original_configure_logging

    # Restore so other tests are not affected
    _uvicorn_config.Config.configure_logging = original_configure_logging


def test_probes_not_enabled_configure_logging_is_not_patched():
    """When STARTUP_RETRY_IF_FAILURE is not set, configure_logging must not be touched."""
    import uvicorn.config as _uvicorn_config

    credentials = Credentials(
        odm_url="http://test:9060/decisioncenter-api",
        username="test",
        password="test",
    )
    server = MCPServer(
        credentials=credentials,
        transport="streamable-http",
        host="127.0.0.1",
        port=3001,
        path="/mcp",
    )

    original_configure_logging = _uvicorn_config.Config.configure_logging

    with patch('decisioncenter_mcp_server.MCPServer.SDK_MCPServer') as mock_cls, \
         patch('decisioncenter_mcp_server.MCPServer.DecisionCenterManager'), \
         patch.dict(os.environ, {}, clear=False):

        os.environ.pop("STARTUP_RETRY_IF_FAILURE", None)
        mock_fastmcp = mock_cls.return_value
        mock_fastmcp.run = Mock()

        server.start()

        assert _uvicorn_config.Config.configure_logging is original_configure_logging
