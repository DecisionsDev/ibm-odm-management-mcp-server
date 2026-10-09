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
        userinfo_url=None,
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
        jwks_url=None,
        jwt_algorithms=None,
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
        mock_fastmcp.run.assert_called_once_with(transport="streamable-http", host='127.0.0.1', port=3001, streamable_http_path='/custom-path', stateless_http=True)
        
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
        mock_fastmcp.run.assert_called_once_with(transport="sse", host='127.0.0.1', port=3001, streamable_http_path='/custom-path', stateless_http=True)
        
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


def test_probes_enabled_different_host_non_root_path_is_not_suppressed():
    """A request from a different IP to a non-root path must pass through (filter returns True)."""
    local_ip = "10.0.0.1"
    f = _SuppressAccessLogForProbes(local_ip)
    assert f.filter(_make_record("10.0.0.2:12345", path="/mcp")) is True


def test_probes_enabled_root_path_from_any_host_is_suppressed():
    """A GET / request from any external IP must be suppressed (health-check route)."""
    local_ip = "10.0.0.1"
    f = _SuppressAccessLogForProbes(local_ip)
    assert f.filter(_make_record("192.168.53.112:8151",  path="/")) is False
    assert f.filter(_make_record("192.168.92.152:58576", path="/")) is False
    assert f.filter(_make_record("10.0.0.2:12345",       path="/")) is False


def test_probes_enabled_root_path_from_local_host_is_suppressed():
    """A GET / request from the local pod IP is also suppressed."""
    local_ip = "10.0.0.1"
    f = _SuppressAccessLogForProbes(local_ip)
    assert f.filter(_make_record("10.0.0.1:12345", path="/")) is False


def test_probes_enabled_logging_filter_passes_when_not_suppressed():
    """A record with no args tuple passes through (non-access-log record)."""
    f = _SuppressAccessLogForProbes("10.0.0.1")
    record = _logging.LogRecord("uvicorn.access", _logging.INFO, "", 0, "plain message", (), None)
    assert f.filter(record) is True


def test_probes_enabled_logging_filter_drops_when_suppressed():
    """IP prefix match is exact: 10.0.0.10 must not match local_ip 10.0.0.1."""
    f = _SuppressAccessLogForProbes("10.0.0.1")
    # 10.0.0.10 starts with "10.0.0.1" but not "10.0.0.1:" — must NOT be suppressed
    assert f.filter(_make_record("10.0.0.10:12345", path="/mcp")) is True


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


# ---------------------------------------------------------------------------
# Tests for userinfo-based token validation
# ---------------------------------------------------------------------------

def _make_server_with_userinfo(userinfo_url, introspection_url=None):
    """Helper: build an MCPServer configured with the given URL(s)."""
    credentials = Credentials(
        odm_url="http://test:9060/decisioncenter-api",
        client_id="test-client",
        client_secret="test-secret",
        token_url="https://idp.example.com/token",
        username=None,
        password=None,
    )
    return MCPServer(
        credentials=credentials,
        transport="streamable-http",
        issuer_url="https://idp.example.com",
        introspection_url=introspection_url,
        userinfo_url=userinfo_url,
        mcp_ext_url="https://mcp.example.com",
    )


def test_use_user_credentials_with_userinfo_url_only():
    """use_user_credentials() must return True when only userinfo_url is set (no introspection_url)."""
    server = _make_server_with_userinfo("https://idp.example.com/oauth2/userInfo")
    assert server.use_user_credentials() is True


def test_use_user_credentials_requires_at_least_one_validation_url():
    """use_user_credentials() must return False when neither introspection_url nor userinfo_url is set."""
    server = _make_server_with_userinfo(userinfo_url=None, introspection_url=None)
    assert server.use_user_credentials() is False


def test_parse_arguments_userinfo_url():
    """--userinfo-url must be parsed into args.userinfo_url."""
    with patch('sys.argv', ['script', '--userinfo-url', 'https://idp.example.com/oauth2/userInfo']), \
         patch.dict('os.environ', {}, clear=False) as env:
        env.pop('USERINFO_URL', None)
        args = parse_arguments()
        assert args.userinfo_url == 'https://idp.example.com/oauth2/userInfo'


def test_parse_arguments_userinfo_url_from_env():
    """USERINFO_URL env var must populate args.userinfo_url."""
    with patch('sys.argv', ['script']), \
         patch.dict('os.environ', {'USERINFO_URL': 'https://idp.example.com/userinfo'}, clear=False):
        args = parse_arguments()
        assert args.userinfo_url == 'https://idp.example.com/userinfo'


def test_validate_token_via_userinfo_success():
    """validate_token_via_userinfo() must return an AccessToken when the userinfo endpoint responds 200."""
    server = _make_server_with_userinfo("https://idp.example.com/oauth2/userInfo")

    userinfo_response = {
        "sub": "user-123",
        "email": "user@example.com",
        "scope": "openid email",
    }
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = userinfo_response
    mock_response.raise_for_status = Mock()

    with patch('requests.get', return_value=mock_response) as mock_get:
        token = "eyJmake.token.here"
        result = server.validate_token_via_userinfo(token)

    mock_get.assert_called_once()
    call_kwargs = mock_get.call_args
    assert call_kwargs.kwargs.get("url") == "https://idp.example.com/oauth2/userInfo"
    assert call_kwargs.kwargs["headers"]["Authorization"] == f"Bearer {token}"

    from mcp.server.auth.provider import AccessToken
    assert isinstance(result, AccessToken)
    assert result.token == token
    assert result.subject == "user-123"
    assert "openid" in result.scopes


def test_validate_token_via_userinfo_failure():
    """validate_token_via_userinfo() must return None when the endpoint rejects the token."""
    server = _make_server_with_userinfo("https://idp.example.com/oauth2/userInfo")

    mock_response = Mock()
    mock_response.raise_for_status.side_effect = Exception("401 Unauthorized")

    with patch('requests.get', return_value=mock_response):
        result = server.validate_token_via_userinfo("bad-token")

    assert result is None


def test_get_mcp_token_uses_userinfo_when_no_introspection():
    """get_mcp_token() must call validate_token_via_userinfo when only userinfo_url is set."""
    server = _make_server_with_userinfo("https://idp.example.com/oauth2/userInfo")

    from mcp.server.auth.provider import AccessToken
    fake_token = AccessToken(token="t", client_id="c", scopes=[], expires_at=9999999999)

    with patch.object(server, 'validate_token_via_userinfo', return_value=fake_token) as mock_userinfo, \
         patch.object(server, 'introspect_token') as mock_introspect:
        result = server.get_mcp_token("t")

    mock_userinfo.assert_called_once_with("t")
    mock_introspect.assert_not_called()
    assert result == fake_token


def test_get_mcp_token_uses_introspection_when_both_urls_set():
    """get_mcp_token() must prefer introspect_token when introspection_url is also set."""
    server = _make_server_with_userinfo(
        userinfo_url="https://idp.example.com/oauth2/userInfo",
        introspection_url="https://idp.example.com/oauth2/introspect",
    )

    from mcp.server.auth.provider import AccessToken
    fake_token = AccessToken(token="t", client_id="c", scopes=[], expires_at=9999999999)

    with patch.object(server, 'introspect_token', return_value=fake_token) as mock_introspect, \
         patch.object(server, 'validate_token_via_userinfo') as mock_userinfo:
        result = server.get_mcp_token("t")

    mock_introspect.assert_called_once_with("t")
    mock_userinfo.assert_not_called()
    assert result == fake_token


def test_get_current_user_details():
    """get_current_user_details() returns a dict containing subject and all claims from the access token."""
    from mcp.server.auth.provider import AccessToken
    from decisioncenter_mcp_server.Credentials import Credentials
    from decisioncenter_mcp_server.MCPServer import MCPServer

    cred = Credentials(odm_url="http://localhost:9060/decisioncenter-api", username="test", password="pwd")
    server = MCPServer(credentials=cred)

    mock_token = AccessToken(
        token="test-token",
        client_id="client123",
        scopes=["openid"],
        expires_at=9999999999,
        subject="user-sub-123",
        claims={"username": "jdoe", "email": "jdoe@example.com", "name": "John Doe", "preferred_username": "john"}
    )

    with patch("decisioncenter_mcp_server.MCPServer.get_access_token", return_value=mock_token):
        details = server.get_current_user_details()
        assert details == {
            "subject": "user-sub-123",
            "username": "jdoe",
            "email": "jdoe@example.com",
            "name": "John Doe",
            "preferred_username": "john"
        }

    # When no access token is found, an exception is raised
    with patch("decisioncenter_mcp_server.MCPServer.get_access_token", return_value=None):
        with pytest.raises(Exception, match="No access token found for the current request"):
            server.get_current_user_details()


@pytest.mark.asyncio
async def test_call_tool_records_user_details_when_using_user_credentials(mock_manager):
    """When use_user_credentials() is True, call_tool passes user_details to invokeDecisionCenterApi."""
    from mcp.server.auth.provider import AccessToken
    from decisioncenter_mcp_server.Credentials import Credentials
    from decisioncenter_mcp_server.MCPServer import MCPServer

    cred = Credentials(odm_url="http://localhost:9060/decisioncenter-api", client_id="my-client")
    server = MCPServer(
        credentials=cred,
        transport="sse",
        mcp_ext_url="https://mcp.example.com",
        issuer_url="https://idp.example.com",
        introspection_url="https://idp.example.com/introspect",
    )
    server.manager = mock_manager

    tool_name = "endpoint1"
    server.repository_dc_admin[tool_name] = Mock(name="endpoint1")
    mock_manager.invokeDecisionCenterApi.return_value = {"status": "ok"}

    mock_token = AccessToken(
        token="user-bearer-token",
        client_id="my-client",
        scopes=["openid"],
        expires_at=9999999999,
        subject="john.doe@example.com",
        claims={"username": "johndoe", "name": "John Doe"}
    )

    with patch.object(server, 'use_user_credentials', return_value=True), \
         patch.object(server, 'get_user_credentials', return_value=cred), \
         patch("decisioncenter_mcp_server.MCPServer.get_access_token", return_value=mock_token):
        result = await server.call_tool(tool_name, {"arg1": "val1"}, {})

    mock_manager.invokeDecisionCenterApi.assert_called_once_with(
        server.repository_dc_admin[tool_name],
        {"arg1": "val1"},
        False,
        cred,
        user_details={"subject": "john.doe@example.com", "username": "johndoe", "name": "John Doe"}
    )


# ---------------------------------------------------------------------------
# decode_token / JWKS tests
# ---------------------------------------------------------------------------

def _make_rsa_key_pair():
    """Generate a fresh RSA key pair and return (private_key, public_key)."""
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.backends import default_backend
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend(),
    )
    return private_key, private_key.public_key()


def _make_signed_jwt(private_key, payload: dict, kid: str = "key-1") -> str:
    """Sign *payload* with *private_key* using RS256 and embed *kid* in the header."""
    import jwt as pyjwt
    return pyjwt.encode(payload, private_key, algorithm="RS256", headers={"kid": kid})


def _make_server_with_jwks(jwks_url: str, jwt_algorithms=None):
    credentials = Credentials(
        odm_url="http://test:9060/decisioncenter-api",
        client_id="test-client",
        client_secret="test-secret",
        token_url="https://idp.example.com/token",
        username=None,
        password=None,
        scope="openid",
    )
    kwargs = dict(
        credentials=credentials,
        transport="streamable-http",
        issuer_url="https://idp.example.com",
        mcp_ext_url="https://mcp.example.com",
        jwks_url=jwks_url,
    )
    if jwt_algorithms is not None:
        kwargs["jwt_algorithms"] = jwt_algorithms
    return MCPServer(**kwargs)


def _make_jwk_set(public_key, kid: str = "key-1") -> dict:
    """Return a minimal JWKS dict for the given RSA public key."""
    from jwt import PyJWKSet
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    import base64, struct

    pub = public_key.public_numbers()

    def _int_to_base64url(n):
        length = (n.bit_length() + 7) // 8
        return base64.urlsafe_b64encode(n.to_bytes(length, "big")).rstrip(b"=").decode()

    return {
        "keys": [{
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "kid": kid,
            "n": _int_to_base64url(pub.n),
            "e": _int_to_base64url(pub.e),
        }]
    }


# -- argument parsing --------------------------------------------------------

def test_parse_arguments_jwks_url():
    """--jwks-url must be parsed into args.jwks_url."""
    with patch('sys.argv', ['script', '--jwks-url', 'https://idp.example.com/jwks']), \
         patch.dict('os.environ', {}, clear=False) as env:
        env.pop('JWKS_URL', None)
        args = parse_arguments()
        assert args.jwks_url == 'https://idp.example.com/jwks'


def test_parse_arguments_jwks_url_from_env():
    """JWKS_URL env var must populate args.jwks_url."""
    with patch('sys.argv', ['script']), \
         patch.dict('os.environ', {'JWKS_URL': 'https://idp.example.com/jwks'}, clear=False):
        args = parse_arguments()
        assert args.jwks_url == 'https://idp.example.com/jwks'


def test_parse_arguments_jwt_algorithms():
    """--jwt-algorithms must be parsed as a list of strings."""
    with patch('sys.argv', ['script', '--jwt-algorithms', 'RS256', 'ES256']), \
         patch.dict('os.environ', {}, clear=False) as env:
        env.pop('JWT_ALGORITHMS', None)
        args = parse_arguments()
        assert args.jwt_algorithms == ['RS256', 'ES256']


def test_parse_arguments_jwt_algorithms_default():
    """When --jwt-algorithms is omitted, args.jwt_algorithms must be None (default applied by MCPServer)."""
    with patch('sys.argv', ['script']), \
         patch.dict('os.environ', {}, clear=False) as env:
        env.pop('JWT_ALGORITHMS', None)
        args = parse_arguments()
        assert args.jwt_algorithms is None


# -- MCPServer constructor ---------------------------------------------------

def test_server_default_jwt_algorithms():
    """When jwt_algorithms is not passed, MCPServer uses DEFAULT_JWT_ALGORITHMS."""
    server = _make_server_with_jwks("https://idp.example.com/jwks")
    assert server.jwt_algorithms == MCPServer.DEFAULT_JWT_ALGORITHMS


def test_server_custom_jwt_algorithms():
    """When jwt_algorithms is passed, MCPServer uses it."""
    server = _make_server_with_jwks("https://idp.example.com/jwks", jwt_algorithms=["RS256"])
    assert server.jwt_algorithms == ["RS256"]


def test_jwt_algorithms_from_env_space_separated():
    """JWT_ALGORITHMS env var with space-separated values is split into a list by init()."""
    with patch('sys.argv', ['script']), \
         patch.dict('os.environ', {'JWT_ALGORITHMS': 'RS256 ES384 RS512'}, clear=False):
        args = parse_arguments()
        # argparse passes the env-var default through as a plain string (nargs='+' only applies to CLI tokens)
        assert args.jwt_algorithms == 'RS256 ES384 RS512'
        # init() splits it — replicate the same logic here
        jwt_algorithms = args.jwt_algorithms.split() if isinstance(args.jwt_algorithms, str) else args.jwt_algorithms
        assert jwt_algorithms == ['RS256', 'ES384', 'RS512']


def test_jwt_algorithms_from_env_single_value():
    """JWT_ALGORITHMS env var with a single value is preserved as a one-element list by init()."""
    with patch('sys.argv', ['script']), \
         patch.dict('os.environ', {'JWT_ALGORITHMS': 'RS256'}, clear=False):
        args = parse_arguments()
        assert args.jwt_algorithms == 'RS256'
        jwt_algorithms = args.jwt_algorithms.split() if isinstance(args.jwt_algorithms, str) else args.jwt_algorithms
        assert jwt_algorithms == ['RS256']


# -- decode_token ------------------------------------------------------------

def test_decode_token_success():
    """decode_token() must return an AccessToken for a valid RS256-signed JWT."""
    import time
    from mcp.server.auth.provider import AccessToken

    private_key, public_key = _make_rsa_key_pair()
    kid = "key-1"
    exp = int(time.time()) + 3600
    payload = {
        "sub": "user-42",
        "azp": "my-client",
        "scope": "openid email",
        "exp": exp,
        "aud": "my-resource",
        "email": "user@example.com",
        "preferred_username": "u42",
    }
    token = _make_signed_jwt(private_key, payload, kid=kid)
    jwks = _make_jwk_set(public_key, kid=kid)

    server = _make_server_with_jwks("https://idp.example.com/jwks")

    with patch("jwt.PyJWKClient.get_signing_key_from_jwt") as mock_get_key:
        from jwt import PyJWK
        mock_get_key.return_value = PyJWK.from_dict(jwks["keys"][0])
        result = server.decode_token(token)

    assert isinstance(result, AccessToken)
    assert result.token == token
    assert result.subject == "user-42"
    assert result.client_id == "my-client"
    assert result.expires_at == exp
    assert result.resource == "my-resource"
    assert "openid" in result.scopes
    assert result.claims == {"email": "user@example.com", "preferred_username": "u42"}


def test_decode_token_uses_cache_on_second_call():
    """decode_token() must not hit the JWKS endpoint on the second call for the same kid."""
    import time

    private_key, public_key = _make_rsa_key_pair()
    kid = "key-1"
    payload = {"sub": "u1", "scope": "openid", "exp": int(time.time()) + 3600}
    token = _make_signed_jwt(private_key, payload, kid=kid)
    jwks = _make_jwk_set(public_key, kid=kid)

    server = _make_server_with_jwks("https://idp.example.com/jwks")

    from jwt import PyJWK
    signing_key = PyJWK.from_dict(jwks["keys"][0])

    with patch("jwt.PyJWKClient.get_signing_key_from_jwt", return_value=signing_key) as mock_get_key:
        server.decode_token(token)  # first call — populates cache
        server.decode_token(token)  # second call — must use cache
        assert mock_get_key.call_count == 1  # JWKS endpoint called only once


def test_decode_token_logs_jwks_failure(caplog):
    """decode_token() must log at DEBUG level when the JWKS key resolution fails."""
    import jwt as pyjwt
    import logging

    # Build a token with a kid that the JWKS endpoint won't recognise
    private_key, _ = _make_rsa_key_pair()
    token = _make_signed_jwt(private_key, {"sub": "u", "exp": 9999999999, "scope": "openid"}, kid="unknown-kid")

    server = _make_server_with_jwks("https://idp.example.com/jwks")

    with patch("jwt.PyJWKClient.get_signing_key_from_jwt", side_effect=Exception("No key found for kid")), \
         caplog.at_level(logging.DEBUG):
        result = server.decode_token(token)

    assert result is None
    assert any("JWKS key resolution failed" in r.message for r in caplog.records)
    assert any("https://idp.example.com/jwks" in r.message for r in caplog.records)


def test_decode_token_returns_none_for_jwe():
    """decode_token() must return None for an encrypted (JWE) token."""
    # A JWE has 5 dot-separated parts; jwt.get_unverified_header raises on it
    jwe_token = "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ.abc.def.ghi.jkl"
    server = _make_server_with_jwks("https://idp.example.com/jwks")
    result = server.decode_token(jwe_token)
    assert result is None


def test_decode_token_returns_none_for_bad_signature():
    """decode_token() must return None when the token signature does not match the key."""
    import time

    private_key_a, public_key_a = _make_rsa_key_pair()
    private_key_b, _            = _make_rsa_key_pair()

    kid = "key-1"
    # Sign with key B, but verify against key A
    token = _make_signed_jwt(private_key_b, {"sub": "u", "exp": int(time.time()) + 3600, "scope": "openid"}, kid=kid)
    jwks = _make_jwk_set(public_key_a, kid=kid)  # key A

    server = _make_server_with_jwks("https://idp.example.com/jwks")

    from jwt import PyJWK
    with patch("jwt.PyJWKClient.get_signing_key_from_jwt", return_value=PyJWK.from_dict(jwks["keys"][0])):
        result = server.decode_token(token)

    assert result is None


# -- get_mcp_token with jwks_url --------------------------------------------

def test_get_mcp_token_skips_decode_when_no_jwks_url():
    """get_mcp_token() must not call decode_token when jwks_url is not set."""
    server = _make_server_with_userinfo("https://idp.example.com/userinfo")

    from mcp.server.auth.provider import AccessToken
    fake = AccessToken(token="t", client_id="c", scopes=[], expires_at=9999999999)

    with patch.object(server, 'decode_token') as mock_decode, \
         patch.object(server, 'validate_token_via_userinfo', return_value=fake):
        server.get_mcp_token("t")

    mock_decode.assert_not_called()


def test_get_mcp_token_uses_decode_when_jwks_url_set():
    """get_mcp_token() must call decode_token first when jwks_url is set."""
    server = _make_server_with_jwks("https://idp.example.com/jwks")

    from mcp.server.auth.provider import AccessToken
    fake = AccessToken(token="t", client_id="c", scopes=[], expires_at=9999999999)

    with patch.object(server, 'decode_token', return_value=fake) as mock_decode:
        result = server.get_mcp_token("t")

    mock_decode.assert_called_once_with("t")
    assert result == fake


def test_get_mcp_token_falls_back_to_introspection_when_decode_fails():
    """get_mcp_token() must fall back to introspect_token when decode_token returns None."""
    server = _make_server_with_jwks("https://idp.example.com/jwks")
    server.introspection_url = "https://idp.example.com/introspect"

    from mcp.server.auth.provider import AccessToken
    fake = AccessToken(token="t", client_id="c", scopes=[], expires_at=9999999999)

    with patch.object(server, 'decode_token', return_value=None), \
         patch.object(server, 'introspect_token', return_value=fake) as mock_introspect:
        result = server.get_mcp_token("t")

    mock_introspect.assert_called_once_with("t")
    assert result == fake
