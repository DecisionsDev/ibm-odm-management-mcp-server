# Copyright contributors to the IBM ODM MCP Server project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0

"""
Integration tests that exercise the real `mcp` package.

MCPServer.start() is run against the real SDK server (only `run()` is stubbed so
that no transport is opened), then an in-memory SDK `Client` talks to it through
the actual MCP protocol. Only DecisionCenterManager is faked.
"""

import json
from unittest.mock import Mock, patch

import pytest
from mcp.client import Client
from mcp.server import MCPServer as SDK_MCPServer
from mcp_types import Tool

from decisioncenter_mcp_server.Credentials import Credentials
from decisioncenter_mcp_server.MCPServer import MCPServer


def _endpoint(name: str, description: str) -> Mock:
    return Mock(tool=Tool(
        name=name,
        title=name,
        description=description,
        inputSchema={
            "type": "object",
            "properties": {"param": {"type": "string"}},
        },
    ))


@pytest.fixture
def started_server():
    """An MCPServer whose start() built a real SDK server, without running a transport."""
    credentials = Credentials(odm_url="http://test:9060/decisioncenter-api",
                              username="test", password="test")
    server = MCPServer(credentials=credentials)

    repo = {"endpoint1": _endpoint("endpoint1", "first tool"),
            "endpoint2": _endpoint("endpoint2", "second tool")}
    server.manager = Mock()
    server.manager.generate_tools_format.return_value = (repo, repo)
    server.manager.fetch_endpoints.return_value = []
    server.manager.invokeDecisionCenterApi.return_value = {"result": "endpoint_result"}

    with patch.object(SDK_MCPServer, "run") as run:
        server.start()
        run.assert_called_once()
    assert isinstance(server.server, SDK_MCPServer)
    return server


@pytest.mark.asyncio
async def test_initialize_returns_server_info_and_instructions(started_server):
    async with Client(started_server.server) as client:
        assert client.server_info.name == "ibm-odm-management-mcp-server"
        assert client.instructions


@pytest.mark.asyncio
async def test_list_tools_through_protocol(started_server):
    async with Client(started_server.server) as client:
        result = await client.list_tools()

    assert [t.name for t in result.tools] == ["endpoint1", "endpoint2"]
    assert result.tools[0].description == "first tool"
    assert result.tools[0].input_schema["properties"]["param"] == {"type": "string"}


@pytest.mark.asyncio
async def test_call_tool_through_protocol(started_server):
    async with Client(started_server.server) as client:
        # list first so the repository is populated like a real client session
        await client.list_tools()
        result = await client.call_tool("endpoint1", {"param": "value"})

    assert not result.is_error
    assert json.loads(result.content[0].text) == {"result": "endpoint_result"}
    endpoint, arguments, *_ = started_server.manager.invokeDecisionCenterApi.call_args.args
    assert endpoint is started_server.repository_dc_admin["endpoint1"]
    assert arguments == {"param": "value"}


@pytest.mark.asyncio
async def test_call_tool_failure_is_reported_as_error_result(started_server):
    started_server.manager.invokeDecisionCenterApi.side_effect = RuntimeError("boom")

    async with Client(started_server.server) as client:
        result = await client.call_tool("endpoint1", {})

    assert result.is_error
    assert "boom" in result.content[0].text


@pytest.mark.asyncio
async def test_call_unknown_tool_through_protocol(started_server):
    async with Client(started_server.server) as client:
        result = await client.call_tool("no_such_tool", {})

    assert result.is_error
    assert "Unknown tool: no_such_tool" in result.content[0].text


@pytest.mark.asyncio
async def test_list_and_read_resources_through_protocol(started_server, tmp_path):
    trace_file = tmp_path / "trace.json"
    trace_file.write_text('{"hello": "world"}')
    started_server.trace_recorder.trace_files = [str(trace_file)]

    async with Client(started_server.server) as client:
        resources = (await client.list_resources()).resources
        assert [r.name for r in resources] == ["trace.json"]

        content = await client.read_resource(str(resources[0].uri))

    assert json.loads(content.contents[0].text) == {"hello": "world"}
