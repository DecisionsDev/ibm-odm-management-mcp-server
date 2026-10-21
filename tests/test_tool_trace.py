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

import json
import os
from unittest.mock import Mock
from datetime import datetime
from decisioncenter_mcp_server.ToolTrace import DiskTraceStorage, ToolExecutionTrace


def test_tool_execution_trace_initializes_iso_timestamp():
    endpoint = Mock()
    trace = ToolExecutionTrace(
        endpoint=endpoint,
        inputs={"arg": "val"},
        http_code="200",
        results={"res": "ok"},
        user={"username": "testuser"},
    )
    assert hasattr(trace, "iso_timestamp")
    parsed_dt = datetime.fromisoformat(trace.iso_timestamp)
    assert parsed_dt.tzinfo is not None


def test_save_execution_with_content_writes_timestamp(tmp_path):
    storage = DiskTraceStorage(
        trace_executions=True,
        verbose=True,
        trace_configuration=False,
        storage_dir=str(tmp_path),
    )
    endpoint = Mock()
    endpoint.tool.name = "testTool"

    trace = ToolExecutionTrace(
        endpoint=endpoint,
        inputs={"key": "input_val"},
        http_code="200",
        results={"key": "result_val"},
        user={"username": "odmadmin"},
    )

    storage.save(trace)

    assert len(storage.trace_files) == 1
    trace_file_path = storage.trace_files[0]
    assert os.path.exists(trace_file_path)

    with open(trace_file_path, "r") as f:
        data = json.load(f)

    assert "timestamp" in data
    assert data["timestamp"] == trace.iso_timestamp
    parsed_dt = datetime.fromisoformat(data["timestamp"])
    assert parsed_dt.tzinfo is not None
    assert data["inputs"] == {"key": "input_val"}
    assert data["results"] == {"key": "result_val"}
    assert data["user"] == {"username": "odmadmin"}


def test_save_execution_disabled_writes_nothing(tmp_path):
    storage = DiskTraceStorage(
        trace_executions=False,
        verbose=False,
        trace_configuration=False,
        storage_dir=str(tmp_path),
    )
    endpoint = Mock()
    endpoint.tool.name = "testTool"

    storage.save(ToolExecutionTrace(endpoint=endpoint, inputs={}, http_code="200", results={}))

    assert storage.trace_files == []
    assert list(tmp_path.glob("*.json")) == []


def test_save_execution_without_content_does_not_write_timestamp(tmp_path):
    storage = DiskTraceStorage(
        trace_executions=True,
        verbose=False,
        trace_configuration=False,
        storage_dir=str(tmp_path),
    )
    endpoint = Mock()
    endpoint.tool.name = "testTool"

    trace = ToolExecutionTrace(
        endpoint=endpoint,
        inputs={"key": "input_val"},
        http_code="200",
        results={"key": "result_val"},
    )

    storage.save(trace)

    assert len(storage.trace_files) == 1
    trace_file_path = storage.trace_files[0]
    assert os.path.exists(trace_file_path)

    # In non-verbose mode (EXECUTIONS), file is empty
    with open(trace_file_path, "r") as f:
        content = f.read()
    assert content == ""


def test_save_execution_fallback_timestamp_when_no_iso_timestamp(tmp_path):
    storage = DiskTraceStorage(
        trace_executions=True,
        verbose=True,
        trace_configuration=False,
        storage_dir=str(tmp_path),
    )
    endpoint = Mock()
    endpoint.tool.name = "testTool"

    trace = ToolExecutionTrace(
        endpoint=endpoint,
        inputs={"key": "input_val"},
        http_code="200",
        results={"key": "result_val"},
    )
    # Simulate a trace object without iso_timestamp attribute
    delattr(trace, "iso_timestamp")

    storage.save(trace)

    assert len(storage.trace_files) == 1
    trace_file_path = storage.trace_files[0]
    with open(trace_file_path, "r") as f:
        data = json.load(f)

    assert "timestamp" in data
    parsed_dt = datetime.fromisoformat(data["timestamp"])
    assert parsed_dt.tzinfo is not None


def test_tool_execution_trace_hex_and_iso_timestamp_consistency():
    endpoint = Mock()
    trace = ToolExecutionTrace(
        endpoint=endpoint,
        inputs={},
        http_code="200",
        results={},
    )
    # Hex timestamp should equal the integer second timestamp of iso_timestamp
    iso_dt = datetime.fromisoformat(trace.iso_timestamp)
    expected_hex = f"{int(iso_dt.timestamp()):x}"
    assert trace.timestamp == expected_hex
