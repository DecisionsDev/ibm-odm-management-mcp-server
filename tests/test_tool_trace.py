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
import pytest
from unittest.mock import Mock
from datetime import datetime
from decisioncenter_mcp_server.ToolTrace import Access, DiskTraceStorage, ToolExecutionAccess, ToolExecutionTrace


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


# ---------------------------------------------------------------------------
# Access / ToolExecutionAccess
# ---------------------------------------------------------------------------

def test_access_enum_helpers():
    assert Access.GRANTED.granted() and not Access.GRANTED.rejected()
    assert Access.REJECTED.rejected() and not Access.REJECTED.granted()
    assert Access.NEED_USER_DETAILS.user_details_needed()
    assert not Access.GRANTED.user_details_needed()


def test_access_full_access_grants_everything():
    policy = ToolExecutionAccess(full_access=True)
    assert policy.toolExecutionAccess("branches").granted()
    assert policy.toolExecutionAccess("getRuleApps").granted()
    assert policy.toolExecutionAccess("unknownTool").granted()


def test_access_dc_admin_granted_on_dc_tool_only():
    policy = ToolExecutionAccess(dcAdmin=True, resDeployer=False, user_details={"subject": "u1"})
    assert policy.toolExecutionAccess("branches").granted()
    # RES tool: not a deployer, so ownership of the trace must be checked
    assert policy.toolExecutionAccess("getRuleApps").user_details_needed()


def test_access_res_deployer_granted_on_res_tool_only():
    policy = ToolExecutionAccess(dcAdmin=False, resDeployer=True, user_details={"subject": "u1"})
    assert policy.toolExecutionAccess("getRuleApps").granted()
    assert policy.toolExecutionAccess("branches").user_details_needed()


def test_access_non_admin_requires_matching_user_details():
    policy = ToolExecutionAccess(dcAdmin=False, resDeployer=False, user_details={"subject": "u1"})
    assert policy.toolExecutionAccess("branches").user_details_needed()
    assert policy.toolExecutionAccess("branches", {"subject": "u1"}).granted()
    assert policy.toolExecutionAccess("branches", {"subject": "u2"}).rejected()


# ---------------------------------------------------------------------------
# DiskTraceStorage.get_executions
# ---------------------------------------------------------------------------

def _save_trace(storage, tool_name, user=None, http_code="200"):
    endpoint = Mock()
    endpoint.tool.name = tool_name
    storage.save(ToolExecutionTrace(endpoint=endpoint, inputs={"in": tool_name}, http_code=http_code,
                                    results={"out": tool_name}, user=user))


@pytest.fixture
def storage(tmp_path):
    return DiskTraceStorage(trace_executions=True, verbose=True, trace_configuration=False,
                            storage_dir=str(tmp_path))


def test_get_executions_full_access_returns_all_with_tool_name(storage):
    _save_trace(storage, "branches")
    _save_trace(storage, "getRuleApps")

    executions = storage.get_executions(policy=ToolExecutionAccess(full_access=True))

    assert sorted(e["tool"] for e in executions) == ["branches", "getRuleApps"]
    assert all(e["http_code"] == "200" for e in executions)
    assert all("inputs" not in e for e in executions)


def test_get_executions_with_content(storage):
    _save_trace(storage, "branches", user={"subject": "u1"})

    executions = storage.get_executions(policy=ToolExecutionAccess(full_access=True), with_content=True)

    assert len(executions) == 1
    assert executions[0]["inputs"] == {"in": "branches"}
    assert executions[0]["results"] == {"out": "branches"}
    assert executions[0]["user"] == {"subject": "u1"}


def test_get_executions_filter(storage):
    _save_trace(storage, "branches")
    _save_trace(storage, "getRuleApps")

    executions = storage.get_executions(policy=ToolExecutionAccess(full_access=True), filter="getRuleApps")

    assert [e["tool"] for e in executions] == ["getRuleApps"]


def test_get_executions_skips_unknown_tools_without_full_access(storage):
    _save_trace(storage, "unknownTool")
    _save_trace(storage, "branches")

    policy = ToolExecutionAccess(dcAdmin=True, resDeployer=False, user_details={"subject": "u1"})
    executions = storage.get_executions(policy=policy)

    assert [e["tool"] for e in executions] == ["branches"]


def test_get_executions_restricts_non_admin_to_own_traces(storage):
    _save_trace(storage, "branches", user={"subject": "u1"})
    _save_trace(storage, "rules", user={"subject": "u2"})

    policy = ToolExecutionAccess(dcAdmin=False, resDeployer=False, user_details={"subject": "u1"})
    executions = storage.get_executions(policy=policy, with_content=True)

    assert [e["tool"] for e in executions] == ["branches"]
    assert executions[0]["user"] == {"subject": "u1"}


def test_get_executions_non_admin_without_content_does_not_leak_content(storage):
    _save_trace(storage, "branches", user={"subject": "u1"})

    policy = ToolExecutionAccess(dcAdmin=False, resDeployer=False, user_details={"subject": "u1"})
    executions = storage.get_executions(policy=policy)

    assert len(executions) == 1
    assert "inputs" not in executions[0] and "results" not in executions[0]


def test_get_executions_dc_admin_sees_dc_tools_of_all_users_but_not_res_of_others(storage):
    _save_trace(storage, "branches", user={"subject": "u2"})
    _save_trace(storage, "getRuleApps", user={"subject": "u2"})

    policy = ToolExecutionAccess(dcAdmin=True, resDeployer=False, user_details={"subject": "u1"})
    executions = storage.get_executions(policy=policy)

    assert [e["tool"] for e in executions] == ["branches"]
