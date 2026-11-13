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

from typing import Dict, Any, Optional
import json
import os
import glob
import logging
from enum import Enum
from datetime import datetime, timezone
from .DecisionCenterEndpoint import DecisionCenterEndpoint
from mcp_types import Resource

class ToolExecutionTrace:
    """
    Class to store details about a tool execution or configuration
    Captures all relevant information for tracing and debugging purposes.
    """
    
    def __init__(
        self,
        endpoint: str,
        inputs: Dict[str, Any],
        http_code: str,
        results: Any,
        user: Optional[Dict[str, Any]] = None,
    ):
        """
        Initialize a new ToolExecutionTrace.
        """
        self.endpoint = endpoint
        self.http_code = http_code
        self.inputs = inputs
        self.results = results
        self.user = user
        now = datetime.now(timezone.utc)
        self.timestamp = f"{int(now.timestamp()):x}"
        self.iso_timestamp = now.isoformat()

class Access(Enum):
    GRANTED = 1
    REJECTED = 2
    NEED_USER_DETAILS = 3

    def granted(self):
        return self == Access.GRANTED

    def rejected(self):
        return self == Access.REJECTED

    def user_details_needed(self):
        return self == Access.NEED_USER_DETAILS

class ToolExecutionAccess:
    """
    Class to assess if a user should have access to a tool execution
    """
    
    def __init__(
        self,
        dcAdmin: Optional[bool] = None,
        resDeployer: Optional[bool] = None,
        user_details: Optional[Dict[str, Any]] = None,
        full_access: Optional[bool] = None,
    ):
        """
        Initialize a new ToolExecutionAccess.
        """
        self.dcAdmin = dcAdmin
        self.resDeployer = resDeployer
        self.user_details = user_details
        self.full_access = full_access

    def toolExecutionAccess(self, tool:str|None, user_details_or_subject:Optional[Dict[str,Any]|str] = None) -> Access:
        if self.full_access:
            return Access.GRANTED

        from .DecisionCenterManager import DecisionCenterManager
        if self.dcAdmin and tool in DecisionCenterManager.dc_tools:
            return Access.GRANTED
        if self.resDeployer and tool in DecisionCenterManager.res_tools:
            return Access.GRANTED

        if user_details_or_subject is None:
            return Access.NEED_USER_DETAILS

        if isinstance(user_details_or_subject, dict):
            subject = subject_from_dict(user_details_or_subject)
        else:
            subject = subject_from_str(user_details_or_subject)

        my_subject = subject_from_dict(self.user_details)
        return Access.GRANTED if (my_subject and my_subject == subject) \
          else Access.REJECTED

class DiskTraceStorage:
    """
    A storage mechanism for ToolExecutionTrace objects that saves them to disk.
    Maintains a limited number of traces by removing the oldest ones when limit is reached.
    """
    
    def __init__(self, trace_executions: bool, verbose: bool, trace_configuration: bool,
                 storage_dir: Optional[str] = None, max_traces: int = 200):
        """
        Initialize the disk-based trace storage.
        
        Args:
            storage_dir: Directory to store traces (defaults to ~/.ibm-odm-management-mcp-server/traces)
            max_traces: Maximum number of traces to keep (defaults to 200)
        """
        if storage_dir is None:
            home_dir    = os.path.expanduser("~")
            storage_dir = os.path.join(home_dir, ".ibm-odm-management-mcp-server", "traces")
        
        self.storage_dir         = storage_dir
        self.max_traces          = max_traces
        self.logger              = logging.getLogger(__name__)
        self.trace_executions    = trace_executions
        self.verbose             = verbose
        self.trace_configuration = trace_configuration
        self.configuration_size_saved = 0

        if trace_executions or trace_configuration:
            self.logger.info("Tracing is enabled")

        if self._exists_storage_dir():
            self._init_trace_files()
    
    def _exists_storage_dir(self):
        if not os.path.isdir(self.storage_dir):
            os.makedirs(self.storage_dir, exist_ok=True)
            self.trace_files = []
            return False
        return True
        
    def _init_trace_files(self):
        # Initialize an in-memory index of available traces
        self.trace_files = list(filter(os.path.isfile, glob.glob(os.path.join(self.storage_dir, "*.json"))))
        i = 0
        while i < len(self.trace_files):
            trace_file = self.trace_files[i]
            filename = os.path.basename(trace_file)
            tool, http_code, timestamp, subject = self.parse_trace_filename(filename)
            if not tool:
                del self.trace_files[i]
            else:
                i += 1
        self.trace_files.sort(key=lambda x: os.path.getctime(x))   # sort by creation time (from the oldest to the newest)

    def save(self, arg):
        if isinstance(arg, ToolExecutionTrace): self.saveExecution(arg)
        else:                                   self.saveConfiguration(arg)

    def saveConfiguration(self, repository: dict[str, DecisionCenterEndpoint]):
        """
        save the tools configuration to storage.
        """
        def to_dict(obj):
            if hasattr(obj, "__dict__"):
                return to_dict(vars(obj))
            if isinstance(obj, dict):
                return dict([(k, to_dict(v)) for k, v in obj.items()])
            if isinstance(obj, list):
                return [to_dict(el) for el in obj]
            return obj  # Default for primitive types

        if not self.trace_configuration:
            # not configured to save configuration/list of tools
            return
        
        dict_repository = to_dict(repository)
        len_repository = len(dict_repository)
        if len_repository <= self.configuration_size_saved:
            # already saved
            return
        
        if self._exists_storage_dir():
            self.configuration_size_saved = len_repository
            with open(os.path.join(self.storage_dir, "parsing.json"), 'w') as f:
                f.write(json.dumps(dict_repository, indent=2))

    def saveExecution(self, trace: ToolExecutionTrace):
        """
        save a trace to storage.
        If the number of traces exceeds max_traces, the oldest traces will be removed.
        
        Args:
            trace: The ToolExecutionTrace to save
            
        Returns:
            str: The ID of the saved trace
        """
        def convert(data):
            if data is None:
                return ""
            elif isinstance(data, dict):
                return data
            elif isinstance(data, (bytes, bytearray)):
                return data.decode("utf-8", errors="replace")
            else:
                if not isinstance(data, str):
                    data = str(data)
                try:
                    return json.loads(data)
                except json.JSONDecodeError:
                    return data
        
        if not self.trace_executions:
            # not configured to save executions
            return

        # Make sure the storage directory still exists
        self._exists_storage_dir()

        # Save the trace to disk
        user_sub = subject_from_dict(trace.user)
        filename = f"{trace.endpoint.tool.name}-{trace.http_code}-{trace.timestamp}{f'-{user_sub}' if user_sub else ''}.json"
        file_path = os.path.join(self.storage_dir, filename)
        with open(file_path, 'w') as f:
            if self.verbose:
                traces = {
                    "timestamp": getattr(trace, "iso_timestamp", datetime.now(timezone.utc).isoformat()),
                    "inputs":  convert(trace.inputs),
                    "results": convert(trace.results)
                }
                if trace.user:
                    traces["user"] = convert(trace.user)
                json.dump(traces, f, indent=2)
            self.logger.debug(f"Saved traces file {file_path}")
        
        # Enforce the maximum number of traces
        self._enforce_max_traces(file_path)
    
    def _enforce_max_traces(self, file_path:str = None):
        """Remove oldest created traces file if the number exceeds max_traces."""
        if file_path:
            self.trace_files.append(file_path)

        while len(self.trace_files) > self.max_traces:
            file2remove_path = self.trace_files.pop(0)
            try:
                os.remove(file2remove_path)
                self.logger.debug(f"Removed traces file {file2remove_path}")
            except Exception as e:
                self.logger.warning(f"Error removing traces file {file2remove_path}: {e}")

    def parse_trace_filename(self, filename: str):
        tool = http_code = timestamp = subject = None
        # Expected filename format: {tool_name}-{http_code}-{timestamp}[-{subject}].json
        parts = filename.rsplit('.', maxsplit=1)[0].rsplit('-', maxsplit=3)
        l = len(parts)
        if l >= 3 and l <=4:
            if   l == 3:  tool, http_code, timestamp          = parts
            elif l == 4:  tool, http_code, timestamp, subject = parts

            # check HTTP code is decimal
            if not http_code or not http_code.isdigit():
                return None, None, None, None

            # check timestamp is hexadecimal
            try:
                int(timestamp, 16)
            except:
                return None, None, None, None

        return tool, http_code, timestamp, subject

    def get_executions(self, policy:ToolExecutionAccess, filter: Optional[str] = None, with_content: Optional[bool] = False, output:Optional[type[Resource]|type[dict]] = dict) -> list:
        """
        Get the list of saved tool executions, optionally filtered by tool name.
        
        Args:
            filter: Optional string to filter executions by tool name (matches if tool name contains the filter string)
            with_content: Whether to include the inputs and results content in the returned executions
        """
        def timestamp_to_date(timestamp:str|None):
            if timestamp:
                try:  # convert hex timestamp
                    return str(datetime.fromtimestamp(int(timestamp, 16)))
                except Exception as e:
                    self.logger.debug(f"Error converting timestamp {timestamp}: {e}")
            return timestamp

        executions = []
        for trace_file in self.trace_files:
            filename = os.path.basename(trace_file)
            if filter and filter not in filename:
                continue
            tool, http_code, timestamp, subject = self.parse_trace_filename(filename)
            if not tool:
                continue
            access = policy.toolExecutionAccess(tool,subject)
            if access.rejected():
                continue
            if output == dict:
                execution_info = {
                    "trace_file":filename,
                    "tool":      tool,
                    "http_code": http_code,
                    "date":      timestamp_to_date(timestamp)
                }
            if with_content or access.user_details_needed():
                try:
                    with open(trace_file, 'r') as f:
                        trace_data = json.load(f)
                    if not policy.toolExecutionAccess(tool,trace_data.get("user")).granted():
                        continue
                    if with_content and output == dict:
                        if "user" in trace_data:
                            execution_info["user"] = trace_data["user"]
                        execution_info["inputs"]  = trace_data.get("inputs", {})
                        execution_info["results"] = trace_data.get("results", {})
                except Exception as e:
                    self.logger.debug(f"Error reading trace file {trace_file}: {e}")
                    if access.user_details_needed():
                        continue
            if output == Resource:
                execution_info = Resource(name=filename, uri=f'file://{trace_file}')
            executions.append(execution_info)
        return executions

def subject_from_str(subject:Optional[str] = None) -> str:
    return subject.replace('-','_') if subject else ""

def subject_from_dict(user_details:Optional[dict[str,Any]] = None) -> str:
    return subject_from_str(user_details.get("subject")) if isinstance(user_details, dict) else ""
