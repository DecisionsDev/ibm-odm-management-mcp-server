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
import time
from .DecisionCenterEndpoint import DecisionCenterEndpoint
            
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
    ):
        """
        Initialize a new ToolExecutionTrace.
        """
        self.endpoint = endpoint
        self.http_code = http_code
        self.inputs = inputs
        self.results = results
        self.timestamp = f"{int(time.time()):x}"

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
        if 'parsing.json' in self.trace_files:
            self.trace_files.remove('parsing.json')
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

        # Make sure the storage directory still exists
        self._exists_storage_dir()

        if self.trace_configuration:
            with open(os.path.join(self.storage_dir, "parsing.json"), 'w') as f:
                f.write(json.dumps(to_dict(repository), indent=2))

    def saveExecution(self, trace: ToolExecutionTrace):
        """
        save a trace to storage.
        If the number of traces exceeds max_traces, the oldest traces will be removed.
        
        Args:
            trace: The ToolExecutionTrace to save
            
        Returns:
            str: The ID of the saved trace
        """
        def write(f, data):
            if data is not None:
                if isinstance(data, bytes):
                    f.write(bytes(data, 'utf-8'))
                elif isinstance(data, str):
                    try:
                        d = json.loads(data)
                        f.write(json.dumps(d, indent=2))
                    except json.JSONDecodeError:
                        f.write(data)
                else:
                    f.write(json.dumps(data, indent=2))
        
        # Make sure the storage directory still exists
        self._exists_storage_dir()

        # Save the trace to disk
        file_path = os.path.join(self.storage_dir, f"{trace.endpoint.tool.name}-{trace.http_code}-{trace.timestamp}.json")
        with open(file_path, 'w') as f:
            if self.verbose:
                write(f, trace.inputs)
                write(f, '\n')
                write(f, trace.results)
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
