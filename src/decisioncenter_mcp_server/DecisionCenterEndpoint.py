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

import mcp.types as types
class DecisionCenterEndpoint:
    """
    This class encapsulates the metadata and tool description for a Decision Center REST API uri.
    Attributes:
        method (str): GET, PUT,...
        url    (str):  full URL of a Decision Center REST API eg. https://myhost/decisioncenter-api/v1/about
        parameters (dict): list of the parameters expected with their location in the request (path, query or body)
        tool   (types.Tool): An object describing the tool, including its name, description, and input schema.

    Args:
        tool_name (str): The name of the tool.
        summary (string): 
        description (string): 
        method (string): 
        url (string): 
        parameters (dict): list of the parameters expected with their location in the request (path, query or body)
        input_schema (dict): The schema describing the expected input for the tool.
    """
    def __init__(self, tool_name:str, summary:str, description:str, method:str, url:str, parameters:dict, input_schema:dict[str,str], headers:list=[]):
        if description is None:
            description=summary
        self.method = method
        self.url    = url
        self.parameters = parameters
        self.headers = headers
        self.tool   = types.Tool(
            name=tool_name,
            title=summary,
            description=description,
            inputSchema=input_schema,
        )

   