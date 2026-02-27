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
from unittest.mock import Mock, patch, MagicMock
from decisioncenter_mcp_server.DecisionCenterManager import DecisionCenterManager
from decisioncenter_mcp_server.DecisionCenterEndpoint import DecisionCenterEndpoint
from http.server import BaseHTTPRequestHandler, HTTPServer
from decisioncenter_mcp_server.Credentials import Credentials
import json
import threading
import os
import tempfile
import base64

class MockServerRequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/decisioncenter-api/v1/endpoint':
            self.send_response(200)
            self.end_headers()
            mock_data = {"status": "ok"}
            self.wfile.write(json.dumps(mock_data).encode('utf-8'))
        else:
            self.send_response(404)
            self.end_headers()

def run_mock_server(server_class=HTTPServer, handler_class=MockServerRequestHandler, port=8885):
    server_address = ('', port)
    httpd = server_class(server_address, handler_class)
    httpd.serve_forever()

@pytest.fixture(scope='module', autouse=True)
def mock_server():
    # Start the mock server in a separate thread
    mock_server_thread = threading.Thread(target=run_mock_server)
    mock_server_thread.daemon = True
    mock_server_thread.start()
    yield
    # Cleanup code can be added here if needed

class Parameter:
    def __init__(self, name:str, type:str, location:str, required:bool, description:str|None=None, enum:list[str]|None=None, format:str|None=None):
        self.name = name
        self.type = type
        self.location = location
        self.required = required
        self.enum = enum
        self.format = format
        self.description = description

# Locate the folder where the script is stored
base_dir = os.path.dirname(os.path.abspath(__file__))
@pytest.fixture
def openapi9501_filepath():
    # Combine folder path with the target file name
    return os.path.join(base_dir, 'openapi-9501.json')

@pytest.mark.parametrize("tags, expected_tools_total", [
    (["explore","govern"],  60), # 33 + 27
    (["admin",  "dbadmin"], 48), # 31 + 17
    (["manage", "build"],   23), # 17 + 6
])
def test_dc_tools_tags_filtering(tags, expected_tools_total, openapi9501_filepath):
    manager = DecisionCenterManager(credentials=Credentials(odm_url='http://localhost:8885/decisioncenter-api', username='mock_user', password='mock_password'))
    endpoints  = manager._fetch_endpoints(openapi9501_filepath)
    repository = manager.generate_tools_format(endpoints, tags, isDcAdmin=True)

    # verify tools were filtered by tags
    assert len(repository) == expected_tools_total

@pytest.fixture
def wadl9501_filepath():
    # Combine folder path with the target file name
    return os.path.join(base_dir, 'DecisionServer-9501.wadl')

@pytest.mark.parametrize("tags, expected_tools_total", [
    (["ruleapps","rulesets"], 42), # 40 + 2
    (["libraries",  "xoms"],  21), # 10 + 11
    (["decisiontraces", "executionunits", "utilities"], 15), # 6 + 5 + 4
])
def test_res_tools_tags_filtering(tags, expected_tools_total, wadl9501_filepath):
    manager = DecisionCenterManager(credentials=Credentials(odm_res_url='http://localhost:8885/res', username='mock_user', password='mock_password'))
    wadl  = manager._fetch_res_api_endpoints(wadl9501_filepath)
    repository = manager.generate_res_tools(wadl, tools={}, tags_to_publish=tags, tools_to_publish=[], tools_to_ignore=[], isResDeployer=True)

    # verify tools were filtered by tags
    assert len(repository) == expected_tools_total

@pytest.mark.parametrize("tags, tools, no_tools, expected_tools_total", [
    (["explore"], ["addserver", "importdt"], [],                                             35),   # publish all the tools of the 'explore' tag/category (33 in total) plus 2 from the 'manage' category
    ([],          [],                        ["launchcleanup", "wipe", "executesqlscript"], 130),   # publish all but the 3 ignored
    ([],          [],                        [],                                            133),   # publish all the tools
])
def test_tools_filtering(tags, tools, no_tools, expected_tools_total, openapi9501_filepath):
    manager = DecisionCenterManager(credentials=Credentials(odm_url='http://localhost:8885/decisioncenter-api', username='mock_user', password='mock_password'))
    endpoints  = manager._fetch_endpoints(openapi9501_filepath)
    repository = manager.generate_tools_format(endpoints, tags_to_publish=tags, tools_to_publish=tools, tools_to_ignore=no_tools, isDcAdmin=True)

    # verify tools were filtered by explicit list of tools to publish or discard
    assert len(repository) == expected_tools_total

@pytest.mark.parametrize("openapi_file, expected_tools_total", [
    (os.path.join(base_dir, 'openapi-9501.json'),  133),
    (os.path.join(base_dir, 'openapi-9001.json'),  128),
    (os.path.join(base_dir, 'openapi-81201.json'), 112),
])
def test_generate_tools_format(openapi_file, expected_tools_total):
    odm_url = 'http://localhost:8885/decisioncenter-api'

    manager = DecisionCenterManager(credentials=Credentials(odm_url=odm_url, username='mock_user', password='mock_password'))
    endpoints  = manager._fetch_endpoints(openapi_file)
    repository = manager.generate_tools_format(endpoints, isDcAdmin=True)

    # verify all tools were generated
    assert len(repository) == expected_tools_total

    def check_endpoint(tool_name:str, method:str, url:str, summary:str, parameters:list[Parameter]):
        endpoint = repository[tool_name]
        assert endpoint
        assert endpoint.method  == method
        assert endpoint.url     == odm_url + url
        assert len(endpoint.parameters) == len(parameters), print(repr(endpoint.parameters))

        assert endpoint.tool
        assert endpoint.tool.name  == tool_name
        assert endpoint.tool.title == summary
        assert len(endpoint.tool.inputSchema['properties']) == len(parameters), print(repr(endpoint.tool.inputSchema['properties']))

        for expected_param in parameters:
            actual_parameter = endpoint.parameters.get(expected_param.name)
            assert actual_parameter,                                        print(actual_parameter, expected_param.name, repr(endpoint.parameters))
            assert actual_parameter['in'] == expected_param.location,       print(repr(endpoint.parameters.get(expected_param.name)))
            assert actual_parameter.get('format') == expected_param.format, print(repr(endpoint.parameters.get(expected_param.name)))

            actual_prop = endpoint.tool.inputSchema['properties'][expected_param.name]
            assert actual_prop
            assert actual_prop['type'] == expected_param.type,                      print(expected_param.name, repr(actual_prop))
            assert actual_prop.get('enum') == expected_param.enum,                  print(expected_param.name, repr(actual_prop))
            assert actual_prop.get('description') == expected_param.description,    print(expected_param.name, repr(actual_prop))
            assert (expected_param.name in endpoint.tool.inputSchema['required']) == expected_param.required

    # check a representative subset of tools
    check_endpoint('registerWebhook', 
                   'PUT',
                   '/v1/webhook/notify',
                   'Register a webhook to notify other applications of events that are coming from Decision Center',
                   [
                       Parameter('url',        'string', 'query',      True, "The URL of the server to send notifications"),
                       Parameter('datasource', 'string', 'query',     False, "The JNDI name of the Decision Center data source. If not specified, it defaults to jdbc/ilogDataSource"),
                       Parameter('body',       'string', 'body/json', False, "The authentication token of the remote server"),
                    ]
                   )
    check_endpoint('rejectRelease', 
                   'POST',
                   '/v1/releases/{releaseId}/reject',
                   'Reject the open release of a decision service',
                   [
                       Parameter('releaseId',  'string', 'path',        True, None),
                       Parameter('userName',   'string', 'query',      False, "the name of the user on behalf of whom rejecting the release."),
                       Parameter('datasource', 'string', 'query',      False, "The JNDI name of the Decision Center data source. If not specified, it defaults to jdbc/ilogDataSource"),
                       Parameter('body',       'string', 'body/plain', False, "the rejection comment."),
                    ]
                   )
    check_endpoint('updateServer', 
                   'POST',
                   '/v1/servers/{serverId}',
                   'Update a target server to use for deployments, simulations, and tests',
                   [
                       Parameter('serverId',              'string', 'path',       True, "The ID of the server"),
                       Parameter('datasource',            'string', 'query',     False, "The JNDI name of the Decision Center data source. If not specified, it defaults to jdbc/ilogDataSource"),
                   ] + \
                  ([] if openapi_file.endswith('openapi-81201.json') else \
                   [
                       Parameter('createdBy',             'string', 'body/json', False),
                       Parameter('createdOn',             'string', 'body/json', False, format="date-time"),
                       Parameter('lastchangedBy',         'string', 'body/json', False),
                       Parameter('lastChangedOn',         'string', 'body/json', False, format="date-time"),
                   ]) + \
                   [
                       Parameter('url',                   'string', 'body/json', False, "The URL of the server"),
                       Parameter('description',           'string', 'body/json', False, "The description of the server"),
                       Parameter('loginServer',           'string', 'body/json', False, "The name of the user allowed to access the server"),
                       Parameter('loginPassword',         'string', 'body/json', False, "The password of the user allowed to access the server"),
                       Parameter('authenticationKind',    'string', 'body/json', False, enum=['BASIC_AUTH', 'OAUTH'], description="The type of authentication used by the server"),
                       Parameter('authenticationProvider','string', 'body/json', False, "The name of the authentication provider to use (for OAUTH authentication kind)"),
                       Parameter('groups',                'array',  'body/json', False, "A list of groups allowed to use this server. A list with the single element * means all groups are allowed to use this server"),
                    ]
                   )
    check_endpoint('branchImport', 
                   'POST',
                   '/v1/decisionservices/{decisionServiceId}/import',
                   'Import a decision service on top of an existing branch',
                   [
                       Parameter('decisionServiceId',  'string', 'path',        True, "ID of the target decision service"),
                       Parameter('override',          'boolean', 'query',      False, "Override all the artifacts that have the same ID in the database"),
                       Parameter('baselineId',         'string', 'query',      False, "ID of the target branch, activity, or release. If none is specified, it defaults to the 'main' branch."),
                       Parameter('datasource',         'string', 'query',      False, "The JNDI name of the Decision Center data source. If not specified, it defaults to jdbc/ilogDataSource"),
                       Parameter('file',               'string', 'body/form',   True, format="binary", description="Compressed file that contains the decision service to import"),
                    ]
                   )

# Tests for invokeDecisionCenterApi function
class TestInvokeDecisionCenterApi:
   """Test suite for the invokeDecisionCenterApi function"""

   @pytest.fixture
   def mock_credentials(self):
       """Create mock credentials for testing"""
       creds = Mock(spec=Credentials)
       creds.odm_url = 'http://localhost:8885/decisioncenter-api'
       creds.cacert = None
       mock_session = Mock()
       mock_session.headers = {'Authorization': 'Bearer test_token'}
       creds.get_session.return_value = mock_session
       creds.cleanup = Mock()
       return creds

   @pytest.fixture
   def manager(self, mock_credentials):
       """Create a DecisionCenterManager instance with mock credentials"""
       return DecisionCenterManager(credentials=mock_credentials)

   @pytest.fixture
   def sample_endpoint(self):
       """Create a sample endpoint for testing"""
       input_schema: dict[str, str | dict[str, dict[str, str]] | list[str]] = {
           'type': 'object',
           'properties': {
               'testId': {'type': 'string'},
               'datasource': {'type': 'string'},
               'filter': {'type': 'string'},
               'name': {'type': 'string'},
               'description': {'type': 'string'},
               'file': {'type': 'string'},
               'comment': {'type': 'string'}
           },
           'required': ['testId']
       }
       return DecisionCenterEndpoint(
           tool_name='testEndpoint',
           summary='Test endpoint',
           description='A test endpoint for unit testing',
           method='GET',
           url='http://localhost:8885/decisioncenter-api/v1/test/{testId}',
           parameters={
               'testId': {'in': 'path'},
               'datasource': {'in': 'query'},
               'filter': {'in': 'query'},
               'name': {'in': 'body/json'},
               'description': {'in': 'body/json'},
               'file': {'in': 'body/form', 'format': 'binary'},
               'comment': {'in': 'body/plain'}
           },
           input_schema=input_schema  # type: ignore
       )

   def test_invoke_with_path_parameter(self, manager, sample_endpoint, mock_credentials):
       """Test invoking API with path parameter replacement"""
       mock_session = mock_credentials.get_session.return_value
       mock_response = Mock()
       mock_response.status_code = 200
       mock_response.headers = {'Content-Type': 'application/json'}
       mock_response.json.return_value = {'status': 'success'}
       mock_session.request.return_value = mock_response

       arguments = {'testId': '12345'}
       result = manager.invokeDecisionCenterApi(sample_endpoint, arguments, run_locally=True)

       # Verify path parameter was replaced in URL
       call_args = mock_session.request.call_args
       assert 'v1/test/12345' in call_args[1]['url']
       assert result == {'status': 'success'}

   def test_invoke_with_missing_required_path_parameter(self, manager, sample_endpoint):
       """Test that missing required path parameter raises ValueError"""
       arguments = {}  # Missing required 'testId'
       
       with pytest.raises(ValueError, match='Missing argument testId'):
           manager.invokeDecisionCenterApi(sample_endpoint, arguments, run_locally=True)

   def test_invoke_with_query_parameters(self, manager, sample_endpoint, mock_credentials):
       """Test invoking API with query parameters"""
       mock_session = mock_credentials.get_session.return_value
       mock_response = Mock()
       mock_response.status_code = 200
       mock_response.headers = {'Content-Type': 'application/json'}
       mock_response.json.return_value = {'data': 'test'}
       mock_session.request.return_value = mock_response

       arguments = {
           'testId': '12345',
           'datasource': 'jdbc/testDB',
           'filter': 'active'
       }
       result = manager.invokeDecisionCenterApi(sample_endpoint, arguments, run_locally=True)

       # Verify query parameters were passed correctly
       call_args = mock_session.request.call_args
       assert call_args[1]['params'] == {'datasource': 'jdbc/testDB', 'filter': 'active'}
       assert result == {'data': 'test'}

   def test_invoke_with_json_body_parameters(self, manager, sample_endpoint, mock_credentials):
       """Test invoking API with JSON body parameters"""
       mock_session = mock_credentials.get_session.return_value
       mock_response = Mock()
       mock_response.status_code = 200
       mock_response.headers = {'Content-Type': 'application/json'}
       mock_response.json.return_value = {'created': True}
       mock_session.request.return_value = mock_response

       arguments = {
           'testId': '12345',
           'name': 'Test Name',
           'description': 'Test Description'
       }
       result = manager.invokeDecisionCenterApi(sample_endpoint, arguments, run_locally=True)

       # Verify JSON body parameters were passed correctly
       call_args = mock_session.request.call_args
       assert call_args[1]['json'] == {'name': 'Test Name', 'description': 'Test Description'}
       assert result == {'created': True}

   def test_invoke_with_plain_text_body(self, manager, sample_endpoint, mock_credentials):
       """Test invoking API with plain text body"""
       mock_session = mock_credentials.get_session.return_value
       mock_response = Mock()
       mock_response.status_code = 200
       mock_response.headers = {'Content-Type': 'application/json'}
       mock_response.json.return_value = {'updated': True}
       mock_session.request.return_value = mock_response

       arguments = {
           'testId': '12345',
           'comment': 'This is a plain text comment'
       }
       result = manager.invokeDecisionCenterApi(sample_endpoint, arguments, run_locally=True)

       # Verify plain text data was passed correctly
       call_args = mock_session.request.call_args
       assert call_args[1]['data'] == 'This is a plain text comment'
       assert result == {'updated': True}

   def test_invoke_with_file_upload(self, manager, sample_endpoint, mock_credentials):
       """Test invoking API with file upload"""
       mock_session = mock_credentials.get_session.return_value
       mock_response = Mock()
       mock_response.status_code = 200
       mock_response.headers = {'Content-Type': 'application/json'}
       mock_response.json.return_value = {'uploaded': True}
       mock_session.request.return_value = mock_response

       # Create a temporary file for testing
       with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as tmp_file:
           tmp_file.write('test content')
           tmp_file_path = tmp_file.name

       try:
           arguments = {
               'testId': '12345',
               'file': tmp_file_path
           }
           result = manager.invokeDecisionCenterApi(sample_endpoint, arguments, run_locally=True)

           # Verify file was opened and passed correctly
           call_args = mock_session.request.call_args
           assert 'file' in call_args[1]['files']
           assert result == {'uploaded': True}
       finally:
           # Cleanup temporary file
           os.unlink(tmp_file_path)

   def test_invoke_response_json(self, manager, sample_endpoint, mock_credentials):
       """Test handling JSON response"""
       mock_session = mock_credentials.get_session.return_value
       mock_response = Mock()
       mock_response.status_code = 200
       mock_response.headers = {'Content-Type': 'application/json'}
       mock_response.json.return_value = {'key': 'value', 'number': 42}
       mock_session.request.return_value = mock_response

       arguments = {'testId': '12345'}
       result = manager.invokeDecisionCenterApi(sample_endpoint, arguments, run_locally=True)

       assert result == {'key': 'value', 'number': 42}

   def test_invoke_response_text(self, manager, sample_endpoint, mock_credentials):
       """Test handling plain text response"""
       mock_session = mock_credentials.get_session.return_value
       mock_response = Mock()
       mock_response.status_code = 200
       mock_response.headers = {'Content-Type': 'text/plain'}
       mock_response.text = 'Plain text response'
       mock_session.request.return_value = mock_response

       arguments = {'testId': '12345'}
       result = manager.invokeDecisionCenterApi(sample_endpoint, arguments, run_locally=True)

       assert result == 'Plain text response'

   def test_invoke_response_binary_run_locally(self, manager, sample_endpoint, mock_credentials):
       """Test handling binary response when run_locally=True"""
       mock_session = mock_credentials.get_session.return_value
       mock_response = Mock()
       mock_response.status_code = 200
       mock_response.headers = {
           'Content-Type': 'application/octet-stream',
           'Content-Disposition': 'attachment; filename="test_file.zip"'
       }
       mock_response.content = b'binary content here'
       mock_session.request.return_value = mock_response

       arguments = {'testId': '12345'}
       result = manager.invokeDecisionCenterApi(sample_endpoint, arguments, run_locally=True)

       # Verify file was saved locally
       assert 'filename' in result
       assert 'url' in result
       assert result['url'].startswith('file://')
       assert os.path.exists(result['filename'])
       
       # Cleanup
       os.unlink(result['filename'])

   def test_invoke_response_binary_run_remotely(self, manager, sample_endpoint, mock_credentials):
       """Test handling binary response when run_locally=False"""
       mock_session = mock_credentials.get_session.return_value
       mock_response = Mock()
       mock_response.status_code = 200
       mock_response.headers = {
           'Content-Type': 'application/octet-stream',
           'Content-Disposition': 'attachment; filename="test_file.zip"'
       }
       mock_response.content = b'binary content here'
       mock_session.request.return_value = mock_response

       arguments = {'testId': '12345'}
       result = manager.invokeDecisionCenterApi(sample_endpoint, arguments, run_locally=False)

       # Verify base64 encoded response
       assert 'mimeType' in result
       assert 'filename' in result
       assert 'data' in result
       assert result['mimeType'] == 'application/octet-stream'
       assert result['filename'] == 'test_file.zip'
       # Verify base64 encoding
       decoded = base64.b64decode(result['data'])
       assert decoded == b'binary content here'

   def test_invoke_error_response(self, manager, sample_endpoint, mock_credentials):
       """Test handling error response from API"""
       mock_session = mock_credentials.get_session.return_value
       mock_response = Mock()
       mock_response.status_code = 404
       mock_response.content = b'Resource not found'
       mock_session.request.return_value = mock_response

       arguments = {'testId': '12345'}
       
       with pytest.raises(Exception, match='Resource not found'):
           manager.invokeDecisionCenterApi(sample_endpoint, arguments, run_locally=True)

   def test_invoke_with_mixed_parameters(self, manager, sample_endpoint, mock_credentials):
       """Test invoking API with mixed parameter types"""
       mock_session = mock_credentials.get_session.return_value
       mock_response = Mock()
       mock_response.status_code = 200
       mock_response.headers = {'Content-Type': 'application/json'}
       mock_response.json.return_value = {'success': True}
       mock_session.request.return_value = mock_response

       arguments = {
           'testId': '12345',           # path parameter
           'datasource': 'jdbc/testDB', # query parameter
           'name': 'Test Name',         # body/json parameter
           'description': 'Test Desc'   # body/json parameter
       }
       result = manager.invokeDecisionCenterApi(sample_endpoint, arguments, run_locally=True)

       # Verify all parameter types were handled correctly
       call_args = mock_session.request.call_args
       assert 'v1/test/12345' in call_args[1]['url']
       assert call_args[1]['params'] == {'datasource': 'jdbc/testDB'}
       assert call_args[1]['json'] == {'name': 'Test Name', 'description': 'Test Desc'}
       assert result == {'success': True}

   def test_invoke_cleanup_called(self, manager, sample_endpoint, mock_credentials):
       """Test that credentials cleanup is called after API invocation"""
       mock_session = mock_credentials.get_session.return_value
       mock_response = Mock()
       mock_response.status_code = 200
       mock_response.headers = {'Content-Type': 'application/json'}
       mock_response.json.return_value = {'data': 'test'}
       mock_session.request.return_value = mock_response

       arguments = {'testId': '12345'}
       manager.invokeDecisionCenterApi(sample_endpoint, arguments, run_locally=True)

       # Verify cleanup was called
       mock_credentials.cleanup.assert_called_once()

   def test_invoke_with_empty_arguments(self, manager, sample_endpoint, mock_credentials):
       """Test that empty arguments for optional parameters work correctly"""
       # Create endpoint with no required parameters
       input_schema: dict[str, str | dict[str, dict[str, str]] | list[str]] = {
           'type': 'object',
           'properties': {'datasource': {'type': 'string'}},
           'required': []
       }
       endpoint = DecisionCenterEndpoint(
           tool_name='testEndpoint',
           summary='Test endpoint',
           description='A test endpoint',
           method='GET',
           url='http://localhost:8885/decisioncenter-api/v1/test',
           parameters={
               'datasource': {'in': 'query'}
           },
           input_schema=input_schema  # type: ignore
       )

       mock_session = mock_credentials.get_session.return_value
       mock_response = Mock()
       mock_response.status_code = 200
       mock_response.headers = {'Content-Type': 'application/json'}
       mock_response.json.return_value = {'data': 'test'}
       mock_session.request.return_value = mock_response

       arguments = {}
       result = manager.invokeDecisionCenterApi(endpoint, arguments, run_locally=True)

       # Verify request was made with empty parameters
       call_args = mock_session.request.call_args
       assert call_args[1]['params'] == {}
       assert result == {'data': 'test'}