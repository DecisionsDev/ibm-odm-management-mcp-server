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

import logging
import json
import mcp.types as types
from .DecisionCenterEndpoint import DecisionCenterEndpoint
import os.path
from openapi_parser import parse
import base64
from email.message import Message
from pathlib import Path
import tempfile

class DecisionCenterManager:

    # tools that require the admin role when invoking them
    admin_tools = [
        # DBAdmin
        'launchCleanup', 'stopCleanup',
        'executeSQLScript', 'generateMigrationRole', 'generateMigrationScript', 'generateExtensionModelScript', 'uploadExtensionModelFiles', 'uploadMessagesFile', 'getModelExtensionFiles', 'setPersistenceLocale',
        'generate', 'results',

        # Admin
        'ldapSync', 'metrics', 'deleteDecisionService',
        'exportPermissions', 'importCommandPermissions', 'exportCommandPermissions', 'importTabPermissions', 'exportTabPermissions',
        'setUsersRolesRegistry', 'getUsersRolesRegistry',
        'users',   'user', 'addUser',  'deleteUser',  'eraseAllUsers', 
        'groups', 'group', 'addGroup', 'deleteGroup', 'eraseAllGroups',
        'branchGroups', 'branchSecurity', 'branch_1', 'branchSecurity_1',

        # Manage
        'addServer', 'updateServer', 'deleteServer',
        'discardBuildState',
        'webhooks', 'registerWebhook', 'registerWebhook_1', 'deleteWebhook',
    ]

    def __init__(self, credentials):
        """
        :no-index:
        Initializes the DecisionCenterManager with the provided credentials.

        Args:
            credentials (object): An object containing authentication details for Decision Center

        Attributes:
            logger (logging.Logger): Logger instance for logging information.
            credentials (object): The provided Decision Center credentials.
        """
        # Get logger for this class
        self.logger = logging.getLogger(__name__)

        # Initialize with provided credentials
        self.credentials = credentials

    def isAdmin(self, uri:str, session):
        try:
            response = session.get(uri + '/v1/users/fake-user',
                                   headers=session.headers, 
                                   verify=self.credentials.cacert)
            if response.status_code == 403:
                self.logger.info("Connected without admin role")
                return False
            elif response.status_code in (404, 200):
                self.logger.info("Connected with admin role")
                return True
            else:
                # bad credentials - no need to report it as it will be reported later on
                return False
        except Exception as e:
            self.logger.warning("Failed to check if the credentials grant admin role: %s", e)
            self.logger.info("Assuming connected without admin role")
            return False
            
    def checkRole(self, uri:str, session):
        self.credentials.isAdmin = self.isAdmin(uri, session)

    def fix_openapi(self, json):
        def fix_bool_literals(d: dict):
            if 'type' in d and d.get('type') == 'boolean':
                # replace any incorrect boolean literals
                for k, v in d.items():
                    if v == 'true':
                        d[k] = True
                    elif v == 'false':
                        d[k] = False

            for k, v in d.items():
                if isinstance(v, dict):
                    fix_bool_literals(v)

            return d

        def fix_duplicate_refs(paths:dict):
            for key_path, value_methods in paths.items():
                for key_method, values in value_methods.items():
                    seen = set()
                    new_parameters = []
                    found_duplicate = False
                    for parameter in values.get('parameters'):
                        if '$ref' not in parameter:
                            new_parameters.append(parameter)
                        else:
                            t = tuple(parameter.items())
                            if t in seen:
                                found_duplicate = True
                            else:
                                seen.add(t)
                                new_parameters.append(parameter)
                    if found_duplicate:
                        values['parameters'] = new_parameters

        def fix_missing_type(components:dict):
            for param_name, properties in components.get('parameters').items():
                schema = properties.get('schema')
                if schema is None:
                    properties['schema'] = {'type': 'string'}
                elif schema.get('type') is None:
                    schema['type'] = 'string'

        def fix_missing_enum(components:dict):
            if schema := components.get('schemas'):
                if group := schema.get('Group'):
                    if properties := group.get('properties'):
                        if securityProfile := properties.get('securityProfile'):
                            if securityProfile.get('enum') is None:
                                securityProfile['enum'] = ['NOACCESS', 'READONLY', 'FULLACCESS', 'CUSTOM']

        self.logger.debug("fixing duplicate refs"); fix_duplicate_refs(json.get('paths'))
        self.logger.debug("fixing missing types");  fix_missing_type(json.get('components'))
        self.logger.debug("fixing missing enum");   fix_missing_enum(json.get('components'))
        self.logger.debug("fixing bool literals");  fix_bool_literals(json)
        return json

    def _fetch_endpoints(self, uri:str):
        """
        :no-index:
        Fetches the openapi description of the decision center REST API and extracts the endpoints.

        Returns:
            dict: A dictionary containing the endpoints, or raise an exception is an error occurred.
        """
        try:
            if uri.startswith('http') == False:
                # file
                endpoints = parse(uri=uri, strict_enum=False)
                return endpoints
            else:
                session = self.credentials.get_session()

                # check if the credentials grant special roles (admin, installer)
                # (useful when filtering out the tools requiring a special role)
                self.checkRole(uri, session)

                uri += '/v3/api-docs'
                self.logger.info("Parsing " + uri)
                response = session.get(uri, 
                                       headers=session.headers, 
                                       verify=self.credentials.cacert,
                                      )
                self.credentials.cleanup()

                # Check if the request was successful
                if response.status_code == 200:
                    self.logger.info("successfully retrieved openapi!")

                    openapi_json = self.fix_openapi(response.json())

                    debug = self.logger.isEnabledFor(logging.DEBUG)
                    with tempfile.NamedTemporaryFile(delete=not debug, delete_on_close=False) as temp:

                        # convert json to bytes
                        json_str = json.dumps(openapi_json)
                        bytes_obj = bytes(json_str, 'utf-8')

                        # save in a temporary file
                        temp.write(bytes_obj)
                        temp.close()
                        if debug: print(temp.name)

                        # Parse
                        self.logger.debug("parsing")
                        previous_level = self.logger.root.level
                        logging.getLogger().setLevel(logging.WARNING)   # avoid lots of INFO msg that slows down and can cause a timeout

                        endpoints = parse(uri=temp.name,
                                          strict_enum=False)

                        logging.getLogger().setLevel(previous_level) # restore the previous level

                        self.logger.info("Decision Center openapi parsing successful")
                        return endpoints
                else:
                    self.logger.error("Request failed with status code: %s", response.status_code)
                    self.logger.error("Response: %s", response.text)
                    raise(Exception(response.text))

        except Exception as e:
            self.logger.error("An error occurred: %s", e)
            raise(e)

    # returns the openapi
    # and sets self.credentials.isAdmin to True is the credentials grants the admin Role
    def fetch_endpoints(self):
        return self._fetch_endpoints(uri = self.credentials.odm_url)

    def generate_tools_format(self, endpoints, tags: list[str] = [], tools_to_publish: list[str] = [], tools_to_ignore: list[str] = [],
                              isAdmin: bool = False) -> dict[str, types.Tool]:
        """
        :no-index:
        Convert the endpoints to the tools format

        Args:
            data (list): an OpenApi description of Decision Center REST API endpoints

        Returns:
            dict: A dictionary containing the tools.
        """
        def add_param(input_schema, parameters, param_in, param_name, param_type, param_format, param_enum, param_desc, param_required):

            # workaround
            if param_enum and len(param_enum) == 1: # this is likely to be an error -> create a list out of the single element
                param_enum = param_enum[0].split(',')
                param_enum = [enum.strip() for enum in param_enum]

            # add in input_schema (for the MCP client)
            input_schema.get('properties')[param_name] = {'type':        param_type}                        | \
                                                        ({'enum':        param_enum} if param_enum else {}) | \
                                                        ({'description': param_desc} if param_desc else {})
            if param_required == True:
                input_schema.get('required').append(param_name)

            # add in parameters (for the MCP server)
            parameters[param_name] = {'in':     param_in} | \
                                    ({'format': param_format} if param_format else {})

        def add_body_parameters(input_schema:dict, parameters:dict, request_body):

            if getattr(request_body, 'content', None) is None:
                return
            
            for element in request_body.content:

                type = element.type.value
                if   type.startswith('application/json'):
                    param_in = 'body/json'
                elif type.startswith('multipart/form-data'):
                    param_in = 'body/form'
                elif type.startswith('text/plain'):
                    param_in = 'body/plain'
                else:
                    logging.warning("unexpected type value %s in %s", type, repr(request_body))

                if not hasattr(element, 'schema'):
                    logging.warning("schema attribute missing in %s", repr(request_body))
                    continue

                if hasattr(element.schema, 'properties'):
                    required_list = element.schema.required if hasattr(element.schema,'required') else []
                    for props in element.schema.properties:
                        add_param(input_schema, parameters,
                                param_in       = param_in,
                                param_name     = props.name,
                                param_type     = getattr(props.schema.type,   'value',      'string')  if hasattr(props.schema,'type')   else 'string',
                                param_format   = getattr(props.schema.format, 'value',       None)     if hasattr(props.schema,'format') else None,
                                param_enum     = getattr(props.schema,        'enum',        None),
                                param_desc     = getattr(props.schema,        'description', None),
                                param_required = props.name in required_list)
                else:
                    add_param(input_schema, parameters,
                            param_in       = param_in,
                            param_name     = getattr(element,               'name',       'body'),
                            param_type     = getattr(element.schema.type,   'value',      'string')  if hasattr(element.schema,'type')   else 'string',
                            param_format   = getattr(element.schema.format, 'value',       None)     if hasattr(element.schema,'format') else None,
                            param_enum     = getattr(element.schema,        'enum',        None),
                            param_desc     = getattr(element.schema,        'description', None),
                            param_required = getattr(request_body,          'required',    False))

        tools : dict[str, DecisionCenterEndpoint] = {}
        base_url = self.credentials.odm_url

        for path in endpoints.paths:
            for info in path.operations:

                try:
                    # optionally filter out tools based on their tag
                    if len(tags) > 0:
                        found = False
                        for tag in info.tags:
                            if tag.lower() in tags:
                                found = True
                        if not found:
                            continue    # ignore this tool

                    path_url     = path.url
                    summary      = info.summary
                    description  = info.description
                    method       = info.method.name
                    operation_id = info.operation_id
                    tool_name    = operation_id

                    # filter out the tools that requires the Admin role if the credentials used do not grant this role
                    if not isAdmin and tool_name in DecisionCenterManager.admin_tools:
                        continue

                    # optionally ignore tools based on their name
                    if   len(tools_to_publish) > 0 and tool_name.lower() not in tools_to_publish:
                        continue # ignore this tool as it is not in the list of tools to be published
                    elif len(tools_to_ignore) > 0  and tool_name.lower()     in tools_to_ignore:
                        continue # ignore this tool as it is in the list of tools to be discarded/not published

                    input_schema = {'type': 'object', 'properties': {}, 'required': []}
                    parameters   = {}

                    for parameter in info.parameters:

                        type = getattr(parameter.schema.type, 'value', 'string') if hasattr(parameter.schema,'type') else 'string'
                        if type == 'integer':
                            type = 'number'

                        add_param(input_schema, parameters,
                                  param_in       = parameter.location.value,
                                  param_name     = parameter.name,
                                  param_type     = type,
                                  param_format   = None,
                                  param_enum     = getattr(parameter, 'enum',        None),
                                  param_desc     = getattr(parameter, 'description', None),
                                  param_required = getattr(parameter, 'required',    False))

                    add_body_parameters(input_schema, parameters,
                                        getattr(info, 'request_body', None))

                    if tool_name in tools:
                        raise Exception(f'tool {tool_name} already defined')
                    else:
                        tools[tool_name] = DecisionCenterEndpoint(tool_name=tool_name,
                                                                  summary=summary,
                                                                  description=description,
                                                                  method=method,
                                                                  url= base_url + path_url,
                                                                  parameters=parameters,
                                                                  input_schema=input_schema)

                except Exception as e:
                    self.logger.error(e)
                    continue # ignore this REST API endpoint

        return tools

    def _invokeDecisionCenterApi(self, method:str, url:str, params_query:dict = {}, params_body:dict = {}, params_file:dict = {}, raw_data = None, run_locally:bool = True):
        """
        :no-index:
        Invokes a decision center REST API.
        Raises an exception if an error occurred

        Args:
            method (str): GET, PUT, ...
            url (str): URL of the REST API endpoint
            arguments (dict): A dictionary of inputs.

        Returns:
            dict: The response from the decision center
        """

        session = self.credentials.get_session()
        if raw_data:
            session.headers.update({'Content-Type': 'text/plain'})

        response = session.request(method=method, 
                                   url=url, 
                                   headers=session.headers,
                                   params=params_query,
                                   data  =raw_data,
                                   json  =params_body,
                                   files =params_file)
        self.credentials.cleanup()

        # check response
        if response.status_code == 200:
            content_type = response.headers.get('Content-Type', '')
            self.logger.debug(f"Request successful, response content-type={content_type}")

            if 'application/json' in content_type:
                return response.json()
                
            elif 'application/octet-stream' in content_type:
                content = response.content

                msg = Message()
                msg['content-disposition'] = response.headers.get('Content-Disposition')
                filename = msg.get_filename()
                extension = Path(filename).suffix
                prefix = filename[:-len(extension)] + '_'

                if run_locally:
                    with tempfile.NamedTemporaryFile(prefix=prefix, suffix=extension, dir=Path.home(), delete=False, delete_on_close=False) as f:
                        f.write(content)
                        f.close()
                    return {'filename': f.name, 'url': f'file://{f.name}'}
                
                else:
                    if debug := self.logger.isEnabledFor(logging.DEBUG):
                        with tempfile.NamedTemporaryFile(prefix=prefix, suffix=extension, delete=False, delete_on_close=False) as f:
                            f.write(content)
                            f.close()
                            self.logger.debug(f"Saved response in file {f.name}")

                    base64str=base64.b64encode(content).decode()
                    return {'mimeType': content_type, 'filename': filename, 'data': base64str}

            else:
                return response.text
        else:
            err = response.content.decode('utf-8')
            self.logger.error(f"Request error, status: {response.status_code}, error: {err}")
            raise Exception(err)

    def invokeDecisionCenterApi(self, endpoint:DecisionCenterEndpoint, arguments:dict[str, str], run_locally:bool):

        # replace any placeholder(s) in the URL by actual value(s)
        url = endpoint.url
        for param,props in endpoint.parameters.items():
            if props['in'] != 'path':
                continue
            if arguments.get(param) is None:
                raise ValueError(f'Missing argument {param}')          
            url = url.replace('{'+param+'}', arguments.get(param))

        params_query = {}
        params_body  = {}
        params_file  = {}
        raw_data     = None

        for param,value in arguments.items():
            if props := endpoint.parameters.get(param):
                if props['in'] == 'query':
                    params_query[param] = value
                elif props['in'] == 'body/json':
                    params_body[param] = value
                elif props['in'] == 'body/form' and props.get('format', '') == 'binary':
                    params_file[param] = open(value,'rb') if os.path.isfile(value) else value
                elif props['in'] == 'body/plain':
                    raw_data = value

        if self.logger.isEnabledFor(logging.DEBUG):
            logging.debug("params_query=%s", params_query)
            logging.debug("params_body=%s",  params_body)
            logging.debug("params_file=%s",  params_file)
            logging.debug("raw_data=%s",     raw_data)

        return self._invokeDecisionCenterApi(method=endpoint.method, 
                                             url=url,
                                             params_query= params_query,
                                             params_body = params_body,
                                             params_file = params_file,
                                             raw_data = raw_data,
                                             run_locally = run_locally)