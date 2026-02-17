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
from .ToolTrace import ToolExecutionTrace, DiskTraceStorage
import os.path
from openapi_parser import parse
import base64
from email.message import Message
from pathlib import Path
import tempfile
import re
import xml.etree.ElementTree
import copy

# adds a parameter into 'input_shema' (for the MCP server client (the AI agent)) and in 'parameters' (for the MCP server)
# used to generate the tools for both REST APIs (DC and RES Console)
def add_param(input_schema, parameters, 
              param_in, param_name, param_type, param_format, 
              param_enum, param_enumNames, 
              param_desc, param_required):

    # workaround
    if param_enum and len(param_enum) == 1: # this is likely to be an error -> create a list out of the single element
        param_enum = param_enum[0].split(',')
        param_enum = [enum.strip() for enum in param_enum]

    # add in input_schema (for the MCP client) - https://modelcontextprotocol.io/specification/draft/schema#legacytitledenumschema
    if len(input_schema) == 0:
        input_schema |= {'type': 'object', 'properties': {}, 'required': []}
    input_schema.get('properties')[param_name] = {'type':        param_type}                                  | \
                                                ({'enum':        param_enum}      if param_enum      else {}) | \
                                                ({'enumNames':   param_enumNames} if param_enumNames else {}) | \
                                                ({'description': param_desc}      if param_desc      else {})
    if param_required == True:
        input_schema.get('required').append(param_name)

    # add in parameters (for the MCP server)
    parameters[param_name] = {'in':     param_in} | \
                            ({'format': param_format} if param_format else {})


class DecisionCenterManager:

    # tools that require the rtsAdministrator role when invoking them
    rtsAdministrator_tools = [
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

    resDeployer_tools = [
        # ruleapps
        'addRuleApp', 'addRuleAppProperty', 'deleteRuleApp', 'deleteRuleAppProperty', 'deployRuleAppArchive', 'updateRuleApp', 'updateRuleAppProperty', 
        'addRuleset', 'addRulesetProperty', 'deleteRuleset', 'deleteRulesetProperty', 'deployRulesetArchive', 'updateRuleset', 'updateRulesetProperty', 'updateRulesetArchive', 

        # decisiontraces
        'deleteDecisionTrace', 'deleteDecisionTraces', 'deleteDecisionTracesByIds', 

        # libraries
        'deleteLibrary', 'addLibrary', 'deleteUnusedLibraries', 'updateLibrary', 

        # xoms
        'deleteResource', 'deleteUnusedXomResources', 'deployResource', 

        # executionunits
        'resetRulesetStatistics'
    ]

    def __init__(self, credentials, trace_recorder : DiskTraceStorage = None):
        """
        :no-index:
        Initializes the DecisionCenterManager with the provided credentials and object to record traces

        Args:
            credentials (object): An object containing authentication details for Decision Center
            trace_recorder (object): an object allowing to record the tool execution traces

        Attributes:
            logger (logging.Logger): Logger instance for logging information.
            credentials (object): The provided Decision Center credentials.
            trace_recorder (object): an object allowing to record the tool execution traces
        """
        # Get logger for this class
        self.logger = logging.getLogger(__name__)
        self.credentials = credentials
        self.trace_recorder = trace_recorder

    def isDcAdmin(self, uri:str, session):
        try:
            response = session.get(uri + '/v1/users/fake-user',
                                   headers=session.headers, 
                                   verify=self.credentials.cacert)
            if response.status_code == 403:
                self.logger.info("Connected without rtsAdministrator role")
                return False
            elif response.status_code in (404, 200):
                self.logger.info("Connected with rtsAdministrator role")
                return True
            else:
                # bad credentials - no need to report it as it will be reported later on
                return False
        except Exception as e:
            self.logger.warning("Failed to check if the credentials grant rtsAdministrator role: %s", e)
            self.logger.info("Assuming connected without rtsAdministrator role")
            return False
            
    def checkDcRole(self, uri:str, session):
        self.credentials.isDcAdmin = self.isDcAdmin(uri, session)

    def isResDeployer(self, uri:str, session):
        try:
            response = session.delete(uri + '/apiauth/v1/executionunits/statistics/fake-ruleapp/99999.9/fake-ruleset/99999.9',
                                      headers=session.headers, 
                                      verify=self.credentials.cacert)
            if response.status_code == 403:
                self.logger.info("Connected without the resDeployer role")
                return False
            elif response.status_code in [200]:
                self.logger.info("Connected with the resDeployer role")
                return True
            else:
                # unexpected (bad credentials?)
                self.logger.warning("Unexpected HTTP response code %s while checking if the credentials grant the resDeployer role: %s", response.status_code, response.text)
        except Exception as e:
            self.logger.warning("Failed to check if the credentials grant the resDeployer role: %s", e)

        self.logger.info("Assuming connected without the resDeployer role")
        return False
            
    def checkResRole(self, uri:str, session):
        self.credentials.isResDeployer = self.isResDeployer(uri, session)

    def publish_tool(self, tool_name, tool_tags : list, tools_to_publish, tools_to_ignore, tags_to_publish):
        if len(tools_to_publish) > 0 and tool_name.lower() in tools_to_publish:
            return True # publish as this tool is explicitly specified

        if len(tools_to_ignore) > 0 and tool_name.lower() in tools_to_ignore:
            return False # do not publish this tool as it is in the list of tools to be discarded/not published

        if len(tags_to_publish) > 0 and len( [tag for tag in tool_tags if tag.lower() in tags_to_publish] ) == 0:
            return False # do not publish this tool as it does not belong to a category to publish

        return True

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
                self.checkDcRole(uri, session)

                openapi_uri = uri + '/v3/api-docs'
                self.logger.info("Parsing " + openapi_uri)
                response = session.get(openapi_uri, 
                                       headers=session.headers, 
                                       verify=self.credentials.cacert,
                                      )
                self.credentials.cleanup()

                # Check if the request was successful
                if response.status_code == 200:
                    openapi_json = response.json()
                    self.logger.info("successfully retrieved Decision Center REST API openapi")
                    openapi_json = self.fix_openapi(openapi_json)

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
                elif response.status_code == 401:
                    self.logger.error("Wrong credentials. Therefore no access to Decision Center tools.")
                else:
                    self.logger.error("Request failed with status code: %s", response.status_code)
                    self.logger.error("Response: %s", response.text)
                    raise(Exception(response.text))

        except json.JSONDecodeError as e:
            self.logger.error("Could not retrieve openapi. Please check that the Decision Center API is valid: %s", uri)
        except Exception as e:
            self.logger.error("An error occurred: %s", e)
            raise(e)

    # returns the openapi
    # and sets self.credentials.isDcAdmin to True if the credentials grant the rtsAdministrator role
    def fetch_endpoints(self):
        return self._fetch_endpoints(uri = self.credentials.odm_url)


    def generate_tools_format(self, endpoints, tags_to_publish: list[str] = [], tools_to_publish: list[str] = [], tools_to_ignore: list[str] = [], isDcAdmin: bool = False) -> dict[str, types.Tool]:
        """
        :no-index:
        Convert the endpoints to the tools format

        Args:
            data (list): an OpenApi description of Decision Center REST API endpoints

        Returns:
            dict: A dictionary containing the tools.
        """

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
                                  param_in        = param_in,
                                  param_name      = props.name,
                                  param_type      = getattr(props.schema.type,   'value',      'string')  if hasattr(props.schema,'type')   else 'string',
                                  param_format    = getattr(props.schema.format, 'value',       None)     if hasattr(props.schema,'format') else None,
                                  param_enum      = getattr(props.schema,        'enum',        None),
                                  param_enumNames = None,
                                  param_desc      = getattr(props.schema,        'description', None),
                                  param_required  = props.name in required_list)
                else:
                    add_param(input_schema, parameters,
                              param_in        = param_in,
                              param_name      = getattr(element,               'name',       'body'),
                              param_type      = getattr(element.schema.type,   'value',      'string')  if hasattr(element.schema,'type')   else 'string',
                              param_format    = getattr(element.schema.format, 'value',       None)     if hasattr(element.schema,'format') else None,
                              param_enum      = getattr(element.schema,        'enum',        None),
                              param_enumNames = None,
                              param_desc      = getattr(element.schema,        'description', None),
                              param_required  = getattr(request_body,          'required',    False))

        tools : dict[str, DecisionCenterEndpoint] = {}
        base_url = self.credentials.odm_url

        if endpoints is None:
            return tools
        
        for path in endpoints.paths:
            for info in path.operations:

                try:
                    path_url     = path.url
                    summary      = info.summary
                    description  = info.description
                    method       = info.method.name
                    operation_id = info.operation_id
                    tool_name    = operation_id

                    # filter out the tools that require the rtsAdministrator role if the credentials used do not grant this role
                    if not isDcAdmin and tool_name in DecisionCenterManager.rtsAdministrator_tools:
                        continue

                    if not self.publish_tool(tool_name, info.tags, tools_to_publish, tools_to_ignore, tags_to_publish):
                        continue

                    input_schema = {'type': 'object', 'properties': {}, 'required': []}
                    parameters   = {}

                    for parameter in info.parameters:

                        type = getattr(parameter.schema.type, 'value', 'string') if hasattr(parameter.schema,'type') else 'string'
                        if type == 'integer':
                            type = 'number'

                        add_param(input_schema, parameters,
                                  param_in        = parameter.location.value,
                                  param_name      = parameter.name,
                                  param_type      = type,
                                  param_format    = None,
                                  param_enum      = getattr(parameter, 'enum',        None),
                                  param_enumNames = None,
                                  param_desc      = getattr(parameter, 'description', None),
                                  param_required  = getattr(parameter, 'required',    False))

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
        
        self.logger.info("Successfully generated the MCP tools for the Decision Center REST API")
        return tools

    def _fetch_res_api_endpoints(self, uri:str):
        """
        :no-index:
        Fetches the WADL description of the Decision Server REST API

        Returns:
            str: WADL as a string or raises an exception is an error occurred.
        """
        if uri.startswith('http') == False:
            with open(uri, "r") as file: # the uri is actually a file (useful for testing)
                content = file.read()
                return content

        try:
            session = self.credentials.get_session()

            wadl_uri = uri + '/apiauth/v1/DecisionServer.wadl'
            self.logger.info("Retrieving " + wadl_uri)
            response = session.get(wadl_uri, 
                                   headers=session.headers, 
                                   verify=self.credentials.cacert)
            
            # Check if the request was successful
            if response.status_code == 200:
                self.logger.info("successfully retrieved Decision Server REST API WADL")

                # at this point, we know the credentials grant the resMonitor role (giving access to most RES tools)
                # check if the credentials also grant the resDeployer role (giving access to the restricted RES tools)
                self.checkResRole(uri, session)

                return response.text
            else:
                if response.status_code == 403:
                    self.logger.error("Connected without the resMonitor role. Therefore no access to the RES tools.")
                elif response.status_code == 401:
                    self.logger.error("Wrong credentials. Therefore no access to the RES tools.")
                elif response.status_code == 500 and "NoResourceFoundException" in response.text:
                    self.logger.error("Could not retrieve RES API WADL. Please check that the RES Console URL is valid: %s", uri)
                else: 
                    self.logger.error("Request failed with status code: %s", response.status_code)
                    self.logger.error("Response: %s", response.text)
                    raise(Exception(response.text))
            
        except Exception as e:
            self.logger.error("An error occurred: %s", e)
            raise(e)

        finally:
            self.credentials.cleanup()

    # returns the WADL description of the RES console REST API
    # and sets self.credentials.isResDeployer to True if the credentials grant the resDeployer Role
    def fetch_res_api_endpoints(self):
        return self._fetch_res_api_endpoints(uri = self.credentials.odm_res_url)

    def generate_res_tools(self, wadl : str, tools : dict[str, DecisionCenterEndpoint], tags_to_publish: list[str] = [], tools_to_publish: list[str] = [], tools_to_ignore: list[str] = [], isResDeployer: bool = False) -> dict[str, types.Tool]:
        """
        :no-index:
            Converts the WADL description into a list of MCP tools

        Args:
            wadl:  a WADL description of Decision Server REST API endpoints
            tools: a dictionary containing the tools.

        Returns:
            tools: a dictionary containing the tools.
        """

        def add_body_params(input_schema, parameters, dict_representations, xmlRepresentationGlobalList, xmlRepresentation):

            def build_inputSchema(input_schema, parameters, key, value, hierarchy : list = []):
                # special parameters (found in jsonRulesetIn and jsonRuleAppIn)
                if key == 'archive':
                    if len(value) > 1000:
                        # replace "UEsDBBQACAgIAImZbVsA..."
                        value = 'archive file path or content'
                    param_format = 'binary'
                else:
                    param_format = None

                # add the parameter in 'parameters'
                rootLevel = (len(hierarchy) == 0)
                if key is not None:
                    if rootLevel:
                        parameters[key] = {'in':    'body/json'} | \
                                         ({'format': param_format} if param_format is not None else {})
                    elif param_format is not None:
                        key_hierarchy = hierarchy[1:]
                        key_hierarchy.append(key)
                        root_key = hierarchy[0]
                        parameters[root_key] = {'in':        'body/json',
                                                'format':    param_format,
                                                'hierarchy': key_hierarchy}

                # add the parameter in 'input_schema'
                if key is not None:
                    input_schema[key] = {}
                    input_schema = input_schema[key]
                    if isinstance(value, dict) or isinstance(value, list):
                        hierarchy = hierarchy.copy()
                        hierarchy.append(key)

                if isinstance(value, str):
                    input_schema |= {'type': 'string',
                                     'description': value}

                elif isinstance(value, dict):
                    input_schema |= {'type': 'object',
                                     'properties': {},
                                     'required': []}
                    for item_key, item_value in value.items():
                        if item_key not in ['displayName', 'description']:
                            input_schema.get('required').append(item_key)
                        build_inputSchema(input_schema['properties'], parameters, item_key, item_value, hierarchy)

                if isinstance(value, list):
                    dict_element = value[0]
                    if len(dict_element) == 1:
                        # if the array elements are made of one single field, declare the element in the inputSchema as an object anyway (not a string) even though the payload will contain just a string
                        # only the tool 'deleteDecisionTracesByIds' is that way
                        for item_key, item_value in dict_element.items():
                            pass
                        input_schema |= {'type': 'object',
                                         'properties': {
                                            item_key: {
                                                'type': 'array',
                                                'items': {
                                                    'type': 'string',
                                                    'description': item_value
                                                }
                                            }
                                         },
                                         'required': [item_key]
                                        }
                        if rootLevel:
                            parameters[item_key] = {'in': 'body/jsonarray'}
                    else:
                        input_schema |= {'type': 'array',
                                         'items': {}}
                        for element in value:
                            build_inputSchema(input_schema['items'], parameters, None, element, hierarchy)

            href = xmlRepresentation.attrib.get('href')
            if href:
                if href[0] != '#':
                    raise Exception(f'Unexpected body parameter(s) reference "{href}"')
                if href[0:4] == '#xml':
                    return  # ignore (use the json format instead)

                # check in the cache ('dict_representations') if those body parameters have already been parsed
                id = href[1:]
                body_params = dict_representations.get(id)
                if body_params is not None:
                    input_schema |= body_params.get('input_schema')
                    parameters   |= body_params.get('parameters')
                    return
                
                # otherwise find them
                for xmlRepresentation in xmlRepresentationGlobalList:
                    if xmlRepresentation.attrib.get('id') != id:
                        continue

                    # then parse them
                    mediaType = xmlRepresentation.attrib.get('mediaType')
                    if mediaType != 'application/json':
                        raise Exception(f'Unexpected mediaType "{mediaType}" while parsing representation "{id}"')

                    xmlDoc    = xmlRepresentation.find('{http://wadl.dev.java.net/2009/02}doc')
                    json_str  = xmlDoc.findtext('{http://wadl.dev.java.net/2009/02}pre')

                    # convert 'json_str' to json and then build a input schema out of it
                    try:
                        build_inputSchema(input_schema, parameters, None, json.loads(json_str))
                    except json.JSONDecodeError as e:
                        raise Exception(f'Invalid JSON found while parsing representation "{id}": "{json_str}"') from e

                    # save in cache (to avoid parsing several times the same representation)
                    dict_representations[id] = {'input_schema': copy.deepcopy(input_schema),
                                                'parameters':   copy.deepcopy(parameters)}
                    return

                # not found!
                raise Exception(f'Missing representation "{id}"')
            else:
                mediaType   = xmlRepresentation.attrib.get('mediaType', '')
                param_descr = xmlRepresentation.findtext('{http://wadl.dev.java.net/2009/02}doc')

                if   mediaType == 'text/plain':                param_in = 'body/plain'
                elif mediaType == 'application/octet-stream':  param_in = 'body/octet-stream'
                else:                                          param_in = 'body/json'

                add_param(input_schema, parameters,
                        param_in        = param_in, 
                        param_type      = 'string', 
                        param_name      = ('file'   if mediaType == 'application/octet-stream' else 'value'),
                        param_format    = ('binary' if mediaType == 'application/octet-stream' else None),
                        param_enum      = None,
                        param_enumNames = None,
                        param_desc      = param_descr, 
                        param_required  = True)

        def get_param(dict_params, xmlParam):
            href = xmlParam.attrib.get('href')
            if href:
                if href[0] != '#':
                    raise Exception(f'Invalid parameter reference "{href}"')

                param = dict_params.get(href[1:])
                if param is None:
                    raise Exception(f'Missing parameter "{href[1:]}"')
                return param

            id        = xmlParam.attrib.get('id')
            fixed     = xmlParam.attrib.get('fixed')
            name      = xmlParam.attrib.get('name')
            style     = xmlParam.attrib.get('style')
            type      = xmlParam.attrib.get('type')
            required  = xmlParam.attrib.get('required', 'false')
            default   = xmlParam.attrib.get('default')
            doc       = xmlParam.findtext('{http://wadl.dev.java.net/2009/02}doc')
            enum      = None
            enumNames = None

            xmlOptionList = xmlParam.findall('{http://wadl.dev.java.net/2009/02}option')
            for option in xmlOptionList:
                if value := option.attrib.get('value'):
                    if not enum:
                        enum = []
                    enum += [value]
                if value_doc := option.findtext('{http://wadl.dev.java.net/2009/02}doc'):
                    if not enumNames:
                        enumNames = []
                    enumNames += [value_doc]

            if id == 'RULESET_PROPERTY_NAME':
                enum +=      ['agent.enabled',
                              'agent.name',
                              'agent.description']
                enumNames += ['Controls whether the ruleset is exposed as a MCP tool.',
                              'Customizes the name of the MCP tool as exposed to AI assistants.',
                              'Overrides the default description of the ruleset when exposed as a MCP tool.']

            return  ({'id':        id}         if id else {}) | \
                    ({'fixed':     fixed}      if fixed else {}) | \
                    ({'name':      name}       if name else {}) | \
                    ({'style':     style}      if style else {}) | \
                    ({'type':      type}       if type else {}) | \
                    ({'required':  required}   if required else {}) | \
                    ({'doc':       doc}        if doc else {}) | \
                    ({'default':   default}    if default else {}) | \
                    ({'enum':      enum}       if enum else {}) | \
                    ({'enumNames': enumNames}  if enumNames else {})

        def parse_params(dict_params, xmlParam):        
            param = get_param(dict_params, xmlParam)
            if param is not None:
                dict_params[param.get('id')] = param

        def Accept_header(xmlResponseRepresentationList):
            for xmlRepresentation in xmlResponseRepresentationList:
                href = xmlRepresentation.attrib.get('href')
                if href:
                    if href[0:5] == '#json':
                        return [{'Accept': 'application/json'}]
                else:
                    mediaType = xmlRepresentation.attrib.get('mediaType')
                    if mediaType == 'application/json':
                        return [{'Accept': 'application/json'}]
            return []

        def parse_resources(tools, dict_params, dict_representations, xmlRepresentationGlobalList,
                            xmlResource, path, base_url,
                            tools_to_publish: list[str] = [], tools_to_ignore: list[str] = [], isResDeployer: bool = False):
            path += '/'
            path += xmlResource.attrib.get('path')

            tool_tag = re.search('[^/]+', path).group()

            for xmlSubelement in xmlResource.iterfind('./*'):

                if xmlSubelement.tag == '{http://wadl.dev.java.net/2009/02}resource':
                    xmlResource = xmlSubelement
                    parse_resources(tools, dict_params, dict_representations, xmlRepresentationGlobalList,
                                    xmlResource, path, base_url,
                                    tools_to_publish, tools_to_ignore, isResDeployer)

                elif xmlSubelement.tag == '{http://wadl.dev.java.net/2009/02}method':
                    xmlMethod = xmlSubelement

                    http_method              = xmlMethod.attrib.get('name')
                    xmlDoc                   = xmlMethod.find('{http://wadl.dev.java.net/2009/02}doc')
                    xmlRequest               = xmlMethod.find('{http://wadl.dev.java.net/2009/02}request')
                    xmlResponse              = xmlMethod.find('{http://wadl.dev.java.net/2009/02}response')
                    tool_name                = xmlDoc.attrib.get('title')
                    description              = xmlDoc.text
                    xmlParamList             = xmlRequest.findall('{http://wadl.dev.java.net/2009/02}param')
                    xmlRequestRepresentationList  = xmlRequest.findall('{http://wadl.dev.java.net/2009/02}representation')
                    xmlResponseRepresentationList = xmlResponse.findall('{http://wadl.dev.java.net/2009/02}representation')

                    # filter out the tools that require the resDeployer role if the credentials used do not grant this role
                    if not isResDeployer and tool_name in DecisionCenterManager.resDeployer_tools:
                        continue

                    if not self.publish_tool(tool_name, [tool_tag], tools_to_publish, tools_to_ignore, tags_to_publish):
                        continue

                    # always ignore this endpoint (not displayed in the UI and identical to /utilities/consoleinfo)
                    if tool_name == 'registerApplication' and path == '/configuration' and http_method == 'GET':
                        continue

                    # set the summary
                    # 1) special case: replace a generic sentence by a more informative summary
                    if description == 'Counts the number of elements in this list.':
                        # regex to split the Camel case 'tool_name' into words
                        matches = re.finditer('.+?(?:(?<=[a-z])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])|$)', tool_name.replace('RuleApp', 'Ruleapp'))
                        summary = ' '.join([m.group(0).lower() for m in matches]).capitalize()   # eg. 'Get count of ruleapps'

                    # 2) general case: first sentence of the description
                    else:
                        sentences = description.split('. ')
                        summary = sentences[0] if len(sentences)>1 else description

                    input_schema = {} if len(xmlRequestRepresentationList) > 0 else {'type': 'object', 'properties': {}, 'required': []}
                    parameters   = {}

                    # body parameter(s)
                    for xmlRepresentation in xmlRequestRepresentationList:
                        add_body_params(input_schema, parameters, dict_representations, xmlRepresentationGlobalList, xmlRepresentation)

                    # other parameters (path, query)
                    for xmlParam in xmlParamList:
                        try:
                            param = get_param(dict_params, xmlParam)

                            param_name      = param.get('name')
                            param_id        = param.get('id')
                            param_enum      = param.get('enum')
                            param_desc      = param.get('doc')
                            param_required  = param.get('required')
                            param_enumNames = param.get('enumNames')
                            # default       = param.get('default')

                            param_in = param.get('style')       # 'template' (=path), 'query' or 'header' (ignored)
                            if param_in == 'header':
                                # ignore all header parameters
                                continue
                            elif param_in == 'template':
                                param_in = 'path'
                                param_required = 'true'
        
                            # ignore some query parameters
                            if param_id in ['dateFormat', 'acceptAsQuery', 'acceptLanguageAsQuery',
                                            'xMethodOverrideAsQueryGET',    'xHTTPMethodOverrideAsQueryGET',
                                            'xMethodOverrideAsQueryPOST',   'xHTTPMethodOverrideAsQueryPOST',
                                            'xMethodOverrideAsQueryPUT',    'xHTTPMethodOverrideAsQueryPUT',
                                            'xMethodOverrideAsQueryDELETE', 'xHTTPMethodOverrideAsQueryDELETE',
                                            ]:
                                continue

                            # query parameters with a static/constant value
                            static_value = param.get('fixed')
                            if static_value is not None and param_in == 'query':
                                parameters[param_name] = {'in':     param_in} | \
                                                        {'fixed':  static_value}
                                continue # set by the MCP server only, not the AI agent, so don't include it in the input_schema

                            # normalize type value
                            param_type = param.get('type')
                            if param_type and 'boolean' in param_type.lower():  # 'xsd:string', 'xsd:boolean' or 'string'
                                param_type = 'boolean'
                            else:
                                param_type = 'string'

                            add_param(input_schema, parameters, 
                                      param_in, 
                                      param_name, 
                                      param_type, 
                                      None,  # param_format
                                      param_enum,
                                      param_enumNames,
                                      param_desc, 
                                      param_required = True if param_required == 'true' else False)

                        except Exception as e:
                            raise Exception(f'Error while parsing Decision Server REST API "{tool_name}": {str(e)}')

                    if tool_name in tools:
                        if tool_name == 'getResources' and tool_tag == 'configuration':
                            continue # ignore this tool to avoid overwriting a legit one and because it is best replaced by 'getConsoleInfo'
                        elif tool_name == 'getRulesetWithHighestNumberArchive':
                            tool_name =   'getRulesetWithHighestNumberArchive2' # minor flaw (the 2 tools should have different ids)
                        else:
                            self.logger.warning("Found tools with the same id: %s", tool_name)

                    tools[tool_name] = DecisionCenterEndpoint(tool_name    = tool_name,
                                                              summary      = summary,
                                                              description  = description,
                                                              method       = http_method,
                                                              url          = base_url + path,
                                                              parameters   = parameters,
                                                              input_schema = input_schema,
                                                              headers      = Accept_header(xmlResponseRepresentationList))

        if wadl is None:
            return tools

        xmlRoot      = xml.etree.ElementTree.fromstring(wadl)
        xmlResources = xmlRoot.find('{http://wadl.dev.java.net/2009/02}resources')
        base_url     = xmlResources.attrib.get('base')

        xmlParamList                =      xmlRoot.findall('{http://wadl.dev.java.net/2009/02}param')
        xmlRepresentationGlobalList =      xmlRoot.findall('{http://wadl.dev.java.net/2009/02}representation')
        xmlResourceList             = xmlResources.findall('{http://wadl.dev.java.net/2009/02}resource')

        dict_params={}
        dict_representations={}

        for xmlParam in xmlParamList:
            parse_params(dict_params, xmlParam)

        for xmlResource in xmlResourceList:
            parse_resources(tools, dict_params, dict_representations, xmlRepresentationGlobalList, 
                            xmlResource, '', base_url,
                            tools_to_publish, tools_to_ignore, isResDeployer)

        self.logger.info("Successfully generated the MCP tools for the RES Console REST API")

        return tools

    def save_execution_trace(self, trace : ToolExecutionTrace):
        if self.trace_recorder:
            self.trace_recorder.save(trace)

    def _invokeDecisionCenterApi(self, endpoint, arguments:dict, method:str, url:str, params_query:dict = {}, params_body:dict = {}, params_file:dict = {}, raw_data = None, raw_data_type = None, run_locally:bool = True):
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
        if raw_data_type:
            session.headers.update({'Content-Type': raw_data_type})
        for header in endpoint.headers:
            session.headers.update(header)

        response = session.request(method=method, 
                                   url=url, 
                                   headers=session.headers,
                                   params=params_query,
                                   data  =raw_data,
                                   json  =params_body,
                                   files =params_file)
        self.credentials.cleanup()

        # check response
        if response.status_code in [200, 201, 204]:
            content_type = response.headers.get('Content-Type', '')
            self.logger.debug(f"Request successful, response content-type={content_type}")

            if 'application/json' in content_type:
                self.save_execution_trace(ToolExecutionTrace(endpoint, arguments, response.status_code, response.json()))
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
                    result = {'filename': f.name, 'url': f'file://{f.name}'}
                    self.save_execution_trace(ToolExecutionTrace(endpoint, arguments, response.status_code, result))
                    return result
                
                else:
                    if debug := self.logger.isEnabledFor(logging.DEBUG):
                        with tempfile.NamedTemporaryFile(prefix=prefix, suffix=extension, delete=False, delete_on_close=False) as f:
                            f.write(content)
                            f.close()
                            self.logger.debug(f"Saved response in file {f.name}")

                    base64str=base64.b64encode(content).decode()
                    result = {'mimeType': content_type, 'filename': filename, 'data': base64str}
                    self.save_execution_trace(ToolExecutionTrace(endpoint, arguments, response.status_code, result))
                    return result

            else:
                self.save_execution_trace(ToolExecutionTrace(endpoint, arguments, response.status_code, response.text))
                return response.text
        else:
            err = response.content.decode('utf-8')
            if err == '':
                err = response.reason
            self.save_execution_trace(ToolExecutionTrace(endpoint, arguments, response.status_code, err))
            self.logger.error(f"Request error, status: {response.status_code}, error: {err}")
            raise Exception(err)

    def invokeDecisionCenterApi(self, endpoint:DecisionCenterEndpoint, arguments:dict[str, str], run_locally:bool):

        def replace_filepath_by_content(value, hierarchy):
            if isinstance(value, list):
                replace_filepath_by_content(value[0], hierarchy)
            elif isinstance(value, dict):
                if len(hierarchy) > 0:
                    key = hierarchy[0]
                    if key in value:
                        value[key] = replace_filepath_by_content(value[key], hierarchy[1:])
            elif os.path.isfile(value):
                with open(value, 'rb') as f:
                    value = base64.b64encode(f.read()).decode()
            return value

        params_query = {}
        params_body  = {}
        params_file  = {}
        raw_data     = None
        raw_data_type= None

        # replace any placeholder(s) in the URL by actual value(s)
        url = endpoint.url
        for param,props in endpoint.parameters.items():
            if props['in'] == 'path':
                if arguments.get(param) is None:
                    raise ValueError(f'Missing argument {param}')          
                url = url.replace('{'+param+'}', arguments.get(param))
            elif props['in'] == 'query':
                fixed = props.get('fixed')
                if fixed is not None:
                    params_query[param] = fixed


        for param,value in arguments.items():
            if props := endpoint.parameters.get(param):
                if props['in'] == 'query':
                    params_query[param] = value

                elif props['in'] == 'body/form' and props.get('format', '') == 'binary':
                    params_file[param] = open(value,'rb') if os.path.isfile(value) else value

                elif props['in'] == 'body/json' and props.get('format', '') == 'binary':
                    params_body[param] = replace_filepath_by_content(value, props.get('hierarchy'))

                elif props['in'] == 'body/json':
                    params_body[param] = value

                elif props['in'] == 'body/jsonarray':
                    params_body = value

                elif props['in'] == 'body/plain':
                    raw_data_type = 'text/plain'
                    raw_data = value

                elif props['in'] == 'body/octet-stream' and props.get('format', '') == 'binary':
                    raw_data_type = 'application/octet-stream'
                    if os.path.isfile(value):
                        with open(value, 'rb') as f:
                            raw_data = f.read()
                    else:
                        raw_data = value

        if self.logger.isEnabledFor(logging.DEBUG):
            logging.debug("params_query=%s", params_query)
            logging.debug("params_body=%s",  params_body)
            logging.debug("params_file=%s",  params_file)
            logging.debug("raw_data=%s",     raw_data)

        return self._invokeDecisionCenterApi(endpoint, arguments,
                                             method=endpoint.method, 
                                             url=url,
                                             params_query= params_query,
                                             params_body = params_body,
                                             params_file = params_file,
                                             raw_data    = raw_data,
                                             raw_data_type = raw_data_type,
                                             run_locally = run_locally)