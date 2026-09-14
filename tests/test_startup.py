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

import os
import subprocess
import sys
import pytest

# Add the root directory to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../')))

STARTUP_SCRIPT = os.path.abspath(os.path.join(os.path.dirname(__file__), '../container/script/startup.sh'))

def run_startup(tmp_path, env_overrides=None, xml_content=None, props_content=None):
    """
    Helper to set up a test environment and run container/script/startup.sh.
    Returns a dict of the parsed environment variables that were passed to the mock server,
    along with stdout and stderr of the startup script execution.
    """
    # Create mock bin directory
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    
    mock_server = bin_dir / "ibm-odm-management-mcp-server"
    # Write mock server that prints the OIDC env vars in a parsable format
    mock_server.write_text(
        "#!/usr/bin/env bash\n"
        "echo \"===MOCK_SERVER_START===\"\n"
        "echo \"CLIENT_ID=${CLIENT_ID}\"\n"
        "echo \"CLIENT_SECRET=${CLIENT_SECRET}\"\n"
        "echo \"TOKEN_URL=${TOKEN_URL}\"\n"
        "echo \"SCOPE=${SCOPE}\"\n"
        "echo \"ISSUER_URL=${ISSUER_URL}\"\n"
        "echo \"INTROSPECTION_URL=${INTROSPECTION_URL}\"\n"
        "echo \"===MOCK_SERVER_END===\"\n"
    )
    mock_server.chmod(0o755)

    # Set up authOidc directory
    auth_dir = tmp_path / "authOidc"
    auth_dir.mkdir(exist_ok=True)

    if xml_content is not None:
        (auth_dir / "openIdWebSecurity.xml").write_text(xml_content)
    if props_content is not None:
        (auth_dir / "openIdParameters.properties").write_text(props_content)

    # Build the environment
    env = os.environ.copy()
    # Prepend our mock bin to PATH so startup.sh executes our mock server
    env["PATH"] = f"{bin_dir}:{env.get('PATH', '')}"
    env["AUTHOIDC_DIR"] = str(auth_dir)

    # Clean any current env vars that might interfere
    for var in ["CLIENT_ID", "CLIENT_SECRET", "TOKEN_URL", "SCOPE", "ISSUER_URL", "INTROSPECTION_URL"]:
        env.pop(var, None)

    if env_overrides:
        env.update(env_overrides)

    # Run the startup.sh script
    res = subprocess.run(
        [STARTUP_SCRIPT],
        env=env,
        capture_output=True,
        text=True
    )

    # Parse variables from mock server output
    parsed_vars = {}
    in_mock_output = False
    for line in res.stdout.splitlines():
        if "===MOCK_SERVER_START===" in line:
            in_mock_output = True
            continue
        if "===MOCK_SERVER_END===" in line:
            in_mock_output = False
            continue
        if in_mock_output and "=" in line:
            k, v = line.split("=", 1)
            parsed_vars[k] = v

    return parsed_vars, res.stdout, res.stderr


def test_startup_xml_with_introspect(tmp_path):
    xml = """<server>
      <openidConnectClient id="default"
                           clientId="xml-id"
                           clientSecret="xml-secret"
                           tokenEndpointUrl="https://xml.token"
                           scope="openid email"
                           issuerIdentifier="https://xml.issuer"
                           validationEndpointUrl="https://xml.introspect"
                           validationMethod="introspect" />
    </server>"""
    parsed_vars, stdout, stderr = run_startup(tmp_path, xml_content=xml)
    
    assert parsed_vars.get("CLIENT_ID") == "xml-id"
    assert parsed_vars.get("CLIENT_SECRET") == "xml-secret"
    assert parsed_vars.get("TOKEN_URL") == "https://xml.token"
    assert parsed_vars.get("SCOPE") == "openid email"
    assert parsed_vars.get("ISSUER_URL") == "https://xml.issuer"
    assert parsed_vars.get("INTROSPECTION_URL") == "https://xml.introspect"


def test_startup_xml_with_default_introspect(tmp_path):
    # validationMethod is absent, should default to introspect
    xml = """<server>
      <openidConnectClient id="default"
                           clientId="xml-id"
                           clientSecret="xml-secret"
                           tokenEndpointUrl="https://xml.token"
                           scope="openid"
                           issuerIdentifier="https://xml.issuer"
                           validationEndpointUrl="https://xml.introspect" />
    </server>"""
    parsed_vars, stdout, stderr = run_startup(tmp_path, xml_content=xml)
    
    assert parsed_vars.get("CLIENT_ID") == "xml-id"
    assert parsed_vars.get("INTROSPECTION_URL") == "https://xml.introspect"


def test_startup_xml_with_non_introspect(tmp_path):
    # validationMethod is userinfo, should not extract validationEndpointUrl as INTROSPECTION_URL
    xml = """<server>
      <openidConnectClient id="default"
                           clientId="xml-id"
                           clientSecret="xml-secret"
                           tokenEndpointUrl="https://xml.token"
                           scope="openid"
                           issuerIdentifier="https://xml.issuer"
                           validationEndpointUrl="https://xml.userinfo"
                           validationMethod="userinfo" />
    </server>"""
    parsed_vars, stdout, stderr = run_startup(tmp_path, xml_content=xml)
    
    assert parsed_vars.get("CLIENT_ID") == "xml-id"
    assert parsed_vars.get("INTROSPECTION_URL") == ""


def test_startup_comment_handling(tmp_path):
    # Commented-out client should be ignored, and second active one picked up
    xml = """<server>
      <!-- <openidConnectClient clientId="commented-id" /> -->
      <openidConnectClient id="default"
                           clientId="active-id"
                           clientSecret="active-secret" />
    </server>"""
    parsed_vars, stdout, stderr = run_startup(tmp_path, xml_content=xml)
    
    assert parsed_vars.get("CLIENT_ID") == "active-id"


def test_startup_xml_namespace_handling(tmp_path):
    # Test namespace resilience via local-name()
    xml = """<server xmlns="http://www.ibm.com/xsd/liberty">
      <openidConnectClient id="default"
                           clientId="xml-id-ns"
                           clientSecret="xml-secret-ns" />
    </server>"""
    parsed_vars, stdout, stderr = run_startup(tmp_path, xml_content=xml)
    
    assert parsed_vars.get("CLIENT_ID") == "xml-id-ns"


def test_startup_already_set_env_vars_skipped(tmp_path):
    xml = """<server>
      <openidConnectClient id="default"
                           clientId="xml-id"
                           clientSecret="xml-secret" />
    </server>"""
    env_overrides = {
        "CLIENT_ID": "already-set-id",
        "CLIENT_SECRET": "already-set-secret"
    }
    parsed_vars, stdout, stderr = run_startup(tmp_path, env_overrides=env_overrides, xml_content=xml)
    
    # Pre-set environment variables must not be overwritten
    assert parsed_vars.get("CLIENT_ID") == "already-set-id"
    assert parsed_vars.get("CLIENT_SECRET") == "already-set-secret"


def test_startup_xml_with_variables(tmp_path):
    # Exact scenario provided by the user
    xml = """<server>
<variable name="ServerHost" value="https://keycloak-https-pkjwt-tls.apps.fme.cp.fyre.ibm.com/auth/realms/myrealm"/>
<openidConnectClient authFilterRef="browserAuthFilter" id="odm" inboundPropagation="supported"
    scope="openid"
    clientId="myclient"
    tokenEndpointAuthMethod="private_key_jwt" keyAliasName="pkjwt" sslRef="odmDefaultSSLConfig"
    signatureAlgorithm="RS256"
    issuerIdentifier="${ServerHost}"
    authorizationEndpointUrl="${ServerHost}/protocol/openid-connect/auth"
    tokenEndpointUrl="${ServerHost}/protocol/openid-connect/token"
    jwkEndpointUrl="${ServerHost}/protocol/openid-connect/certs"
    validationEndpointUrl="${ServerHost}/protocol/openid-connect/token/introspect"
    userIdentifier="preferred_username"
    groupIdentifier="groupIds"
    httpsRequired="false"
    audiences="ALL_AUDIENCES"
    tokenReuse="true"/>
</server>"""
    parsed_vars, stdout, stderr = run_startup(tmp_path, xml_content=xml)
    
    expected_host = "https://keycloak-https-pkjwt-tls.apps.fme.cp.fyre.ibm.com/auth/realms/myrealm"
    assert parsed_vars.get("CLIENT_ID") == "myclient"
    assert parsed_vars.get("ISSUER_URL") == expected_host
    assert parsed_vars.get("TOKEN_URL") == f"{expected_host}/protocol/openid-connect/token"
    assert parsed_vars.get("INTROSPECTION_URL") == f"{expected_host}/protocol/openid-connect/token/introspect"


def test_startup_xml_with_nested_variables(tmp_path):
    xml = """<server>
      <variable name="Base" value="https://example.com" />
      <variable name="Api" value="${Base}/v1" />
      <openidConnectClient id="default"
                           clientId="test-id"
                           tokenEndpointUrl="${Api}/token" />
    </server>"""
    parsed_vars, stdout, stderr = run_startup(tmp_path, xml_content=xml)
    
    assert parsed_vars.get("CLIENT_ID") == "test-id"
    assert parsed_vars.get("TOKEN_URL") == "https://example.com/v1/token"

