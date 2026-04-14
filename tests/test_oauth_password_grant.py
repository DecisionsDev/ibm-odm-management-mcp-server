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

import sys
import os

# Add the root directory to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../')))

import pytest
import responses
import requests
from decisioncenter_mcp_server.Credentials import Credentials


@responses.activate
def test_oauth_password_grant_with_client_secret():
    """Test OAuth 2.0 Password Grant with client secret (confidential client)."""
    
    # Mock token URL
    token_url = "https://auth.example.com/token"
    
    # Expected access token that will be returned by the mock server
    expected_token = "password_grant_access_token_12345"
    
    # Set up the mock response for the token endpoint
    responses.add(
        responses.POST,
        token_url,
        json={
            "access_token": expected_token,
            "token_type": "Bearer",
            "expires_in": 3600,
            "scope": "openid profile",
            "refresh_token": "refresh_token_67890"
        },
        status=200
    )
    
    # Create credentials with OAuth password grant parameters
    cred = Credentials(
        odm_url="http://localhost:9060/decisioncenter-api",
        username="test_user",
        password="test_password",
        client_id="test_client_id",
        client_secret="test_client_secret",
        token_url=token_url,
        scope="openid profile",
    )
    
    # Call get_auth which should make the token request
    headers = cred.get_auth()
    
    # Verify the token request was made correctly
    assert len(responses.calls) == 1
    assert responses.calls[0].request.url == token_url
    
    # Verify the request body contains the correct parameters
    request_body = responses.calls[0].request.body
    if isinstance(request_body, bytes):
        request_body = request_body.decode('utf-8')
    
    assert request_body is not None
    assert "grant_type=password" in request_body
    assert "username=test_user" in request_body
    assert "password=test_password" in request_body
    assert "scope=openid+profile" in request_body
    
    # Verify the auth header uses HTTP Basic auth with client_id and client_secret
    auth_header = responses.calls[0].request.headers['Authorization']
    assert auth_header.startswith('Basic ')
    
    # Verify the returned headers contain the expected token
    assert headers == {
        'Authorization': f'Bearer {expected_token}'
    }


def test_oauth_password_grant_missing_username():
    """Test OAuth password grant with missing username."""
    cred = Credentials(
        odm_url="http://localhost:9060/decisioncenter-api",
        password="test_password",
        client_id="test_client_id",
        token_url="https://auth.example.com/token",
    )
    
    with pytest.raises(ValueError, match="Both 'username' and 'password' are required for OAuth password grant."):
        cred.get_auth()


def test_oauth_password_grant_missing_password():
    """Test OAuth password grant with missing password."""
    cred = Credentials(
        odm_url="http://localhost:9060/decisioncenter-api",
        username="test_user",
        client_id="test_client_id",
        token_url="https://auth.example.com/token",
    )
    
    with pytest.raises(ValueError, match="Both 'username' and 'password' are required for OAuth password grant."):
        cred.get_auth()


def test_oauth_password_grant_missing_token_url():
    """Test OAuth password grant with missing token_url."""
    cred = Credentials(
        odm_url="http://localhost:9060/decisioncenter-api",
        username="test_user",
        password="test_password",
        client_id="test_client_id",
    )
    
    with pytest.raises(ValueError, match="Both 'client_id' and 'token_url' are required for OpenId authentication."):
        cred.get_auth()


@responses.activate
def test_oauth_password_grant_error_handling():
    """Test error handling in OAuth password grant flow."""
    
    # Mock token URL
    token_url = "https://auth.example.com/token"
    
    # Set up the mock response to simulate invalid credentials
    responses.add(
        responses.POST,
        token_url,
        json={
            "error": "invalid_grant",
            "error_description": "Invalid username or password"
        },
        status=401
    )
    
    # Create credentials with OAuth password grant parameters
    cred = Credentials(
        odm_url="http://localhost:9060/decisioncenter-api",
        username="invalid_user",
        password="invalid_password",
        client_id="test_client_id",
        client_secret="test_client_secret",
        token_url=token_url,
    )
    
    # Call get_auth which should make the token request and raise an exception
    with pytest.raises(requests.exceptions.HTTPError) as excinfo:
        cred.get_auth()
    
    # Verify the correct error was raised
    assert "401" in str(excinfo.value)
    
    # Verify the token request was made
    assert len(responses.calls) == 1
    assert responses.calls[0].request.url == token_url

# Made with Bob
