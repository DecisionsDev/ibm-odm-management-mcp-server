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

import requests
from requests.adapters import HTTPAdapter
import ssl
import base64
import logging
from validator_collection import checkers
import time
import uuid
import hashlib

class CustomHTTPAdapter(HTTPAdapter):
    """
    A class that modifies the default behaviour with regards to certificates in order to
        - accept self-signed certificates
        - skip hostname verification
    """
    def __init__(self, certfile=None):
         self.certfile = certfile
         HTTPAdapter.__init__(self)
         
    def init_poolmanager(self, *args, **kwargs):
        context = ssl.create_default_context(cafile = self.certfile)
        context.verify_flags = ssl.VERIFY_ALLOW_PROXY_CERTS | ssl.VERIFY_X509_TRUSTED_FIRST | ssl.VERIFY_X509_PARTIAL_CHAIN
        kwargs['ssl_context'] = context
        kwargs['assert_hostname'] = False
        return super().init_poolmanager(*args, **kwargs)

class Credentials:

    def __init__(self, odm_url, odm_res_url=None,
                 token_url=None, scope='openid', client_id=None, client_secret=None, 
                 pkjwt_cert_path=None, pkjwt_key_path=None, pkjwt_key_password=None, 
                 username=None, password=None, 
                 zenapikey=None, 
                 verify_ssl=True, ssl_cert_path=None, 
                 mtls_cert_path=None, mtls_key_path=None, mtls_key_password=None):

        # Get logger for this class with explicit name to ensure consistency
        self.logger = logging.getLogger("decisioncenter_mcp_server.Credentials")

        # remove the ending / and check the URL of DC REST API and the RES console
        self.odm_url     = None
        self.odm_res_url = None
        if odm_url:
            self.odm_url     = odm_url.rstrip('/')
            if not checkers.is_url(self.odm_url):     raise ValueError("'"+self.odm_url+"' is not a valid URL")
        if odm_res_url:
            self.odm_res_url = odm_res_url.rstrip('/')
            if not checkers.is_url(self.odm_res_url): raise ValueError("'"+self.odm_res_url+"' is not a valid URL")
        if odm_url is None and odm_res_url is None:   raise ValueError("Please set the URL of at least the Decision Center REST API or the RES Console")

        if verify_ssl:
            import certifi
            self.cacert = certifi.where()
        else:
            self.cacert = None

        self.isAdmin = False
        self.username = username
        self.password = password
        self.token_url = token_url
        self.scope = scope
        self.client_id = client_id
        self.client_secret = client_secret
        self.zenapikey = zenapikey
        self.verify_ssl = verify_ssl
        self.ssl_cert_path = ssl_cert_path

        self.pkjwt_cert_path = None
        self.pkjwt_key_path  = None
        self.pkjwt_key_password = None
        self.pkjwt_key_data  = None

        self.mtls_cert_path = None
        self.mtls_key_path  = None
        self.mtls_key_password = None
        self.mtls_key_data  = None

        if pkjwt_key_path or pkjwt_cert_path:
            # Ensure both private and public certificates are provided
            if ((    pkjwt_key_path and not pkjwt_cert_path) or
                (not pkjwt_key_path and     pkjwt_cert_path)):
                raise ValueError("Both 'pkjwt_key_path' and 'pkjwt_cert_path' are required for PKJWT authentication.")
            self.pkjwt_cert_path = pkjwt_cert_path
            self.pkjwt_key_path  = pkjwt_key_path
            self.pkjwt_key_password = pkjwt_key_password
            self.pkjwt_key_data  = self.get_unencrypted_key_data(pkjwt_key_path, pkjwt_key_password)

        if mtls_key_path or mtls_cert_path:
            # Ensure both private and public certificates are provided
            if ((    mtls_key_path and not mtls_cert_path) or
                (not mtls_key_path and     mtls_cert_path)):
                raise ValueError("Both 'mtls_key_path' and 'mtls_cert_path' are required for mTLS authentication.")
            self.mtls_cert_path    = mtls_cert_path
            self.mtls_key_path     = mtls_key_path
            self.mtls_key_password = mtls_key_password
            self.mtls_key_data     = self.get_unencrypted_key_data(mtls_key_path, mtls_key_password)

    def get_auth(self):
        if self.zenapikey:
            # Concatenate the strings with a colon
            concatenated_key = f"{self.username}:{self.zenapikey}"
            # Encode the concatenated string in Base64
            if not self.username:
                raise ValueError("Username must be provided when using zenapikey.")
            encoded_zen_key = base64.b64encode(concatenated_key.encode()).decode()
            return {
                'Authorization': f'ZenApiKey {encoded_zen_key}'
            }
        elif self.client_id or self.client_secret:
            if not self.client_id or not self.token_url:
                raise ValueError("Both 'client_id' and 'token_url' are required for OpenId authentication.")
            
            # Check if we're using PKJWT (certificate-based) or client_secret
            if self.pkjwt_cert_path:
                from cryptography import x509
                from cryptography.hazmat.backends import default_backend
                from cryptography.hazmat.primitives import serialization
                
                # PKJWT (Private Key Json Web Token) authentication
                # Note: PyJWT package is required for PKJWT authentication
                # If you get an error, install it with: pip install PyJWT
                try:
                    # Try to import PyJWT dynamically
                    # pylint: disable=import-outside-toplevel
                    # type: ignore
                    import jwt  # type: ignore # noqa
                except ImportError:
                    raise ImportError("PyJWT package is required for PKJWT authentication. Install with 'pip install PyJWT'.")
                
                # Create JWT token with required claims
                now = int(time.time())
                exp_time = now + 3600  # Token valid for 1 hour
                
                payload = {
                    'iss': self.client_id,  # Issuer is the client_id
                    'sub': self.client_id,  # Subject is also the client_id for client credentials
                    'aud': self.token_url,  # Audience is the token endpoint
                    'exp': exp_time,        # Expiration time
                    'iat': now,             # Issued at time
                    'jti': str(uuid.uuid4()) # Unique identifier for the JWT
                }
                
                try:
                    # Calculate the certificate thumbprint from the public certificate
                    try:
                        with open(self.pkjwt_cert_path, 'rb') as cert_file:
                            cert_data = cert_file.read()
                        
                        # Load the certificate
                        if b"BEGIN CERTIFICATE" in cert_data:
                            cert = x509.load_pem_x509_certificate(cert_data, default_backend())
                        else:
                            cert = x509.load_der_x509_certificate(cert_data, default_backend())
                        
                        # Calculate SHA-1 thumbprint (x5t)
                        sha1_hash = hashlib.sha1(cert.public_bytes(encoding=serialization.Encoding.DER)).digest()
                        sha1_b64 = base64.urlsafe_b64encode(sha1_hash).decode('utf-8').rstrip('=')
                        

                        # Calculate SHA-256 thumbprint
                        sha256_hash = hashlib.sha256(cert.public_bytes(encoding=serialization.Encoding.DER)).digest()
                        sha256_b64 = base64.urlsafe_b64encode(sha256_hash).decode('utf-8').rstrip('=')
                        
                        # Add thumbprints to JWT header
                        headers = {
                            'x5t': sha1_b64     # Use the calculated SHA-1 thumbprint
                        }
                        self.logger.debug(f"Using calculated x5t from public certificate: {sha1_b64}")
                    except Exception as e:
                        # Don't fallback to hardcoded value, raise an error instead
                        raise ValueError(f"Error calculating certificate thumbprint from public certificate: {str(e)}")
                    
                    # Sign the JWT with the private key and include headers
                    encoded_jwt = jwt.encode(payload, self.pkjwt_key_data, algorithm='RS256', headers=headers)
                    self.logger.info("JWT token created successfully.");   
                    self.logger.debug("msg encoded JWT "+encoded_jwt)                # Prepare the token request with the JWT assertion
                    data = {
                        'grant_type': 'client_credentials',
                        'scope': self.scope,
                        'client_assertion_type': 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
                        'client_assertion': encoded_jwt
                    }
                    
                    # Make the token request without auth header (the JWT is the auth)
                    if self.verify_ssl:
                        response = requests.post(self.token_url, data=data, verify=self.cacert)
                    else:
                        response = requests.post(self.token_url, data=data, verify=False)
                except Exception as e:
                    raise ValueError(f"Error creating or sending JWT token: {str(e)}")
            else:
                # Standard OpenID client_secret authentication
                if not self.client_secret:
                    if self.pkjwt_cert_path:
                        raise ValueError("Both 'pkjwt_key_path' and 'pkjwt_cert_path' are required for PKJWT authentication.")
                    else:
                        raise ValueError("Either 'client_secret' or 'pkjwt_key_path' is required for OpenId authentication.")
                
                data = {
                    'grant_type': 'client_credentials',
                    'scope': self.scope,
                }
                auth = requests.auth.HTTPBasicAuth(self.client_id, self.client_secret)
                if self.verify_ssl:
                    response = requests.post(self.token_url, data=data, auth=auth, verify=self.cacert)
                else:
                    response = requests.post(url=self.token_url, data=data, auth=auth, verify=False)
            response.raise_for_status() # raise an HTTPError if the request failed
            token_data = response.json()
            access_token = token_data['access_token']
            return {
                'Authorization': f'Bearer {access_token}'
            }
        elif self.username and self.password:
            concatenated_key = f"{self.username}:{self.password}"
            encoded_user_cred = base64.b64encode(concatenated_key.encode()).decode()
            return { 
                'Authorization': f'Basic {encoded_user_cred}'
            }
        else:
            raise ValueError("Either username and password, bearer token, or zenapikey must be provided.")
    
    def get_session(self):
        """
        Creates and returns a requests Session object configured with SSL settings
        """ 
        session = requests.Session()

        use_https = self.odm_url     is not None and self.odm_url.startswith('https') \
                 or self.odm_res_url is not None and self.odm_res_url.startswith('https')

        if use_https and self.verify_ssl:
            session.verify = True
            session.mount('https://', CustomHTTPAdapter(certfile = self.ssl_cert_path))
        else:
            session.verify = False
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        headers = self.get_auth()
        session.headers.update(headers)

        if self.mtls_cert_path:
            session.cert = self.mtls_cert_tuple()

        self.logger.debug(f"Session created with URL: {self.odm_url} and headers: {session.headers}")        
        return session

    # remove the temporary file that might have been created
    def cleanup(self):
        if self.mtls_key_password:
            import os
            os.remove(self.mtls_unencrypted_key_path)

    # return the mTLS keys tuple (private, cert)
    # optionally create temporary certificate file if the private key is encrypted
    def mtls_cert_tuple(self):
        if not self.mtls_key_password:
            return (self.mtls_cert_path,
                    self.mtls_key_path)
        else:
            try:
                # write the unencrypted private key into a temporary file
                import tempfile
                with tempfile.NamedTemporaryFile(delete=False, delete_on_close=False) as fp:
                    fp.write(self.mtls_key_data.encode())
                    fp.close()
                    self.mtls_unencrypted_key_path = fp.name
            except IOError as e:
                raise ValueError(f"Error writing unencrypted key file for mTLS: {str(e)}")
            return (self.mtls_cert_path,
                    self.mtls_unencrypted_key_path)

    # return content of a private key in PEM format, and not password protected
    def get_unencrypted_key_data(self, key_path, key_password=None):
        try:
            # Read the private key
            with open(key_path, 'r') as key_file:
                key_data = key_file.read()
            
            if key_password is None:
                # Use the key as-is if no password
                unencrypted_key_data = key_data
            else:
                # If a password is provided, decrypt the private key
                from cryptography.hazmat.primitives.serialization import load_pem_private_key
                from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
                from cryptography.hazmat.backends import default_backend

                try:
                    # Load the encrypted private key
                    key_obj = load_pem_private_key(
                        key_data.encode(),
                        password=key_password.encode(),
                        backend=default_backend()
                    )
                    
                    # Convert back to PEM format (unencrypted for use with PyJWT)
                    unencrypted_key_data = key_obj.private_bytes(
                        encoding=Encoding.PEM,
                        format=PrivateFormat.PKCS8,
                        encryption_algorithm=NoEncryption()
                    ).decode('utf-8')
                    
                    self.logger.info("Successfully decrypted password-protected private key")
                except Exception as e:
                    raise ValueError(f"Failed to decrypt private key with provided password: {str(e)}")
        except FileNotFoundError:
            raise ValueError(f"Private key file not found at path: {key_path}")
        except IOError as e:
            raise ValueError(f"Error reading private key file {key_path}: {str(e)}")
        return unencrypted_key_data