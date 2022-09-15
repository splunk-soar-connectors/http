# File: http_connector.py
#
# Copyright (c) 2016-2022 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under
# the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific language governing permissions
# and limitations under the License.

import json
import os
import re
import shutil
import socket
import sys
import uuid
from urllib.parse import quote, unquote_plus, urlparse

import encryption_helper
import magic
import phantom.app as phantom
import phantom.rules as ph_rules
import requests
import validators
import xmltodict
from bs4 import BeautifulSoup, UnicodeDammit
from phantom.action_result import ActionResult
from phantom.base_connector import BaseConnector
from phantom.vault import Vault as Vault
from requests.auth import HTTPBasicAuth

from http_consts import *


class RetVal(tuple):
    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class HttpConnector(BaseConnector):

    MAGIC_FORMATS = [
        (re.compile('^PE.* Windows'), ['pe file'], '.exe'),
        (re.compile('^MS-DOS executable'), ['pe file'], '.exe'),
        (re.compile('^PDF '), ['pdf'], '.pdf'),
        (re.compile('^MDMP crash'), ['process dump'], '.dmp'),
        (re.compile('^Macromedia Flash'), ['flash'], '.flv'),
        (re.compile('^tcpdump capture'), ['pcap'], '.pcap'),
    ]

    def __init__(self):

        super(HttpConnector, self).__init__()

        self._state = None
        self._base_url = None
        self._test_path = None
        self._timeout = None
        self._token_name = None
        self._token = None
        self._username = None
        self._password = None
        self._oauth_token_url = None
        self._client_id = None
        self._client_secret = None
        self._state = None
        self._access_token = None
        self.access_token_retry = True

    def encrypt_state(self, encrypt_var, token_name):
        """ Handle encryption of token.
        :param encrypt_var: Variable needs to be encrypted
        :return: encrypted variable
        """
        self.debug_print(HTTP_ENCRYPT_TOKEN.format(token_name))   # nosemgrep
        return encryption_helper.encrypt(encrypt_var, self.get_asset_id())

    def decrypt_state(self, decrypt_var, token_name):
        """ Handle decryption of token.
        :param decrypt_var: Variable needs to be decrypted
        :return: decrypted variable
        """
        self.debug_print(HTTP_DECRYPT_TOKEN.format(token_name))    # nosemgrep
        return encryption_helper.decrypt(decrypt_var, self.get_asset_id())

    def _get_error_message_from_exception(self, e):
        """ This function is used to get appropriate error message from the exception.
        :param e: Exception object
        :return: error message
        """
        error_msg = HTTP_ERROR_MESSAGE
        error_code = HTTP_ERROR_CODE_MESSAGE
        try:
            if hasattr(e, 'args'):
                if len(e.args) > 1:
                    error_code = e.args[0]
                    error_msg = e.args[1]
                elif len(e.args) == 1:
                    error_code = HTTP_ERROR_CODE_MESSAGE
                    error_msg = e.args[0]
        except Exception as ex:
            self.error_print("Exception occurred.", ex)

        return "Error Code: {0}. Error Message: {1}".format(error_code, error_msg)

    def _validate_integers(self, action_result, parameter, key, allow_zero=False):
        """ This method is to check if the provided input parameter value
        is a non-zero positive integer and returns the integer value of the parameter itself.
        :param action_result: Action result or BaseConnector object
        :param parameter: input parameter
        :return: integer value of the parameter or None in case of failure
        """
        try:
            if not float(parameter).is_integer():
                self.set_status(phantom.APP_ERROR, HTTP_VALIDATE_INTEGER_MESSAGE.format(key=key))
                return None
            parameter = int(parameter)

        except Exception as ex:
            self.error_print("Exception occurred.", ex)
            self.set_status(phantom.APP_ERROR, HTTP_VALIDATE_INTEGER_MESSAGE.format(key=key))
            return None

        if parameter < 0:
            self.set_status(phantom.APP_ERROR, "Please provide a valid non-negative integer value in the {} parameter".format(key))
            return None
        if not allow_zero and parameter == 0:
            self.set_status(phantom.APP_ERROR, "Please provide a positive integer value in the {} parameter".format(key))
            return None

        return parameter

    def initialize(self):

        self._state = self.load_state()

        if not isinstance(self._state, dict):
            self.debug_print("Resetting the state file with the default format")
            self._state = {
                "app_version": self.get_app_json().get('app_version')
            }

        config = self.get_config()
        self._base_url = config['base_url'].strip('/')
        self._token_name = config.get('auth_token_name', 'ph-auth-token')
        self._token = config.get('auth_token')

        self._username = config.get('username')
        self._password = config.get('password', '')
        self._test_http_method = config.get('test_http_method', 'get').lower()

        self._oauth_token_url = config.get('oauth_token_url')
        if self._oauth_token_url:
            self._oauth_token_url = self._oauth_token_url.strip('/')
        self._client_id = config.get('client_id')
        self._client_secret = config.get('client_secret')
        self._access_token = self._state.get(HTTP_JSON_ACCESS_TOKEN)

        if 'test_path' in config:
            try:
                if not config['test_path'].startswith('/'):
                    self._test_path = '/' + config['test_path']
                else:
                    self._test_path = config['test_path']
            except Exception as e:
                error_message = self._get_error_message_from_exception(e)
                return self.set_status(phantom.APP_ERROR, "Given endpoint value is invalid: {0}".format(error_message))

        if 'timeout' in config:
            self._timeout = self._validate_integers(self, config.get("timeout"), "timeout")
            if self._timeout is None:
                return self.get_status()

        parsed = urlparse(self._base_url)

        if not parsed.scheme or not parsed.hostname:
            return self.set_status(phantom.APP_ERROR, 'Failed to parse URL ({}). Should look like "http(s)://location/optional_path"'.format(
                self._base_url))

        # Make sure base_url isn't 127.0.0.1
        addr = parsed.hostname
        try:
            unpacked = socket.gethostbyname(addr)
        except Exception as ex:
            self.error_print("Exception occurred.", ex)
            try:
                packed = socket.inet_aton(addr)
                unpacked = socket.inet_aton(packed)
            except Exception as ex:
                self.error_print("Exception occurred.", ex)
                # gethostbyname can fail even when the addr is a hostname
                # If that happens, I think we can assume that it isn't localhost
                unpacked = ""

        if unpacked.startswith('127.'):
            return self.set_status(phantom.APP_ERROR, 'Accessing 127.0.0.1 is not allowed')

        if self._state.get(HTTP_STATE_IS_ENCRYPTED):
            try:
                if self._access_token:
                    self._access_token = self.decrypt_state(self._access_token, "access")
            except Exception as e:
                self.error_print(HTTP_DECRYPTION_ERR, e)
                return self.set_status(phantom.APP_ERROR, HTTP_DECRYPTION_ERR)

        return phantom.APP_SUCCESS

    def finalize(self):
        try:
            if self._access_token:
                self._state[HTTP_JSON_ACCESS_TOKEN] = self.encrypt_state(self._access_token, "access")
                self._state[HTTP_STATE_IS_ENCRYPTED] = True
        except Exception as e:
            self.error_print(HTTP_ENCRYPTION_ERR, e)
            return self.set_status(phantom.APP_ERROR, HTTP_ENCRYPTION_ERR)

        self.save_state(self._state)
        return phantom.APP_SUCCESS

    def _process_empty_reponse(self, response, action_result):
        if 200 <= response.status_code < 400:
            if response.headers.get('Content-Type') == 'application/octet-stream':
                return RetVal(phantom.APP_SUCCESS, "Response includes a file")
            return RetVal(phantom.APP_SUCCESS, None)
        return RetVal(action_result.set_status(phantom.APP_ERROR, "Empty response and no information in the header"), None)

    def _process_html_response(self, response, action_result):

        status_code = response.status_code

        try:
            soup = BeautifulSoup(response.text, "html.parser")
            for element in soup(["script", "style", "footer", "nav"]):
                element.extract()
            error_text = soup.text
            split_lines = error_text.split('\n')
            split_lines = [x.strip() for x in split_lines if x.strip()]
            error_text = '\n'.join(split_lines)
        except Exception as ex:
            self.error_print("Exception occurred.", ex)
            error_text = "Cannot parse error details"

        response_data = error_text
        if 200 <= response.status_code < 400:
            return RetVal(phantom.APP_SUCCESS, response_data)

        message = "Status Code: {0}. Data from server:\n{1}\n".format(status_code, unquote_plus(error_text))

        message = message.replace('{', '{{').replace('}', '}}')

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), response_data)

    def _process_json_response(self, response, action_result):

        resp_json = {}
        try:
            if response:
                resp_json = response.json()
        except Exception as e:
            error_message = self._get_error_message_from_exception(e)
            self.error_print("Unable to parse the response into a dictionary", error_message)
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Unable to parse JSON response. Error: {0}".format(error_message)))

        if 200 <= response.status_code < 400:
            return RetVal(phantom.APP_SUCCESS, resp_json)

        message_template = 'Error from server. Status Code: {0} Data from server: {1}'
        message = message_template.format(
            response.status_code, response.text.replace('{', '{{').replace('}', '}}'))

        error_field_name = 'error'
        message_field_name = 'message'
        if error_field_name in resp_json:
            error_field = resp_json[error_field_name]

            if isinstance(error_field, dict) and message_field_name in error_field:
                error_message = error_field[message_field_name]
            else:
                error_message = error_field

            message = message_template.format(response.status_code, error_message)

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), resp_json)

    def _process_xml_response(self, r, action_result):

        resp_json = None
        try:
            if r.text:
                resp_json = xmltodict.parse(r.text)
        except Exception as e:
            error_message = self._get_error_message_from_exception(e)
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Unable to parse XML response. Error: {0}".format(error_message)))

        if 200 <= r.status_code < 400:
            return RetVal(phantom.APP_SUCCESS, resp_json)

        message = "Error from server. Status Code: {0} Data from server: {1}".format(
            r.status_code, r.text.replace('{', '{{').replace('}', '}}'))

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), resp_json)

    def _process_response(self, r, action_result):
        if r.headers.get('Content-Type', '') == 'application/octet-stream':
            r_text = ""
        else:
            r_text = r.text

        if hasattr(action_result, 'add_debug_data'):
            action_result.add_debug_data({'r_status_code': r.status_code})
            action_result.add_debug_data({'r_text': r_text})
            action_result.add_debug_data({'r_headers': r.headers})

        if not r_text:
            return self._process_empty_reponse(r, action_result)
        if 'xml' in r.headers.get('Content-Type', ''):
            return self._process_xml_response(r, action_result)
        if 'json' in r.headers.get('Content-Type', '') or 'javascript' in r.headers.get('Content-Type', ''):
            return self._process_json_response(r, action_result)
        if 'html' in r.headers.get('Content-Type', ''):
            return self._process_html_response(r, action_result)
        if 200 <= r.status_code < 400:
            return RetVal(phantom.APP_SUCCESS, r_text)

        message = "Can't process response from server. Status Code: {0} Data from server: {1}".format(
            r.status_code, r.text.replace('{', '{{').replace('}', '}}'))

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), r.text)

    def _make_http_call(self, action_result, endpoint='', method='get', headers=None, params=None,
                        verify=False, data=None, files=None, use_default_endpoint=False):

        auth = None
        headers = {} if not headers else headers
        access_token = ''
        if self._username:
            self.save_progress("Using HTTP Basic auth to authenticate")
            auth = (self._username, self._password)
        elif self._oauth_token_url and self._client_id:
            self.save_progress("Using OAuth to authenticate")
            access_token = self._generate_api_token(action_result)
            if not access_token:
                return action_result.get_status(), None
            headers['Authorization'] = 'Bearer {}'.format(access_token)
        elif self._token_name:
            self.save_progress("Using provided token to authenticate")
            if self._token and self._token_name not in headers:
                headers[self._token_name] = self._token
        else:
            return action_result.set_status(phantom.APP_ERROR, "No authentication method set"), None

        if self.get_action_identifier() == 'get_file' or self.get_action_identifier() == 'put_file':
            url = endpoint
            if not use_default_endpoint:
                auth = None
        else:
            url = self._base_url + endpoint

        try:
            r = requests.request(
                method=method,
                url=url,
                auth=auth,
                params=params,
                data=UnicodeDammit(data).unicode_markup.encode('utf-8') if isinstance(data, str) else data,
                verify=verify,
                headers=headers,
                files=files,
                timeout=self._timeout)

        except Exception as e:
            error_message = self._get_error_message_from_exception(e)
            return action_result.set_status(phantom.APP_ERROR, "Error Connecting to server. Details: {0}".format(error_message)), None

        # fetch new token if old one has expired
        if access_token and r.status_code == 401 and self.access_token_retry:
            self.save_progress("Got error: {}".format(r.status_code))
            self._state.pop('access_token')
            self.access_token_retry = False  # make it to false to avoid getting access token after one time (prevents recursive loop)
            return self._make_http_call(action_result, endpoint, method, headers, verify, data)

        # Return success for get headers action as it returns empty response body
        if self.get_action_identifier() == 'http_head' and r.status_code == 200:
            resp_data = {'method': method.upper(), 'location': url}
            try:
                resp_data['response_headers'] = dict(r.headers)
            except Exception:
                pass
            action_result.add_data(resp_data)
            action_result.update_summary({
                'status_code': r.status_code,
                'reason': r.reason
            })
            self.access_token_retry = True
            return action_result.set_status(phantom.APP_SUCCESS), None

        ret_val, parsed_body = self._process_response(r, action_result)

        if self.get_action_identifier() == 'get_file' or self.get_action_identifier() == 'put_file':
            return ret_val, r

        resp_data = {
            'method': method.upper(),
            'location': url, 'parsed_response_body': parsed_body,
            'response_body': r.text if 'json' not in r.headers.get('Content-Type',
                                                                   '') and 'javascript' not in r.headers.get(
                'Content-Type', '') else parsed_body
        }
        try:
            resp_data['response_headers'] = dict(r.headers)
        except Exception:
            pass
        action_result.add_data(resp_data)
        action_result.update_summary({
            'status_code': r.status_code,
            'reason': r.reason
        })

        if self.get_action_identifier() == 'test_connectivity':
            self.save_progress('Got status code {0}'.format(r.status_code))

        if phantom.is_fail(ret_val):
            return ret_val, None

        return action_result.set_status(phantom.APP_SUCCESS), None

    def _get_headers(self, action_result, headers):
        # Not to be confused with the action "get headers"
        if headers is None:
            return RetVal(phantom.APP_SUCCESS)

        if hasattr(headers, 'decode'):
            headers = headers.decode('utf-8')

        try:
            headers = json.loads(headers)
        except Exception as e:
            error_message = self._get_error_message_from_exception(e)
            return RetVal(action_result.set_status(
                phantom.APP_ERROR,
                'Failed to parse headers as JSON object. error: {}, headers: {}'.format(
                    error_message, headers)
            ))

        return RetVal(phantom.APP_SUCCESS, headers)

    def _generate_api_token(self, action_result, new_token=False):
        """ This function is used to generate token

        :param action_result: object of ActionResult class
        :param new_token: boolean. weather to fetch new token or fetch old access token
        :return: access token
        """
        self.save_progress("Fetching access token")

        if self._access_token and not new_token:
            self.save_progress("Using old token")
            return self._access_token

        payload = {"grant_type": "client_credentials"}

        self.save_progress("Fetching new token")
        # Querying endpoint to generate token
        response = requests.post(self._oauth_token_url, auth=HTTPBasicAuth(self._client_id, self._client_secret),  # nosemgrep
                                 data=payload, timeout=DEFAULT_REQUEST_TIMEOUT)
        if response.status_code not in [200, 201]:
            action_result.set_status(phantom.APP_ERROR, "Error fetching token from {}. Server returned {}".format(
                self._oauth_token_url, response.status_code))
            return None

        try:
            self._access_token = json.loads(response.text).get(HTTP_JSON_ACCESS_TOKEN)
        except Exception:
            action_result.set_status(phantom.APP_ERROR, "Error parsing response from server while fetching token")
            return None

        if not self._access_token:
            action_result.set_status(phantom.APP_ERROR, "Access token not found in response body")
            return None

        self._state[HTTP_JSON_ACCESS_TOKEN] = self._access_token
        return self._access_token

    def _handle_test_connectivity(self, param):
        self.save_progress("In action handler for: {}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))
        test_path = self._test_path

        if test_path:
            self.save_progress("Querying base url, {0}{1}, to test credentials".format(self._base_url, self._test_path))
            ret_val, _ = self._make_http_call(action_result, test_path, method=self._test_http_method)
        else:
            self.save_progress("Querying base url, {0}, to test credentials".format(self._base_url))
            ret_val, _ = self._make_http_call(action_result, method=self._test_http_method)

        if phantom.is_fail(ret_val):
            self.save_progress("Test Connectivity Failed")
        else:
            self.save_progress("Test Connectivity Passed")

        return ret_val

    def _verb(self, param, method):
        # These three are all the same thing except for the 'method'
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        location = param['location']
        body = param.get('body')

        if not location.startswith('/'):
            location = '/' + location

        if hasattr(location, 'decode'):
            location = location.decode('utf-8')

        ret_val, headers = self._get_headers(action_result, param.get('headers'))

        if phantom.is_fail(ret_val):
            return ret_val

        ret_val, _ = self._make_http_call(
            action_result,
            endpoint=location,
            method=method,
            headers=headers,
            verify=param.get('verify_certificate', False),
            data=body
        )
        return ret_val

    def _handle_get_file(self, param, method):

        action_result = ActionResult(dict(param))
        self.add_action_result(action_result)

        file_path = param[HTTP_JSON_FILE_PATH]
        file_path = file_path.strip(" ")
        file_path = file_path.rstrip("/")
        hostname = param.get(HTTP_JSON_HOSTNAME)
        if not hostname:
            hostname = self._base_url
            use_default_endpoint = True
        else:
            use_default_endpoint = False
        hostname = hostname.strip(" ")
        hostname = hostname.strip("/")

        if file_path == "":
            return action_result.set_status(phantom.APP_ERROR, HTTP_INVALID_PATH_ERR)

        encoded_file_path = quote(file_path)
        endpoint = "{0}/{1}".format(hostname, file_path)
        validate_endpoint = "{0}/{1}".format(hostname, encoded_file_path)

        if not validators.url(validate_endpoint):
            return action_result.set_status(phantom.APP_ERROR, HTTP_INVALID_URL_ERR)
        file_name = file_path.split('/')[-1]
        file_name = unquote_plus(file_name)
        try:
            ret_val, r = self._make_http_call(
                action_result,
                endpoint=endpoint,
                method=method,
                verify=param.get('verify_certificate', False),
                use_default_endpoint=use_default_endpoint
            )
        except Exception as e:
            err = self._get_error_message_from_exception(e)
            return action_result.set_status(phantom.APP_ERROR, HTTP_SERVER_CONNECTION_ERROR_MESSAGE.format(error=err))

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        if r.status_code == 200:
            return self._save_file_to_vault(action_result, r, file_name)
        else:
            return action_result.set_status(phantom.APP_ERROR, HTTP_SERVER_CONNECTION_ERROR_MESSAGE.format(error=r.status_code))

    def _handle_put_file(self, param, method):
        action_result = ActionResult(dict(param))
        self.add_action_result(action_result)

        input_filename = param.get(HTTP_JSON_FILE_NAME, "")

        # fetching phantom vault details
        try:
            success, message, vault_meta_info = ph_rules.vault_info(vault_id=param[HTTP_JSON_VAULT_ID])
            if not success or not vault_meta_info:
                error_msg = " Error Details: {}".format(unquote_plus(message)) if message else ''
                return action_result.set_status(phantom.APP_ERROR,
                                                "{}.{}".format(HTTP_UNABLE_TO_RETRIEVE_VAULT_ITEM_ERR_MSG, error_msg))
            vault_meta_info = list(vault_meta_info)
        except Exception as e:
            err = self._get_error_message_from_exception(e)
            return action_result.set_status(phantom.APP_ERROR,
                                            "{}. {}".format(HTTP_UNABLE_TO_RETRIEVE_VAULT_ITEM_ERR_MSG, err))

        file_is_present = False
        if input_filename:
            input_filename = input_filename.strip()
            for vault_data in vault_meta_info:
                if vault_data.get('name') == input_filename:
                    file_is_present = True
                    break
            if not file_is_present:
                return action_result.set_status(phantom.APP_ERROR, HTTP_ERR_FILENAME_NOT_IN_VAULT)
            else:
                vault_meta_info[0]['name'] = input_filename

        # phantom vault file path
        vault_path = vault_meta_info[0].get('path')
        try:
            f = open(vault_path, 'rb')
            files = {
                'file': f
            }
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, self._get_error_message_from_exception(e))

        # phantom vault file name
        dest_file_name = vault_meta_info[0].get('name')
        file_dest = param[HTTP_JSON_FILE_DEST]
        endpoint = param.get(HTTP_JSON_HOST)
        if not endpoint:
            endpoint = self._base_url
            use_default_endpoint = True
        else:
            use_default_endpoint = False

        file_dest = file_dest.strip('/')
        endpoint = endpoint.rstrip('/')

        # encoding input file name
        dest_file_name = dest_file_name.strip("/")
        validate_dest_file_name = quote(dest_file_name)

        # Returning an error if the filename is included in the file_destination path
        if dest_file_name in file_dest:
            return action_result.set_status(phantom.APP_ERROR, HTTP_EXCLUDE_FILENAME_ERR_MSG)

        destination_path = "{}/{}/{}".format(endpoint, file_dest, dest_file_name)
        validate_destination_path = "{}/{}/{}".format(endpoint, file_dest, validate_dest_file_name)

        if not validators.url(validate_destination_path):
            return action_result.set_status(phantom.APP_ERROR, HTTP_INVALID_URL_ERR)

        params = {'file_path': file_dest}

        try:
            ret_val, response = self._make_http_call(
                action_result,
                endpoint=destination_path,
                method=method,
                params=params,
                verify=param.get('verify_certificate', False),
                files=files,
                use_default_endpoint=use_default_endpoint
            )
        except Exception as e:
            err = self._get_error_message_from_exception(e)
            return action_result.set_status(phantom.APP_ERROR, HTTP_SERVER_CONNECTION_ERROR_MESSAGE.format(error=err))
        finally:
            f.close()

        if response.status_code == 200:
            summary = {'file_sent': destination_path}
            action_result.update_summary(summary)
            return action_result.set_status(phantom.APP_SUCCESS)
        else:
            return action_result.set_status(phantom.APP_ERROR, HTTP_SERVER_CONNECTION_ERROR_MESSAGE.format(error=response.status_code))

    def _save_file_to_vault(self, action_result, response, file_name):
        # Create a tmp directory on the vault partition

        guid = uuid.uuid4()
        if hasattr(Vault, 'get_vault_tmp_dir'):
            temp_dir = Vault.get_vault_tmp_dir()
        else:
            temp_dir = '/vault/tmp'

        local_dir = temp_dir + '/{}'.format(guid)
        self.save_progress("Using temp directory: {0}".format(guid))
        try:
            os.makedirs(local_dir)
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR,
                                            "Unable to create temporary folder {0}.".format(temp_dir), e)
        file_path = "{0}/{1}".format(local_dir, file_name)
        # open and download the file
        with open(file_path, 'wb') as f:
            f.write(response.content)
        contains = []
        file_ext = ''
        magic_str = magic.from_file(file_path)
        for regex, cur_contains, extension in self.MAGIC_FORMATS:
            if regex.match(magic_str):
                contains.extend(cur_contains)
                if not file_ext:
                    file_ext = extension
        file_name = '{}{}'.format(file_name, file_ext)

        # move the file to the vault
        status, vault_ret_message, vault_id = ph_rules.vault_add(file_location=file_path,
                                                                 container=self.get_container_id(), file_name=file_name,
                                                                 metadata={'contains': contains})
        curr_data = {}

        if status:
            curr_data[phantom.APP_JSON_VAULT_ID] = vault_id
            curr_data[phantom.APP_JSON_NAME] = file_name
            if contains:
                curr_data['file_type'] = ','.join(contains)
            action_result.add_data(curr_data)
            action_result.update_summary(curr_data)
            action_result.set_status(phantom.APP_SUCCESS, "File successfully retrieved and added to vault")
        else:
            action_result.set_status(phantom.APP_ERROR, phantom.APP_ERR_FILE_ADD_TO_VAULT)
            action_result.append_to_message(vault_ret_message)

        # remove the /tmp/<> temporary directory
        shutil.rmtree(local_dir)

        return action_result.get_status()

    def _handle_http_get(self, param):
        return self._verb(param, 'get')

    def _handle_http_post(self, param):
        return self._verb(param, 'post')

    def _handle_http_patch(self, param):
        return self._verb(param, 'patch')

    def _handle_http_put(self, param):
        return self._verb(param, 'put')

    def _handle_http_delete(self, param):
        return self._verb(param, 'delete')

    def _handle_http_head(self, param):
        return self._verb(param, 'head')

    def _handle_http_options(self, param):
        return self._verb(param, 'options')

    def handle_action(self, param):

        ret_val = phantom.APP_SUCCESS

        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        if action_id == 'test_connectivity':
            ret_val = self._handle_test_connectivity(param)

        elif action_id == 'http_get':
            ret_val = self._handle_http_get(param)

        elif action_id == 'http_post':
            ret_val = self._handle_http_post(param)

        elif action_id == 'http_put':
            ret_val = self._handle_http_put(param)

        elif action_id == 'http_patch':
            ret_val = self._handle_http_patch(param)

        elif action_id == 'http_delete':
            ret_val = self._handle_http_delete(param)

        elif action_id == 'http_head':
            ret_val = self._handle_http_head(param)

        elif action_id == 'http_options':
            ret_val = self._handle_http_options(param)

        elif action_id == 'get_file':
            ret_val = self._handle_get_file(param, 'get')

        elif action_id == 'put_file':
            ret_val = self._handle_put_file(param, 'post')

        return ret_val


if __name__ == '__main__':

    import argparse

    import pudb
    pudb.set_trace()

    argparser = argparse.ArgumentParser()

    argparser.add_argument('input_test_json', help='Input Test JSON file')
    argparser.add_argument('-u', '--username', help='username', required=False)
    argparser.add_argument('-p', '--password', help='password', required=False)
    argparser.add_argument('-v', '--verify', action='store_true', help='verify', required=False, default=False)

    args = argparser.parse_args()
    verify = args.verify
    session_id = None
    verify = args.verify

    if args.username and args.password:
        login_url = BaseConnector._get_phantom_base_url() + "login"
        try:
            print("Accessing the Login page")
            r = requests.get(login_url, verify=verify, timeout=DEFAULT_REQUEST_TIMEOUT)
            csrftoken = r.cookies['csrftoken']
            data = {'username': args.username, 'password': args.password, 'csrfmiddlewaretoken': csrftoken}
            headers = {'Cookie': 'csrftoken={0}'.format(csrftoken), 'Referer': login_url}

            print("Logging into Platform to get the session id")
            r2 = requests.post(login_url, verify=verify, data=data, headers=headers, timeout=DEFAULT_REQUEST_TIMEOUT)
            session_id = r2.cookies['sessionid']

        except Exception as e:
            print("Unable to get session id from the platform. Error: {0}".format(str(e)))
            sys.exit(1)

    if len(sys.argv) < 2:
        print("No test json specified as input")
        sys.exit(0)

    with open(sys.argv[1]) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = HttpConnector()
        connector.print_progress_message = True

        if session_id is not None:
            in_json['user_session_token'] = session_id

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    sys.exit(0)
