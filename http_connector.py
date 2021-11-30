# File: http_connector.py
# Copyright (c) 2016-2021 Splunk Inc.
#
# SPLUNK CONFIDENTIAL - Use or disclosure of this material in whole or in part
# without a valid written license from Splunk Inc. is PROHIBITED.
#

#
# --

# Phantom imports
import phantom.app as phantom

# THIS Connector imports
from http_consts import *

from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult

import json
import requests
import xmltodict
from bs4 import BeautifulSoup, UnicodeDammit

try:
    from urllib.parse import urlparse, unquote_plus
except ImportError:
    from urllib import unquote_plus
    from urlparse import urlparse

import socket
import sys


class RetVal(tuple):
    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class HttpConnector(BaseConnector):

    def __init__(self):

        super(HttpConnector, self).__init__()

        self._state = None
        self._base_url = None
        self._test_path = None
        self._timeout = None
        self._python_version = None
        self._token_name = None
        self._token = None
        self._username = None
        self._password = None
        self._oauth_token_url = None
        self._client_id = None
        self._client_secret = None
        self._state = None
        self.access_token_retry = True

    def _handle_py_ver_compat_for_input_str(self, input_str):
        """
        This method returns the encoded|original string based on the Python version.
        :param input_str: Input string to be processed
        :return: input_str (Processed input string based on following logic 'input_str - Python 3; encoded input_str - Python 2')
        """
        try:
            if input_str and self._python_version < 3:
                input_str = UnicodeDammit(input_str).unicode_markup.encode('utf-8')
        except Exception as ex:
            self.debug_print("Exception: {}".format(ex))
            self.debug_print("Error occurred while handling python 2to3 compatibility for the input string")

        return input_str

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
            self.debug_print("Exception: {}".format(ex))
            pass

        try:
            error_msg = self._handle_py_ver_compat_for_input_str(error_msg)
        except TypeError:
            error_msg = TYPE_ERROR_MESSAGE
        except Exception as ex:
            self.debug_print("Exception: {}".format(ex))
            error_msg = HTTP_ERROR_MESSAGE

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
            self.debug_print("Exception: {}".format(ex))
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
        # Fetching the Python major version
        try:
            self._python_version = int(sys.version_info[0])
        except Exception as ex:
            self.debug_print("Exception: {}".format(ex))
            return self.set_status(phantom.APP_ERROR, "Error occurred while getting the Phantom server's Python major version.")

        config = self.get_config()
        self._base_url = self._handle_py_ver_compat_for_input_str(config['base_url'].strip('/'))
        self._token_name = self._handle_py_ver_compat_for_input_str(config.get('auth_token_name', 'ph-auth-token'))
        self._token = config.get('auth_token')

        self._username = config.get('username')
        self._password = config.get('password', '')

        self._oauth_token_url = config.get('oauth_token_url')
        if self._oauth_token_url:
            self._oauth_token_url = self._oauth_token_url.strip('/')
        self._client_id = config.get('client_id')
        self._client_secret = config.get('client_secret')

        self._state = self.load_state()

        if 'test_path' in config:
            try:
                if not config['test_path'].startswith('/'):
                    self._test_path = '/' + config['test_path']
                else:
                    self._test_path = config['test_path']
                self._test_path = self._handle_py_ver_compat_for_input_str(self._test_path)
            except Exception as e:
                error_message = self._get_error_message_from_exception(e)
                return self.set_status(phantom.APP_ERROR, "Given endpoint value is invalid: {0}".format(error_message))

        if 'timeout' in config:
            self._timeout = self._validate_integers(self, config.get("timeout"), "timeout")
            if self._timeout is None:
                return self.get_status()

        parsed = urlparse(self._base_url)

        if not parsed.scheme or not parsed.hostname:
            return self.set_status(phantom.APP_ERROR, 'Failed to parse URL ({}). Should look like "http(s)://location/optional_path"'.format(self._base_url))

        # Make sure base_url isn't 127.0.0.1
        addr = parsed.hostname
        try:
            unpacked = socket.gethostbyname(addr)
        except Exception as ex:
            self.debug_print("Exception: {}".format(ex))
            try:
                packed = socket.inet_aton(addr)
                unpacked = socket.inet_aton(packed)
            except Exception as ex:
                self.debug_print("Exception: {}".format(ex))
                # gethostbyname can fail even when the addr is a hostname
                # If that happens, I think we can assume that it isn't localhost
                unpacked = ""

        if unpacked.startswith('127.'):
            return self.set_status(phantom.APP_ERROR, 'Accessing 127.0.0.1 is not allowed')

        return phantom.APP_SUCCESS

    def finalize(self):

        self.save_state(self._state)
        return phantom.APP_SUCCESS

    def _process_empty_reponse(self, response, action_result):

        if 200 <= response.status_code < 400:
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
            self.debug_print("Exception: {}".format(ex))
            error_text = "Cannot parse error details"

        if 200 <= response.status_code < 400:
            return RetVal(phantom.APP_SUCCESS, soup.text)

        error_text = self._handle_py_ver_compat_for_input_str(error_text)
        message = "Status Code: {0}. Data from server:\n{1}\n".format(status_code, unquote_plus(error_text))

        message = message.replace('{', '{{').replace('}', '}}')

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), soup.text)

    def _process_json_response(self, response, action_result):

        resp_json = {}
        try:
            if response:
                resp_json = response.json()
        except Exception as e:
            error_message = self._get_error_message_from_exception(e)
            self.debug_print("Unable to parse the response into a dictionary", error_message)
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Unable to parse JSON response. Error: {0}".format(error_message)))

        if 200 <= response.status_code < 400:
            return RetVal(phantom.APP_SUCCESS, resp_json)

        message_template = 'Error from server. Status Code: {0} Data from server: {1}'
        message = message_template.format(
            response.status_code, self._handle_py_ver_compat_for_input_str(response.text.replace('{', '{{').replace('}', '}}')))

        error_field_name = 'error'
        message_field_name = 'message'
        if error_field_name in resp_json:
            error_field = resp_json[error_field_name]

            if isinstance(error_field, dict) and message_field_name in error_field:
                error_message = error_field[message_field_name]
            else:
                error_message = error_field

            message = message_template.format(response.status_code, self._handle_py_ver_compat_for_input_str(error_message))

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
                r.status_code, self._handle_py_ver_compat_for_input_str(r.text.replace('{', '{{').replace('}', '}}')))

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), resp_json)

    def _process_response(self, r, action_result):

        if hasattr(action_result, 'add_debug_data'):
            action_result.add_debug_data({'r_status_code': r.status_code})
            action_result.add_debug_data({'r_text': r.text})
            action_result.add_debug_data({'r_headers': r.headers})

        if not r.text:
            return self._process_empty_reponse(r, action_result)

        if 'xml' in r.headers.get('Content-Type', ''):
            return self._process_xml_response(r, action_result)

        if 'json' in r.headers.get('Content-Type', '') or 'javascript' in r.headers.get('Content-Type', ''):
            return self._process_json_response(r, action_result)

        if 'html' in r.headers.get('Content-Type', ''):
            return self._process_html_response(r, action_result)

        if 200 <= r.status_code < 400:
            return RetVal(phantom.APP_SUCCESS, r.text)

        message = "Can't process response from server. Status Code: {0} Data from server: {1}".format(
                r.status_code, self._handle_py_ver_compat_for_input_str(r.text.replace('{', '{{').replace('}', '}}')))

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), r.text)

    def _make_http_call(self, action_result, endpoint='', method='get', headers=None, verify=False, data=None):

        auth = None
        headers = {} if not headers else headers
        if self._username:
            self.save_progress("Using HTTP Basic auth to authenticate")
            auth = (self._username, self._password)
        elif self._oauth_token_url and self._client_id:
            self.save_progress("Using OAuth to authenticate")
            access_token = self._generate_api_token(action_result)
            if phantom.is_fail(access_token):
                return None
            headers['Authorization'] = 'Bearer {}'.format(access_token)
        elif self._token_name:
            self.save_progress("Using provided token to authenticate")
            if self._token and self._token_name not in headers:
                headers[self._token_name] = self._token
        else:
            return action_result.set_status(phantom.APP_ERROR, "No authentication method set")

        try:
            request_func = getattr(requests, method)
        except AttributeError:
            return action_result.set_status(phantom.APP_ERROR, "Invalid method: {0}".format(method))

        url = self._base_url + endpoint

        try:
            r = request_func(
                    url,
                    auth=auth,
                    data=UnicodeDammit(data).unicode_markup.encode('utf-8') if isinstance(data, str) else data,
                    verify=verify,
                    headers=headers,
                    timeout=self._timeout)
        except Exception as e:
            error_message = self._get_error_message_from_exception(e)
            return action_result.set_status(phantom.APP_ERROR, "Error Connecting to server. Details: {0}".format(error_message))

        # fetch new token if old one has expired
        if (r.status_code == 401) and self.access_token_retry:
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
            return action_result.set_status(phantom.APP_SUCCESS)

        ret_val, parsed_body = self._process_response(r, action_result)
        resp_data = {
            'method': method.upper(),
            'location': url, 'parsed_response_body': parsed_body,
            'response_body': r.text if 'json' not in r.headers.get('Content-Type', '') and 'javascript' not in r.headers.get('Content-Type', '') else parsed_body
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
            return ret_val

        return action_result.set_status(phantom.APP_SUCCESS)

    def _get_headers(self, action_result, headers):
        # Not to be confused with the action "get headers"
        if headers is None:
            return RetVal(phantom.APP_SUCCESS)

        headers = self._handle_py_ver_compat_for_input_str(headers)

        if hasattr(headers, 'decode'):
            headers = headers.decode('utf-8')

        try:
            headers = json.loads(headers)
        except Exception as e:
            error_message = self._get_error_message_from_exception(e)
            return RetVal(action_result.set_status(
                phantom.APP_ERROR,
                'Failed to parse headers as JSON object. error: {}, headers: {}'.format(error_message, self._handle_py_ver_compat_for_input_str(headers))
            ))

        return RetVal(phantom.APP_SUCCESS, headers)

    def _generate_api_token(self, action_result, new_token=False):
        """ This function is used to generate token

        :param action_result: object of ActionResult class
        :param new_token: boolean. weather to fetch new token or fetch old access token
        :return: access token
        """
        self.save_progress("Fetching access token")

        access_token = None
        if not new_token:
            self.save_progress("Using old token")
            access_token = self._state.get('access_token')

        if access_token is not None:
            return access_token

        payload = {"grant_type": "client_credentials"}

        self.save_progress("Fetching new token")
        # Querying endpoint to generate token
        response = requests.post(self._oauth_token_url, auth=(self._client_id, self._client_secret), data=payload)
        if response.status_code != 200:
            return action_result.set_status(phantom.APP_ERROR, "Error fetching token from {}. Server returned {}".format(self._oauth_token_url, response.status_code))

        try:
            access_token = json.loads(response.text).get("access_token")
        except Exception:
            return action_result.set_status(phantom.APP_ERROR, "Error parsing response from server while fetching token")

        if not access_token:
            return action_result.set_status(phantom.APP_ERROR, "Access token not found in response body")

        self._state['access_token'] = access_token
        return access_token

    def _handle_test_connectivity(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))
        test_path = self._test_path

        if test_path:
            self.save_progress("Querying base url, {0}{1}, to test credentials".format(self._base_url, self._test_path))
            ret_val = self._make_http_call(action_result, test_path)
        else:
            self.save_progress("Querying base url, {0}, to test credentials".format(self._base_url))
            ret_val = self._make_http_call(action_result)

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

        location = self._handle_py_ver_compat_for_input_str(location)

        if hasattr(location, 'decode'):
            location = location.decode('utf-8')

        if body:
            body = self._handle_py_ver_compat_for_input_str(body)

        ret_val, headers = self._get_headers(action_result, param.get('headers'))

        if phantom.is_fail(ret_val):
            return ret_val

        return self._make_http_call(
            action_result,
            endpoint=location,
            method=method,
            headers=headers,
            verify=param.get('verify_certificate', False),
            data=body
        )

    def _handle_get(self, param):
        return self._verb(param, 'get')

    def _handle_post(self, param):
        return self._verb(param, 'post')

    def _handle_patch(self, param):
        return self._verb(param, 'patch')

    def _handle_put(self, param):
        return self._verb(param, 'put')

    def _handle_delete(self, param):
        return self._verb(param, 'delete')

    def _handle_head(self, param):
        return self._verb(param, 'head')

    def _handle_options(self, param):
        return self._verb(param, 'options')

    def handle_action(self, param):

        ret_val = phantom.APP_SUCCESS

        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        if action_id == 'test_connectivity':
            ret_val = self._handle_test_connectivity(param)

        elif action_id == 'http_get':
            ret_val = self._handle_get(param)

        elif action_id == 'http_post':
            ret_val = self._handle_post(param)

        elif action_id == 'http_put':
            ret_val = self._handle_put(param)

        elif action_id == 'http_patch':
            ret_val = self._handle_patch(param)

        elif action_id == 'http_delete':
            ret_val = self._handle_delete(param)

        elif action_id == 'http_head':
            ret_val = self._handle_head(param)

        elif action_id == 'http_options':
            ret_val = self._handle_options(param)

        return ret_val


if __name__ == '__main__':

    import pudb
    import argparse
    pudb.set_trace()

    argparser = argparse.ArgumentParser()

    argparser.add_argument('input_test_json', help='Input Test JSON file')
    argparser.add_argument('-u', '--username', help='username', required=False)
    argparser.add_argument('-p', '--password', help='password', required=False)

    args = argparser.parse_args()
    session_id = None

    if args.username and args.password:
        login_url = BaseConnector._get_phantom_base_url() + "login"
        try:
            print("Accessing the Login page")
            r = requests.get(login_url, verify=False)
            csrftoken = r.cookies['csrftoken']
            data = {'username': args.username, 'password': args.password, 'csrfmiddlewaretoken': csrftoken}
            headers = {'Cookie': 'csrftoken={0}'.format(csrftoken), 'Referer': login_url}

            print("Logging into Platform to get the session id")
            r2 = requests.post(login_url, verify=False, data=data, headers=headers)
            session_id = r2.cookies['sessionid']

        except Exception as e:
            print("Unable to get session id from the platform. Error: {0}".format(str(e)))
            exit(1)

    if len(sys.argv) < 2:
        print("No test json specified as input")
        exit(0)

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

    exit(0)
