# --
# File: https_connector.py
#
# Copyright (c) Phantom Cyber Corporation, 2014-2017
#
# This unpublished material is proprietary to Phantom Cyber.
# All rights reserved. The methods and
# techniques described herein are considered trade secrets
# and/or confidential. Reproduction or distribution, in whole
# or in part, is forbidden except by express written permission
# of Phantom Cyber.
#
# --

# Phantom imports
import phantom.app as phantom

from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult

import json
import requests
import xmltodict
from bs4 import BeautifulSoup

import urlparse
import socket


class RetVal(tuple):
    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class HttpConnector(BaseConnector):

    def __init__(self):

        super(HttpConnector, self).__init__()

        self._state = None
        self._base_url = None
        self._timeout = None

    def initialize(self):

        self._state = self.load_state()

        config = self.get_config()
        self._base_url = config['base_url'].strip('/')
        self._token = config.get('auth_token')
        self._username = config.get('username')
        self._password = config.get('password', '')

        if 'timeout' in config:
            self._timeout = int(config['timeout'])

        # Verify base URL. Make sure it's not 127.0.0.1
        try:

            addr = urlparse.urlparse(self._base_url).hostname

            try:
                unpacked = socket.gethostbyname(addr)
            except:
                packed = socket.inet_aton(addr)
                unpacked = socket.inet_ntoa(packed)

            if unpacked.startswith('127.'):
                return self.set_status(phantom.APP_ERROR, 'Accessing 127.0.0.1 is not allowed')

        except TypeError:
            return self.set_status(phantom.APP_ERROR, 'Failed to parse URL ({}). Should look like "http(s)://location/optional_path"'.format(self._base_url))

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
            error_text = soup.text
            split_lines = error_text.split('\n')
            split_lines = [x.strip() for x in split_lines if x.strip()]
            error_text = '\n'.join(split_lines)
        except:
            error_text = "Cannot parse error details"

        if 200 <= response.status_code < 400:
            return RetVal(phantom.APP_SUCCESS, soup.text)

        message = "Status Code: {0}. Data from server:\n{1}\n".format(status_code, error_text)

        message = message.replace('{', '{{').replace('}', '}}')

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), soup.text)

    def _process_json_response(self, response, action_result):

        try:
            resp_json = response.json()
        except Exception as e:
            self.debug_print("Unable to parse the response into a dictionary", e)
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Unable to parse JSON response. Error: {0}".format(str(e))))

        if 200 <= response.status_code < 400:
            return RetVal(phantom.APP_SUCCESS, resp_json)

        message = "Error from server. Status Code: {0} Data from server: {1}".format(response.status_code,
                                                                                     response.text.replace('{', '{{').
                                                                                     replace('}', '}}'))

        if resp_json.get('error'):
            message = "Error from server. Status Code: {0} Data from server: {1}".format(
                response.status_code, resp_json['error']['message'])

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), resp_json)

    def _process_xml_response(self, r, action_result):

        try:
            resp_json = xmltodict.parse(r.text)
        except Exception as e:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Unable to parse XML response. Error: {0}".format(str(e))))

        if 200 <= r.status_code < 400:
            return RetVal(phantom.APP_SUCCESS, resp_json)

        message = "Error from server. Status Code: {0} Data from server: {1}".format(
                r.status_code, r.text.replace('{', '{{').replace('}', '}}'))

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), resp_json)

    def _process_response(self, r, action_result):

        if hasattr(action_result, 'add_debug_data'):
            action_result.add_debug_data({'r_status_code': r.status_code})
            action_result.add_debug_data({'r_text': r.text})
            action_result.add_debug_data({'r_headers': r.headers})

        if 'xml' in r.headers.get('Content-Type', ''):
            return self._process_xml_response(r, action_result)

        if 'json' in r.headers.get('Content-Type', ''):
            return self._process_json_response(r, action_result)

        if 'html' in r.headers.get('Content-Type', ''):
            return self._process_html_response(r, action_result)

        if not r.text:
            return self._process_empty_reponse(r, action_result)

        if 200 <= r.status_code < 400:
            return RetVal(phantom.APP_SUCCESS, r.text)

        message = "Can't process response from server. Status Code: {0} Data from server: {1}".format(
                r.status_code, r.text.replace('{', '{{').replace('}', '}}'))

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), r.text)

    def _make_http_call(self, action_result, endpoint='', method='get', headers=None, verify=False, data=None):

        auth = None
        if self._token:
            if 'ph-auth-token' not in headers:
                headers['ph-auth-token'] = self._token
        elif self._username:
            auth = (self._username, self._password)

        try:
            request_func = getattr(requests, method)
        except AttributeError:
            return action_result.set_status(phantom.APP_ERROR, "Invalid method: {0}".format(method))

        url = self._base_url + endpoint

        try:
            r = request_func(
                    url,
                    auth=auth,
                    data=data,
                    verify=verify,
                    headers=headers,
                    timeout=self._timeout)
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, "Error Connecting to server. Details: {0}".format(str(e)))

        ret_val, parsed_body = self._process_response(r, action_result)

        resp_data = {'method': method.upper(), 'location': url}
        resp_data['parsed_response_body'] = parsed_body
        resp_data['response_body'] = r.text if 'json' not in r.headers.get('Content-Type', '') else parsed_body
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

    def _handle_test_connectivity(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        self.save_progress("Querying base url, {0}, to test credentials".format(self._base_url))

        ret_val = self._make_http_call(action_result)

        if phantom.is_fail(ret_val):
            self.save_progress("Test connectivity failed")
        else:
            self.save_progress("Test connectivity passed")

        return ret_val

    def _handle_get(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        location = param['location']
        if not location.startswith('/'):
            location = '/' + location

        headers = param.get('headers')
        if headers:
            try:
                headers = json.loads(headers)
            except Exception as e:
                return action_result.set_status(phantom.APP_ERROR, u'Failed to parse headers as JSON object. error: {}, headers: {}'.format(str(e), unicode(headers)))

        return self._make_http_call(action_result, endpoint=location, headers=headers, verify=param['verify_certificate'])

    def _handle_post(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        location = param['location']
        if not location.startswith('/'):
            location = '/' + location

        headers = param.get('headers')
        if headers:
            try:
                headers = json.loads(headers)
            except Exception as e:
                return action_result.set_status(phantom.APP_ERROR, u'Failed to parse headers as JSON object. error: {}, headers: {}'.format(str(e), unicode(headers)))

        return self._make_http_call(action_result, endpoint=location, method='post', headers=headers, verify=param['verify_certificate'], data=param['body'])

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

        return ret_val


if __name__ == '__main__':

    import sys
    # import pudb
    # pudb.set_trace()

    if (len(sys.argv) < 2):
        print "No test json specified as input"
        exit(0)

    with open(sys.argv[1]) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = HttpConnector()
        connector.print_progress_message = True
        ret_val = connector._handle_action(json.dumps(in_json), None)
        print json.dumps(json.loads(ret_val), indent=4)

    exit(0)
