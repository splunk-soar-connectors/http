# --
# File: https_connector.py
#
# Copyright (c) Phantom Cyber Corporation, 2014-2016
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
from requests.exceptions import Timeout, SSLError

import urlparse
import socket

TIMEOUT = 120


class HttpConnector(BaseConnector):

    def _http_get(self, param):
        action_result = ActionResult(dict(param))
        self.add_action_result(action_result)
        base = self.config.get('base_url', '')
        if base.endswith('/'):
            base = base[:-1]
        location = param['location']
        if not location.startswith('/'):
            location = '/' + location
        url = base + location
        try:
            response = requests.get(url, verify=param.get('verify_certificate', False), auth=self.use_auth, headers=self.headers, timeout=TIMEOUT)
        except Timeout as e:
            action_result.set_status(phantom.APP_ERROR, 'HTTP GET request timed out: ' + str(e))
        except SSLError as e:
            action_result.set_status(phantom.APP_ERROR, 'HTTPS SSL validation failed: ' + str(e))
        else:
            data = {'method': 'GET', 'location': url}
            try:
                data['response_body'] = response.json()
            except Exception:
                data['response_body'] = response.text
            try:
                data['response_headers'] = dict(response.headers)
            except Exception:
                pass
            action_result.add_data(data)
            action_result.update_summary({
                'status_code': response.status_code,
                'reason': response.reason,
            })
            if response.status_code >= 200 and response.status_code < 300:
                action_result.set_status(phantom.APP_SUCCESS, 'Request succeeded')
            else:
                action_result.set_status(phantom.APP_ERROR, 'Request returned error')
        return action_result.get_status()

    def _http_post(self, param):
        action_result = ActionResult(dict(param))
        self.add_action_result(action_result)
        base = self.config.get('base_url', '')
        if base.endswith('/'):
            base = base[:-1]
        location = param['location']
        if not location.startswith('/'):
            location = '/' + location
        url = base + location
        try:
            response = requests.post(url, data=param.get('body'), verify=param.get('verify_certificate', False), auth=self.use_auth, headers=self.headers, timeout=TIMEOUT)
        except Timeout as e:
            action_result.set_status(phantom.APP_ERROR, 'HTTP POST request timed out: ' + str(e))
        except SSLError as e:
            action_result.set_status(phantom.APP_ERROR, 'HTTPS SSL validation failed: ' + str(e))
        else:
            data = {'method': 'POST', 'location': url}
            try:
                data['response_body'] = response.json()
            except Exception:
                data['response_body'] = response.text
            try:
                data['response_headers'] = dict(response.headers)
            except Exception:
                pass
            action_result.add_data(data)
            action_result.update_summary({
                'status_code': response.status_code,
                'reason': response.reason,
            })
            if response.status_code >= 200 and response.status_code < 300:
                action_result.set_status(phantom.APP_SUCCESS, 'Request succeeded')
            else:
                action_result.set_status(phantom.APP_ERROR, 'Request returned error')
        return action_result.get_status()

    def handle_action(self, param):
        """Function that handles all the actions

        Args:

        Return:
            A status code
        """

        result = None
        action = self.get_action_identifier()
        self.config = config = self.get_config()

        self.use_auth = None
        if config.get('username') and config.get('password'):
            self.use_auth = (config['username'], config['password'])
        headers = param.get('headers', {})
        base_url = self.config.get('base_url', '')
        try:
            addr = urlparse.urlparse(base_url).hostname
            
            try:
                unpacked = socket.gethostbyname(addr)
            except:
                packed = socket.inet_aton(addr)
                unpacked = socket.inet_ntoa(packed)
        except TypeError as e:
            self.set_status(phantom.APP_ERROR, 'Failed to parse URL ({}). Should look like "http(s)://location/optional_path"'.format(base_url))
            return self.get_status()

        if unpacked.startswith('127.'):
            self.set_status(phantom.APP_ERROR, 'Accessing 127.0.0.1 is not allowed')
            return self.get_status()
        if headers:
            try:
                headers = json.loads(headers)
            except Exception as e:
                raise Exception(u'Failed to parse headers as JSON object. error: {}, headers: {}'.format(str(e), unicode(headers)))
        if config.get('auth_token'):
            if 'ph-auth-token' not in headers:
                headers['ph-auth-token'] = config.get('auth_token')
        self.headers = headers and headers or None

        if (action == 'http_get'):
            result = self._http_get(param)
        elif (action == 'http_post'):
            result = self._http_post(param)

        return result

if __name__ == '__main__':

    import sys
    # import simplejson as json
    import pudb

    pudb.set_trace()

    with open(sys.argv[1]) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=' ' * 4))

        connector = HttpConnector()
        connector.print_progress_message = True
        ret_val = connector._handle_action(json.dumps(in_json), None)
        print json.dumps(json.loads(ret_val), indent=4)

    exit(0)
