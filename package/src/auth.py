# Copyright (c) 2025 Splunk Inc.
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
import json
from abc import ABC, abstractmethod
from typing import Optional, Tuple

import requests
from requests.auth import AuthBase, HTTPBasicAuth
from soar_sdk.exceptions import ActionFailure


class Authorization(ABC):
    @abstractmethod
    def create_auth(self, headers) -> Tuple[Optional[AuthBase], dict]:
        pass


class BasicAuth(Authorization):
    def __init__(self, asset):
        self.username = asset.username
        self.password = asset.password

    def create_auth(self, headers):
        return (self.username, self.password), headers


class TokenAuth(Authorization):
    def __init__(self, asset):
        self.auth_token_name = asset.auth_token_name
        self.auth_token = asset.auth_token

    def create_auth(self, headers):
        if self.auth_token and self.auth_token_name not in headers:
            headers[self.auth_token_name] = self.auth_token
        return None, headers


class OAuth(Authorization):
    def __init__(self, asset, soar_client):
        self.asset = asset
        self.soar = soar_client
        self.state_key = f"oauth_token_{asset.asset_id}"

    def _generate_new_token(self):
        token_url = self.asset.oauth_token_url
        client_id = self.asset.client_id
        client_secret = self.asset.client_secret

        payload = {"grant_type": "client_credentials"}

        try:
            response = requests.post(
                token_url,
                auth=HTTPBasicAuth(client_id, client_secret),
                data=payload,
                timeout=30,
            )
            response.raise_for_status()

            access_token = json.loads(response.text).get("access_token")

        except requests.exceptions.RequestException as e:
            raise ActionFailure(f"Error fetching OAuth token from {token_url}. Details: {e}") from e
        except json.JSONDecodeError as e:
            raise ActionFailure("Error parsing response from server while fetching token") from e

        if not access_token:
            raise ActionFailure("Access token not found in response body")

        self.soar.auth_state[self.state_key] = access_token

        return access_token

    def get_token(self, force_new: bool = False) -> str:
        cached_token = self.soar.auth_state.get(self.state_key)

        if cached_token and not force_new:
            return cached_token

        return self._generate_new_token()

    def create_auth(self, headers: dict) -> tuple[None, dict]:
        access_token = self.__get_token()

        headers["Authorization"] = f"Bearer {access_token}"

        return None, headers


class NoAuth(Authorization):
    def __init__(self, asset):
        pass

    def create_auth(self, headers):
        return None, headers


def get_auth_method(asset, soar_client):
    if asset.username and asset.password:
        return BasicAuth(asset)
    elif asset.auth_token_name and asset.auth_token:
        return TokenAuth(asset)
    elif asset.oauth_token_url and asset.client_id:
        return OAuth(asset, soar_client)
    return NoAuth(asset)
