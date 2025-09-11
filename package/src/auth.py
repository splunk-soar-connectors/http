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
    """
    Abstract base class for defining an authentication strategy.

    Each strategy must implement the `create_auth` method, which is responsible
    for preparing the necessary authentication objects and headers for a request.
    """

    @abstractmethod
    def create_auth(self, headers) -> Tuple[Optional[AuthBase], dict]:
        """
        Prepares authentication components for an HTTP request.

        Args:
            headers (dict): The initial dictionary of headers for the request.

        Returns:
            Tuple[Optional[AuthBase], dict]: A tuple containing:
                - An optional `requests.auth.AuthBase` object.
                - The updated headers dictionary.
        """
        pass


class BasicAuth(Authorization):
    """
    Implements HTTP Basic Authentication using username and password.
    """

    def __init__(self, asset):
        self.username = asset.username
        self.password = asset.password

    def create_auth(self, headers):
        return (self.username, self.password), headers


class TokenAuth(Authorization):
    """
    Implements authentication using a static token in a specified header.
    """

    def __init__(self, asset):
        self.auth_token_name = asset.auth_token_name
        self.auth_token = asset.auth_token

    def create_auth(self, headers):
        if self.auth_token and self.auth_token_name not in headers:
            headers[self.auth_token_name] = self.auth_token
        return None, headers


class OAuth(Authorization):
    """
    Implements OAuth 2.0 Client Credentials Grant Flow.

    This strategy fetches an access token from a token URL, caches it in the
    app's authentication state, and adds it to the request as a Bearer token.
    """

    def __init__(self, asset, soar_client):
        self.asset = asset
        self.soar = soar_client
        self.state_key = f"oauth_token_{asset.asset_id}"

    def _generate_new_token(self):
        """
        Fetches a new OAuth access token and saves it to the app's auth_state.
        """
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
        """
        Retrieves a token, either from the cached state or by fetching a new one.

        Args:
            force_new (bool): If True, forces a new token to be fetched,
                              ignoring any cached token.
        """
        cached_token = self.soar.auth_state.get(self.state_key)

        if cached_token and not force_new:
            return cached_token

        return self._generate_new_token()

    def create_auth(self, headers: dict) -> tuple[None, dict]:
        access_token = self.__get_token()

        headers["Authorization"] = f"Bearer {access_token}"

        return None, headers


class NoAuth(Authorization):
    """
    Represents an anonymous request with no authentication.
    """

    def __init__(self, asset):
        pass

    def create_auth(self, headers):
        return None, headers


def get_auth_method(asset, soar_client):
    """
    Factory function to select and instantiate the appropriate auth strategy.

    Based on the provided asset configuration, this function determines which
    authentication method to use (Basic, Token, OAuth, or None) and returns
    an instance of the corresponding strategy class.

    Args:
        asset (Asset): The asset configuration object.
        soar_client (SOARClient): The SOAR client, needed for stateful strategies like OAuth.

    Returns:
        Authorization: An instance of a class that implements the Authorization strategy.
    """
    if asset.username and asset.password:
        return BasicAuth(asset)
    elif asset.auth_token_name and asset.auth_token:
        return TokenAuth(asset)
    elif asset.oauth_token_url and asset.client_id:
        return OAuth(asset, soar_client)
    return NoAuth(asset)
