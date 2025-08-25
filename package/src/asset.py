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
from soar_sdk.asset import AssetField, BaseAsset


class Asset(BaseAsset):
    base_url: str = AssetField(
        required=True,
        description="Base URL for making queries. (e.g. https://myservice/)",
    )
    test_path: str = AssetField(
        required=False,
        description="Endpoint for test connectivity. (e.g. /some/specific/endpoint , appended to Base URL)",
    )
    auth_token_name: str = AssetField(
        required=False,
        description="Type of authentication token",
        default="ph-auth-token",
    )
    auth_token: str = AssetField(
        required=False, description="Value of authentication token"
    )
    username: str = AssetField(
        required=False, description="Username (for HTTP basic auth)"
    )
    password: str = AssetField(
        required=False, description="Password (for HTTP basic auth)"
    )
    oauth_token_url: str = AssetField(
        required=False, description="URL to fetch oauth token from"
    )
    client_id: str = AssetField(required=False, description="Client ID (for OAuth)")
    client_secret: str = AssetField(
        required=False, description="Client Secret (for OAuth)"
    )
    timeout: float = AssetField(required=False, description="Timeout for HTTP calls")
    test_http_method: str = AssetField(
        required=False,
        description="HTTP Method for Test Connectivity",
        default="GET",
        value_list=[
            "GET",
            "HEAD",
            "POST",
            "PUT",
            "DELETE",
            "OPTIONS",
            "TRACE",
            "PATCH",
        ],
    )
