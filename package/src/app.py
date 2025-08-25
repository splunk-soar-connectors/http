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
import requests
from soar_sdk.abstract import SOARClient
from soar_sdk.app import App
from soar_sdk.exceptions import ActionFailure

from .actions.action_get import http_get, get_action_type, get_action_description
from .asset import Asset

from .common import logger


app = App(
    name="http",
    app_type="generic",
    logo="logo.svg",
    logo_dark="logo_dark.svg",
    product_vendor="Splunk Inc.",
    product_name="http",
    publisher="Splunk Inc.",
    appid="dc312038-005f-470f-badb-8a353ba9bb5b",
    fips_compliant=False,
    asset_cls=Asset,
)


@app.test_connectivity()
def test_connectivity(soar: SOARClient, asset: Asset) -> None:
    logger.info("Action 'Test Connectivity' started.")
    full_url = asset.base_url.rstrip("/")
    if asset.test_path:
        full_url = full_url + "/" + asset.test_path.lstrip("/")
    logger.info(f"Querying base url, {full_url}, to test credentials.")

    try:
        response = requests.request(
            method=asset.test_http_method,
            url=full_url,
            verify=False,
            timeout=asset.timeout,
        )
        logger.info(f"Got status code {response.status_code}.")
        response.raise_for_status()

    except requests.exceptions.RequestException as e:
        logger.error(f"Test connectivity failed, error: {e}.")
        raise ActionFailure(f"Test connectivity failed, details: {e}.") from e

    logger.info("Test connectivity passed!")


app.register_action(
    http_get, action_type=get_action_type, description=get_action_description
)

if __name__ == "__main__":
    app.cli()
