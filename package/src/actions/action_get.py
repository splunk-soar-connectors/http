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
from soar_sdk.abstract import SOARClient

from ..asset import Asset
from ..classes import BaseHttpOutput, BaseHttpParams
from ..common import logger
from ..request_maker import make_request


class GetDataOutput(BaseHttpOutput):
    """
    Defines the structured output for the 'GET Request' action.
    """

    pass


class GetDataParams(BaseHttpParams):
    """
    Defines the input parameters for the 'GET Request' action.
    """

    pass


def get_data(params: GetDataParams, soar: SOARClient, asset: Asset) -> GetDataOutput:
    """Perform a REST GET call to the server."""
    logger.info("In action handler for: get_data")
    return make_request(
        asset=asset,
        soar=soar,
        method="GET",
        location=params.location,
        headers=params.headers,
        verify=params.verify_certificate,
        output=GetDataOutput,
        body=None,
    )
