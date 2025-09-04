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
from soar_sdk.params import Param, Params

from ..asset import Asset
from ..classes import BaseHttpOutput
from ..common import logger
from ..request_maker import make_request

action_type = "investigate"
action_description = "This App facilitates making HTTP requests as actions"


class GetDataOutput(BaseHttpOutput):
    pass


class GetDataParams(Params):
    location: str = Param(
        description="Location (e.g. path/to/endpoint?query=string)",
        primary=True,
        cef_types=["endpoint"],
    )
    verify_certificate: bool = Param(description="Verify certificates (if using HTTPS)")
    headers: str = Param(description="Additional headers (JSON object with headers)", required=False)


def get_data(params: GetDataParams, soar: SOARClient, asset: Asset) -> GetDataOutput:
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
