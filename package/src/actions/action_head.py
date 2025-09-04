from soar_sdk.abstract import SOARClient
from soar_sdk.params import Param, Params

from ..asset import Asset
from ..classes import BaseHttpOutput
from ..common import logger
from ..request_maker import make_request

action_description = "Perform a REST HEAD call to the server"
action_type = "investigate"


class GetHeadersOutput(BaseHttpOutput):
    pass


class GetHeadersParams(Params):
    location: str = Param(
        description="Location (e.g. path/to/endpoint?query=string)",
        primary=True,
        cef_types=["endpoint"],
    )
    verify_certificate: bool = Param(description="Verify certificates (if using HTTPS)")
    headers: str = Param(description="Additional headers (JSON object with headers)")


def get_headers(params: GetHeadersParams, soar: SOARClient, asset: Asset) -> GetHeadersOutput:
    logger.info("In action handler for: head_data")
    return make_request(
        asset=asset,
        soar=soar,
        method="HEAD",
        location=params.location,
        headers=params.headers,
        verify=params.verify_certificate,
        output=GetHeadersOutput,
        body=None,
    )
