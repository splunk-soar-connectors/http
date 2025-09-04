from soar_sdk.abstract import SOARClient

from ..asset import Asset
from ..classes import BaseHttpOutput, BaseHttpParams
from ..common import logger
from ..request_maker import make_request

action_description = "Perform a REST HEAD call to the server"
action_type = "investigate"


class GetHeadersOutput(BaseHttpOutput):
    pass


class GetHeadersParams(BaseHttpParams):
    pass


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
