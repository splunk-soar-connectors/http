from soar_sdk.abstract import SOARClient

from ..asset import Asset
from ..classes import BaseHttpOutput, BaseHttpParams
from ..common import logger
from ..request_maker import make_request

action_description = "Perform a REST OPTIONS call to the server"
action_type = "investigate"


class GetOptionsParams(BaseHttpParams):
    pass


class GetOptionsOutput(BaseHttpOutput):
    pass


def get_options(params: GetOptionsParams, soar: SOARClient, asset: Asset) -> GetOptionsOutput:
    logger.info("In action handler for: get_options")
    return make_request(
        asset=asset,
        soar=soar,
        method="OPTIONS",
        location=params.location,
        headers=params.headers,
        verify=params.verify_certificate,
        output=GetOptionsOutput,
        body=None,
    )
