from soar_sdk.abstract import SOARClient
from soar_sdk.params import Param

from ..asset import Asset
from ..classes import BaseHttpOutput, BaseHttpParams
from ..common import logger
from ..request_maker import make_request

action_description = "Perform a REST PATCH call to the server"
action_type = "generic"


class PatchDataParams(BaseHttpParams):
    body: str = Param(description="PATCH body (query string, JSON, etc.)")


class PatchDataOutput(BaseHttpOutput):
    pass


def patch_data(params: PatchDataParams, soar: SOARClient, asset: Asset) -> PatchDataOutput:
    logger.info("In action handler for: patch_data")
    return make_request(
        asset=asset,
        soar=soar,
        method="PATCH",
        location=params.location,
        headers=params.headers,
        verify=params.verify_certificate,
        output=PatchDataOutput,
        body=None,
    )
