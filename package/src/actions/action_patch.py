from soar_sdk.abstract import SOARClient
from soar_sdk.params import Param, Params

from ..asset import Asset
from ..classes import BaseHttpOutput
from ..common import logger
from ..request_maker import make_request

action_description = "Perform a REST PATCH call to the server"
action_type = "generic"


class PatchDataParams(Params):
    location: str = Param(
        description="Location (e.g. path/to/endpoint?query=string)",
        primary=True,
        cef_types=["endpoint"],
    )
    body: str = Param(description="PATCH body (query string, JSON, etc.)")
    verify_certificate: bool = Param(description="Verify certificates (if using HTTPS)")
    headers: str = Param(description="Additional headers (JSON object with headers)")


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
