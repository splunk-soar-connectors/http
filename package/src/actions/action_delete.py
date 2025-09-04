from soar_sdk.abstract import SOARClient
from soar_sdk.params import Param

from ..asset import Asset
from ..classes import BaseHttpOutput, BaseHttpParams
from ..common import logger
from ..request_maker import make_request

action_description = "Perform a REST DELETE call to the server"
action_type = "generic"


class DeleteDataOutput(BaseHttpOutput):
    pass


class DeleteDataParams(BaseHttpParams):
    body: str = Param(description="DELETE body (query string, JSON, etc.)")


def delete_data(params: DeleteDataParams, soar: SOARClient, asset: Asset) -> DeleteDataOutput:
    logger.info("In action handler for: delete_data")
    return make_request(
        asset=asset,
        soar=soar,
        method="DELETE",
        location=params.location,
        headers=params.headers,
        verify=params.verify_certificate,
        output=DeleteDataOutput,
        body=None,
    )
