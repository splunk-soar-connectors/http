from soar_sdk.abstract import SOARClient
from soar_sdk.params import Param

from ..asset import Asset
from ..classes import BaseHttpOutput, BaseHttpParams
from ..common import logger
from ..request_maker import make_request


class DeleteDataOutput(BaseHttpOutput):
    """
    Defines the structured output for the 'DELETE Request' action.
    """

    pass


class DeleteDataParams(BaseHttpParams):
    """
    Defines the input parameters for the 'DELETE Request' action.
    """

    body: str = Param(description="DELETE body (query string, JSON, etc.)", required=False)


def delete_data(params: DeleteDataParams, soar: SOARClient, asset: Asset) -> DeleteDataOutput:
    """Perform a REST DELETE call to the server."""
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
