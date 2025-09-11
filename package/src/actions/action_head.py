from soar_sdk.abstract import SOARClient

from ..asset import Asset
from ..classes import BaseHttpOutput, BaseHttpParams
from ..common import logger
from ..request_maker import make_request


class GetHeadersOutput(BaseHttpOutput):
    """
    Defines the structured output for the 'HEAD Request' action.
    """

    pass


class GetHeadersParams(BaseHttpParams):
    """
    Defines the input parameters for the 'HEAD Request' action.
    """

    pass


def get_headers(params: GetHeadersParams, soar: SOARClient, asset: Asset) -> GetHeadersOutput:
    """Perform a REST HEAD call to the server."""
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
