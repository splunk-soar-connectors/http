from soar_sdk.abstract import SOARClient
from soar_sdk.params import Param

from ..asset import Asset
from ..classes import BaseHttpOutput, BaseHttpParams
from ..common import logger
from ..request_maker import make_request


class PostDataOutput(BaseHttpOutput):
    """
    Defines the structured output for the 'POST Request' action.
    """

    pass


class PostDataParams(BaseHttpParams):
    """
    Defines the input parameters for the 'POST Request' action.
    """

    body: str = Param(description="POST body (query string, JSON, etc.)", required=False)


def post_data(params: PostDataParams, soar: SOARClient, asset: Asset) -> PostDataOutput:
    """Perform a REST POST call to the server."""
    logger.info("In action handler for: http_post")
    return make_request(
        asset=asset,
        soar=soar,
        method="POST",
        location=params.location,
        headers=params.headers,
        verify=params.verify_certificate,
        body=params.body,
        output=PostDataOutput,
    )
