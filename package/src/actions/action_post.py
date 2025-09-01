from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionOutput, OutputField
from soar_sdk.params import Param, Params

from ..asset import Asset
from ..classes import ParsedResponseBody
from ..common import logger
from ..request_maker import make_request

post_action_type = "generic"
post_action_description = "Perform a REST POST call to the server"


class PostDataOutput(ActionOutput):
    message: str
    location: str = OutputField(cef_types=["url"], example_values=["http://192.168.1.26/rest/assets"])
    method: str = OutputField(example_values=["POST"])
    parsed_response_body: ParsedResponseBody = OutputField(example_values=['{"failed": true, "message": "Requested item not found"}'])
    response_body: str = OutputField(example_values=['{"failed": true, "message": "Requested item not found"}'])
    response_headers: str


class PostDataParams(Params):
    location: str = Param(
        description="Location (e.g. path/to/endpoint)",
        primary=True,
        cef_types=["endpoint"],
    )
    body: str = Param(description="POST body (query string, JSON, etc.)", required=False)
    verify_certificate: bool = Param(description="Verify certificates (if using HTTPS)")
    headers: str = Param(description="Additional headers (JSON object with headers)", required=False)


def post_data(params: PostDataParams, soar: SOARClient, asset: Asset) -> PostDataOutput:
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
