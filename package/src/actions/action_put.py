from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionOutput, OutputField
from soar_sdk.params import Param, Params

from ..asset import Asset
from ..classes import ParsedResponseBody
from ..common import logger
from ..request_maker import make_request

action_description = "Perform a REST PUT call to the server"
action_type = "generic"


class PutDataOutput(ActionOutput):
    location: str = OutputField(cef_types=["url"], example_values=["http://192.168.1.26/rest/assets"])
    method: str = OutputField(example_values=["PUT"])
    parsed_response_body: ParsedResponseBody = OutputField(example_values=['{"failed": true, "message": "Requested item not found"}'])
    response_body: str = OutputField(example_values=['{"failed": true, "message": "Requested item not found"}'])
    response_headers: str


class PutDataParams(Params):
    location: str = Param(
        description="Location (e.g. path/to/endpoint?query=string)",
        primary=True,
        cef_types=["endpoint"],
    )
    body: str = Param(description="PATCH body (query string, JSON, etc.)")
    verify_certificate: bool = Param(description="Verify certificates (if using HTTPS)")
    headers: str = Param(description="Additional headers (JSON object with headers)")


def put_data(params: PutDataParams, soar: SOARClient, asset: Asset) -> PutDataOutput:
    logger.info("In action handler for: put_data")
    return make_request(
        asset=asset,
        soar=soar,
        method="PUT",
        location=params.location,
        headers=params.headers,
        verify=params.verify_certificate,
        body=params.body,
        output=PutDataOutput,
    )
