import requests
import json
from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionOutput, OutputField
from soar_sdk.exceptions import ActionFailure
from soar_sdk.logging import getLogger
from soar_sdk.params import Param, Params
from ..asset import Asset
from .. import helpers
from ..common import logger


get_action_type = "investigate"
get_action_description = "This App facilitates making HTTP requests as actions"


class GetDataOutput(ActionOutput):
    location: str = OutputField(
        cef_types=["url"], example_values=["http://192.168.1.26/rest/cont"]
    )
    method: str = OutputField(example_values=["GET"])
    parsed_response_body: str = OutputField(
        example_values=['{"failed": true, "message": "Requested item not found"}']
    )
    response_body: str = OutputField(
        example_values=['{"failed": true, "message": "Requested item not found"}']
    )
    response_headers: str

class GetDataParams(Params):
    location: str = Param(
        description="Location (e.g. path/to/endpoint?query=string)",
        primary=True,
        cef_types=["endpoint"],
    )
    verify_certificate: bool = Param(description="Verify certificates (if using HTTPS)")
    headers: str = Param(description="Additional headers (JSON object with headers)", required=False)


def http_get(params: GetDataParams, soar: SOARClient, asset: Asset) -> GetDataOutput:
    
    logger.info(f"In action handler for: http_get with location: {params.location}")

    parsed_headers = helpers.parse_headers(params.headers)
    

    full_url = asset.base_url.rstrip("/") + "/" + params.location.lstrip('/')    
    logger.info(f"Making GET request to: {full_url}")

    try:
        response = requests.get(
            uri=full_url,
            headers=parsed_headers,
            verify=params.verify_certificate,
            timeout=asset.timeout,
        )
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        error_message = f"Failed to get data from {full_url}. Details: {e}"
        logger.error(error_message)
        raise ActionFailure(error_message)


    parsed_body = helpers.handle_various_response(response)

    raw_body = json.dumps(parsed_body, indent=4) if isinstance(parsed_body, dict) else response.text 

    logger.info(f"Successfully processed data. Status: {response.status_code}")
    

    return GetDataOutput(
        location=full_url,
        method="GET",
        parsed_response_body=str(parsed_body),
        response_body=raw_body,
        response_headers=str(dict(response.headers))
    )