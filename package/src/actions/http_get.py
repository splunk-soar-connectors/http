import requests
import json
from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionOutput, OutputField
from soar_sdk.app import App
from soar_sdk.asset import AssetField, BaseAsset
from soar_sdk.exceptions import ActionFailure
from soar_sdk.logging import getLogger
from soar_sdk.params import Param, Params
from ..app import Asset

logger = getLogger()

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

    parsed_headers = {}
    if params.headers:
        try:
            parsed_headers = json.loads(params.headers)
            if not isinstance(parsed_headers, dict):
                raise ActionFailure("Headers parameter must be a valid JSON object (dictionary).")
        except json.JSONDecodeError as e:
            error_message = f"Failed to parse headers. Ensure it's a valid JSON object. Error: {e}"
            logger.error(error_message)
            raise ActionFailure(error_message)
        
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

        try:
            parsed_body_object  = response.json()
            parsed_body_as_string = json.dumps(parsed_body_object, indent=4) 
        except requests.exceptions.JSONDecodeError:
            parsed_body_as_string  = response.text
            
        logger.info(f"Successfully fetched data. Status: {response.status_code}")
        
        return GetDataOutput(
            location=full_url,
            method="GET",
            parsed_response_body=parsed_body_as_string,      
            response_body=response.text,
            response_headers=str(dict(response.headers)) 
        )

    except requests.exceptions.RequestException as e:
        error_message = f"Failed to get data from {full_url}. Details: {e}"
        logger.error(error_message)
        raise ActionFailure(error_message)
    