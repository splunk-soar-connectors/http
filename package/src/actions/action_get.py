import requests
import json
from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionOutput, OutputField
from soar_sdk.exceptions import ActionFailure
from soar_sdk.logging import getLogger
from soar_sdk.params import Param, Params
from ..asset import Asset
from .. import helpers



get_action_type = "investigate"
get_action_description = "This App facilitates making HTTP requests as actions"
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


RESPONSE_HANDLERS = {
    "json": helpers.process_json_response,
    "javascript": helpers.process_json_response,
    "xml": helpers.process_xml_response,
    "html": helpers.process_html_response,
}


def http_get(params: GetDataParams, soar: SOARClient, asset: Asset) -> GetDataOutput:
    
    logger.info(f"In action handler for: http_get with location: {params.location}")


    # logic to parsing headers (we need them to sent GET request):

    parsed_headers = {}
    if params.headers:

        try:
            parsed_headers = json.loads(params.headers)
        except json.JSONDecodeError as e:
            error_message = f"Failed to parse headers. Ensure it's a valid JSON object. Error: {e}"
            logger.error(error_message)
            raise ActionFailure(error_message)
        
    if not isinstance(parsed_headers, dict):
        raise ActionFailure("Headers parameter must be a valid JSON object (dictionary).")
        


    # sending GET request:

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



    # logic to handle various types of responses (in output we have to have parsed body and raw_body):

    content_type = response.headers.get("Content-Type", "").lower()

    if not response.text.strip():
        parsed_body = helpers.process_empty_response(response)
    else:
        parser = helpers.process_text_response
        for key, handler in RESPONSE_HANDLERS.items():
            if key in content_type:
                logger.info(f"Found handler for content type: {key}")
                parser = handler
                break
        
        parsed_body = parser(response)  

    if isinstance(parsed_body, dict):
        raw_body = json.dumps(parsed_body, indent=4)
    else:
        raw_body = response.text

    logger.info(f"Successfully processed data. Status: {response.status_code}")
    

    #output:

    return GetDataOutput(
        location=full_url,
        method="GET",
        parsed_response_body=str(parsed_body),
        response_body=raw_body,
        response_headers=str(dict(response.headers))
    )