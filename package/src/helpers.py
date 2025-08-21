import json
from bs4 import BeautifulSoup
import xmltodict
from soar_sdk.exceptions import ActionFailure

from .common import logger

def process_xml_response(response) -> dict:
    try:
        return xmltodict.parse(response.text)
    except Exception as e:
        raise ActionFailure(f"Unable to parse XML response. Error: {e}")
    
def process_json_response(response) -> dict:
    try:
        return response.json()
    except json.JSONDecodeError as e:
        raise ActionFailure(f"Unable to parse JSON response. Error: {e}")

def process_html_response(response) -> str:
    try:
        soup = BeautifulSoup(response.text, "html.parser")
        for element in soup(["script", "style", "footer", "nav"]):
            element.extract()
        error_text_lines = [x.strip() for x in soup.text.split("\n") if x.strip()]
        return "\n".join(error_text_lines)
    
    except Exception as e:
        raise ActionFailure(f"Unable to parse HTML response. Error: {e}")

def process_empty_response(content_type) -> dict:
    message = "Response includes a file" if "octet-stream" in content_type else "Empty response body"
    return {"message": message}

def process_text_response(response) -> str:
    return response.text

RESPONSE_HANDLERS = {
    "json": process_json_response,
    "javascript": process_json_response,
    "xml": process_xml_response,
    "html": process_html_response,
}


def parse_headers(headers_str: str | None) -> dict:

    if not headers_str:
        return {}

    try:
        parsed_headers = json.loads(headers_str)

    except json.JSONDecodeError as e:
        error_message = f"Failed to parse headers. Ensure it's a valid JSON object. Error: {e}"
        logger.error(error_message)
        raise ActionFailure(error_message)

    if not isinstance(parsed_headers, dict):
        raise ActionFailure("Headers parameter must be a valid JSON object (dictionary).")
    
    return parsed_headers


def handle_various_response(response):
    content_type = response.headers.get("Content-Type", "").lower()

    if not response.text.strip():
        return process_empty_response(response)

    parser = process_text_response(response)
    for key, handler in RESPONSE_HANDLERS.items():
        if key in content_type:
            logger.info(f"Found handler for content type: {key}")
            parser = handler
            break
    
    return parser(response)