import json
from typing import Optional

import xmltodict
from bs4 import BeautifulSoup
from pydantic import ValidationError
from soar_sdk.exceptions import ActionFailure

from .classes import ParsedResponseBody
from .common import logger


def process_xml_response(response) -> dict:
    try:
        return xmltodict.parse(response.text)
    except Exception as e:
        raise ActionFailure(f"Unable to parse XML response. Error: {e}")


def process_json_response(response) -> dict:
    try:
        return ParsedResponseBody(**response.json())
    except json.JSONDecodeError as e:
        raise ActionFailure(f"Server claimed JSON but failed to parse. Error: {e}")
    except ValidationError as e:
        raise ActionFailure(f"Response JSON did not match expected structure. Details: {e}")


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


def parse_headers(headers_str: Optional[str]) -> dict:
    if headers_str is None:
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
    if not response.text.strip() or ("application/octet-stream" in content_type):
        return process_empty_response(content_type), ""

    parser = process_text_response
    for key, handler in RESPONSE_HANDLERS.items():
        if key in content_type:
            parser = handler
            break

    parsed_body = parser(response)

    if isinstance(parsed_body, (dict, list)):
        raw_body = json.dumps(parsed_body, indent=4)
    else:
        raw_body = response.text
    return parsed_body, raw_body
