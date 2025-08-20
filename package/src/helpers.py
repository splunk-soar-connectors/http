import json
from bs4 import BeautifulSoup
import xmltodict
from soar_sdk.exceptions import ActionFailure



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
