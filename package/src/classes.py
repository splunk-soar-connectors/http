from pydantic import Extra
from soar_sdk.action_results import ActionOutput, GenericActionOutput, OutputField


class ParsedResponseBody(ActionOutput):

    class Config:
        extra = Extra.allow


class BaseHttpOutput(GenericActionOutput):
    location: str = OutputField(cef_types=["url"], example_values=["http://192.168.1.26/rest/assets"])
    method: str = OutputField(example_values=["POST"])
    parsed_response_body: ParsedResponseBody = OutputField(example_values=['{"failed": true, "message": "Requested item not found"}'])
    response_body: str = OutputField(example_values=['{"failed": true, "message": "Requested item not found"}'])
    response_headers: str

    def generate_action_summary_message(self) -> str:
        return f"Status code: {self.status_code}"
