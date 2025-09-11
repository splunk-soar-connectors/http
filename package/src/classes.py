from pydantic import Extra
from soar_sdk.action_results import ActionOutput, GenericActionOutput, OutputField
from soar_sdk.params import Param, Params


class EmptyOutput(ActionOutput):
    """Empty output for test_connectivity."""

    pass


class ParsedResponseBody(ActionOutput):
    """A flexible model for any JSON response."""

    class Config:
        extra = Extra.allow


class BaseHttpOutput(GenericActionOutput):
    """Base class for all standard action outputs."""

    location: str = OutputField(cef_types=["url"], example_values=["http://192.168.1.26/rest/assets"])
    method: str = OutputField(example_values=["POST"])
    parsed_response_body: ParsedResponseBody = OutputField(example_values=['{"failed": true, "message": "Requested item not found"}'])
    response_body: str = OutputField(example_values=['{"failed": true, "message": "Requested item not found"}'])
    response_headers: str

    def generate_action_summary_message(self) -> str:
        return f"Status code: {self.status_code}"


class BaseHttpParams(Params):
    """Base class for all standard action parameters."""

    location: str = Param(
        description="Location (e.g. path/to/endpoint)",
        primary=True,
        cef_types=["endpoint"],
    )
    verify_certificate: bool = Param(description="Verify certificates (if using HTTPS)", default=False, required=False)
    headers: str = Param(description="Additional headers (JSON object with headers)", required=False)
