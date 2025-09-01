from pydantic import Extra
from soar_sdk.action_results import ActionOutput


class ParsedResponseBody(ActionOutput):

    class Config:
        extra = Extra.allow
