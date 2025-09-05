from typing import Optional

import requests
from bs4 import UnicodeDammit
from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionOutput
from soar_sdk.exceptions import ActionFailure

from . import helpers
from .asset import Asset
from .auth import get_auth_method
from .common import logger


def make_request(
    asset: Asset,
    soar: SOARClient,
    method: str,
    location: str,
    output: type[ActionOutput],
    verify: bool,
    headers: Optional[str],
    body: Optional[str],
) -> ActionOutput:

    logger.info(f"Preparing to make {method} http request.")
    parsed_headers = helpers.parse_headers(headers)

    full_url = asset.base_url.rstrip("/") + "/" + location.lstrip("/")

    logger.info(f"Making {method} request to: {full_url}")

    auth_method = get_auth_method(asset, soar)
    auth_object, final_headers = auth_method.create_auth(parsed_headers)

    body = UnicodeDammit(body).unicode_markup.encode("utf-8") if isinstance(body, str) else body

    try:
        response = requests.request(
            method=method,
            url=full_url,
            auth=auth_object,
            data=body,
            verify=verify,
            headers=final_headers,
            timeout=asset.timeout,
            params=None,
        )
        response.raise_for_status()

    except requests.exceptions.RequestException as e:
        logger.error(f"Request failed for {full_url}. Details: {e}")
        raise ActionFailure(f"Request failed for {full_url}. Details: {e}") from e

    parsed_body, raw_body = helpers.handle_various_response(response)
    logger.info(f"Successfully processed data. Status: {response.status_code}")

    return output(
        status_code=response.status_code,
        location=full_url,
        method=method,
        parsed_response_body=parsed_body,
        response_body=raw_body,
        response_headers=str(dict(response.headers)),
    )
