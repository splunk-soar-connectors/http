from urllib.parse import quote, unquote_plus

import requests
import validators
from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionOutput
from soar_sdk.exceptions import ActionFailure
from soar_sdk.params import Param, Params

from ..asset import Asset
from ..auth import get_auth_method


class GetFileParams(Params):
    hostname: str = Param(
        description="Hostname to execute command on",
        primary=True,
        cef_types=["hostname"],
    )
    file_path: str = Param(
        required=True,
        description="Path of the file to download (include filename)",
        primary=True,
        cef_types=["file path"],
    )
    verify_certificate: bool = Param(description="Verify certificates (if using HTTPS)")


class GetFileOutput(ActionOutput):
    vault_id: str
    file_name: str


action_description = "Retrieve a file from the endpoint and save it to the vault"
action_type = "investigate"
verbose = "Provide the file path and file name to download into the vault. For example, <b>/web_storage/file.tgz</b>."


def get_file(params: GetFileParams, soar: SOARClient, asset: Asset) -> GetFileOutput:
    hostname = params.hostname.strip(" ").strip("/") or asset.base_url
    file_path = params.file_path.strip()
    encoded_file_path = quote(file_path)
    validate_url = f"{hostname}/{encoded_file_path}"

    if not validators.url(validate_url):
        raise ActionFailure(f"Invalid URL constructed based on hostname and file_path: {validate_url}")
    full_url = f"{hostname}/{file_path}"

    file_name = unquote_plus(file_path.split("/")[-1])

    auth_strategy = get_auth_method(asset, soar)
    auth_object, final_headers = auth_strategy.create_auth({})

    try:
        response = requests.get(
            url=full_url,
            auth=auth_object,
            headers=final_headers,
            verify=params.verify_certificate,
            timeout=asset.timeout,
        )
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        raise ActionFailure(f"Failed to download file from {full_url}. Details: {e}")

    try:
        file_content = response.content
        if not file_content:
            raise ActionFailure("Downloaded file is empty.")

        container_id_to_use = soar.get_container_id()

        if not (
            new_vault_id := soar.vault.create_attachment(
                file_content=file_content, file_name=file_name, container_id=container_id_to_use, metadata=None
            )
        ):
            raise ActionFailure("Failed to add file to vault.")

    except Exception as e:
        raise ActionFailure(f"An error occurred while saving the file to the vault. Details: {e}")

    return GetFileOutput(vault_id=new_vault_id, file_name=file_name)
