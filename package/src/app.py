import requests
from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionOutput, OutputField
from soar_sdk.app import App
from soar_sdk.asset import AssetField, BaseAsset
from soar_sdk.exceptions import ActionFailure
from soar_sdk.logging import getLogger

from soar_sdk.params import Param, Params

logger = getLogger()


class Asset(BaseAsset):
    base_url: str = AssetField(
        required=True,
        description="Base URL for making queries. (e.g. https://myservice/)",
    )
    test_path: str = AssetField(
        required=False,
        description="Endpoint for test connectivity. (e.g. /some/specific/endpoint , appended to Base URL)",
    )
    auth_token_name: str = AssetField(
        required=False,
        description="Type of authentication token",
        default="ph-auth-token",
    )
    auth_token: str = AssetField(required=False, description="Value of authentication token")
    username: str = AssetField(required=False, description="Username (for HTTP basic auth)")
    password: str = AssetField(required=False, description="Password (for HTTP basic auth)")
    oauth_token_url: str = AssetField(required=False, description="URL to fetch oauth token from")
    client_id: str = AssetField(required=False, description="Client ID (for OAuth)")
    client_secret: str = AssetField(required=False, description="Client Secret (for OAuth)")
    timeout: float = AssetField(required=False, description="Timeout for HTTP calls")
    test_http_method: str = AssetField(
        required=False,
        description="HTTP Method for Test Connectivity",
        default="GET",
        value_list=[
            "GET",
            "HEAD",
            "POST",
            "PUT",
            "DELETE",
            "OPTIONS",
            "TRACE",
            "PATCH",
        ],
    )


app = App(
    name="http",
    app_type="generic",
    logo="logo.svg",
    logo_dark="logo_dark.svg",
    product_vendor="Splunk Inc.",
    product_name="http",
    publisher="Splunk Inc.",
    appid="dc312038-005f-470f-badb-8a353ba9bb5b",
    fips_compliant=False,
    asset_cls=Asset,
)


@app.test_connectivity()
def test_connectivity(soar: SOARClient, asset: Asset) -> None:

    logger.info("Action 'Test Connectivity' started.")
    full_url = asset.base_url.rstrip("/")
    if asset.test_path:
        full_url = full_url + "/" + asset.test_path.lstrip("/")
    logger.info(f"Querying base url, {full_url}, to test credentials.")


    try:
        response = requests.request(
            method=asset.test_http_method,
            url=full_url,
            verify=False,
            timeout=asset.timeout,
        )
        logger.info(f"Got status code {response.status_code}.")
        response.raise_for_status()


    except requests.exceptions.RequestException as e:
        logger.error(f"Test connectivity failed, error: {e}.")
        raise ActionFailure(f"Test connectivity failed, details: {e}.")

    logger.info("Test connectivity passed!")

if __name__ == "__main__":
    app.cli()

