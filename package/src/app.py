import requests
from soar_sdk.abstract import SOARClient
from soar_sdk.app import App
from soar_sdk.exceptions import ActionFailure
from soar_sdk.logging import getLogger

from .actions.action_get import http_get, get_action_type, get_action_description
from .asset import Asset

logger = getLogger()


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

app.register_action(
    http_get,
    action_type = get_action_type,
    description = get_action_description
)

if __name__ == "__main__":
    app.cli()

