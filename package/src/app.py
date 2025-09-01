from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionOutput
from soar_sdk.app import App

from .actions.action_get import get_action_description, get_action_type, get_data
from .actions.action_post import post_action_description, post_action_type, post_data
from .asset import Asset
from .common import logger
from .request_maker import make_request

app = App(
    name="HTTP",
    app_type="generic",
    logo="logo.svg",
    logo_dark="logo_dark.svg",
    product_vendor="Generic",
    product_name="HTTP",
    publisher="Splunk Inc.",
    appid="dc312038-005f-470f-badb-8a353ba9bb5b",
    fips_compliant=False,
    asset_cls=Asset,
)


class EmptyOutput(ActionOutput):
    """An empty output class for actions that do not return data, like test_connectivity."""

    pass


@app.test_connectivity()
def test_connectivity(soar: SOARClient, asset: Asset) -> None:

    logger.info("Action 'Test Connectivity' started.")

    make_request(
        asset=asset,
        soar=soar,
        method=asset.test_http_method,
        location=asset.test_path if asset.test_path else "",
        output=EmptyOutput,
        verify=False,
        headers=None,
        body=None,
    )

    logger.info("Test connectivity passed!")


app.register_action(get_data, action_type=get_action_type, description=get_action_description)

app.register_action(
    post_data,
    action_type=post_action_type,
    description=post_action_description,
    read_only=False,
)


if __name__ == "__main__":
    app.cli()
