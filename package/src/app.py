from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionOutput
from soar_sdk.app import App

from .actions import action_delete, action_get, action_head, action_options, action_patch, action_post, action_put
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


app.register_action(action_get.get_data, action_type=action_get.action_type, description=action_get.action_description)
app.register_action(action_post.post_data, action_type=action_post.action_type, description=action_post.action_description, read_only=False)
app.register_action(action_put.put_data, action_type=action_put.action_type, description=action_put.action_description, read_only=False)
app.register_action(action_patch.patch_data, action_type=action_patch.action_type, description=action_patch.action_description)
app.register_action(action_delete.delete_data, action_type=action_delete.action_type, description=action_delete.action_description)
app.register_action(action_head.get_headers, action_type=action_head.action_type, description=action_head.action_description)
app.register_action(action_options.get_options, action_type=action_options.action_type, description=action_options.action_description)

if __name__ == "__main__":
    app.cli()
