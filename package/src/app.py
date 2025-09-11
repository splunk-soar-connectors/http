from soar_sdk.abstract import SOARClient
from soar_sdk.app import App

from .actions import action_delete, action_get, action_head, action_options, action_patch, action_post, action_put, get_file, put_file
from .asset import Asset
from .classes import EmptyOutput
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


@app.test_connectivity()
def test_connectivity(soar: SOARClient, asset: Asset) -> None:
    """Validate connection using the configured credentials."""
    logger.info("In action handler for: test_connectivity")

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


app.register_action(action_get.get_data, action_type="investigate")
app.register_action(action_post.post_data, action_type="generic", read_only=False)
app.register_action(action_put.put_data, action_type="generic", read_only=False)
app.register_action(action_patch.patch_data, action_type="generic", read_only=False)
app.register_action(action_delete.delete_data, action_type="generic", read_only=False)
app.register_action(action_head.get_headers, action_type="investigate")
app.register_action(action_options.get_options, action_type="investigate")
app.register_action(put_file.put_file, action_type="generic", read_only=False, verbose=put_file.verbose)
app.register_action(get_file.get_file, action_type="investigate", verbose=get_file.verbose)


if __name__ == "__main__":
    app.cli()
