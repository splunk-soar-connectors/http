import requests
from soar_sdk.abstract import SOARClient

# from soar_sdk.action_results import ActionOutput, OutputField
from soar_sdk.app import App
from soar_sdk.asset import AssetField, BaseAsset
from soar_sdk.exceptions import ActionFailure
from soar_sdk.logging import getLogger

# from soar_sdk.params import Param, Params

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
    app_type="information",
    logo="logo_splunk.svg",
    logo_dark="logo_splunk_dark.svg",
    product_vendor="Generic",
    product_name="HTTP",
    publisher="Splunk",
    appid="290b7499-0374-4930-9cdc-5e9b05d65827",
    fips_compliant=True,
    asset_cls=Asset,
)


@app.test_connectivity()
def test_connectivity(soar: SOARClient, asset: Asset) -> None:
    # raise NotImplementedError()

    # zbudujmy pelen adres url
    # nawet jesli nie ma test_patha to bedzie dzialac
    full_url = asset.base_url.rstrip("/")
    if asset.test_path:
        full_url = full_url + "/" + asset.test_path.lstrip("/")
    soar.save_progress(f"Wysylanie testowego zadania na adres: {full_url}")

    # źądanie
    try:
        response = requests.request(
            method=asset.test_http_method,
            url=full_url,
            verify=False,
            timeout=asset.timeout,
        )

        response.raise_for_status()

        soar.save_progress(f"Otrzymano pomyślną odpowiedź (Status: {response.status_code})")
    except requests.exceptions.HTTPError as e:
        # Błąd zwrócony przez serwer (np. 401, 403, 404, 500)
        error_message = f"Serwer zwrócił błąd: {e.response.status_code} {e.response.reason}. " f"Treść odpowiedzi: {e.response.text}"
        raise ActionFailure(error_message)

    except requests.exceptions.RequestException as e:
        # Inne błędy połączenia (np. problem z DNS, odmowa połączenia, timeout)
        error_message = f"Błąd połączenia z serwerem. Szczegóły: {e}"
        raise ActionFailure(error_message)

    soar.save_progress("Test łączności zakończony pomyślnie.")


if __name__ == "__main__":
    app.cli()


# dobrze otestuj przypadek gdzie test_path nie istnieje lub jest "/"
