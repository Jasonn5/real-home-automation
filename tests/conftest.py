import pytest
from api.endpoints.authentication import AuthenticationEndpoints
from api.request.api_request import RealHomeRequest

@pytest.fixture
def get_headers():
    def _get_headers(username, password, confirm_password):
        url = AuthenticationEndpoints.authenticate()
        headers = {'accept': '*/*', 'Content-Type': 'application/json-patch+json'}
        data = {
            "username": username,
            "password": password,
            "confirmPassword": confirm_password
        }
        response = RealHomeRequest.post_json(url, headers, data)
        token = response.json().get('token')
        if not token:
            raise ValueError("No se pudo obtener el token de autenticación.")

        return {
            'accept': '*/*',
            'Content-Type': 'application/json-patch+json',
            'Authorization': f'Bearer {token}'
        }

    return _get_headers

