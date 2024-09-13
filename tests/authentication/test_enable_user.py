import pytest
import allure
from api.endpoints.authentication import AuthenticationEndpoints
from api.request.api_request import RealHomeRequest
from core.assertions.status_code import assert_status_code_ok, assert_status_code_bad_request, \
    assert_status_code_unauthorized, assert_status_code_not_found
from resources.auth.auth import Auth


@allure.suite('Enable User')
@allure.epic('Authentication')
@allure.feature('Enable User')
@allure.story('Enable User with Valid Email and Enable True')
@pytest.mark.functional
@pytest.mark.positive
def test_enable_user_with_valid_email_and_enable_true(get_headers, enable_user_payload):
    url = AuthenticationEndpoints.enable_user()
    headers = Auth().auth_valid_credential(get_headers)
    response = RealHomeRequest.post(url, headers, enable_user_payload)

    assert_status_code_ok(response)


@allure.suite('Enable User')
@allure.epic('Authentication')
@allure.feature('Enable User')
@allure.story('Enable User with Empty Email')
@pytest.mark.functional
@pytest.mark.negative
def test_enable_user_with_empty_email(get_headers, enable_user_payload):
    url = AuthenticationEndpoints.enable_user()
    headers = Auth().auth_valid_credential(get_headers)
    enable_user_payload['email'] = ""
    response = RealHomeRequest.post(url, headers, enable_user_payload)

    assert_status_code_bad_request(response)


@allure.suite('Enable User')
@allure.epic('Authentication')
@allure.feature('Enable User')
@allure.story('Enable User with Invalid Email Format')
@pytest.mark.functional
@pytest.mark.negative
def test_enable_user_with_invalid_email_format(get_headers, enable_user_payload):
    url = AuthenticationEndpoints.enable_user()
    headers = Auth().auth_valid_credential(get_headers)
    enable_user_payload['email'] = "invalid-email-format"
    response = RealHomeRequest.post(url, headers, enable_user_payload)

    assert_status_code_bad_request(response)


@allure.suite('Enable User')
@allure.epic('Authentication')
@allure.feature('Enable User')
@allure.story('Enable User without Enable Field')
@pytest.mark.functional
@pytest.mark.negative
def test_enable_user_without_enable_field(get_headers, enable_user_payload):
    url = AuthenticationEndpoints.enable_user()
    headers = Auth().auth_valid_credential(get_headers)
    enable_user_payload.pop('enable')
    response = RealHomeRequest.post(url, headers, enable_user_payload)

    assert_status_code_bad_request(response)


@allure.suite('Enable User')
@allure.epic('Authentication')
@allure.feature('Enable User')
@allure.story('Enable User with Unregistered Email')
@pytest.mark.functional
@pytest.mark.negative
def test_enable_user_with_unregistered_email(get_headers, enable_user_payload):
    url = AuthenticationEndpoints.enable_user()
    headers = Auth().auth_valid_credential(get_headers)
    enable_user_payload['email'] = "unregistered@example.com"
    response = RealHomeRequest.post(url, headers, enable_user_payload)

    assert_status_code_not_found(response)


@allure.suite('Enable User')
@allure.epic('Authentication')
@allure.feature('Enable User')
@allure.story('Enable User without Authentication Token')
@pytest.mark.functional
@pytest.mark.negative
def test_enable_user_without_authentication_token(get_header,enable_user_payload):
    url = AuthenticationEndpoints.enable_user()
    response = RealHomeRequest.post(url, get_header, enable_user_payload)

    assert_status_code_unauthorized(response)


@allure.suite('Enable User')
@allure.epic('Authentication')
@allure.feature('Enable User')
@allure.story('Enable User with Invalid Authentication Token')
@pytest.mark.functional
@pytest.mark.negative
def test_enable_user_with_invalid_authentication_token(enable_user_payload):
    url = AuthenticationEndpoints.enable_user()
    headers = {
        'accept': '*/*',
        'Content-Type': 'application/json-patch+json',
        'Authorization': 'Bearer invalid_token'
    }
    response = RealHomeRequest.post(url, headers, enable_user_payload)

    assert_status_code_unauthorized(response)
