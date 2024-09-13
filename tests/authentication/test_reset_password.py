import pytest
import allure
from api.endpoints.authentication import AuthenticationEndpoints
from api.request.api_request import RealHomeRequest
from core.assertions.status_code import assert_status_code_ok, assert_status_code_bad_request, \
    assert_status_code_unauthorized, assert_status_code_not_found
from resources.auth.auth import Auth


@allure.suite('Reset Password')
@allure.epic('Authentication')
@allure.feature('Reset Password')
@allure.story('Reset Password with Valid Email and Password')
@pytest.mark.functional
@pytest.mark.positive
def test_reset_password_with_valid_email_and_password(get_headers, reset_password_payload):
    url = AuthenticationEndpoints.reset_password()
    headers = Auth().auth_valid_credential(get_headers)
    response = RealHomeRequest.post(url, headers, reset_password_payload)

    assert_status_code_ok(response)


@allure.suite('Reset Password')
@allure.epic('Authentication')
@allure.feature('Reset Password')
@allure.story('Reset Password with Empty Email')
@pytest.mark.functional
@pytest.mark.negative
def test_reset_password_with_empty_email(get_headers, reset_password_payload):
    url = AuthenticationEndpoints.reset_password()
    headers = Auth().auth_valid_credential(get_headers)
    reset_password_payload['email'] = ""
    response = RealHomeRequest.post(url, headers, reset_password_payload)

    assert_status_code_bad_request(response)


@allure.suite('Reset Password')
@allure.epic('Authentication')
@allure.feature('Reset Password')
@allure.story('Reset Password with Empty Password')
@pytest.mark.functional
@pytest.mark.negative
def test_reset_password_with_empty_password(get_headers, reset_password_payload):
    url = AuthenticationEndpoints.reset_password()
    headers = Auth().auth_valid_credential(get_headers)
    reset_password_payload['password'] = ""
    response = RealHomeRequest.post(url, headers, reset_password_payload)

    assert_status_code_bad_request(response)


@allure.suite('Reset Password')
@allure.epic('Authentication')
@allure.feature('Reset Password')
@allure.story('Reset Password with Invalid Email Format')
@pytest.mark.functional
@pytest.mark.negative
def test_reset_password_with_invalid_email_format(get_headers, reset_password_payload):
    url = AuthenticationEndpoints.reset_password()
    headers = Auth().auth_valid_credential(get_headers)
    reset_password_payload['email'] = "invalid-email-format"
    response = RealHomeRequest.post(url, headers, reset_password_payload)

    assert_status_code_bad_request(response)


@allure.suite('Reset Password')
@allure.epic('Authentication')
@allure.feature('Reset Password')
@allure.story('Reset Password without Authentication Token')
@pytest.mark.functional
@pytest.mark.negative
def test_reset_password_without_authentication_token(get_header,reset_password_payload):
    url = AuthenticationEndpoints.reset_password()
    response = RealHomeRequest.post(url, get_header, reset_password_payload)

    assert_status_code_unauthorized(response)


@allure.suite('Reset Password')
@allure.epic('Authentication')
@allure.feature('Reset Password')
@allure.story('Reset Password with Invalid Authentication Token')
@pytest.mark.functional
@pytest.mark.negative
def test_reset_password_with_invalid_authentication_token(reset_password_payload):
    url = AuthenticationEndpoints.reset_password()
    headers = {
        'accept': '*/*',
        'Content-Type': 'application/json-patch+json',
        'Authorization': 'Bearer invalid_token'
    }
    response = RealHomeRequest.post(url, headers, reset_password_payload)

    assert_status_code_unauthorized(response)


@allure.suite('Reset Password')
@allure.epic('Authentication')
@allure.feature('Reset Password')
@allure.story('Reset Password with Unregistered Email')
@pytest.mark.functional
@pytest.mark.negative
def test_reset_password_with_unregistered_email(get_headers, reset_password_payload):
    url = AuthenticationEndpoints.reset_password()
    headers = Auth().auth_valid_credential(get_headers)
    reset_password_payload['email'] = "unregistered@example.com"
    response = RealHomeRequest.post(url, headers, reset_password_payload)

    assert_status_code_bad_request(response)
