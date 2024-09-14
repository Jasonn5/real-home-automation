import pytest
import allure
from api.endpoints.authentication import AuthenticationEndpoints
from api.request.api_request import RealHomeRequest
from core.assertions.status_code import assert_status_code_bad_request, assert_status_code_unauthorized, assert_status_code_internal_server_error
from resources.auth.auth import Auth

@allure.suite('Change Password')
@allure.epic('Authentication')
@allure.feature('Change Password')
@allure.story('Change Password with Empty Username')
@allure.tag('author: Jeyson')
@pytest.mark.functional
@pytest.mark.negative
def test_change_password_with_empty_username(get_headers, change_password_payload):
    url = AuthenticationEndpoints.change_password()
    headers = Auth().auth_valid_credential(get_headers)
    change_password_payload['username'] = ""
    response = RealHomeRequest.post(url, headers, change_password_payload)

    assert_status_code_bad_request(response)

@allure.suite('Change Password')
@allure.epic('Authentication')
@allure.feature('Change Password')
@allure.story('Change Password with Empty Password')
@allure.tag('author: Jeyson')
@pytest.mark.functional
@pytest.mark.negative
def test_change_password_with_empty_password(get_headers, change_password_payload):
    url = AuthenticationEndpoints.change_password()
    headers = Auth().auth_valid_credential(get_headers)
    change_password_payload['password'] = ""
    response = RealHomeRequest.post(url, headers, change_password_payload)

    assert_status_code_bad_request(response)

@allure.suite('Change Password')
@allure.epic('Authentication')
@allure.feature('Change Password')
@allure.story('Change Password with Empty Confirm Password')
@allure.tag('author: Jeyson')
@pytest.mark.functional
@pytest.mark.negative
def test_change_password_with_empty_confirm_password(get_headers, change_password_payload):
    url = AuthenticationEndpoints.change_password()
    headers = Auth().auth_valid_credential(get_headers)
    change_password_payload['confirmPassword'] = ""
    response = RealHomeRequest.post(url, headers, change_password_payload)

    assert_status_code_bad_request(response)

@allure.suite('Change Password')
@allure.epic('Authentication')
@allure.feature('Change Password')
@allure.story('Change Password with Empty Old Password')
@allure.tag('author: Jeyson')
@pytest.mark.functional
@pytest.mark.negative
def test_change_password_with_empty_old_password(get_headers, change_password_payload):
    url = AuthenticationEndpoints.change_password()
    headers = Auth().auth_valid_credential(get_headers)
    change_password_payload['oldPassword'] = ""
    response = RealHomeRequest.post(url, headers, change_password_payload)

    assert_status_code_bad_request(response)

@allure.suite('Change Password')
@allure.epic('Authentication')
@allure.feature('Change Password')
@allure.story('Change Password with Non-Matching Passwords')
@allure.tag('author: Jeyson')
@pytest.mark.functional
@pytest.mark.negative
def test_change_password_with_non_matching_passwords(get_headers, change_password_payload):
    url = AuthenticationEndpoints.change_password()
    headers = Auth().auth_valid_credential(get_headers)
    change_password_payload['confirmPassword'] = "DifferentPassword!"
    response = RealHomeRequest.post(url, headers, change_password_payload)

    assert_status_code_bad_request(response)

@allure.suite('Change Password')
@allure.epic('Authentication')
@allure.feature('Change Password')
@allure.story('Change Password with Invalid Token')
@allure.tag('author: Jeyson')
@pytest.mark.functional
@pytest.mark.negative
def test_change_password_with_invalid_token(change_password_payload):
    url = AuthenticationEndpoints.change_password()
    headers = {
        'accept': '*/*',
        'Content-Type': 'application/json-patch+json',
        'Authorization': 'Bearer invalid_token'
    }
    response = RealHomeRequest.post(url, headers, change_password_payload)

    assert_status_code_unauthorized(response)

@allure.suite('Change Password')
@allure.epic('Authentication')
@allure.feature('Change Password')
@allure.story('Change Password without Token')
@allure.tag('author: Jeyson')
@pytest.mark.functional
@pytest.mark.negative
def test_change_password_without_token(get_header, change_password_payload):
    url = AuthenticationEndpoints.change_password()
    response = RealHomeRequest.post(url, get_header, change_password_payload)

    assert_status_code_unauthorized(response)

@allure.suite('Change Password')
@allure.epic('Authentication')
@allure.feature('Change Password')
@allure.story('Change Password with Weak Password')
@allure.tag('author: Jeyson')
@pytest.mark.functional
@pytest.mark.negative
def test_change_password_with_weak_password(get_headers, change_password_payload):
    url = AuthenticationEndpoints.change_password()
    headers = Auth().auth_valid_credential(get_headers)
    change_password_payload['password'] = "weakpassword"
    change_password_payload['confirmPassword'] = "weakpassword"
    response = RealHomeRequest.post(url, headers, change_password_payload)

    assert_status_code_bad_request(response)

@allure.suite('Change Password')
@allure.epic('Authentication')
@allure.feature('Change Password')
@allure.story('Change Password with Incorrect Old Password')
@allure.tag('author: Jeyson')
@pytest.mark.functional
@pytest.mark.negative
def test_change_password_with_incorrect_old_password(get_headers, change_password_payload):
    url = AuthenticationEndpoints.change_password()
    headers = Auth().auth_valid_credential(get_headers)
    change_password_payload['oldPassword'] = "IncorrectOldPassword"
    response = RealHomeRequest.post(url, headers, change_password_payload)

    assert_status_code_internal_server_error(response)

@allure.suite('Change Password')
@allure.epic('Authentication')
@allure.feature('Change Password')
@allure.story('Change Password with Invalid Auth Scheme')
@allure.tag('author: Jeyson')
@pytest.mark.functional
@pytest.mark.negative
def test_change_password_with_invalid_auth_scheme(change_password_payload):
    url = AuthenticationEndpoints.change_password()
    headers = {
        'accept': '*/*',
        'Content-Type': 'application/json-patch+json',
        'Authorization': 'InvalidScheme token'
    }
    response = RealHomeRequest.post(url, headers, change_password_payload)

    assert_status_code_unauthorized(response)

@allure.suite('Change Password')
@allure.epic('Authentication')
@allure.feature('Change Password')
@allure.story('Change Password with Incorrect HTTP Method')
@allure.tag('author: Jeyson')
@pytest.mark.functional
@pytest.mark.negative
def test_change_password_with_incorrect_http_method(get_headers):
    url = AuthenticationEndpoints.change_password()
    headers = Auth().auth_valid_credential(get_headers)
    response = RealHomeRequest.get_with_url_headers(url, headers)

    assert_status_code_bad_request(response)
