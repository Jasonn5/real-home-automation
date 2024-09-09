from core.assertions.status_code import (
    assert_status_code_ok,
    assert_status_code_unauthorized,
    assert_status_bad_request, assert_status_code_internal_server_error
)
from api.endpoints.authentication import AuthenticationEndpoints
from api.request.api_request import RealHomeRequest
import allure
import pytest

@allure.suite('EspoCRM')
@allure.sub_suite('Authentication')
@allure.epic('EspoCRM')
@allure.feature('Login')
@allure.story('User Login')
@allure.tag('author: Jeyson')
@pytest.mark.functional
@pytest.mark.positive
@pytest.mark.smoke
def test_get_login_success(get_header, valid_credentials):
    url = AuthenticationEndpoints.authenticate()
    response = RealHomeRequest.post_json(url, get_header, valid_credentials)

    assert_status_code_ok(response)


@allure.suite('EspoCRM')
@allure.sub_suite('Authentication')
@allure.epic('EspoCRM')
@allure.feature('Login')
@allure.story('Invalid Username')
@allure.tag('author: Jeyson')
@pytest.mark.functional
@pytest.mark.negative
def test_get_login_invalid_username(get_header, invalid_username):
    url = AuthenticationEndpoints.authenticate()
    response = RealHomeRequest.post_json(url, get_header, invalid_username)
    assert_status_code_unauthorized(response)


@allure.suite('EspoCRM')
@allure.sub_suite('Authentication')
@allure.epic('EspoCRM')
@allure.feature('Login')
@allure.story('Invalid Password')
@allure.tag('author: Jeyson')
@pytest.mark.functional
@pytest.mark.negative
def test_get_login_invalid_password(get_header, invalid_password):
    url = AuthenticationEndpoints.authenticate()
    response = RealHomeRequest.post_json(url, get_header, invalid_password)
    assert_status_code_unauthorized(response)


@allure.suite('EspoCRM')
@allure.sub_suite('Authentication')
@allure.epic('EspoCRM')
@allure.feature('Login')
@allure.story('Invalid Credentials')
@allure.tag('author: Jeyson')
@pytest.mark.functional
@pytest.mark.negative
def test_get_login_invalid_credentials(get_header, invalid_credentials):
    url = AuthenticationEndpoints.authenticate()
    response = RealHomeRequest.post_json(url, get_header, invalid_credentials)
    assert_status_code_unauthorized(response)


@allure.suite('EspoCRM')
@allure.sub_suite('Authentication')
@allure.epic('EspoCRM')
@allure.feature('Login')
@allure.story('Empty Fields')
@allure.tag('author: Jeyson')
@pytest.mark.functional
@pytest.mark.negative
def test_get_login_empty_fields(get_header, empty_fields):
    url = AuthenticationEndpoints.authenticate()
    response = RealHomeRequest.post_json(url, get_header, empty_fields)

    assert_status_bad_request(response)


@allure.suite('EspoCRM')
@allure.sub_suite('Authentication')
@allure.epic('EspoCRM')
@allure.feature('Login')
@allure.story('Empty Username')
@allure.tag('author: Jeyson')
@pytest.mark.functional
@pytest.mark.negative
def test_get_login_empty_username(get_header, empty_username):
    url = AuthenticationEndpoints.authenticate()
    response = RealHomeRequest.post_json(url, get_header, empty_username)

    assert_status_code_internal_server_error(response)


@allure.suite('EspoCRM')
@allure.sub_suite('Authentication')
@allure.epic('EspoCRM')
@allure.feature('Login')
@allure.story('Empty Password')
@allure.tag('author: Jeyson')
@pytest.mark.functional
@pytest.mark.negative
def test_get_login_empty_password(get_header, empty_password):
    url = AuthenticationEndpoints.authenticate()
    response = RealHomeRequest.post_json(url, get_header, empty_password)

    assert_status_bad_request(response)


@allure.suite('EspoCRM')
@allure.sub_suite('Authentication')
@allure.epic('EspoCRM')
@allure.feature('Login')
@allure.story('Valid Username, Empty Password')
@allure.tag('author: Jeyson')
@pytest.mark.functional
@pytest.mark.negative
def test_get_login_valid_username_empty_password(get_header, valid_username_empty_password):
    url = AuthenticationEndpoints.authenticate()
    response = RealHomeRequest.post_json(url, get_header, valid_username_empty_password)

    assert_status_bad_request(response)


@allure.suite('EspoCRM')
@allure.sub_suite('Authentication')
@allure.epic('EspoCRM')
@allure.feature('Login')
@allure.story('Empty Username, Valid Password')
@allure.tag('author: Jeyson')
@pytest.mark.functional
@pytest.mark.negative
def test_get_login_empty_username_valid_password(get_header, empty_username_valid_password):
    url = AuthenticationEndpoints.authenticate()
    response = RealHomeRequest.post_json(url, get_header, empty_username_valid_password)

    assert_status_bad_request(response)


@allure.suite('EspoCRM')
@allure.sub_suite('Authentication')
@allure.epic('EspoCRM')
@allure.feature('Login')
@allure.story('Mismatched Passwords')
@allure.tag('author: Jeyson')
@pytest.mark.functional
@pytest.mark.negative
def test_get_login_mismatched_passwords(get_header, mismatched_passwords):
    url = AuthenticationEndpoints.authenticate()
    response = RealHomeRequest.post_json(url, get_header, mismatched_passwords)

    assert_status_bad_request(response)


@allure.suite('EspoCRM')
@allure.sub_suite('Authentication')
@allure.epic('EspoCRM')
@allure.feature('Login')
@allure.story('Missing Confirm Password')
@allure.tag('author: Jeyson')
@pytest.mark.functional
@pytest.mark.negative
def test_get_login_missing_confirm_password(get_header, missing_confirm_password):
    url = AuthenticationEndpoints.authenticate()
    response = RealHomeRequest.post_json(url, get_header, missing_confirm_password)

    assert_status_bad_request(response)
