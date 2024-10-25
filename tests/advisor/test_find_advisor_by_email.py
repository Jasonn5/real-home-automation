import pytest
import allure
from api.endpoints.advisor import AdvisorEndpoints
from resources.auth.auth import Auth
from api.request.api_request import RealHomeRequest
from core.assertions.status_code import *

@allure.suite('Find advisor By Email')
@allure.epic('Advisor')
@allure.feature('Find advisor By Email')
@allure.story('Find advisor by Valid Email')
@allure.tag('author: Jeyson')
@pytest.mark.functional
@pytest.mark.positive
@pytest.mark.smoke
def test_find_advisor_by_valid_email(get_headers):
    valid_email = "jasson.n021@gmail.com"
    url = f"{AdvisorEndpoints.get_advisor_by_email(valid_email)}"
    headers = Auth().auth_valid_credential(get_headers)
    response = RealHomeRequest.get_with_url_headers(url, headers)

    assert_status_code_ok(response)
    assert response.json()['email'] == valid_email, "El email no coincide con el asesor devuelto"

@allure.suite('Find advisor By Email')
@allure.epic('Advisor')
@allure.feature('Find advisor By Email')
@allure.story('Find advisor by Non-Existent Email')
@allure.tag('author: Jeyson')
@pytest.mark.functional
@pytest.mark.negative
@pytest.mark.regression
@pytest.mark.xfail(reason="This test case is expected to fail due to known issue.",condition=True)
def test_find_advisor_by_non_existent_email(get_headers):
    non_existent_email = "nonexistent@example.com"
    url = f"{AdvisorEndpoints.get_advisor_by_email(non_existent_email)}"
    headers = Auth().auth_valid_credential(get_headers)
    response = RealHomeRequest.get_with_url_headers(url, headers)

    assert_status_code_not_found(response)

@allure.suite('Find advisor By Email')
@allure.epic('Advisor')
@allure.feature('Find advisor By Email')
@allure.story('Find advisor by Invalid Email Format')
@allure.tag('author: Jeyson')
@pytest.mark.functional
@pytest.mark.negative
@pytest.mark.regression
@pytest.mark.xfail(reason="This test case is expected to fail due to known issue.",condition=True)
def test_find_advisor_by_invalid_email_format(get_headers):
    invalid_email = "invalid-email"
    url = f"{AdvisorEndpoints.get_advisor_by_email(invalid_email)}"
    headers = Auth().auth_valid_credential(get_headers)
    response = RealHomeRequest.get_with_url_headers(url, headers)

    assert_status_code_bad_request(response)

@allure.suite('Find advisor By Email')
@allure.epic('Advisor')
@allure.feature('Find advisor By Email')
@allure.story('Unauthorized Access to Find advisor')
@allure.tag('author: Jeyson')
@pytest.mark.functional
@pytest.mark.negative
@pytest.mark.smoke
def test_find_advisor_without_authentication():
    valid_email = "jasson.n021@gmail.com"
    url = f"{AdvisorEndpoints.get_advisor_by_email(valid_email)}"
    response = RealHomeRequest.get_with_url(url)

    assert_status_code_unauthorized(response)

@allure.suite('Find advisor By Email')
@allure.epic('Advisor')
@allure.feature('Find advisor By Email')
@allure.story('Find advisor by Empty Email')
@allure.tag('author: Jeyson')
@pytest.mark.functional
@pytest.mark.negative
@pytest.mark.regression
def test_find_advisor_by_empty_email(get_headers):
    empty_email = ""
    url = f"{AdvisorEndpoints.get_advisor_by_email(empty_email)}"
    headers = Auth().auth_valid_credential(get_headers)
    response = RealHomeRequest.get_with_url_headers(url, headers)

    assert_status_code_bad_request(response)

@allure.suite('Find advisor By Email')
@allure.epic('Advisor')
@allure.feature('Find advisor By Email')
@allure.story('Find advisor by Email with Leading or Trailing Spaces')
@allure.tag('author: Jeyson')
@pytest.mark.functional
@pytest.mark.negative
@pytest.mark.regression
def test_find_advisor_by_email_with_spaces(get_headers):
    email_with_spaces = "  jasson.n021@gmail.com  "
    url = f"{AdvisorEndpoints.get_advisor_by_email(email_with_spaces.strip())}"
    headers = Auth().auth_valid_credential(get_headers)
    response = RealHomeRequest.get_with_url_headers(url, headers)

    assert_status_code_ok(response)

@allure.suite('Find advisor By Email')
@allure.epic('Advisor')
@allure.feature('Find advisor By Email')
@allure.story('Find advisor by Email in Uppercase')
@allure.tag('author: Jeyson')
@pytest.mark.functional
@pytest.mark.negative
def test_find_advisor_by_email_uppercase(get_headers):
    uppercase_email = "JASSON.N021@GMAIL.COM"
    url = f"{AdvisorEndpoints.get_advisor_by_email(uppercase_email)}"
    headers = Auth().auth_valid_credential(get_headers)
    response = RealHomeRequest.get_with_url_headers(url, headers)

    assert_status_code_ok(response)

@allure.suite('Find advisor By Email')
@allure.epic('Advisor')
@allure.feature('Find advisor By Email')
@allure.story('Find advisor by Email with Uppercase Domain')
@allure.tag('author: Jeyson')
@pytest.mark.functional
@pytest.mark.negative
def test_find_advisor_by_email_with_uppercase_domain(get_headers):
    email_uppercase_domain = "jasson.n021@GMAIL.COM"
    url = f"{AdvisorEndpoints.get_advisor_by_email(email_uppercase_domain)}"
    headers = Auth().auth_valid_credential(get_headers)
    response = RealHomeRequest.get_with_url_headers(url, headers)

    assert_status_code_ok(response)

@allure.suite('Find advisor By Email')
@allure.epic('Advisor')
@allure.feature('Find advisor By Email')
@allure.story('Find advisor by Email with Missing Authorization Header')
@allure.tag('author: Jeyson')
@pytest.mark.functional
@pytest.mark.negative
def test_find_advisor_by_email_missing_auth_header(get_headers):
    valid_email = "jasson.n021@gmail.com"
    url = f"{AdvisorEndpoints.get_advisor_by_email(valid_email)}"
    headers = Auth().auth_valid_credential(get_headers).copy()
    headers.pop('Authorization')
    response = RealHomeRequest.get_with_url_headers(url, headers)

    assert_status_code_unauthorized(response)


@allure.suite('Find advisor By Email')
@allure.epic('Advisor')
@allure.feature('Find advisor By Email')
@allure.story('Find advisor by Email with Invalid Content-Type Header')
@allure.tag('author: Jeyson')
@pytest.mark.functional
@pytest.mark.negative
@pytest.mark.xfail(reason="This test case is expected to fail due to known issue.",condition=True)
def test_find_advisor_by_email_invalid_content_type(get_headers):
    valid_email = "jasson.n021@gmail.com"
    url = f"{AdvisorEndpoints.get_advisor_by_email(valid_email)}"
    headers = Auth().auth_valid_credential(get_headers).copy()
    headers['Content-Type'] = 'application/xml'
    response = RealHomeRequest.get_with_url_headers(url, headers)

    assert_status_code_bad_request(response)


@allure.suite('Find advisor By Email')
@allure.epic('Advisor')
@allure.feature('Find advisor By Email')
@allure.story('Find advisor by Email with Missing Accept Header')
@allure.tag('author: Jeyson')
@pytest.mark.functional
@pytest.mark.negative
def test_find_advisor_by_email_missing_accept_header(get_headers):
    valid_email = "jasson.n021@gmail.com"
    url = f"{AdvisorEndpoints.get_advisor_by_email(valid_email)}"
    headers = Auth().auth_valid_credential(get_headers).copy()
    headers.pop('accept')
    response = RealHomeRequest.get_with_url_headers(url, headers)

    assert_status_code_ok(response)
