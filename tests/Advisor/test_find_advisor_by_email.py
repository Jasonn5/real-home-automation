import pytest
import allure
from api.endpoints.advisor import AdvisorEndpoints
from resources.auth.auth import Auth
from api.request.api_request import RealHomeRequest
from core.assertions.status_code import *

@allure.suite('Advisor')
@allure.epic('Find Advisor By Email')
@allure.feature('Advisor')
@allure.story('Find Advisor by Valid Email')
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

@allure.suite('Advisor')
@allure.epic('Find Advisor By Email')
@allure.feature('Advisor')
@allure.story('Find Advisor by Non-Existent Email')
@pytest.mark.functional
@pytest.mark.negative
@pytest.mark.regression
def test_find_advisor_by_non_existent_email(get_headers):
    non_existent_email = "nonexistent@example.com"
    url = f"{AdvisorEndpoints.get_advisor_by_email(non_existent_email)}"
    headers = Auth().auth_valid_credential(get_headers)
    response = RealHomeRequest.get_with_url_headers(url, headers)

    assert_status_code_not_found(response)

@allure.suite('Advisor')
@allure.epic('Find Advisor By Email')
@allure.feature('Advisor')
@allure.story('Find Advisor by Invalid Email Format')
@pytest.mark.functional
@pytest.mark.negative
@pytest.mark.regression
def test_find_advisor_by_invalid_email_format(get_headers):
    invalid_email = "invalid-email"
    url = f"{AdvisorEndpoints.get_advisor_by_email(invalid_email)}"
    headers = Auth().auth_valid_credential(get_headers)
    response = RealHomeRequest.get_with_url_headers(url, headers)

    assert_status_code_bad_request(response)

@allure.suite('Advisor')
@allure.epic('Find Advisor By Email')
@allure.feature('Advisor')
@allure.story('Unauthorized Access to Find Advisor')
@pytest.mark.functional
@pytest.mark.negative
@pytest.mark.smoke
def test_find_advisor_without_authentication():
    valid_email = "jasson.n021@gmail.com"
    url = f"{AdvisorEndpoints.get_advisor_by_email(valid_email)}"
    response = RealHomeRequest.get_with_url(url)

    assert_status_code_unauthorized(response)

@allure.suite('Advisor')
@allure.epic('Find Advisor By Email')
@allure.feature('Advisor')
@allure.story('Find Advisor by Empty Email')
@pytest.mark.functional
@pytest.mark.negative
@pytest.mark.regression
def test_find_advisor_by_empty_email(get_headers):
    empty_email = ""
    url = f"{AdvisorEndpoints.get_advisor_by_email(empty_email)}"
    headers = Auth().auth_valid_credential(get_headers)
    response = RealHomeRequest.get_with_url_headers(url, headers)

    assert_status_code_bad_request(response)

@allure.suite('Advisor')
@allure.epic('Find Advisor By Email')
@allure.feature('Advisor')
@allure.story('Find Advisor by Email with Leading or Trailing Spaces')
@pytest.mark.functional
@pytest.mark.negative
@pytest.mark.regression
def test_find_advisor_by_email_with_spaces(get_headers):
    email_with_spaces = "  jasson.n021@gmail.com  "
    url = f"{AdvisorEndpoints.get_advisor_by_email(email_with_spaces.strip())}"
    headers = Auth().auth_valid_credential(get_headers)
    response = RealHomeRequest.get_with_url_headers(url, headers)

    assert_status_code_ok(response)
