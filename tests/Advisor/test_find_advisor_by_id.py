import pytest
import allure
from api.endpoints.advisor import AdvisorEndpoints
from resources.auth.auth import Auth
from api.request.api_request import RealHomeRequest
from core.assertions.status_code import *

@allure.suite('Advisor')
@allure.epic('Get Advisor By ID')
@allure.feature('Advisor')
@allure.story('Get Advisor by Valid ID')
@pytest.mark.functional
@pytest.mark.positive
@pytest.mark.smoke
def test_get_advisor_by_valid_id(get_headers):
    advisor_id = 1
    url = f"{AdvisorEndpoints.get_advisor_by_id(advisor_id)}"
    headers = Auth().auth_valid_credential(get_headers)
    response = RealHomeRequest.get_with_url_headers(url, headers)

    assert_status_code_ok(response)
    assert response.json()['id'] == advisor_id, "El ID no coincide con el asesor devuelto"

@allure.suite('Advisor')
@allure.epic('Get Advisor By ID')
@allure.feature('Advisor')
@allure.story('Get Advisor by Non-Existent ID')
@pytest.mark.functional
@pytest.mark.negative
@pytest.mark.regression
def test_get_advisor_by_non_existent_id(get_headers):
    non_existent_id = 99999
    url = f"{AdvisorEndpoints.get_advisor_by_id(non_existent_id)}"
    headers = Auth().auth_valid_credential(get_headers)
    response = RealHomeRequest.get_with_url_headers(url, headers)

    assert_status_code_not_found(response)

@allure.suite('Advisor')
@allure.epic('Get Advisor By ID')
@allure.feature('Advisor')
@allure.story('Get Advisor by Non-Numeric ID')
@pytest.mark.functional
@pytest.mark.negative
@pytest.mark.regression
def test_get_advisor_by_non_numeric_id(get_headers):
    non_numeric_id = "abc"
    url = f"{AdvisorEndpoints.get_advisor_by_id(non_numeric_id)}"
    headers = Auth().auth_valid_credential(get_headers)
    response = RealHomeRequest.get_with_url_headers(url, headers)

    assert_status_code_bad_request(response)

@allure.suite('Advisor')
@allure.epic('Get Advisor By ID')
@allure.feature('Advisor')
@allure.story('Unauthorized Access to Get Advisor')
@pytest.mark.functional
@pytest.mark.negative
@pytest.mark.smoke
def test_get_advisor_without_authentication():
    advisor_id = 1
    url = f"{AdvisorEndpoints.get_advisor_by_id(advisor_id)}"
    response = RealHomeRequest.get_with_url(url)

    assert_status_code_unauthorized(response)

@allure.suite('Advisor')
@allure.epic('Get Advisor By ID')
@allure.feature('Advisor')
@allure.story('Get Advisor by Negative ID')
@pytest.mark.functional
@pytest.mark.negative
@pytest.mark.regression
def test_get_advisor_by_negative_id(get_headers):
    negative_id = -1
    url = f"{AdvisorEndpoints.get_advisor_by_id(negative_id)}"
    headers = Auth().auth_valid_credential(get_headers)
    response = RealHomeRequest.get_with_url_headers(url, headers)

    assert_status_code_bad_request(response)

@allure.suite('Advisor')
@allure.epic('Get Advisor By ID')
@allure.feature('Advisor')
@allure.story('Get Advisor by Zero ID')
@pytest.mark.functional
@pytest.mark.negative
@pytest.mark.regression
def test_get_advisor_by_zero_id(get_headers):
    zero_id = 0
    url = f"{AdvisorEndpoints.get_advisor_by_id(zero_id)}"
    headers = Auth().auth_valid_credential(get_headers)
    response = RealHomeRequest.get_with_url_headers(url, headers)

    assert_status_code_bad_request(response)
