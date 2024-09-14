import pytest
import allure
from api.endpoints.advisor import AdvisorEndpoints
from resources.auth.auth import Auth
from api.request.api_request import RealHomeRequest
from core.assertions.status_code import *

@allure.suite('List Advisors')
@allure.epic('Advisor')
@allure.feature('List Advisors')
@allure.story('List All Advisors')
@allure.tag('author: Jeyson')
@pytest.mark.functional
@pytest.mark.positive
@pytest.mark.smoke
def test_smoke_list_all_advisors(get_headers):
    url = AdvisorEndpoints.get_advisors()
    headers = Auth().auth_valid_credential(get_headers)
    response = RealHomeRequest.get_with_url_headers(url, headers)

    assert_status_code_ok(response)
    assert isinstance(response.json(), list), "La respuesta no es una lista"

@allure.suite('List Advisors')
@allure.epic('Advisor')
@allure.feature('List Advisors')
@allure.story('Search Advisors by Name')
@allure.tag('author: Jeyson')
@pytest.mark.functional
@pytest.mark.positive
@pytest.mark.smoke
def test_smoke_list_advisors_search_by_name(get_headers):
    search_term = "Test"
    url = f"{AdvisorEndpoints.get_advisors()}?Search={search_term}"
    headers = Auth().auth_valid_credential(get_headers)
    response = RealHomeRequest.get_with_url_headers(url, headers)

    assert_status_code_ok(response)
    assert isinstance(response.json(), list), "La respuesta no es una lista"

@allure.suite('List Advisors')
@allure.epic('Advisor')
@allure.feature('List Advisors')
@allure.story('Unauthorized Access')
@allure.tag('author: Jeyson')
@pytest.mark.functional
@pytest.mark.negative
@pytest.mark.smoke
def test_list_advisors_unauthorized_access():
    url = AdvisorEndpoints.get_advisors()
    response = RealHomeRequest.get_with_url(url)

    assert_status_code_unauthorized(response)

@allure.suite('List Advisors')
@allure.epic('Advisor')
@allure.feature('List Advisors')
@allure.story('Search Advisors by Name')
@allure.tag('author: Jeyson')
@pytest.mark.functional
@pytest.mark.positive
@pytest.mark.regression
def test_list_advisors_search_by_name(get_headers):
    search_term = "Test"
    url = f"{AdvisorEndpoints.get_advisors()}?Search={search_term}"
    headers = Auth().auth_valid_credential(get_headers)
    response = RealHomeRequest.get_with_url_headers(url, headers)

    assert_status_code_ok(response)
    assert response.json(), "La lista de asesores está vacía"
    for advisor in response.json():
        assert search_term.lower() in advisor['firstName'].lower(), "El nombre no coincide con el término de búsqueda"

@allure.suite('List Advisors')
@allure.epic('Advisor')
@allure.feature('List Advisors')
@allure.story('Search Advisors by Last Name')
@allure.tag('author: Jeyson')
@pytest.mark.functional
@pytest.mark.positive
@pytest.mark.regression
def test_list_advisors_search_by_last_name(get_headers):
    search_term = "test"
    url = f"{AdvisorEndpoints.get_advisors()}?Search={search_term}"
    headers = Auth().auth_valid_credential(get_headers)
    response = RealHomeRequest.get_with_url_headers(url, headers)
    assert_status_code_ok(response)

    assert response.json(), "La lista de asesores está vacía"
    for advisor in response.json():
        assert search_term.lower() in advisor['lastName'].lower(), "El apellido no coincide con el término de búsqueda"


@allure.suite('List Advisors')
@allure.epic('Advisor')
@allure.feature('List Advisors')
@allure.story('Search Advisors by CI')
@allure.tag('author: Jeyson')
@pytest.mark.functional
@pytest.mark.positive
@pytest.mark.regression
def test_list_advisors_search_by_ci(get_headers):
    search_term = "909090"
    url = f"{AdvisorEndpoints.get_advisors()}?Search={search_term}"
    headers = Auth().auth_valid_credential(get_headers)
    response = RealHomeRequest.get_with_url_headers(url, headers)

    assert_status_code_ok(response)
    assert response.json(), "La lista de asesores está vacía"
    for advisor in response.json():
        assert search_term in advisor['ci'], "El CI no coincide con el término de búsqueda"


@allure.suite('List Advisors')
@allure.epic('Advisor')
@allure.feature('List Advisors')
@allure.story('Search Advisors with No Results')
@allure.tag('author: Jeyson')
@pytest.mark.functional
@pytest.mark.negative
@pytest.mark.regression
def test_list_advisors_search_no_results(get_headers):
    search_term = "nonexistent"
    url = f"{AdvisorEndpoints.get_advisors()}?Search={search_term}"
    headers = Auth().auth_valid_credential(get_headers)
    response = RealHomeRequest.get_with_url_headers(url, headers)

    assert_status_code_ok(response)
    assert response.json() == [], "La lista de asesores no está vacía cuando debería estarlo"

@allure.suite('List Advisors')
@allure.epic('Advisor')
@allure.feature('List Advisors')
@allure.story('Search Advisors with Special Characters')
@allure.tag('author: Jeyson')
@pytest.mark.functional
@pytest.mark.negative
@pytest.mark.regression
def test_list_advisors_search_special_characters(get_headers):
    search_term = "@!#$"
    url = f"{AdvisorEndpoints.get_advisors()}?Search={search_term}"
    headers = Auth().auth_valid_credential(get_headers)
    response = RealHomeRequest.get_with_url_headers(url, headers)

    assert_status_code_ok(response)
    assert response.json() == [], "La lista de asesores no está vacía cuando debería estarlo"

@allure.suite('List Advisors')
@allure.epic('Advisor')
@allure.feature('List Advisors')
@allure.story('List Advisors with Missing Authorization Header')
@allure.tag('author: Jeyson')
@pytest.mark.functional
@pytest.mark.negative
def test_list_advisors_missing_auth_header(get_headers):
    url = AdvisorEndpoints.get_advisors()
    headers = Auth().auth_valid_credential(get_headers).copy()
    headers.pop('Authorization')
    response = RealHomeRequest.get_with_url_headers(url, headers)

    assert_status_code_unauthorized(response)


@allure.suite('List Advisors')
@allure.epic('Advisor')
@allure.feature('List Advisors')
@allure.story('List Advisors with Invalid Content-Type Header')
@allure.tag('author: Jeyson')
@pytest.mark.functional
@pytest.mark.negative
def test_list_advisors_invalid_content_type(get_headers):
    url = AdvisorEndpoints.get_advisors()
    headers = Auth().auth_valid_credential(get_headers).copy()
    headers['Content-Type'] = 'application/xml'
    response = RealHomeRequest.get_with_url_headers(url, headers)

    assert_status_code_bad_request(response)


@allure.suite('List Advisors')
@allure.epic('Advisor')
@allure.feature('List Advisors')
@allure.story('List Advisors with Missing Accept Header')
@allure.tag('author: Jeyson')
@pytest.mark.functional
@pytest.mark.negative
def test_list_advisors_missing_accept_header(get_headers):
    url = AdvisorEndpoints.get_advisors()
    headers = Auth().auth_valid_credential(get_headers).copy()
    headers.pop('accept')
    response = RealHomeRequest.get_with_url_headers(url, headers)

    assert_status_code_ok(response)
