import pytest
import allure
from api.endpoints.advisor import AdvisorEndpoints
from resources.auth.auth import Auth
from api.request.api_request import RealHomeRequest
from core.assertions.status_code import *

@allure.suite('Update advisor')
@allure.epic('Advisor')
@allure.feature('Update advisor')
@allure.story('Update advisor with Valid Data')
@allure.tag('author: Jeyson')
@pytest.mark.functional
@pytest.mark.positive
@pytest.mark.smoke
def test_patch_advisor_with_valid_data(get_headers, advisor_patch_payload):
    url = AdvisorEndpoints.update_advisor()
    headers = Auth().auth_valid_credential(get_headers)
    response = RealHomeRequest.patch(url, headers, advisor_patch_payload)

    assert_status_code_ok(response)

@allure.suite('Update advisor')
@allure.epic('Advisor')
@allure.feature('Update advisor')
@allure.story('Update advisor with Empty First Name')
@allure.tag('author: Jeyson')
@pytest.mark.functional
@pytest.mark.negative
@pytest.mark.regression
def test_patch_advisor_with_empty_first_name(get_headers, advisor_patch_payload):
    url = AdvisorEndpoints.update_advisor()
    headers = Auth().auth_valid_credential(get_headers)
    payload = advisor_patch_payload.copy()
    payload['firstName'] = ""
    response = RealHomeRequest.patch(url, headers, payload)

    assert_status_code_bad_request(response)

@allure.suite('Update advisor')
@allure.epic('Advisor')
@allure.feature('Update advisor')
@allure.story('Update advisor with Empty Last Name')
@allure.tag('author: Jeyson')
@pytest.mark.functional
@pytest.mark.negative
@pytest.mark.regression
def test_patch_advisor_with_empty_last_name(get_headers, advisor_patch_payload):
    url = AdvisorEndpoints.update_advisor()
    headers = Auth().auth_valid_credential(get_headers)
    payload = advisor_patch_payload.copy()
    payload['lastName'] = ""
    response = RealHomeRequest.patch(url, headers, payload)

    assert_status_code_bad_request(response)

@allure.suite('Update advisor')
@allure.epic('Advisor')
@allure.feature('Update advisor')
@allure.story('Update advisor with Empty CI')
@allure.tag('author: Jeyson')
@pytest.mark.functional
@pytest.mark.negative
@pytest.mark.regression
def test_patch_advisor_with_empty_ci(get_headers, advisor_patch_payload):
    url = AdvisorEndpoints.update_advisor()
    headers = Auth().auth_valid_credential(get_headers)
    payload = advisor_patch_payload.copy()
    payload['ci'] = ""
    response = RealHomeRequest.patch(url, headers, payload)

    assert_status_code_bad_request(response)

@allure.suite('Update advisor')
@allure.epic('Advisor')
@allure.feature('Update advisor')
@allure.story('Update advisor with Invalid CI Length')
@allure.tag('author: Jeyson')
@pytest.mark.functional
@pytest.mark.negative
@pytest.mark.regression
def test_patch_advisor_with_invalid_ci_length(get_headers, advisor_patch_payload):
    url = AdvisorEndpoints.update_advisor()
    headers = Auth().auth_valid_credential(get_headers)
    payload = advisor_patch_payload.copy()
    payload['ci'] = "12345"
    response = RealHomeRequest.patch(url, headers, payload)

    assert_status_code_bad_request(response)

@allure.suite('Update advisor')
@allure.epic('Advisor')
@allure.feature('Update advisor')
@allure.story('Update advisor with Empty Cell Phone')
@allure.tag('author: Jeyson')
@pytest.mark.functional
@pytest.mark.negative
@pytest.mark.regression
def test_patch_advisor_with_empty_cellphone(get_headers, advisor_patch_payload):
    url = AdvisorEndpoints.update_advisor()
    headers = Auth().auth_valid_credential(get_headers)
    payload = advisor_patch_payload.copy()
    payload['cellPhone'] = ""
    response = RealHomeRequest.patch(url, headers, payload)

    assert_status_code_bad_request(response)

@allure.suite('Update advisor')
@allure.epic('Advisor')
@allure.feature('Update advisor')
@allure.story('Update advisor with Invalid Cell Phone Format')
@allure.tag('author: Jeyson')
@pytest.mark.functional
@pytest.mark.negative
@pytest.mark.regression
def test_patch_advisor_with_invalid_cellphone_format(get_headers, advisor_patch_payload):
    url = AdvisorEndpoints.update_advisor()
    headers = Auth().auth_valid_credential(get_headers)
    payload = advisor_patch_payload.copy()
    payload['cellPhone'] = "123"
    response = RealHomeRequest.patch(url, headers, payload)

    assert_status_code_bad_request(response)

@allure.suite('Update advisor')
@allure.epic('Advisor')
@allure.feature('Update advisor')
@allure.story('Update advisor with Empty Address')
@allure.tag('author: Jeyson')
@pytest.mark.functional
@pytest.mark.negative
@pytest.mark.regression
def test_patch_advisor_with_empty_address(get_headers, advisor_patch_payload):
    url = AdvisorEndpoints.update_advisor()
    headers = Auth().auth_valid_credential(get_headers)
    payload = advisor_patch_payload.copy()
    payload['address'] = ""
    response = RealHomeRequest.patch(url, headers, payload)

    assert_status_code_ok(response)

@allure.suite('Update advisor')
@allure.epic('Advisor')
@allure.feature('Update advisor')
@allure.story('Update advisor with Empty FanPageUrl')
@allure.tag('author: Jeyson')
@pytest.mark.functional
@pytest.mark.negative
@pytest.mark.regression
def test_patch_advisor_with_empty_fanpage(get_headers, advisor_patch_payload):
    url = AdvisorEndpoints.update_advisor()
    headers = Auth().auth_valid_credential(get_headers)
    payload = advisor_patch_payload.copy()
    payload['fanPageUrl'] = ""
    response = RealHomeRequest.patch(url, headers, payload)

    assert_status_code_ok(response)

@allure.suite('Update advisor')
@allure.epic('Advisor')
@allure.feature('Update advisor')
@allure.story('Update advisor with Invalid Authentication Token')
@allure.tag('author: Jeyson')
@pytest.mark.functional
@pytest.mark.negative
@pytest.mark.regression
def test_patch_advisor_with_invalid_auth_token(advisor_patch_payload):
    url = AdvisorEndpoints.update_advisor()
    headers = {"Authorization": "Bearer invalid-token"}
    payload = advisor_patch_payload.copy()
    response = RealHomeRequest.patch(url, headers, payload)

    assert_status_code_unauthorized(response)

@allure.suite('Update advisor')
@allure.epic('Advisor')
@allure.feature('Update advisor')
@allure.story('Update advisor without Authentication Token')
@allure.tag('author: Jeyson')
@pytest.mark.functional
@pytest.mark.negative
@pytest.mark.smoke
def test_patch_advisor_without_authentication(advisor_patch_payload):
    url = AdvisorEndpoints.update_advisor()
    payload = advisor_patch_payload.copy()
    response = RealHomeRequest.patch(url, {}, payload)

    assert_status_code_unauthorized(response)

@allure.suite('Update advisor')
@allure.epic('Advisor')
@allure.feature('Update advisor')
@allure.story('Update advisor with Updated First Name Only')
@allure.tag('author: Jeyson')
@pytest.mark.functional
@pytest.mark.positive
@pytest.mark.smoke
def test_patch_advisor_with_only_first_name(get_headers, advisor_patch_payload):
    url = AdvisorEndpoints.update_advisor()
    headers = Auth().auth_valid_credential(get_headers)
    payload = advisor_patch_payload.copy()
    payload['firstName'] = "NuevoNombre"
    response = RealHomeRequest.patch(url, headers, payload)

    assert_status_code_ok(response)
    assert response.json()['firstName'] == "NuevoNombre", "El nombre no fue actualizado correctamente"

@allure.suite('Update advisor')
@allure.epic('Advisor')
@allure.feature('Update advisor')
@allure.story('Update advisor with Updated Last Name Only')
@allure.tag('author: Jeyson')
@pytest.mark.functional
@pytest.mark.positive
@pytest.mark.smoke
def test_patch_advisor_with_only_last_name(get_headers, advisor_patch_payload):
    url = AdvisorEndpoints.update_advisor()
    headers = Auth().auth_valid_credential(get_headers)
    payload = advisor_patch_payload.copy()
    payload['lastName'] = "NuevoApellido"
    response = RealHomeRequest.patch(url, headers, payload)

    assert_status_code_ok(response)
    assert response.json()['lastName'] == "NuevoApellido", "El apellido no fue actualizado correctamente"

@allure.suite('Update advisor')
@allure.epic('Advisor')
@allure.feature('Update advisor')
@allure.story('Update advisor with Updated Email Only')
@allure.tag('author: Jeyson')
@pytest.mark.functional
@pytest.mark.positive
@pytest.mark.smoke
def test_patch_advisor_with_only_email(get_headers, advisor_patch_payload):
    url = AdvisorEndpoints.update_advisor()
    headers = Auth().auth_valid_credential(get_headers)
    payload = advisor_patch_payload.copy()
    payload['email'] = "nuevoemail@gmail.com"
    response = RealHomeRequest.patch(url, headers, payload)

    assert_status_code_ok(response)
    assert response.json()['email'] == "nuevoemail@gmail.com", "El email no fue actualizado correctamente"

@allure.suite('Update advisor')
@allure.epic('Advisor')
@allure.feature('Update advisor')
@allure.story('Update advisor with Updated Cell Phone Only')
@allure.tag('author: Jeyson')
@pytest.mark.functional
@pytest.mark.positive
@pytest.mark.smoke
def test_patch_advisor_with_only_cellphone(get_headers, advisor_patch_payload):
    url = AdvisorEndpoints.update_advisor()
    headers = Auth().auth_valid_credential(get_headers)
    payload = advisor_patch_payload.copy()
    payload['cellPhone'] = 12345678
    response = RealHomeRequest.patch(url, headers, payload)

    assert_status_code_ok(response)
    assert response.json()['cellPhone'] == 12345678, "El teléfono no fue actualizado correctamente"

@allure.suite('Update advisor')
@allure.epic('Advisor')
@allure.feature('Update advisor')
@allure.story('Update advisor with Updated Address Only')
@allure.tag('author: Jeyson')
@pytest.mark.functional
@pytest.mark.positive
@pytest.mark.smoke
def test_patch_advisor_with_only_address(get_headers, advisor_patch_payload):
    url = AdvisorEndpoints.update_advisor()
    headers = Auth().auth_valid_credential(get_headers)
    payload = advisor_patch_payload.copy()
    payload['address'] = "Nueva dirección"
    response = RealHomeRequest.patch(url, headers, payload)

    assert_status_code_ok(response)
    assert response.json()['address'] == "Nueva dirección", "La dirección no fue actualizada correctamente"

@allure.suite('Update advisor')
@allure.epic('Advisor')
@allure.feature('Update advisor')
@allure.story('Update advisor with Updated FanPageUrl Only')
@allure.tag('author: Jeyson')
@pytest.mark.functional
@pytest.mark.positive
@pytest.mark.smoke
def test_patch_advisor_with_only_fanpage(get_headers, advisor_patch_payload):
    url = AdvisorEndpoints.update_advisor()
    headers = Auth().auth_valid_credential(get_headers)
    payload = advisor_patch_payload.copy()
    payload['fanPageUrl'] = "https://www.newfanpage.com"
    response = RealHomeRequest.patch(url, headers, payload)

    assert_status_code_ok(response)
    assert response.json()['fanPageUrl'] == "https://www.newfanpage.com", "La fan page no fue actualizada correctamente"

@allure.suite('Update advisor')
@allure.epic('Advisor')
@allure.feature('Update advisor')
@allure.story('Update advisor with Empty Payload')
@allure.tag('author: Jeyson')
@pytest.mark.functional
@pytest.mark.negative
@pytest.mark.regression
def test_patch_advisor_with_empty_payload(get_headers, advisor_patch_payload):
    url = AdvisorEndpoints.update_advisor()
    headers = Auth().auth_valid_credential(get_headers)
    payload = {}
    response = RealHomeRequest.patch(url, headers, payload)

    assert_status_code_bad_request(response)
