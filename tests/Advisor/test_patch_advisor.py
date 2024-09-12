import pytest
import allure
from api.endpoints.advisor import AdvisorEndpoints
from resources.auth.auth import Auth
from api.request.api_request import RealHomeRequest
from core.assertions.status_code import *

@allure.suite('Advisor')
@allure.epic('Update Advisor')
@allure.feature('Advisor')
@allure.story('Update Advisor with Valid Data')
@pytest.mark.functional
@pytest.mark.positive
@pytest.mark.smoke
def test_patch_advisor_with_valid_data(get_headers, advisor_patch_payload):
    url = AdvisorEndpoints.update_advisor()
    headers = Auth().auth_valid_credential(get_headers)
    response = RealHomeRequest.patch(url, headers, advisor_patch_payload)

    assert_status_code_ok(response)

@allure.suite('Advisor')
@allure.epic('Update Advisor')
@allure.feature('Advisor')
@allure.story('Update Advisor with Empty First Name')
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

@allure.suite('Advisor')
@allure.epic('Update Advisor')
@allure.feature('Advisor')
@allure.story('Update Advisor with Empty Last Name')
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

@allure.suite('Advisor')
@allure.epic('Update Advisor')
@allure.feature('Advisor')
@allure.story('Update Advisor with Empty CI')
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

@allure.suite('Advisor')
@allure.epic('Update Advisor')
@allure.feature('Advisor')
@allure.story('Update Advisor with Invalid CI Length')
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

@allure.suite('Advisor')
@allure.epic('Update Advisor')
@allure.feature('Advisor')
@allure.story('Update Advisor with Empty Cell Phone')
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

@allure.suite('Advisor')
@allure.epic('Update Advisor')
@allure.feature('Advisor')
@allure.story('Update Advisor with Invalid Cell Phone Format')
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

@allure.suite('Advisor')
@allure.epic('Update Advisor')
@allure.feature('Advisor')
@allure.story('Update Advisor with Empty Address')
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

@allure.suite('Advisor')
@allure.epic('Update Advisor')
@allure.feature('Advisor')
@allure.story('Update Advisor with Empty FanPageUrl')
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

@allure.suite('Advisor')
@allure.epic('Update Advisor')
@allure.feature('Advisor')
@allure.story('Update Advisor with Invalid Authentication Token')
@pytest.mark.functional
@pytest.mark.negative
@pytest.mark.regression
def test_patch_advisor_with_invalid_auth_token(advisor_patch_payload):
    url = AdvisorEndpoints.update_advisor()
    headers = {"Authorization": "Bearer invalid-token"}
    payload = advisor_patch_payload.copy()
    response = RealHomeRequest.patch(url, headers, payload)

    assert_status_code_unauthorized(response)

@allure.suite('Advisor')
@allure.epic('Update Advisor')
@allure.feature('Advisor')
@allure.story('Update Advisor without Authentication Token')
@pytest.mark.functional
@pytest.mark.negative
@pytest.mark.smoke
def test_patch_advisor_without_authentication(advisor_patch_payload):
    url = AdvisorEndpoints.update_advisor()
    payload = advisor_patch_payload.copy()
    response = RealHomeRequest.patch(url, {}, payload)

    assert_status_code_unauthorized(response)

@allure.suite('Advisor')
@allure.epic('Update Advisor')
@allure.feature('Advisor')
@allure.story('Update Advisor with Updated First Name Only')
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

@allure.suite('Advisor')
@allure.epic('Update Advisor')
@allure.feature('Advisor')
@allure.story('Update Advisor with Updated Last Name Only')
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

@allure.suite('Advisor')
@allure.epic('Update Advisor')
@allure.feature('Advisor')
@allure.story('Update Advisor with Updated Email Only')
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

@allure.suite('Advisor')
@allure.epic('Update Advisor')
@allure.feature('Advisor')
@allure.story('Update Advisor with Updated Cell Phone Only')
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

@allure.suite('Advisor')
@allure.epic('Update Advisor')
@allure.feature('Advisor')
@allure.story('Update Advisor with Updated Address Only')
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

@allure.suite('Advisor')
@allure.epic('Update Advisor')
@allure.feature('Advisor')
@allure.story('Update Advisor with Updated FanPageUrl Only')
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

@allure.suite('Advisor')
@allure.epic('Update Advisor')
@allure.feature('Advisor')
@allure.story('Update Advisor with Empty Payload')
@pytest.mark.functional
@pytest.mark.negative
@pytest.mark.regression
def test_patch_advisor_with_empty_payload(get_headers, advisor_patch_payload):
    url = AdvisorEndpoints.update_advisor()
    headers = Auth().auth_valid_credential(get_headers)
    payload = {}
    response = RealHomeRequest.patch(url, headers, payload)

    assert_status_code_bad_request(response)
