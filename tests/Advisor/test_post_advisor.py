import allure
import pytest
from api.endpoints.advisor import AdvisorEndpoints
from resources.auth.auth import Auth
from api.request.api_request import RealHomeRequest
from core.assertions.status_code import *
@allure.suite('Advisor')
@allure.epic('Crate Advisor Account')
@allure.feature('Advisor')
@allure.story('Post Advisor All Fields Valid')
@allure.tag('author: Jeyson')
@pytest.mark.functional
@pytest.mark.positive
@pytest.mark.smoke
def test_post_advisor_all_fields_valid(get_headers, advisor_payload, unique_user_data):
    url = AdvisorEndpoints.create_advisor()
    headers = Auth().auth_valid_credential(get_headers)
    unique_email = unique_user_data
    advisor_payload['email'] = unique_email
    advisor_payload['user']['username'] = unique_email
    advisor_payload['user']['email'] = unique_email
    response = RealHomeRequest.post_json(url, headers, advisor_payload)

    assert_status_code_created(response)

@allure.suite('Advisor')
@allure.epic('Crate Advisor Account')
@allure.feature('Advisor')
@allure.story('Post Advisor Without First Name')
@pytest.mark.functional
@pytest.mark.negative
@pytest.mark.regression
def test_post_advisor_without_first_name(get_headers, advisor_payload, unique_user_data):
    url = AdvisorEndpoints.create_advisor()
    headers = Auth().auth_valid_credential(get_headers)
    unique_email = unique_user_data
    advisor_payload['firstName'] = ""
    advisor_payload['email'] = unique_email
    advisor_payload['user']['username'] = unique_email
    advisor_payload['user']['email'] = unique_email
    response = RealHomeRequest.post_json(url, headers, advisor_payload)

    assert_status_code_bad_request(response)

@allure.suite('Advisor')
@allure.epic('Crate Advisor Account')
@allure.feature('Advisor')
@allure.story('Post Advisor Invalid Email Format')
@pytest.mark.functional
@pytest.mark.negative
@pytest.mark.regression
def test_post_advisor_invalid_email_format(get_headers, advisor_payload):
    url = AdvisorEndpoints.create_advisor()
    headers = Auth().auth_valid_credential(get_headers)
    advisor_payload['email'] = "invalid-email"
    advisor_payload['user']['username'] = "invalid-email"
    advisor_payload['user']['email'] = "invalid-email"
    response = RealHomeRequest.post_json(url, headers, advisor_payload)

    assert_status_code_bad_request(response)

@allure.suite('Advisor')
@allure.epic('Crate Advisor Account')
@allure.feature('Advisor')
@allure.story('Post Advisor Without Email')
@pytest.mark.functional
@pytest.mark.negative
@pytest.mark.regression
def test_post_advisor_without_email(get_headers, advisor_payload):
    url = AdvisorEndpoints.create_advisor()
    headers = Auth().auth_valid_credential(get_headers)
    advisor_payload.pop('email')
    advisor_payload['user'].pop('email')
    response = RealHomeRequest.post_json(url, headers, advisor_payload)

    assert_status_code_bad_request(response)

@allure.suite('Advisor')
@allure.epic('Crate Advisor Account')
@allure.feature('Advisor')
@allure.story('Post Advisor With Empty Fields')
@pytest.mark.functional
@pytest.mark.negative
@pytest.mark.regression
def test_post_advisor_with_empty_fields(get_headers, advisor_payload):
    url = AdvisorEndpoints.create_advisor()
    headers = Auth().auth_valid_credential(get_headers)
    empty_payload = {}
    response = RealHomeRequest.post_json(url, headers, empty_payload)

    assert_status_code_bad_request(response)


@allure.suite('Advisor')
@allure.epic('Crate Advisor Account')
@allure.feature('Advisor')
@allure.story('Post Advisor With Future Birth Date')
@pytest.mark.functional
@pytest.mark.negative
@pytest.mark.regression
def test_post_advisor_future_birthdate(get_headers, advisor_payload, unique_user_data):
    url = AdvisorEndpoints.create_advisor()
    headers = Auth().auth_valid_credential(get_headers)
    unique_email = unique_user_data
    advisor_payload['birthDate'] = '2100-01-01T00:00:00.000Z'
    advisor_payload['email'] = unique_email
    advisor_payload['user']['username'] = unique_email
    advisor_payload['user']['email'] = unique_email
    response = RealHomeRequest.post_json(url, headers, advisor_payload)

    assert_status_code_bad_request(response)

@allure.suite('Advisor')
@allure.epic('Crate Advisor Account')
@allure.feature('Advisor')
@allure.story('Post Advisor Invalid Birth Date Format')
@pytest.mark.functional
@pytest.mark.negative
@pytest.mark.regression
def test_post_advisor_invalid_birthdate_format(get_headers, advisor_payload, unique_user_data):
    url = AdvisorEndpoints.create_advisor()
    headers = Auth().auth_valid_credential(get_headers)
    unique_email = unique_user_data
    advisor_payload['birthDate'] = 'invalid-date'
    advisor_payload['email'] = unique_email
    advisor_payload['user']['username'] = unique_email
    advisor_payload['user']['email'] = unique_email
    response = RealHomeRequest.post_json(url, headers, advisor_payload)

    assert_status_code_bad_request(response)

@allure.suite('Advisor')
@allure.epic('Crate Advisor Account')
@allure.feature('Advisor')
@allure.story('Post Advisor Invalid Cell Phone Digits')
@pytest.mark.functional
@pytest.mark.negative
@pytest.mark.regression
def test_post_advisor_invalid_cellphone(get_headers, advisor_payload, unique_user_data):
    url = AdvisorEndpoints.create_advisor()
    headers = Auth().auth_valid_credential(get_headers)
    unique_email = unique_user_data
    advisor_payload['cellPhone'] = 12345
    advisor_payload['email'] = unique_email
    advisor_payload['user']['username'] = unique_email
    advisor_payload['user']['email'] = unique_email
    response = RealHomeRequest.post_json(url, headers, advisor_payload)

    assert_status_code_bad_request(response)

@allure.suite('Advisor')
@allure.epic('Crate Advisor Account')
@allure.feature('Advisor')
@allure.story('Post Advisor Duplicate Email')
@pytest.mark.functional
@pytest.mark.negative
@pytest.mark.regression
def test_post_advisor_duplicate_email(get_headers, advisor_payload, unique_user_data):
    url = AdvisorEndpoints.create_advisor()
    headers = Auth().auth_valid_credential(get_headers)
    duplicate_email = "jasson.n021@gmail.com"
    advisor_payload['email'] = duplicate_email
    advisor_payload['user']['username'] = duplicate_email
    advisor_payload['user']['email'] = duplicate_email
    response = RealHomeRequest.post_json(url, headers, advisor_payload)

    assert_status_code_bad_request(response)


@allure.suite('Advisor')
@allure.epic('Crate Advisor Account')
@allure.feature('Advisor')
@allure.story('Post Advisor With Minimum Valid Fields')
@pytest.mark.functional
@pytest.mark.positive
@pytest.mark.regression
def test_post_advisor_with_minimum_fields(get_headers, minimum_valid_advisor_payload):
    url = AdvisorEndpoints.create_advisor()
    headers = Auth().auth_valid_credential(get_headers)
    response = RealHomeRequest.post_json(url, headers, minimum_valid_advisor_payload)

    assert_status_code_created(response)
