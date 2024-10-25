import allure
import pytest
from api.endpoints.advisor import AdvisorEndpoints
from resources.auth.auth import Auth
from api.request.api_request import RealHomeRequest
from core.assertions.status_code import *


@allure.suite('Crate advisor Account')
@allure.epic('Advisor')
@allure.feature('Crate advisor Account')
@allure.story('Post advisor All Fields Valid')
@allure.tag('author: Jeyson')
@pytest.mark.functional
@pytest.mark.positive
@pytest.mark.smoke
@pytest.mark.xfail(reason="This test case is expected to fail due to known issue.",condition=True)
def test_post_advisor_all_fields_valid(get_headers, get_header, advisor_payload, unique_user_data):
    url = AdvisorEndpoints.create_advisor()
    headers = Auth().auth_valid_credential(get_headers)
    unique_email = unique_user_data
    advisor_payload['email'] = unique_email
    advisor_payload['user']['username'] = unique_email
    advisor_payload['user']['email'] = unique_email
    login_data = {
        "username": unique_email,
        "password": advisor_payload['user']['password'],
        "confirmPassword": advisor_payload['user']['confirmPassword']
    }

    response = RealHomeRequest.post(url, headers, advisor_payload)
    response_login = RealHomeRequest.post(url, get_header, login_data)

    assert_status_code_created(response)
    assert_status_code_ok(response_login)


@allure.suite('Crate advisor Account')
@allure.epic('Advisor')
@allure.feature('Crate advisor Account')
@allure.story('Post advisor Without First Name')
@allure.tag('author: Jeyson')
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
    response = RealHomeRequest.post(url, headers, advisor_payload)

    assert_status_code_bad_request(response)


@allure.suite('Crate advisor Account')
@allure.epic('Advisor')
@allure.feature('Crate advisor Account')
@allure.story('Post advisor Invalid Email Format')
@allure.tag('author: Jeyson')
@pytest.mark.functional
@pytest.mark.negative
@pytest.mark.regression
def test_post_advisor_invalid_email_format(get_headers, advisor_payload):
    url = AdvisorEndpoints.create_advisor()
    headers = Auth().auth_valid_credential(get_headers)
    advisor_payload['email'] = "invalid-email"
    advisor_payload['user']['username'] = "invalid-email"
    advisor_payload['user']['email'] = "invalid-email"
    response = RealHomeRequest.post(url, headers, advisor_payload)

    assert_status_code_bad_request(response)


@allure.suite('Crate advisor Account')
@allure.epic('Advisor')
@allure.feature('Crate advisor Account')
@allure.story('Post advisor Without Email')
@allure.tag('author: Jeyson')
@pytest.mark.functional
@pytest.mark.negative
@pytest.mark.regression
def test_post_advisor_without_email(get_headers, advisor_payload):
    url = AdvisorEndpoints.create_advisor()
    headers = Auth().auth_valid_credential(get_headers)
    advisor_payload.pop('email')
    advisor_payload['user'].pop('email')
    response = RealHomeRequest.post(url, headers, advisor_payload)

    assert_status_code_bad_request(response)


@allure.suite('Crate advisor Account')
@allure.epic('Advisor')
@allure.feature('Crate advisor Account')
@allure.story('Post advisor With Empty Fields')
@allure.tag('author: Jeyson')
@pytest.mark.functional
@pytest.mark.negative
@pytest.mark.regression
def test_post_advisor_with_empty_fields(get_headers, advisor_payload):
    url = AdvisorEndpoints.create_advisor()
    headers = Auth().auth_valid_credential(get_headers)
    empty_payload = {}
    response = RealHomeRequest.post(url, headers, empty_payload)

    assert_status_code_bad_request(response)


@allure.suite('Crate advisor Account')
@allure.epic('Advisor')
@allure.feature('Crate advisor Account')
@allure.story('Post advisor With Future Birth Date')
@allure.tag('author: Jeyson')
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
    response = RealHomeRequest.post(url, headers, advisor_payload)

    assert_status_code_bad_request(response)


@allure.suite('Crate advisor Account')
@allure.epic('Advisor')
@allure.feature('Crate advisor Account')
@allure.story('Post advisor Invalid Birth Date Format')
@allure.tag('author: Jeyson')
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
    response = RealHomeRequest.post(url, headers, advisor_payload)

    assert_status_code_bad_request(response)


@allure.suite('Crate advisor Account')
@allure.epic('Advisor')
@allure.feature('Crate advisor Account')
@allure.story('Post advisor Invalid Cell Phone Digits')
@allure.tag('author: Jeyson')
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
    response = RealHomeRequest.post(url, headers, advisor_payload)

    assert_status_code_bad_request(response)


@allure.suite('Crate advisor Account')
@allure.epic('Advisor')
@allure.feature('Crate advisor Account')
@allure.story('Post advisor Duplicate Email')
@allure.tag('author: Jeyson')
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
    response = RealHomeRequest.post(url, headers, advisor_payload)

    assert_status_code_bad_request(response)


@allure.suite('Crate advisor Account')
@allure.epic('Advisor')
@allure.feature('Crate advisor Account')
@allure.story('Post advisor With Minimum Valid Fields')
@allure.tag('author: Jeyson')
@pytest.mark.functional
@pytest.mark.positive
@pytest.mark.regression
@pytest.mark.xfail(reason="This test case is expected to fail due to known issue.",condition=True)
def test_post_advisor_with_minimum_fields(get_headers, minimum_valid_advisor_payload):
    url = AdvisorEndpoints.create_advisor()
    headers = Auth().auth_valid_credential(get_headers)
    response = RealHomeRequest.post(url, headers, minimum_valid_advisor_payload)

    assert_status_code_created(response)


@allure.suite('Crate advisor Account')
@allure.epic('Advisor')
@allure.feature('Crate advisor Account')
@allure.story('Post advisor Without Profile Picture')
@allure.tag('author: Jeyson')
@pytest.mark.functional
@pytest.mark.negative
@pytest.mark.regression
def test_post_advisor_without_profile_picture(get_headers, advisor_payload, unique_user_data):
    url = AdvisorEndpoints.create_advisor()
    headers = Auth().auth_valid_credential(get_headers)
    advisor_payload.pop('profilePicture')
    advisor_payload['email'] = unique_user_data
    advisor_payload['user']['username'] = unique_user_data
    response = RealHomeRequest.post(url, headers, advisor_payload)

    assert_status_code_bad_request(response)


@allure.suite('Crate advisor Account')
@allure.epic('Advisor')
@allure.feature('Crate advisor Account')
@allure.story('Post advisor With CellPhone Less Than 8 Digits')
@allure.tag('author: Jeyson')
@pytest.mark.functional
@pytest.mark.negative
@pytest.mark.regression
def test_post_advisor_with_short_cellphone(get_headers, advisor_payload, unique_user_data):
    url = AdvisorEndpoints.create_advisor()
    headers = Auth().auth_valid_credential(get_headers)
    advisor_payload['CellPhone'] = 1234567  # Menos de 8 dígitos
    advisor_payload['email'] = unique_user_data
    advisor_payload['user']['username'] = unique_user_data
    response = RealHomeRequest.post(url, headers, advisor_payload)

    assert_status_code_bad_request(response)


@allure.suite('Crate advisor Account')
@allure.epic('Advisor')
@allure.feature('Crate advisor Account')
@allure.story('Post advisor with Future BirthDate')
@allure.tag('author: Jeyson')
@pytest.mark.functional
@pytest.mark.negative
@pytest.mark.regression
def test_post_advisor_with_future_birthdate(get_headers, advisor_payload, unique_user_data):
    url = AdvisorEndpoints.create_advisor()
    headers = Auth().auth_valid_credential(get_headers)
    advisor_payload['birthDate'] = '2100-01-01T00:00:00.000Z'
    advisor_payload['email'] = unique_user_data
    advisor_payload['user']['username'] = unique_user_data
    response = RealHomeRequest.post(url, headers, advisor_payload)

    assert_status_code_bad_request(response)


@allure.suite('Crate advisor Account')
@allure.epic('Advisor')
@allure.feature('Crate advisor Account')
@allure.story('Post advisor with Invalid CI Format')
@allure.tag('author: Jeyson')
@pytest.mark.functional
@pytest.mark.negative
@pytest.mark.regression
def test_post_advisor_invalid_ci_format(get_headers, advisor_payload, unique_user_data):
    url = AdvisorEndpoints.create_advisor()
    headers = Auth().auth_valid_credential(get_headers)
    advisor_payload['CI'] = "CI#InvalidFormat"
    advisor_payload['email'] = unique_user_data
    advisor_payload['user']['username'] = unique_user_data
    response = RealHomeRequest.post(url, headers, advisor_payload)

    assert_status_code_bad_request(response)


@allure.suite('Crate advisor Account')
@allure.epic('Advisor')
@allure.feature('Crate advisor Account')
@allure.story('Post advisor Without Email')
@allure.tag('author: Jeyson')
@pytest.mark.functional
@pytest.mark.positive
@pytest.mark.regression
def test_post_advisor_without_email(get_headers, advisor_payload, unique_user_data):
    url = AdvisorEndpoints.create_advisor()
    headers = Auth().auth_valid_credential(get_headers)
    advisor_payload.pop('Email')
    advisor_payload['user'].pop('email')
    response = RealHomeRequest.post(url, headers, advisor_payload)

    assert_status_code_created(response)


@allure.suite('Crate advisor Account')
@allure.epic('Advisor')
@allure.feature('Crate advisor Account')
@allure.story('Post advisor Without FanPageUrl')
@allure.tag('author: Jeyson')
@pytest.mark.functional
@pytest.mark.positive
@pytest.mark.regression
@pytest.mark.xfail(reason="This test case is expected to fail due to known issue.",condition=True)
def test_post_advisor_without_fanpage(get_headers, advisor_payload, unique_user_data):
    url = AdvisorEndpoints.create_advisor()
    headers = Auth().auth_valid_credential(get_headers)
    advisor_payload.pop('fanPageUrl')
    advisor_payload['email'] = unique_user_data
    advisor_payload['user']['username'] = unique_user_data
    response = RealHomeRequest.post(url, headers, advisor_payload)

    assert_status_code_created(response)


@allure.suite('Crate advisor Account')
@allure.epic('Advisor')
@allure.feature('Crate advisor Account')
@allure.story('Post advisor With Duplicate CI')
@allure.tag('author: Jeyson')
@pytest.mark.functional
@pytest.mark.negative
@pytest.mark.regression
def test_post_advisor_duplicate_ci(get_headers, advisor_payload, unique_user_data):
    url = AdvisorEndpoints.create_advisor()
    headers = Auth().auth_valid_credential(get_headers)
    advisor_payload['CI'] = "8489435"  # CI duplicado
    advisor_payload['email'] = unique_user_data
    advisor_payload['user']['username'] = unique_user_data
    response = RealHomeRequest.post(url, headers, advisor_payload)

    assert_status_code_bad_request(response)


@allure.suite('Crate advisor Account')
@allure.epic('Advisor')
@allure.feature('Crate advisor Account')
@allure.story('Post advisor with Invalid Cell Phone (Non-Digits)')
@allure.tag('author: Jeyson')
@pytest.mark.functional
@pytest.mark.negative
@pytest.mark.regression
def test_post_advisor_invalid_cellphone(get_headers, advisor_payload, unique_user_data):
    url = AdvisorEndpoints.create_advisor()
    headers = Auth().auth_valid_credential(get_headers)
    advisor_payload['CellPhone'] = "Phone123"
    advisor_payload['email'] = unique_user_data
    advisor_payload['user']['username'] = unique_user_data
    response = RealHomeRequest.post(url, headers, advisor_payload)

    assert_status_code_bad_request(response)


@allure.suite('Crate advisor Account')
@allure.epic('Advisor')
@allure.feature('Crate advisor Account')
@allure.story('Post advisor Without Birth Date')
@allure.tag('author: Jeyson')
@pytest.mark.functional
@pytest.mark.negative
@pytest.mark.regression
def test_post_advisor_without_birthdate(get_headers, advisor_payload, unique_user_data):
    url = AdvisorEndpoints.create_advisor()
    headers = Auth().auth_valid_credential(get_headers)
    advisor_payload.pop('birthDate')
    advisor_payload['email'] = unique_user_data
    advisor_payload['user']['username'] = unique_user_data
    response = RealHomeRequest.post(url, headers, advisor_payload)

    assert_status_code_bad_request(response)


@allure.suite('Crate advisor Account')
@allure.epic('Advisor')
@allure.feature('Crate advisor Account')
@allure.story('Post advisor With Invalid ProfilePicture URL')
@allure.tag('author: Jeyson')
@pytest.mark.functional
@pytest.mark.negative
@pytest.mark.regression
def test_post_advisor_invalid_profile_picture(get_headers, advisor_payload, unique_user_data):
    url = AdvisorEndpoints.create_advisor()
    headers = Auth().auth_valid_credential(get_headers)
    advisor_payload['ProfilePicture'] = "invalid-url"
    advisor_payload['email'] = unique_user_data
    advisor_payload['user']['username'] = unique_user_data
    response = RealHomeRequest.post(url, headers, advisor_payload)

    assert_status_code_bad_request(response)
