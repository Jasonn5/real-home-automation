import pytest
import json

@pytest.fixture(scope="module")
def get_header():
    return {
       'accept': '*/*',
       'Content-Type': 'application/json-patch+json'
    }

@pytest.fixture(scope="module")
def user_credentials():
    with open('resources/credentials/user.json', 'r') as file:
        return json.load(file)

@pytest.fixture(scope="module")
def valid_credentials(user_credentials):
    return user_credentials["valid_credentials"]

@pytest.fixture(scope="module")
def invalid_username(user_credentials):
    return user_credentials["invalid_username"]

@pytest.fixture(scope="module")
def invalid_password(user_credentials):
    return user_credentials["invalid_password"]

@pytest.fixture(scope="module")
def invalid_credentials(user_credentials):
    return user_credentials["invalid_credentials"]

@pytest.fixture(scope="module")
def empty_fields(user_credentials):
    return user_credentials["empty_fields"]

@pytest.fixture(scope="module")
def empty_username(user_credentials):
    return user_credentials["empty_username"]

@pytest.fixture(scope="module")
def empty_password(user_credentials):
    return user_credentials["empty_password"]

@pytest.fixture(scope="module")
def valid_username_empty_password(user_credentials):
    return user_credentials["valid_username_empty_password"]

@pytest.fixture(scope="module")
def empty_username_valid_password(user_credentials):
    return user_credentials["empty_username_valid_password"]

@pytest.fixture(scope="module")
def mismatched_passwords(user_credentials):
    return user_credentials["mismatched_passwords"]

@pytest.fixture(scope="module")
def missing_confirm_password(user_credentials):
    return user_credentials["missing_confirm_password"]
