import pytest
import json
import time

@pytest.fixture(scope="module")
def advisor_payload():
    with open('core/payloads/advisor.json', 'r') as file:
        return json.load(file)

@pytest.fixture(scope="module")
def advisor_patch_payload():
    with open('core/payloads/advisor_patch_payload.json', 'r') as file:
        return json.load(file)


@pytest.fixture(scope="module")
def unique_user_data():
    timestamp = str(int(time.time()))
    email = f"test_user_{timestamp}@example.com"

    return email

@pytest.fixture
def minimum_valid_advisor_payload(unique_user_data):
    unique_email = unique_user_data
    return {
        'firstName': 'Pedro',
        'lastName': 'Gonzales',
        'email': unique_email,
        'user': {
            'username': unique_email,
            'email': unique_email,
            'password': 'Prueba.321!',
            'confirmPassword': 'Prueba.321!'
        }
    }
