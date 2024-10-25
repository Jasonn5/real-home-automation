def assert_status_code_ok(response):
    assert response.status_code == 200, f"Expected status code 200 but got {response.status_code}. Error message: {extract_error_message(response)}"

def assert_status_code_created(response):
    assert response.status_code == 201, f"Expected status code 201 but got {response.status_code}. Error message: {extract_error_message(response)}"

def assert_status_code_not_found(response):
    assert response.status_code == 404, f"Expected status code 404 but got {response.status_code}. Error message: {extract_error_message(response)}"

def assert_status_code_internal_server_error(response):
    assert response.status_code == 500, f"Expected status code 500 but got {response.status_code}. Error message: {extract_error_message(response)}"

def assert_status_code_unauthorized(response):
    assert response.status_code == 401, f"Expected status code 401 but got {response.status_code}. Error message: {extract_error_message(response)}"

def assert_status_code_forbidden(response):
    assert response.status_code == 403, f"Expected status code 403 but got {response.status_code}. Error message: {extract_error_message(response)}"

def assert_status_code_bad_request(response):
    assert response.status_code == 400, f"Expected status code 400 but got {response.status_code}. Error message: {extract_error_message(response)}"

def assert_status_code_method_not_allowed(response):
    assert response.status_code == 405, f"Expected status code 405 but got {response.status_code}. Error message: {extract_error_message(response)}"

def assert_status_code_conflict(response):
    assert response.status_code == 409, f"Expected status code 409 but got {response.status_code}. Error message: {extract_error_message(response)}"

def assert_status_code_gateway_timeout(response):
    assert response.status_code == 504, f"Expected status code 504 but got {response.status_code}. Error message: {extract_error_message(response)}"

def assert_status_code_service_unavailable(response):
    assert response.status_code == 503, f"Expected status code 503 but got {response.status_code}. Error message: {extract_error_message(response)}"

def assert_status_code_unprocessable_entity(response):
    assert response.status_code == 422, f"Expected status code 422 but got {response.status_code}. Error message: {extract_error_message(response)}"

def extract_error_message(response):
    try:
        error_info = response.json().get('error', {})
        return error_info.get('message', 'No error message provided')
    except ValueError:
        return 'Response body is not JSON or no error message found'

