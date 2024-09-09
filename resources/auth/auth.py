from core.utils.load_resources import load_credential_resource

class Auth:
    def __init__(self):
        self.users = self.load_file()

    @staticmethod
    def load_file() -> dict:
        return load_credential_resource("user.json")

    def get_user(self, user_type: str) -> dict:
        return self.users.get(user_type)

    def auth_valid_credential(self, get_headers) -> dict:
        user = self.get_user("valid_credentials")
        return get_headers(user["username"], user["password"], user["confirmPassword"])

    def auth_invalid_username(self, get_headers) -> dict:
        user = self.get_user("invalid_username")
        return get_headers(user["username"], user["password"], user["confirmPassword"])

    def auth_invalid_password(self, get_headers) -> dict:
        user = self.get_user("invalid_password")
        return get_headers(user["username"], user["password"], user["confirmPassword"])

    def auth_invalid_credentials(self, get_headers) -> dict:
        user = self.get_user("invalid_credentials")
        return get_headers(user["username"], user["password"], user["confirmPassword"])

    def auth_empty_fields(self, get_headers) -> dict:
        user = self.get_user("empty_fields")
        return get_headers(user["username"], user["password"], user["confirmPassword"])

    def auth_empty_username(self, get_headers) -> dict:
        user = self.get_user("empty_username")
        return get_headers(user["username"], user["password"], user["confirmPassword"])

    def auth_empty_password(self, get_headers) -> dict:
        user = self.get_user("empty_password")
        return get_headers(user["username"], user["password"], user["confirmPassword"])

    def auth_valid_username_empty_password(self, get_headers) -> dict:
        user = self.get_user("valid_username_empty_password")
        return get_headers(user["username"], user["password"], user["confirmPassword"])

    def auth_empty_username_valid_password(self, get_headers) -> dict:
        user = self.get_user("empty_username_valid_password")
        return get_headers(user["username"], user["password"], user["confirmPassword"])

    def auth_mismatched_passwords(self, get_headers) -> dict:
        user = self.get_user("mismatched_passwords")
        return get_headers(user["username"], user["password"], user["confirmPassword"])

    def auth_missing_confirm_password(self, get_headers) -> dict:
        user = self.get_user("missing_confirm_password")
        confirm_password = user.get("confirmPassword", "")
        return get_headers(user["username"], user["password"], confirm_password)
