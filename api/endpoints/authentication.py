from core.config.config import BASE_URI

class AuthenticationEndpoints:
    @staticmethod
    def authenticate():
        return f"{BASE_URI}/users/authenticate"

    @staticmethod
    def change_password():
        return f"{BASE_URI}/users/changepassword"

    @staticmethod
    def reset_password():
        return f"{BASE_URI}/users/resetpassword"

    @staticmethod
    def enable_user():
        return f"{BASE_URI}/users/enableuser"