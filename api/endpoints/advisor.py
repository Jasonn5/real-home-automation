from core.config.config import BASE_URI

class AdvisorEndpoints:
    @staticmethod
    def create_advisor():
        return f"{BASE_URI}/advisor"

    @staticmethod
    def get_advisors():
        return f"{BASE_URI}/advisor"

    @staticmethod
    def get_advisor_by_id(advisor_id):
        return f"{BASE_URI}/advisor/{advisor_id}"
    @staticmethod
    def update_advisor():
        return f"{BASE_URI}/advisor"

    @staticmethod
    def enable_user():
        return f"{BASE_URI}/advisor"