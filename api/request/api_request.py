import requests

class RealHomeRequest:
    @staticmethod
    def get_with_url(url):
        response = requests.get(url)
        return response

    @staticmethod
    def get_with_url_headers(url, headers):
        response = requests.get(url, headers=headers)
        return response

    @staticmethod
    def delete(url, headers):
        response = requests.delete(url, headers=headers)
        return response

    @staticmethod
    def post(url, headers, payload):
        response = requests.post(url, headers=headers, json=payload)
        return response

    @staticmethod
    def post_without_headers(url, payload):
        response = requests.post(url, json=payload)
        return response

    @staticmethod
    def delete_without_headers(url):
        response = requests.delete(url)
        return response

    @staticmethod
    def patch(url, headers, payload):
        response = requests.patch(url, headers=headers, json=payload)
        return response