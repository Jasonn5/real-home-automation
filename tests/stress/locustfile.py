from locust import HttpUser, task, between
import random
import time


class AdvisorLoadTest(HttpUser):
    wait_time = between(0.5, 5)

    def on_start(self):
        self.headers = self.get_auth_headers()

    def get_auth_headers(self):
        payload = {
            "username": "admin",
            "password": "Testing.123!",
            "confirmPassword": "Testing.123!"
        }
        with self.client.post("/api/authenticate", json=payload, catch_response=True) as response:
            if response.status_code == 200:
                token = response.json().get("token")
                return {
                    'Authorization': f'Bearer {token}',
                    'Content-Type': 'application/json-patch+json'
                }
            else:
                response.failure(f"Failed to authenticate with {response.status_code}")
                return {}
    @task(1)
    def create_advisor(self):
        timestamp = str(int(time.time()))
        unique_email =  f"test_user_{timestamp}@example.com"
        payload = {
            "firstName": "Pedro",
            "lastName": "Gonzales",
            "email": unique_email,
            "profilePicture": "https://example.com/image.png",
            "ci": "8489435",
            "birthDate": "2004-09-10T07:37:42.273Z",
            "cellPhone": random.randint(60000000, 79999999),
            "address": "Av. Tamborada",
            "fanPageUrl": "https://www.facebook.com/spartansoftbo",
            "user": {
                "username": unique_email,
                "isEnabled": True,
                "email": unique_email,
                "password": "Prueba.321!",
                "confirmPassword": "Prueba.321!"
            }
        }
        with self.client.post("/api/advisor", json=payload, headers=self.headers, catch_response=True) as response:
            if response.status_code == 201:
                response.success()
            else:
                response.failure(f"Failed to create advisor with {response.status_code}")

    @task(1)
    def search_advisor(self):
        search_name = "Pedro"
        with self.client.get(f"/api/advisor?Search={search_name}", catch_response=True) as response:
            if response.status_code == 200:
                response.success()
            else:
                response.failure(f"Failed to search advisor with {response.status_code}")

    @task(1)
    def update_advisor(self):
        advisor_id = random.randint(1, 100)
        payload = {
             "id": 24,
             "firstName": "Pedro",
             "lastName": "Gonzales",
             "email": "pedro@gmail.com",
             "profilePicture": "https://images.pexels.com/photos/771742/pexels-photo-771742.jpeg",
             "ci": "8489435",
             "birthDate": "2004-09-10T07:37:42.273Z",
             "cellPhone": random.randint(60000000, 79999999),
             "address": "Av. Tamborada",
             "fanPageUrl": "https://www.facebook.com/spartansoftbo"
        }
        with self.client.patch(f"/api/advisor/{advisor_id}", json=payload, headers=self.headers,
                               catch_response=True) as response:
            if response.status_code == 200:
                response.success()
            else:
                response.failure(f"Failed to update advisor with {response.status_code}")

    @task(1)
    def stress_authentication(self):
        payload = {
            "username": "admin",
            "password": "Testing.123!",
            "confirmPassword": "Testing.123!"
        }
        with self.client.post("/api/authenticate", json=payload, catch_response=True) as response:
            if response.status_code == 200:
                response.success()
            else:
                response.failure(f"Authentication failed with {response.status_code}")
