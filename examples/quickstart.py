"""Quick-start: install wraithwall, create an app, query health via the SDK."""
from wraithwall import Client, create_app

app = create_app({"TESTING": True, "SECRET_KEY": "dev"})

if __name__ == "__main__":
    with app.test_client() as client:
        response = client.get("/api/health")
        print("health status:", response.status_code)

    api = Client(base_url="http://localhost:8000")
    print("SDK ready — call api.health() against a running instance")