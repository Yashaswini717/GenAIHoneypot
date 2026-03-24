import pytest
from fastapi.testclient import TestClient
from api.main import app

client = TestClient(app)


def test_health_endpoint():
    """Test health check endpoint."""
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert "version" in data


def test_root_endpoint():
    """Test root endpoint."""
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "operational"


def test_generate_honeytoken():
    """Test honeytoken generation endpoint."""
    response = client.post(
        "/api/v1/generate/honeytoken",
        json={
            "token_type": "aws_access_key",
            "context": {},
        },
    )
    
    assert response.status_code == 200
    data = response.json()
    assert data["content"].startswith("AKIA")
    assert data["is_valid"] is True


def test_list_honeytokens():
    """Test listing honeytokens."""
    response = client.get("/api/v1/honeytokens/")
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)


def test_check_honeytoken():
    """Test checking if value is honeytoken."""
    response = client.post(
        "/api/v1/honeytokens/check",
        json={"token_value": "AKIAIOSFODNN7EXAMPLE"},
    )
    
    assert response.status_code == 200
    data = response.json()
    assert "is_honeytoken" in data


def test_metrics_endpoint():
    """Test metrics endpoint."""
    response = client.get("/api/v1/metrics")
    assert response.status_code == 200
    data = response.json()
    assert "total_generations" in data
    assert "total_honeytokens" in data
