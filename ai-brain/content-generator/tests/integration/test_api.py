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


# No session_id in these: without one the bandit picks an action but records
# nothing, so test runs do not leave decisions in the development database.


def test_intent_classify_follows_the_newest_command():
    """The payload the sidecar sends: the last few commands, nothing else."""
    response = client.post(
        "/api/v1/intent-classify",
        json={"commands": ["sudo -l", "ssh -i /tmp/k deploy@erp-web"]},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["intent"] == "lateral_movement"
    assert data["source"] == "rule"
    assert data["action"]


def test_intent_classify_falls_back_to_the_model():
    response = client.post("/api/v1/intent-classify", json={"commands": ["cd /tmp", "chmod +x run"]})
    assert response.status_code == 200
    data = response.json()
    assert data["source"] == "ml"
    assert data["model_name"] == "HistGradientBoostingClassifier"
    assert abs(sum(data["probabilities"].values()) - 1.0) < 1e-6


def test_intent_classify_keeps_the_sessions_stage_through_neutral_commands():
    response = client.post(
        "/api/v1/intent-classify",
        json={"commands": ["cd /tmp", "chmod +x run.sh", "./run.sh"], "previous_intent": "persistence"},
    )
    assert response.status_code == 200
    assert response.json()["intent"] == "persistence"


def test_intent_classify_rejects_an_unknown_previous_intent():
    response = client.post("/api/v1/intent-classify", json={"commands": ["ls"], "previous_intent": "banana"})
    assert response.status_code == 422


def test_legacy_classify_agrees_with_intent_classify():
    """The two endpoints used to run different rule sets and could disagree."""
    commands = ['mysql -h db-01 -u erp_admin -pX -e "select * from erp.students"']
    legacy = client.post("/api/v1/classify", json={"commands": commands}).json()
    current = client.post("/api/v1/intent-classify", json={"commands": commands}).json()
    assert legacy["primary_intent"] == current["intent"] == "data_exfiltration"
