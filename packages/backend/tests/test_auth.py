def test_auth_refresh_flow(client):
    # Register user
    email = "refresh@test.com"
    password = "secret123"
    r = client.post("/auth/register", json={"email": email, "password": password})
    assert r.status_code in (201, 409)  # 409 if already exists

    # Login to get tokens
    r = client.post("/auth/login", json={"email": email, "password": password})
    assert r.status_code == 200
    data = r.get_json()
    assert "access_token" in data and "refresh_token" in data

    # Use refresh to get a new access token
    refresh_token = data["refresh_token"]
    r = client.post(
        "/auth/refresh", headers={"Authorization": f"Bearer {refresh_token}"}
    )
    assert r.status_code == 200
    new_access = r.get_json().get("access_token")
    assert isinstance(new_access, str) and len(new_access) > 10


def test_auth_logout_revokes_refresh_token(client):
    email = "logout@test.com"
    password = "secret123"
    r = client.post("/auth/register", json={"email": email, "password": password})
    assert r.status_code in (201, 409)

    r = client.post("/auth/login", json={"email": email, "password": password})
    assert r.status_code == 200
    refresh_token = r.get_json()["refresh_token"]

    r = client.post(
        "/auth/logout", headers={"Authorization": f"Bearer {refresh_token}"}
    )
    assert r.status_code == 200

    r = client.post(
        "/auth/refresh", headers={"Authorization": f"Bearer {refresh_token}"}
    )
    assert r.status_code == 401


def test_auth_me_and_update_preferred_currency(client):
    email = "profile@test.com"
    password = "secret123"
    r = client.post("/auth/register", json={"email": email, "password": password})
    assert r.status_code in (201, 409)

    r = client.post("/auth/login", json={"email": email, "password": password})
    assert r.status_code == 200
    access = r.get_json()["access_token"]
    auth = {"Authorization": f"Bearer {access}"}

    r = client.get("/auth/me", headers=auth)
    assert r.status_code == 200
    me = r.get_json()
    assert me["email"] == email
    assert me["preferred_currency"] == "INR"

    r = client.patch("/auth/me", json={"preferred_currency": "inr"}, headers=auth)
    assert r.status_code == 200
    updated = r.get_json()
    assert updated["preferred_currency"] == "INR"

    r = client.patch("/auth/me", json={"preferred_currency": "ZZZ"}, headers=auth)
    assert r.status_code == 400


def test_login_brute_force_prevention(client):
    email = "brute@test.com"
    password = "secret123"
    client.post("/auth/register", json={"email": email, "password": password})
    
    # 5 Failed attempts
    for _ in range(5):
        r = client.post("/auth/login", json={"email": email, "password": "wrongpassword"})
        if r.status_code == 429:
            break
        assert r.status_code == 401
        
    # the 6th attempt should definitely be 429
    r = client.post("/auth/login", json={"email": email, "password": "wrongpassword"})
    assert r.status_code == 429

    r = client.post("/auth/login", json={"email": email, "password": password})
    assert r.status_code == 429  # Even with correct password, they are locked out


def test_login_security_alerts_new_device(client):
    email = "alerts@test.com"
    password = "secret123"
    r = client.post("/auth/register", json={"email": email, "password": password})
    assert r.status_code in (201, 409)

    # First successful login
    r = client.post("/auth/login", json={"email": email, "password": password})
    assert r.status_code == 200
    access = r.get_json()["access_token"]
    auth = {"Authorization": f"Bearer {access}"}

    # Fetch alerts
    r = client.get("/auth/alerts", headers=auth)
    assert r.status_code == 200
    alerts = r.get_json()["alerts"]
    assert len(alerts) >= 1
    
    new_device_alert_id = None
    for a in alerts:
        if a["alert_type"] == "NEW_DEVICE_LOGIN":
            new_device_alert_id = a["id"]
            break
            
    assert new_device_alert_id is not None

    # Mark read
    r = client.patch(f"/auth/alerts/{new_device_alert_id}/read", headers=auth)
    assert r.status_code == 200

    r = client.get("/auth/alerts", headers=auth)
    assert r.status_code == 200
    alerts = r.get_json()["alerts"]
    for a in alerts:
        if a["id"] == new_device_alert_id:
            assert a["is_read"] is True
