import pytest
from app import create_app
import base64
import json

access_token = ''

@pytest.fixture
def app():
    app = create_app('testing')
    app.testing = True
    return app

def test_index(client):
    res = client.get('/')
    assert res.json == {'message': 'api v1.0.0'}

def test_login(client):
    response = login(client)
    assert response.status_code == 200

def test_get_all_users(client):
    auth = login(client)
    access_token = auth.json['access_token']
    response = client.get(
        "/user",
        headers={"x-access-token": access_token}
    )
    assert response.status_code == 200    

def test_create_user(client):
    auth = login(client)
    access_token = auth.json['access_token']
    data = {
        "name": "Test",
        "email": "test@test.com",
        "cpf": "123.123.123-22",
        "password": "123123"
    }
    response = client.post(
        "/user",
        json=dict(data),
        headers={"x-access-token": access_token},
    )
    assert response.status_code == 200

# testar criar emails duplicados 
# testar criar cpf errdo
# testar criar email invalido
# testar deletar usuario 
# testar criar produto

# login com admin 
def login(client):
    valid_credentials = base64.b64encode(b"admin@admin.com:admin").decode("utf-8")
    response = client.get(
        "/login",
        headers={"Authorization": "Basic " + valid_credentials}
    )
    return response