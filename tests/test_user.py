import pytest
from fastapi import status
import pytest_asyncio
from datetime import timedelta
from app.api.oauth2 import AuthJWT
from app.api.utils.crypt import hash_password
from app.core.config import settings, AlembicTestData


# TODO:
# send_email
# check_resending
# get_verify
# get_verify_call
# get_password_reset
# logout


@pytest_asyncio.fixture(scope="session")
def fixture_users():
    auth = AuthJWT()
    user_register = {
        "username": "user_register",
        "password": "stringst",
        "password_confirm": "stringst",
        "email": "user1@example.com",
        "born": "2000-12-31",
    }
    user_verify_1 = {
        'username': 'user_verify_1',
        'password': 'stringst',}
    user_verify_2 = {
        'username': 'user_verify_2',
        'password': 'stringst',}
    user_login_1 = {
        'username': 'user_login_1',
        'password': 'stringst',}
    user_login_2 = {
        'username': 'user_login_2',
        'password': 'stringst',}
    user_reset_1 = {
        'username': 'user_reset_1',
        'password': 'stringst',}
    new_password = {
        'password': 'qwerty12',
        'password_confirm': 'qwerty12',}
    user_reset_2 = {
        'username': 'user_reset_2',
        'password': 'stringst',}

    verify_good_token = auth.create_access_token(
        subject=str(user_verify_1['username']), expires_time=timedelta(minutes=settings.VERIFY_MINUTES))
    verify_expired_token = auth.create_access_token(
        subject=str(user_verify_2['username']), expires_time=-timedelta(minutes=1))
    verify_not_in_db_token = auth.create_access_token(
        subject=str('wrong_username'), expires_time=timedelta(minutes=settings.VERIFY_MINUTES))
    verify_fake_token = auth.create_access_token(
        subject=str(user_verify_1['username']), expires_time=timedelta(minutes=settings.VERIFY_MINUTES))

    reset_good_token = auth.create_access_token(
        subject=str(user_reset_1['username']), expires_time=timedelta(minutes=settings.VERIFY_MINUTES))
    reset_expired_token = auth.create_access_token(
        subject=str(user_reset_2['username']), expires_time=-timedelta(minutes=1))
    reset_not_in_db_token = auth.create_access_token(
        subject=str('wrong_username'), expires_time=timedelta(minutes=settings.VERIFY_MINUTES))
    reset_fake_token = auth.create_access_token(
        subject=str(user_reset_1['username']), expires_time=timedelta(minutes=settings.VERIFY_MINUTES))

    user_auth_1 = {
        'username': 'user_auth_1',
        'password': 'stringst',}
    user_auth_2 = {
        'username': 'user_auth_2',
        'password': 'stringst',}

    access_bad = auth.create_access_token(
        subject='wrong_username', expires_time=timedelta(minutes=settings.ACCESS_MINUTES))
    access_good_not_verif = auth.create_access_token(
        subject=user_auth_1['username'], expires_time=timedelta(minutes=settings.ACCESS_MINUTES))
    access_good = auth.create_access_token(
        subject=user_auth_2['username'], expires_time=timedelta(minutes=settings.ACCESS_MINUTES))
    access_expired = auth.create_access_token(
        subject=user_auth_2['username'], expires_time=-timedelta(minutes=1))

    refresh_bad = auth.create_refresh_token(
        subject='wrong_username', expires_time=timedelta(days=settings.REFRESH_DAYS))
    refresh_good_not_verif = auth.create_refresh_token(
        subject=user_auth_1['username'], expires_time=timedelta(days=settings.REFRESH_DAYS))
    refresh_good = auth.create_refresh_token(
        subject=user_auth_2['username'], expires_time=timedelta(days=settings.REFRESH_DAYS))
    refresh_expired = auth.create_refresh_token(
        subject=user_auth_2['username'], expires_time=-timedelta(minutes=1))

    user_role_1 = {
        'username': 'user_role_1',
        'password': 'stringst',}
    user_role_2 = {
        'username': 'user_role_2',
        'password': 'stringst',}
    user_role_3 = {
        'username': 'user_role_3',
        'password': 'stringst',}

    access_user_role_1 = auth.create_access_token(
        subject=user_role_1['username'], expires_time=timedelta(minutes=settings.ACCESS_MINUTES))
    access_user_role_2 = auth.create_access_token(
        subject=user_role_2['username'], expires_time=timedelta(minutes=settings.ACCESS_MINUTES))
    access_user_role_3 = auth.create_access_token(
        subject=user_role_3['username'], expires_time=timedelta(minutes=settings.ACCESS_MINUTES))

    # пользователи, записываемые через alembic передаются через экземпляр настроек settings
    AlembicTestData.users = [
        {
            'username': user_verify_1['username'],
            'hashed_password': hash_password(user_verify_1['password']),
            'email': "user@example.com",
            'role_id': 0,
            'born': "2024-12-29",
            'verified': False,
            "refresh_token": None,
            "verify_code": verify_good_token,
            "reset_code": None,
        },
        {
            'username': user_verify_2['username'],
            'hashed_password': hash_password(user_verify_2['password']),
            'email': "user@example.com",
            'role_id': 0,
            'born': "2024-12-29",
            'verified': False,
            "refresh_token": None,
            "verify_code": verify_expired_token,
            "reset_code": None,
        },
        {
            'username': user_login_1['username'],
            'hashed_password': hash_password(user_login_1['password']),
            'email': "user@example.com",
            'role_id': 0,
            'born': "2024-12-29",
            'verified': True,
            "refresh_token": None,
            "verify_code": None,
            "reset_code": None,
        },
        {
            'username': user_login_2['username'],
            'hashed_password': hash_password(user_login_2['password']),
            'email': "user@example.com",
            'role_id': 0,
            'born': "2024-12-29",
            'verified': False,
            "refresh_token": None,
            "verify_code": None,
            "reset_code": None,
        },
        {
            'username': user_reset_1['username'],
            'hashed_password': hash_password(user_reset_1['password']),
            'email': "user@example.com",
            'role_id': 0,
            'born': "2024-12-29",
            'verified': False,
            "refresh_token": None,
            "verify_code": None,
            "reset_code": reset_good_token,
        },
        {
            'username': user_reset_2['username'],
            'hashed_password': hash_password(user_reset_2['password']),
            'email': "user@example.com",
            'role_id': 0,
            'born': "2024-12-29",
            'verified': False,
            "refresh_token": None,
            "verify_code": None,
            "reset_code": reset_expired_token,
        },
        {
            'username': user_auth_1['username'],
            'hashed_password': hash_password(user_auth_1['password']),
            'email': "user@example.com",
            'role_id': 0,
            'born': "2024-12-29",
            'verified': False,
            "refresh_token": None,
            "verify_code": None,
            "reset_code": None,
        },
        {
            'username': user_auth_2['username'],
            'hashed_password': hash_password(user_auth_2['password']),
            'email': "user@example.com",
            'role_id': 0,
            'born': "2024-12-29",
            'verified': True,
            "refresh_token": None,
            "verify_code": None,
            "reset_code": None,
        },
        {
            'username': user_role_1['username'],
            'hashed_password': hash_password(user_role_1['password']),
            'email': "user@example.com",
            'role_id': 0,
            'born': "2024-12-29",
            'verified': True,
            "refresh_token": None,
            "verify_code": None,
            "reset_code": None,
        },
        {
            'username': user_role_2['username'],
            'hashed_password': hash_password(user_role_2['password']),
            'email': "user@example.com",
            'role_id': 1,
            'born': "2024-12-29",
            'verified': True,
            "refresh_token": None,
            "verify_code": None,
            "reset_code": None,
        },
        {
            'username': user_role_3['username'],
            'hashed_password': hash_password(user_role_3['password']),
            'email': "user@example.com",
            'role_id': 2,
            'born': "2024-12-29",
            'verified': True,
            "refresh_token": None,
            "verify_code": None,
            "reset_code": None,
        },
    ]
    return {
        'register': {
            'passwords_mismatch': user_register | {"password_confirm": "stringstwrong"},
            'short_password': user_register | {"password": "string"},
            'wrong_email': user_register | {"email": "userexample.com"},
            'success': user_register,
            'already_exist': user_register,
        },
        'verify': {
            'bad_jwt': 'badjwt',
            'expired_jwt': verify_expired_token,
            'user_in_jwt_not_in_db': verify_not_in_db_token,
            'fake_jwt': verify_fake_token,
            'success': verify_good_token,
            'already_verified': verify_good_token,
        },
        'login': {
            'not_exist': user_login_1 | {"username": "wrong"},
            'not_verified': user_login_2,
            'wrong_password': user_login_1 | {"password": "wrongwrong"},
            'success': user_login_1,
        },
        'password_reset': {
            'passwords_mismatch': [reset_good_token,
                                   new_password | {'password_confirm': 'wrongwrong'}],
            'short_password': [reset_good_token,
                               {'password': 'string', 'password_confirm': 'string'}],
            'bad_jwt': ['badjwt', new_password],
            'expired_jwt': [reset_expired_token, new_password],
            'user_in_jwt_not_in_db': [reset_not_in_db_token, new_password],
            'fake_jwt': [reset_fake_token, new_password],
            'success': [reset_good_token, new_password],
            'already_reset': [reset_good_token, new_password],
        },
        'me': {
            "not_login": [None, None],
            "not_exist": [access_bad, refresh_good],
            "not_verified": [access_good_not_verif, refresh_good],
            "success": [access_good, refresh_bad],
            "wrong_refresh": [access_expired, refresh_bad],
            "not_exist_refresh": [access_expired, refresh_bad],
            "not_verified_refresh": [access_expired, refresh_good_not_verif],
            "success_with_refresh": [access_expired, refresh_good],
            "expired_refresh": [access_expired, refresh_expired],
        },
        'get_10_users': {
            "role_user": [access_user_role_1, None],
            "role_admin": [access_user_role_2, None],
            "role_s_admin": [access_user_role_3, None],
        },
    }


#@pytest.mark.skip
@pytest.mark.asyncio
@pytest.mark.parametrize(
    "test_name, status_code",
    [
        ["passwords_mismatch", status.HTTP_400_BAD_REQUEST],
        ["short_password", status.HTTP_422_UNPROCESSABLE_ENTITY],
        ["wrong_email", status.HTTP_422_UNPROCESSABLE_ENTITY],
        ["success", status.HTTP_201_CREATED],
        ["already_exist", status.HTTP_409_CONFLICT],
    ])
async def test_register(client, fixture_users, create, request, test_name, status_code):
    data = (request.getfixturevalue('fixture_users'))['register'][test_name]
    response = client.post("/user/register/", json=data, headers={"Content-Type": "application/json"})
    assert response.status_code == status_code


#@pytest.mark.skip
@pytest.mark.asyncio
@pytest.mark.parametrize(
    "test_name, status_code",
    [
        ["bad_jwt", status.HTTP_400_BAD_REQUEST],
        ["expired_jwt", status.HTTP_400_BAD_REQUEST],
        ["user_in_jwt_not_in_db", status.HTTP_500_INTERNAL_SERVER_ERROR],
        ["fake_jwt", status.HTTP_403_FORBIDDEN],
        ["success", status.HTTP_200_OK],
        ["already_verified", status.HTTP_403_FORBIDDEN],
    ])
async def test_verify(client, fixture_users, create, session, request, test_name, status_code):
    code = (request.getfixturevalue('fixture_users'))['verify'][test_name]
    path = f"/user/verify/{code}"
    response = client.get(path)
    assert response.status_code == status_code


#@pytest.mark.skip
@pytest.mark.asyncio
@pytest.mark.parametrize(
    "test_name, status_code",
    [
        ["passwords_mismatch", status.HTTP_400_BAD_REQUEST],
        ["short_password", status.HTTP_422_UNPROCESSABLE_ENTITY],
        ["bad_jwt", status.HTTP_400_BAD_REQUEST],
        ["expired_jwt", status.HTTP_400_BAD_REQUEST],
        ["user_in_jwt_not_in_db", status.HTTP_500_INTERNAL_SERVER_ERROR],
        ["fake_jwt", status.HTTP_403_FORBIDDEN],
        ["success", status.HTTP_200_OK],
        ["already_reset", status.HTTP_403_FORBIDDEN],
    ])
async def test_password_reset(client, fixture_users, create, session, request, test_name, status_code):
    data = (request.getfixturevalue('fixture_users'))['password_reset'][test_name]
    path = f"/user/password_reset/{data[0]}"
    response = client.post(path, json=data[1], headers={"Content-Type": "application/json"})
    assert response.status_code == status_code


#@pytest.mark.skip
@pytest.mark.asyncio
@pytest.mark.parametrize(
    "test_name, status_code",
    [
        ["not_exist", status.HTTP_400_BAD_REQUEST],
        ["not_verified", status.HTTP_401_UNAUTHORIZED],
        ["wrong_password", status.HTTP_400_BAD_REQUEST],
        ["success", status.HTTP_200_OK],
    ])
async def test_login(client, fixture_users, create, request, test_name, status_code):
    data = (request.getfixturevalue('fixture_users'))['login'][test_name]
    response = client.post("/user/login/", json=data, headers={"Content-Type": "application/json"})
    assert response.status_code == status_code


#@pytest.mark.skip
@pytest.mark.asyncio
@pytest.mark.parametrize(
    "test_name, status_code",
    [
        ["not_login", status.HTTP_400_BAD_REQUEST],
        ["not_exist", status.HTTP_400_BAD_REQUEST],
        ["not_verified", status.HTTP_401_UNAUTHORIZED],
        ["success", status.HTTP_200_OK],
        ["wrong_refresh", status.HTTP_400_BAD_REQUEST],
        ["not_exist_refresh", status.HTTP_400_BAD_REQUEST],
        ["not_verified_refresh", status.HTTP_401_UNAUTHORIZED],
        ["success_with_refresh", status.HTTP_200_OK],
        ["expired_refresh", status.HTTP_401_UNAUTHORIZED],
    ])
async def test_me(client, fixture_users, create, request, test_name, status_code):
    data = (request.getfixturevalue('fixture_users'))['me'][test_name]
    cookies = {
        'access_token': data[0],
        'refresh_token': data[1],
    }
    response = client.get("/user/me/", cookies=cookies)
    assert response.status_code == status_code


#@pytest.mark.skip
@pytest.mark.asyncio
@pytest.mark.parametrize(
    "test_name, status_code",
    [
        ["role_user", status.HTTP_403_FORBIDDEN],
        ["role_admin", status.HTTP_200_OK],
        ["role_s_admin", status.HTTP_200_OK],
    ])
async def test_get_10_users(client, fixture_users, create, request, test_name, status_code):
    data = (request.getfixturevalue('fixture_users'))['get_10_users'][test_name]
    cookies = {
        'access_token': data[0],
        'refresh_token': data[1],
    }
    response = client.get("/user/get_10_users/", cookies=cookies)
    assert response.status_code == status_code