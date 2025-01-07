from fastapi import (
    APIRouter, Depends, HTTPException, Response, status, Request, Body, Path,
    Cookie
)

from app.api.schemas.user import UserRegister, UserLogin, UserDB, UserChangePassword, UserAdd
import jwt

from datetime import datetime, timedelta
from app.core.config import settings
from app.api.oauth2 import AuthJWT

from app.db.repository import UserRepository
from app.db.database import get_user_repository

from app.api.utils.crypt import hash_password, verify_password
from app.api.utils.email import SendEmail

from app.api.roles import Role, role_req


user_router = APIRouter(
    prefix="/user",
    tags=["User"]
)


# Регистрация пользователя и отправка кода подтверждения на Email
@user_router.post('/register/', status_code=status.HTTP_201_CREATED)
async def register(
        request: Request,
        user_register: UserRegister = Body(),
        repo: UserRepository = Depends(get_user_repository),
        auth: AuthJWT = Depends(),
        email: SendEmail = Depends()
):
    if await repo.db_user_get(user_register.username):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail='Account already exist')

    if user_register.password != user_register.password_confirm:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail='Passwords do not match')

    user_add = UserAdd(**(
            user_register.__dict__ |
            {'hashed_password': hash_password(user_register.password)})
    )
    n: int = await repo.db_user_add(user_add)
    if n == 0:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail='Error creating user')

    await get_verify(request, user_add.username, repo, auth, email)

    return {'status': 'success', 'message': 'Verification link successfully sent to your email'}



# Проверка перед повторной отправкой кода подтверждения, или кода сброса пароля,
# на предмет прошедшего времени с момента предыдущей отправки
# Время предыдущей отправки достаётся из отправленного ранее токена, если такой есть
def check_resending(
        code: str,
        auth: AuthJWT,
) -> bool:
    try:
        auth._token = code
        decoded = auth.get_raw_jwt()
    except :
        return True
    resending_time = (
            datetime.fromtimestamp(decoded.get('iat')) + timedelta(minutes=settings.RESENDING_MINUTES))
    if datetime.now() > resending_time:
        return True
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f'The minimum time for resending ({settings.RESENDING_MINUTES} min) '
                   f'has not yet expired')


# Отправка кода подтверждения аккаунта
async def get_verify(
        request: Request,
        username: str,
        repo: UserRepository,
        auth: AuthJWT,
        email,
):
    user = await repo.db_user_get(username)
    if user:
        if user.verified:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN, detail='Email can only be verified once')
        if user.verify_code:
            check_resending(user.verify_code, auth)
    code = auth.create_access_token(
        subject=str(user.username), expires_time=timedelta(minutes=settings.VERIFY_MINUTES))

    if not await repo.db_user_update(username, verify_code=code):
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail='Error get user')

    url = (f"{request.url.scheme}://{request.client.host}:{request.url.port}"
           f"{user_router.prefix}/verify/{code}")
    await email.send_email(subject='Verify link', url=url, user=user)
    return {'status': 'success', 'message': 'Verification link successfully sent to your email'}



# Запрос повторной отправки кода подтверждения аккаунта
@user_router.get('/get_verify/{username}')
async def get_verify_call(
        request: Request,
        username: str,
        repo: UserRepository = Depends(get_user_repository),
        auth: AuthJWT = Depends(),
        email: SendEmail = Depends(),
):
    return await get_verify(request, username, repo, auth, email)


# Верификация аккаунта по коду подтверждения
@user_router.get('/verify/{verify_code}/', status_code=status.HTTP_200_OK)
async def verify(
        verify_code: str = Path(),
        repo: UserRepository = Depends(get_user_repository),
        auth: AuthJWT = Depends(),
):
    try:
        auth._token = verify_code
        username = auth.get_jwt_subject()
    except :
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail='Invalid code')

    user = await repo.db_user_get(username)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail='Error get user')

    if user.verify_code != verify_code:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail='Invalid code')

    if not await repo.db_user_update(
            user.username,
            verified=True,
            verify_code=None,
    ):
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail='Error update user')

    return {
        "status": "success",
        "message": "Account verified successfully"
    }


# Запрос отправки кода сброса пароля
@user_router.get('/get_password_reset/{username}')
async def get_password_reset(
        request: Request,
        username: str,
        repo: UserRepository = Depends(get_user_repository),
        auth: AuthJWT = Depends(),
        email: SendEmail = Depends(),
):
    user = await repo.db_user_get(username)
    if user:
        if user.reset_code:
            check_resending(user.verify_code)
    code = auth.create_access_token(
        subject=str(user.username), expires_time=timedelta(days=settings.REFRESH_DAYS))

    if not await repo.db_user_update(username, reset_code=code):
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail='Error get user')

    url = (f"{request.url.scheme}://{request.client.host}:{request.url.port}"
           f"{user_router.prefix}/verify/{code}")
    await email.send_email(subject='Password reset link', url=url, user=user)
    return {'status': 'success', 'message': 'Password reset link successfully sent to your email'}


# Сброс пароля
@user_router.post('/password_reset/{reset_code}')
async def password_reset(
        reset_code: str,
        passwords: UserChangePassword,
        repo: UserRepository = Depends(get_user_repository),
        auth: AuthJWT = Depends(),
):
    # Check passwords
    if passwords.password != passwords.password_confirm:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail='Passwords do not match')

    try:
        auth._token = reset_code
        username = auth.get_jwt_subject()
    except :
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail='Invalid code')

    user = await repo.db_user_get(username)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail='Error get user')

    if user.reset_code != reset_code:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail='Invalid code')

    if not await repo.db_user_update(
            user.username,
            hashed_password=hash_password(passwords.password),
            reset_code=None,
    ):
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail='Error update user')

    return {
        "status": "success",
        "message": "Password changed successfully"
    }

# В случае успеха возвращает cookies с access и refresh токенами
@user_router.post("/login/", status_code=status.HTTP_200_OK)
async def login(
        response: Response,
        user_login: UserLogin,
        repo: UserRepository = Depends(get_user_repository),
        auth: AuthJWT = Depends(),
):
    user = await repo.db_user_get(user_login.username)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail='Invalid credentials')

    if not user.verified:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail='Please verify your email address')

    if not verify_password(user_login.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail='Invalid credentials')

    access_token = auth.create_access_token(
        subject=str(user.username), expires_time=timedelta(minutes=settings.ACCESS_MINUTES))

    refresh_token = auth.create_refresh_token(
        subject=str(user.username), expires_time=timedelta(days=settings.REFRESH_DAYS))

    # Store refresh and access tokens in cookie
    response.set_cookie(
        'access_token',
        access_token,
        timedelta(minutes=settings.ACCESS_MINUTES).seconds,
        timedelta(minutes=settings.ACCESS_MINUTES).seconds,
        '/',
        None,
        False,
        True,
        'lax'
    )

    response.set_cookie(
        'refresh_token',
        refresh_token,
        timedelta(days=settings.REFRESH_DAYS).seconds,
        timedelta(days=settings.REFRESH_DAYS).seconds,
        '/',
        None,
        False,
        True,
        'lax'
    )

    response.set_cookie(
        'logged_in',
        'True',
        timedelta(minutes=settings.ACCESS_MINUTES).seconds,
        timedelta(minutes=settings.ACCESS_MINUTES).seconds,
        '/',
        None,
        False,
        False,
        'lax'
    )

    return {
        'status': 'success',
        'access_token': access_token,
    }


@user_router.get('/logout', status_code=status.HTTP_200_OK)
async def logout(response: Response, auth: AuthJWT = Depends()):
    auth.unset_jwt_cookies()
    response.set_cookie('logged_in', '', -1)
    return {'status': 'success'}


# Вызывается для эдпоинтов, требующих входа
async def require_user(
        response: Response,
        repo: UserRepository = Depends(get_user_repository),
        auth: AuthJWT = Depends()) -> str:
    try:
        auth.jwt_required()
        username = auth.get_jwt_subject()
    except:
        username = await refresh(response, repo, auth)

    user = await repo.db_user_get(username)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail='User no longer exist')
    if not user.verified:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail='Please verify your account')
    return username


# Вызывается из require_user в случае окончания срока действия access токена
# В случае действующего refresh токена генерирует новый access токен в cookies
# и возвращает имя пользователя
async def refresh(
        response: Response,
        repo: UserRepository,
        auth: AuthJWT,
) -> str:
    try:
        auth.jwt_refresh_token_required()
        username = auth.get_jwt_subject()
        if not username:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail='Invalid refresh token')

    except Exception as e:
        error = e.__class__.__name__
        if error == 'MissingTokenError':
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail='Please login, or provide refresh token')
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail='Token is invalid or has expired')

    user = await repo.db_user_get(username)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail='User no longer exist')
    if not user.verified:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail='Please verify your account')

    access_token = auth.create_access_token(
        subject=str(username), expires_time=timedelta(minutes=settings.ACCESS_MINUTES))
    response.set_cookie(
        'access_token',
        access_token,
        timedelta(minutes=settings.ACCESS_MINUTES).seconds,
        timedelta(minutes=settings.ACCESS_MINUTES).seconds,
        '/',
        None,
        False,
        True,
        'lax')
    response.set_cookie(
        'logged_in',
        'True',
        timedelta(minutes=settings.ACCESS_MINUTES).seconds,
        timedelta(minutes=settings.ACCESS_MINUTES).seconds,
        '/',
        None,
        False,
        False,
        'lax')
    return username


# Возвращает информацию о себе в формате:
# ("username", "role_id", "verified")
@user_router.get('/me/', status_code=status.HTTP_200_OK)
async def get_me(repo: UserRepository = Depends(get_user_repository), username = Depends(require_user)):
    user = (await repo.db_user_get(username)).__dict__
    message = {k: user[k] for k in user if k in ("username", "role_id", "verified")}
    return {'message': message}


# Для пользователей с ролью админ или суперадмин,
# возвращает первых 10 пользователей с ролью пользователь в формате:
# ("username", "role_id", "verified")
@user_router.get('/get_10_users/', status_code=status.HTTP_200_OK)
@role_req((Role.ADMIN, Role.S_ADMIN, ))
async def get_10_users(repo: UserRepository = Depends(get_user_repository), username = Depends(require_user)):
    users = await repo.get_n_users_with_roles((Role.USER.value, ))
    message = [{k: u.__dict__[k] for k in u.__dict__ if k in ("username", "role_id", "verified")} for u in users]
    return {'message': message}
