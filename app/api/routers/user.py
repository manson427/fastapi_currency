from fastapi import APIRouter, Depends, HTTPException, Response, status, Request
from app.api.schemas.user import UserRegister, UserLogin, UserDB, UserName, UserChangePassword
#import jwt

from datetime import datetime, timedelta
from app.core.config import settings
#from app.api.oauth2 import require_user
from fastapi_jwt_auth import AuthJWT


from app.db.repository import UserRepository
from app.db.database import get_user_repository

from app.api.utils.crypt import hash_password, verify_password
from app.api.utils.email import Email

user_router = APIRouter(
    prefix="/user",
    tags=["User"]
)



@user_router.post('/register', status_code=status.HTTP_201_CREATED)
async def register(
        request: Request,
        user_register: UserRegister,
        repo: UserRepository = Depends(get_user_repository),
):
    # Check username
    if repo.db_user_get(user_register.username):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail='Account already exist')

    # Check passwords
    if user_register.password != user_register.password_confirm:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail='Passwords do not match')

    # User add
    user = await repo.db_user_add(user_register, hash_password(user_register.password))
    if not user:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail='Error creating user')

    await send_email('Verify code', 'verify', user, request)

    return {'status': 'success', 'message': 'Verification link successfully sent to your email'}


async def send_email(
        subject: str,
        path: str,
        code: str,
        user: UserDB,
        request: Request,
) -> bool:
    try:
        url = (f"{request.url.scheme}://{request.client.host}:{request.url.port}/"
               f"{user_router.prefix}/{path}/{code}")
        await Email(user.username, url, [user.email]).send_code(subject, settings.VERIFY_TIME)
    except Exception as error:
        print('Error', error)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail='There was an error sending email')
    return True


# Check minimum time for resending mail code
def check_resending(code: str) -> bool:
    try:
        expires_time = jwt.decode(code, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
    except :
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f'Minimum time for resending ({settings.RESENDING_TIME}min) has not expired')
    resending_time = (
            expires_time - timedelta(minutes=settings.VERIFY_TIME) + timedelta(minutes=settings.RESENDING_TIME))
    if datetime.now() > resending_time:
        return True
    else:
        return False


# Resending the verify request
@user_router.get('/get_verify/')
async def get_verify(
        request: Request,
        username: str,# = Depends(require_user),
        repo: UserRepository = Depends(get_user_repository),
        auth: AuthJWT = Depends(),
):
    user = await repo.db_user_get(username)
    if user.verify_code:
        check_resending(user.verify_code)
    code = auth.create_access_token(
        subject=str(user.username), expires_time=timedelta(minutes=settings.VERIFY_TIME))

    if not await repo.db_user_update(username, verify_code=code):
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail='Error get user')

    await send_email('Verify link', 'verify', code, user, request)
    return {'status': 'success', 'message': 'Verification link successfully sent to your email'}


# Sending the password reset request
@user_router.get('/get_password_reset/{username}')
async def get_password_reset(
        request: Request,
        username: str,
        repo: UserRepository = Depends(get_user_repository),
        auth: AuthJWT = Depends(),
):
    user = await repo.db_user_get(username)
    if user.verify_code:
        check_resending(user.verify_code)
    code = auth.create_access_token(
        subject=str(user.username), expires_time=timedelta(minutes=settings.VERIFY_TIME))

    if not await repo.db_user_update(username, verify_code=code):
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail='Error get user')

    await send_email('Password reset link', 'password_reset', code, user, request)
    return {'status': 'success', 'message': 'Password reset link successfully sent to your email'}



@user_router.post("/login/")
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

    if not verify_password(user_login.password, user.password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail='Invalid credentials')

    access_token = auth.create_access_token(
        subject=str(user.username), expires_time=timedelta(minutes=settings.ACCESS_TIME))

    refresh_token = auth.create_refresh_token(
        subject=str(user.id), expires_time=timedelta(minutes=settings.REFRESH_TIME))

    # Store refresh and access tokens in cookie
    response.set_cookie(
        'access_token',
        access_token,
        settings.ACCESS_TIME * 60,
        settings.ACCESS_TIME * 60,
        '/',
        None,
        False,
        True,
        'lax')

    response.set_cookie(
        'refresh_token',
        refresh_token,
        settings.REFRESH_TIME * 60,
        settings.REFRESH_TIME * 60,
        '/',
        None,
        False,
        True,
        'lax')

    response.set_cookie(
        'logged_in',
        'True',
        settings.ACCESS_TIME * 60,
        settings.ACCESS_TIME * 60,
        '/',
        None,
        False,
        False,
        'lax')

    return {'status': 'success', 'access_token': access_token}


@user_router.get('/refresh')
async def refresh(
        response: Response,
        repo: UserRepository = Depends(get_user_repository),
        auth: AuthJWT = Depends(),
):
    try:
        auth.jwt_refresh_token_required()
        username = auth.get_jwt_subject()

        if not username:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail='Could not refresh access token')

        if not repo.db_user_get(username):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail='The user belonging to this token no logger exist')

        access_token = auth.create_access_token(
            subject=str(username), expires_time=timedelta(minutes=settings.ACCESS_TIME))

    except Exception as e:
        error = e.__class__.__name__
        if error == 'MissingTokenError':
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail='Please provide refresh token')
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=error)

    response.set_cookie(
        'access_token',
        access_token,
        settings.ACCESS_TIME * 60,
        settings.ACCESS_TIME * 60,
        '/',
        None,
        False,
        True,
        'lax')

    response.set_cookie(
        'logged_in',
        'True',
        settings.ACCESS_TIME * 60,
        settings.ACCESS_TIME * 60,
        '/',
        None,
        False,
        False,
        'lax')

    return {'access_token': access_token}


@user_router.get('/logout', status_code=status.HTTP_200_OK)
async def logout(response: Response, auth: AuthJWT = Depends()):
    auth.unset_jwt_cookies()
    response.set_cookie('logged_in', '', -1)
    return {'status': 'success'}


def check_jwt(code: str) -> UserName:
    try:
        return jwt.decode(code, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="The code has expired")
    except jwt.PyJWTError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail='Invalid code')


@user_router.get('/password_reset/{password_reset_code}')
async def password_reset(
        password_reset_code: str,
        passwords: UserChangePassword,
        repo: UserRepository = Depends(get_user_repository)
):
    user = await repo.db_user_get(check_jwt(password_reset_code))
    if not user:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail='Error get user')

    # Check passwords
    if passwords.password != passwords.password_confirm:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail='Passwords do not match')

    # Set password
    if not await repo.db_user_update(user.username, hashed_password=hash_password(passwords.password)):
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail='Error update user')

    return {
        "status": "success",
        "message": "Password changed successfully"
    }



@user_router.get('/verify/{verify_code}')
async def verify(verify_code: str, repo: UserRepository = Depends(get_user_repository)):
    user = await repo.db_user_get(check_jwt(verify_code))

    if not user:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail='Error get user')

    if user.verify_code != verify_code:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail='Invalid verify code')

    if user.verified:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail='Email can only be verified once')

    if not await repo.db_user_update(user.username, verified=True):
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail='Error update user')

    return {
        "status": "success",
        "message": "Account verified successfully"
    }
