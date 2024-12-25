import base64
from typing import List
from fastapi import Depends, HTTPException, status
from fastapi_jwt_auth import AuthJWT
from pydantic import BaseModel

from app.core.config import settings

from app.db.repository import UserRepository
from app.db.database import get_user_repository


class Settings:
    authjwt_algorithm: str = settings.JWT_ALGORITHM
    authjwt_decode_algorithms: List[str] = [settings.JWT_ALGORITHM]
    authjwt_token_location: set = {'cookies', 'headers'}
    authjwt_access_cookie_key: str = 'access_token'
    authjwt_refresh_cookie_key: str = 'refresh_token'
    authjwt_cookie_csrf_protect: bool = False
    authjwt_public_key: str = settings.JWT_PUBLIC_KEY  # base64.b64decode(settings.JWT_PUBLIC_KEY).decode('utf-8')
    authjwt_private_key: str = settings.JWT_PRIVATE_KEY  # base64.b64decode(settings.JWT_PRIVATE_KEY).decode('utf-8')



@AuthJWT.load_config
def get_config():
    return Settings()


class NotVerified(Exception):
    pass


class UserNotFound(Exception):
    pass


async def require_user(repo: UserRepository = Depends(get_user_repository), auth: AuthJWT = Depends()):
    try:
        auth.jwt_required()
        username = auth.get_jwt_subject()
        user = await repo.db_user_get(username)

        if not user:
            raise UserNotFound('User no longer exist')

        if not user.verified:
            raise NotVerified('You are not verified')

    except Exception as e:
        error = e.__class__.__name__
        print(error)
        if error == 'MissingTokenError':
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail='You are not logged in')
        if error == 'UserNotFound':
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail='User no longer exist')
        if error == 'NotVerified':
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail='Please verify your account')
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail='Token is invalid or has expired')
    return username
