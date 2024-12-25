from fastapi import APIRouter, Depends, HTTPException, Response, status
from app.api.schemas.user import UserRegister, UserPassword, UserLogin
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
import jwt
from datetime import datetime, timedelta
from app.core.config import settings
from app.api.oauth2 import AuthJWT

from app.db.repository import UserRepository
from app.db.database import get_user_repository

from app.api.utils.crypt import hash_password, verify_password

user_router = APIRouter(
    prefix="/user",
    tags=["User"]
)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login")

USERS_DATA = [
    {"username": "admin1", "hashed_password": settings.pwd_context.hash("adminpass"), "age": 21, "confirmed": True},
    {"username": "admin2", "hashed_password": settings.pwd_context.hash("adminpass"), "age": 21, "confirmed": False}
]


def create_jwt_token(data: dict, exp_time: timedelta):
    data.update({"exp": datetime.utcnow() + exp_time})
    return jwt.encode(data, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def authenticate_user(username: str, password: str) -> bool:
    for user in USERS_DATA:
        if user["username"] == username:
            return settings.pwd_context.verify(password, user["hashed_password"])
    return False


@user_router.post("/register/")
async def register(user: UserValidation, repo: UserRepository = Depends(get_user_repository)):
    new_user = user.model_dump()
    new_user = ({k: new_user[k] for k in new_user if k != "password"} |
                {"hashed_password": settings.pwd_context.hash(new_user['password'])} |
                {'confirm_code': settings.pwd_context.hash(new_user['username'])})
    USERS_DATA.append(new_user)
    return {'confirm_code': new_user['confirm_code']}  # Отправить на Email


@user_router.get("/confirm/{confirm_code}")
async def confirm(confirm_code: str):
    for user in USERS_DATA:
        try:  # на случай если в фейк дб поле confirm_code отсутствует
            if user['confirm_code'] == confirm_code:
                user['confirmed'] = True
                return {"message": f"User '{user['username']}' has been successfully activated"}
        except:
            pass
    return {"message": "Illegal confirm code"}


@user_router.get("/reset/")
async def reset(username: str):
    for user in USERS_DATA:
        if user['username'] == username:
            user['reset_code'] = settings.pwd_context.hash(username)
            return {'reset_code': user['reset_code']}
    return {'message': f"User '{username}' is not found"}


@user_router.post("/set_password/{reset_code}")
async def set_password(reset_code: str, password: PasswordValidation):
    for user in USERS_DATA:
        try:  # на случай если в фейк дб поле reset_code отсутствует
            if user['reset_code'] == reset_code:
                user['hashed_password'] = settings.pwd_context.hash(password.password)
                return {"message": f"Password for user '{user['username']}' has been successfully changed"}
        except:
            pass
    return {"message": "Illegal reset code"}


def verify_jwt_token(token: str = Depends(oauth2_scheme)):
    try:
        return jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="The token has expired")
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid token")


def get_current_active_user(current_user_name: str = Depends(verify_jwt_token)):
    for user in USERS_DATA:
        if user['user_name'] == current_user_name:
            if user['confirmed']:
                return user
            else:
                raise HTTPException(status_code=400, detail="Inactive user")


@user_router.get("/about_me")
async def about_me(verified_user: dict = Depends(get_current_active_user)):
    return {
        'me': {verified_user[k] for k in ('username', 'email', 'age')}
    }


@user_router.get("/get_users")
async def get_users(verified_user: dict = Depends(get_current_active_user)):
    if verified_user:
        return {
            'users': [{user[k] for k in ('username', 'email', 'age')} for user in USERS_DATA]
        }

