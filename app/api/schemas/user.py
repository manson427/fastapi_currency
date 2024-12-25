from pydantic import BaseModel, constr, EmailStr, conint
from datetime import date


class UserPassword(BaseModel):
    password: constr(min_length=8, max_length=16)


class UserPasswordConfirm(BaseModel):
    password_confirm: str


class UserName(BaseModel):
    username: str


class UserData(BaseModel):
    email: EmailStr
    born: date


class UserLogin(UserName, UserPassword):
    pass


class UserChangePassword(UserPassword, UserPasswordConfirm):
    pass


class UserRegister(UserData, UserChangePassword):
    pass


class UserDB(UserName, UserData):
    hashed_password: str
    role_id: int
    verified: bool
    refresh_token: str
    verify_code: str
    reset_code: str
