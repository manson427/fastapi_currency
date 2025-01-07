from typing import Callable, Tuple
from functools import wraps
from enum import Enum
from fastapi import HTTPException, status
from app.api.schemas.user import UserDB


# Перечисление ролей пользователей
class Role(Enum):
    USER: int = 0
    ADMIN: int = 1
    S_ADMIN: int = 2


# Декоратор авторизации на основе ролей,
# предоставляет доступ только пользователям с перечисленными ролями
def role_req(roles: Tuple[Role, ...]):
    def decorator(func: Callable):
        @wraps(func)
        async def wrapper(*ar, **kw):
            user: UserDB = await kw['repo'].db_user_get(kw['username'])
            role: Role = Role(user.role_id)
            if role not in roles:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f'Your role {role}, not in role_list {roles}')
            return await func(*ar, **kw)
        return wrapper
    return decorator
