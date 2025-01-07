from abc import ABC, abstractmethod
from app.api.schemas.user import UserRegister, UserDB, UserAdd


class UserRepository(ABC):
    @abstractmethod
    async def db_user_get(self, username: str) -> UserDB | None:
        pass

    @abstractmethod
    async def db_user_add(self, user: UserAdd) -> int():
        pass

    @abstractmethod
    async def db_user_update(self, username, **kw) -> int:
        pass

    @abstractmethod
    async def db_delete_user(self, username: str) -> int:
        pass

    @abstractmethod
    async def db_find_verification_code(self, code: str) -> UserDB:
        pass

    @abstractmethod
    async def get_n_users_with_roles(self, roles: tuple[int, ...]  | None, n: int = 10) -> list[UserDB] | None:
        pass