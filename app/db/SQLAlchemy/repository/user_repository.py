from app.db.repository import UserRepository

from sqlalchemy import select, delete, update, ResultProxy
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.dialects.postgresql import insert

from app.api.schemas.user import UserRegister, UserDB
from app.db.SQLAlchemy.models.user import User

from typing import cast


class AlchemyUserRepository(UserRepository):
    def __init__(self, session: AsyncSession):
        self.session = session

    async def db_user_get(self, username: str) -> UserDB | None:
        return UserDB(**(await self.session.get(User, {'username', username})).__dict__)

    async def db_user_add(self, user: UserRegister, hashed_password: str) -> UserDB:
        data: dict = user.model_dump().pop('password_confirm')
        data['hashed_password'] = hashed_password
        db_user = User(**data)
        self.session.add(db_user)
        await self.session.commit()
        return UserDB(**db_user.__dict__)

    # Alternative
    # async def db_user_add(self, user: UserValidation) -> int():
    #     stmt = insert(User).values(user.model_dump()).on_conflict_do_nothing()
    #     result = await self.session.execute(stmt)
    #     await self.session.commit()
    #     return result.rowcount

    async def db_user_update(self, username, **kw) -> int:  # Returns updated rowcount, must be 1
        stmt = update(User).where(User.username == username).values(kw)
        result = cast(ResultProxy, await self.session.execute(stmt))
        await self.session.commit()
        return result.rowcount()

    async def db_delete_user(self, username: str) -> int:  # Returns deleted rowcount, must be 1
        stmt = delete(User).where(User.username == username)
        result = cast(ResultProxy, await self.session.execute(stmt))
        await self.session.commit()
        return result.rowcount()

    async def db_find_verification_code(self, code: str) -> UserDB:
        return UserDB(**(await self.session.get(User, {'verify_code', code})).__dict__)

    # Not used
    # async def get_n_users(self, list_username: list[str] | None = None, n: int = 10) -> list[User] | None:
    #     stmt = select(User).order_by(User.username).limit(n)
    #     if list_username:
    #         stmt = stmt.where(User.id.in_(list_username))
    #     result = await self.session.execute(stmt)
    #     users = result.scalars().all()
    #     if users:
    #         users = cast(list[User], users)
    #     return users