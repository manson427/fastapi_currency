from app.db.repository import UserRepository

from sqlalchemy import select, delete, update, ResultProxy
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.dialects.postgresql import insert

from app.api.schemas.user import UserRegister, UserDB, UserAdd
from app.db.SQLAlchemy.models.user import User

from typing import cast


class AlchemyUserRepository(UserRepository):
    def __init__(self, session: AsyncSession):
        self.session = session


    async def db_user_get(self, username: str) -> UserDB | None:
        stmt = select(User).where(User.username == username)
        res = (await self.session.execute(stmt)).first()
        if res:
            return UserDB(**res[0].__dict__)


    async def db_user_add(self, user: UserAdd) -> int():
        stmt = insert(User).values(user.__dict__).on_conflict_do_nothing()
        result = await self.session.execute(stmt)
        await self.session.commit()
        return result.rowcount


    async def db_user_update(self, username, **kw) -> int:  # Returns updated rowcount, must be 1
        stmt = update(User).where(User.username == username).values(kw)
        result = await self.session.execute(stmt)
        await self.session.commit()
        return result.rowcount


    async def db_delete_user(self, username: str) -> int:  # Returns deleted rowcount, must be 1
        stmt = delete(User).where(User.username == username)
        result = cast(ResultProxy, await self.session.execute(stmt))
        await self.session.commit()
        return result.rowcount()


    async def db_find_verification_code(self, code: str) -> UserDB:
        return UserDB(**(await self.session.get(User, {'verify_code', code})).__dict__)


    async def get_n_users_with_roles(self, roles: tuple[int, ...] | None, n: int = 10) -> list[UserDB] | None:
        stmt = select(User).order_by(User.username).limit(n)
        if roles:
            stmt = stmt.where(User.role_id.in_(roles))
        result = await self.session.execute(stmt)
        return [UserDB(**user.__dict__) for user in result.scalars().all()]
