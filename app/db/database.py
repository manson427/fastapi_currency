from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
from app.core.config import settings
from app.db.SQLAlchemy.repository.user_repository import AlchemyUserRepository
from sqlalchemy.ext.asyncio import AsyncSession
from app.db.repository import UserRepository
from fastapi import Depends


engine = create_async_engine(
    url=settings.DB_ALCHEMY,
    echo=True
)

SessionPool = async_sessionmaker(engine, expire_on_commit=False)


async def get_db() -> AsyncSession:
    async with SessionPool() as session:
        yield session


async def get_user_repository(session: AsyncSession = Depends(get_db)) -> UserRepository:
    return AlchemyUserRepository(session)
