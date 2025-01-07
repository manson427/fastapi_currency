import pytest_asyncio
from pathlib import Path
from alembic.command import upgrade, downgrade
from alembic.config import Config as AlembicConfig

from fastapi.testclient import TestClient
import pytest
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession

from app.core.config import settings, AlembicTestData
from app.db.database import get_user_repository
from app.api.routers.user import SendEmail
from app.db.repository import UserRepository
from app.db.SQLAlchemy.repository.user_repository import AlchemyUserRepository
from main import app
from override import OverrideSendEmail


@pytest_asyncio.fixture(scope="module")
def engine():
    engine = create_async_engine(settings.DB_ALCHEMY_TEST.get_secret_value())
    yield engine
    engine.sync_engine.dispose()


@pytest_asyncio.fixture(scope="function")
async def session(engine):
    async with AsyncSession(engine) as s:
        yield s


@pytest_asyncio.fixture(scope="function")
async def get_db(session: AsyncSession):
    yield session


@pytest_asyncio.fixture(scope="function")
async def override_get_user_repository(get_db):
    async def _override_get_user_repository() -> UserRepository:
        yield AlchemyUserRepository(get_db)
    return _override_get_user_repository


@pytest_asyncio.fixture(scope="function")
async def client(override_get_user_repository) -> TestClient: #override_send_email
    app.dependency_overrides[get_user_repository] = override_get_user_repository
    app.dependency_overrides[SendEmail] = OverrideSendEmail
    return TestClient(app)


@pytest.fixture(scope="session")
def alembic_config() -> AlembicConfig:
    project_dir = Path(__file__).parent.parent
    alembic_ini_path = Path.joinpath(project_dir.absolute(), "alembic.ini").as_posix()
    alembic_cfg = AlembicConfig(alembic_ini_path)
    migrations_dir_path = Path.joinpath(
        project_dir.absolute(), "app", "db", "SQLAlchemy", "alembic").as_posix()
    alembic_cfg.set_main_option("script_location", migrations_dir_path)
    alembic_cfg.set_main_option("sqlalchemy.url", settings.DB_ALCHEMY_TEST.get_secret_value())
    AlembicTestData.flag_test = True
    return alembic_cfg


@pytest_asyncio.fixture(scope="module")
def create(engine, alembic_config: AlembicConfig):
    upgrade(alembic_config, "head")
    yield engine
    downgrade(alembic_config, "base")


