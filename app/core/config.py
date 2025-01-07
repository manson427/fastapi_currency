from os import getenv
from pathlib import Path

from pydantic import BaseModel, SecretStr, PostgresDsn, EmailStr, HttpUrl
from yaml import load

try:
    from yaml import CSafeLoader as SafeLoader
except ImportError:
    from yaml import SafeLoader


class Settings(BaseModel):
    JWT_PUBLIC_KEY: SecretStr
    JWT_SECRET_KEY: SecretStr
    JWT_ALGORITHM: str
    ACCESS_MINUTES: int
    REFRESH_DAYS: int
    VERIFY_MINUTES: int
    RESENDING_MINUTES: int
    DB_ALCHEMY: SecretStr
    DB_ALCHEMY_TEST: SecretStr
    EMAIL_HOST: str
    EMAIL_PORT: int
    EMAIL_USERNAME: EmailStr
    EMAIL_PASSWORD: SecretStr
    EMAIL_FROM: EmailStr
    CURRENCY_API_KEY: SecretStr
    CURRENCY_API_ADDRESS: HttpUrl
    DEFAULT_USERNAME: str
    DEFAULT_PASSWORD: SecretStr
    DEFAULT_EMAIL: EmailStr


def parse_settings() -> Settings:
    # Название переменной окружения,
    # значение которой есть путь к файлу конфигурации для процесса
    env_var = "FastAPI_CONFIG_FILE"

    file_path = getenv(env_var)

    if file_path is None:
        error = f"Environment variable {env_var} is missing or empty"
        raise ValueError(error)

    if not Path(file_path).is_file():
        error = f"Path {file_path} is not a file or doesn't exist"
        raise ValueError(error)

    with open(file_path, "rt") as file:
        config_data = load(file, SafeLoader)

    return Settings(**config_data)

settings = parse_settings()


# Используется для передачи данных для создания тестовых пользователей
# из фикстуры fixture_users
# в миграцию alembic seed_users
class AlembicTestData:
    flag_test: bool = False
    users: list = []
