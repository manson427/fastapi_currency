from secrets import token_urlsafe
from datetime import datetime, timedelta
from passlib.context import CryptContext


class Settings:
    pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

    JWT_PUBLIC_KEY = token_urlsafe(16)  # 'qweqweasddsafqewrw'
    JWT_PRIVATE_KEY = token_urlsafe(16)  # 'fsdrgwerqweqweads'
    JWT_ALGORITHM = "HS256"
    ACCESS_TIME = timedelta(minutes=1)
    REFRESH_TIME = timedelta(minutes=5)
    VERIFY_TIME = timedelta(minutes=5)
    RESENDING_TIME = timedelta(minutes=1)

    DB_LOGIN = 'postgres'
    DB_PASSWORD = '1111'
    DB_ADDRESS = 'localhost'
    DB_NAME = 'fastapi_currency'
    DB_NAME_TEST = 'fastapi_currency_test'

    # postgresql+psycopg://postgres:1111@localhost/fastapi_currency
    DB_ALCHEMY = f"postgresql+psycopg://{DB_LOGIN}:{DB_PASSWORD}@{DB_ADDRESS}/{DB_NAME}"

    EMAIL_HOST: str
    EMAIL_PORT: int
    EMAIL_USERNAME: str
    EMAIL_PASSWORD: str
    EMAIL_FROM: str


settings = Settings()
