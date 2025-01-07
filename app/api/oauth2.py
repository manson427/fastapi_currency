from typing import List
from fastapi_jwt_auth import AuthJWT
from pydantic import BaseModel
from app.core.config import settings


class Settings(BaseModel):
    authjwt_algorithm: str = settings.JWT_ALGORITHM
    authjwt_decode_algorithms: List[str] = [settings.JWT_ALGORITHM]
    authjwt_token_location: set = {'cookies'} # , 'headers'
    authjwt_access_cookie_key: str = 'access_token'
    authjwt_refresh_cookie_key: str = 'refresh_token'
    authjwt_cookie_csrf_protect: bool = False
    authjwt_secret_key: str = settings.JWT_SECRET_KEY.get_secret_value()


# Библиотека для работы с токенами аутентификации
# находит токены в http запросе на основе конфигурации (см authjwt_token_location)
# и загружает их в приватный атрибут _token
@AuthJWT.load_config
def get_config():
    return Settings()

