from pony.orm import *
#from app.core.config import settings
from datetime import date

db = Database()


class User(db.Entity):
    username = Required(str, unique=True)
    hashed_password = Required(str)
    role_id = Required(int, original_default=0)
    born = Required(date)
    verified = Required(bool, original_default=False)
    refresh_token = Optional(str)
    verify_code = Optional(str)
    reset_code = Optional(str)


try:
    db.bind(
        'postgres',
        user=settings.DB_LOGIN,
        password=settings.DB_PASSWORD,
        host=settings.DB_ADDRESS,
        database=settings.DB_NAME
    )
except Exception as Ex:
    print(Ex)