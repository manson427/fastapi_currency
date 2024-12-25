from sqlalchemy import String, Integer, Date, Boolean
from sqlalchemy.orm import Mapped, mapped_column, relationship
from datetime import date
from app.db.SQLAlchemy.base import Base


class User(Base):
    __tablename__ = 'users'

    username: Mapped[str] = mapped_column(String, nullable=False, primary_key=True)
    hashed_password: Mapped[str] = mapped_column(String, nullable=False)
    email: Mapped[str] = mapped_column(String, nullable=False)
    role_id: Mapped[int] = mapped_column(Integer, default=0)
    born: Mapped[date] = mapped_column(Date, nullable=False)
    verified: Mapped[bool] = mapped_column(Boolean, default=False)
    refresh_token: Mapped[str] = mapped_column(String, nullable=True)
    verify_code: Mapped[str] = mapped_column(String, nullable=True)
    reset_code: Mapped[str] = mapped_column(String, nullable=True)

