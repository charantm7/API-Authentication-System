
from sqlalchemy import TIMESTAMP, Boolean, Column, ForeignKey, Integer, String, DateTime, null
from sqlalchemy.sql.expression import text
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship, mapped_column

from ..database.psql_connection import Base

class Users(Base):
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True, nullable=False)
    username = Column(String, unique=True, nullable=False ) 
    email = Column(String, unique=True, nullable=False)
    password_hash = Column(String, nullable=False)
    created_at = Column(TIMESTAMP(timezone=True), server_default=text('now()'), nullable=False)
    is_active = Column(Boolean, default=True)
    is_superuser = Column(Boolean, default=False)
    provider = Column(String, default='credentials')

    password_reset_token = relationship('PasswordResetToken', back_populates='users', cascade="all, delete-orphan")


class PasswordResetToken(Base):
    __tablename__ = 'password_reset_token'

    id = id = Column(Integer, primary_key=True, nullable=False)
    user_id = Column(Integer, ForeignKey('users.id', ondelete="CASCADE"))
    token = Column(String, unique=True)
    expires_at = Column(DateTime, nullable=False)

    users = relationship("Users", back_populates="password_reset_token")



class PendingUser(Base):
    __tablename__ = "pending_users"

    id = Column(Integer, primary_key=True, nullable=False)
    username = Column(String, unique=True, nullable=False ) 
    email = Column(String, unique=True, nullable=False)
    password_hash = Column(String, nullable=False)
    created_at = Column(TIMESTAMP(timezone=True), server_default=text('now()'), nullable=False)

    validation_token = relationship(
        "ValidationToken",
        back_populates="pending_user",
        cascade="all, delete-orphan"
    )


class ValidationToken(Base):
    __tablename__ = 'validation_token'

    id = id = Column(Integer, primary_key=True, nullable=False)
    user_id = Column(Integer, ForeignKey('pending_users.id', ondelete="CASCADE"))
    token = Column(String, unique=True)
    expires_at = Column(DateTime, nullable=False)

    pending_user = relationship("PendingUser", back_populates="validation_token")
