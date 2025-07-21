
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

    token = relationship("UserToken", back_populates="user")

    def get_context_string(self, context:str):
        return f"{context}{self.password_hash[-6:]}{self.created_at.strftime('%m%d%Y%H%M%S')}".strip()



class UserToken(Base):
    __tablename__ = 'user_tokens'

    id = Column(Integer, primary_key=True, autoincrement=True, nullable=False)
    user_id = mapped_column(ForeignKey('users.id'))
    access_key = Column(String(300), nullable=True, default=None, index=True)
    refresh_key = Column(String(300), nullable=True, index=True, default=None)
    created_at = Column(TIMESTAMP(timezone=True), server_default=text('now()'), nullable=False)
    expires_at = Column(TIMESTAMP(timezone=True), nullable=False)


