
from sqlalchemy import TIMESTAMP, Boolean, Column, Integer, String, DateTime, null
from sqlalchemy.sql.expression import text
from sqlalchemy.sql import func
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


