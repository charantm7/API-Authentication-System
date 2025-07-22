
from fastapi import Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import Optional, Tuple

from app.models.models import Users, PendingUser
from app.utils import security
from app.database.psql_connection import get_db
from app.utils import security
from app.services import email_service

def get_user( db: Session, username: Optional[str] = None, email: Optional[str] = None) -> Optional[Users]:

    """Returns the user information if exists in DB else None"""
    if username:
        query = db.query(Users).filter(Users.username == username)

    if email: 
        query = db.query(Users).filter(Users.email == email)

    return query.first()


    
def get_current_user(token: str = Depends(security.oauth2_scheme) , db: Session = Depends(get_db)):

    credential_exception = HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Could not validate credentials", headers={"WWW-Authenticate":"Bearer"})

    data = security.validate_access_token(credential_exception, token)
    
    user = get_user(db=db, username=data.username)

    if not user:
        raise credential_exception

    return user


async def create_user_account(credentials, db: Session) -> Users:
    user = get_user(db, credentials.username, credentials.email)
    if user:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Username or Email already exists!.")
    
    # check for strong password
    is_valid, message = security.is_strong_password(credentials.password_hash)

    if not is_valid:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"{message}")

    # storing hashed password
    credentials.password_hash = security.hash_password(credentials.password_hash)

    jwt_token = security.create_access_token({'username':credentials.username})

    await email_service.send_account_verification_email(credentials.email, jwt_token)

    new_user = PendingUser(**credentials.dict())
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return {'Message':'Email verification link has been sent'}