
from datetime import datetime, timedelta
from fastapi import Depends, HTTPException, status
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session
from typing import Optional

from app.models.models import Users, PendingUser, ValidationToken
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

def get_user_inpending( db: Session, username: Optional[str] = None, email: Optional[str] = None) -> Optional[PendingUser]:

    """Returns the user information if exists in DB else None"""
    if username:
        query = db.query(PendingUser).filter(PendingUser.username == username)

    if email: 
        query = db.query(PendingUser).filter(PendingUser.email == email)

    return query.first()


    
def get_current_user(token: str = Depends(security.oauth2_scheme) , db: Session = Depends(get_db)):

    credential_exception = HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Could not validate credentials", headers={"WWW-Authenticate":"Bearer"})

    data = security.validate_access_token(credential_exception, token)
    
    user = get_user(db=db, email=data.email)

    if not user:
        raise credential_exception

    return user


async def create_user_account(credentials, db: Session):
    user = get_user(db, credentials.username, credentials.email)
    if user:
        return "Email already exsists"
    
    pending_user = get_user_inpending(db, credentials.username, credentials.email)
    if pending_user:
        token_query = db.query(ValidationToken).filter(ValidationToken.user_id == pending_user.id).first()
        if token_query:
            db.delete(token_query)
        db.delete(pending_user)
        db.commit()
    # check for strong password
    is_valid, message = security.is_strong_password(credentials.password_hash)

    if credentials.password_hash != credentials.confirm_password:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Both field should be same")

    if not is_valid:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"{message}")

    # storing hashed password
    credentials.password_hash = security.hash_password(credentials.password_hash)

    jwt_token = security.create_access_token({'email':credentials.email})

    await email_service.send_account_verification_email(credentials.email, jwt_token)

    new_user = PendingUser(username=credentials.username,
    email=credentials.email,
    password_hash=credentials.password_hash)    
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    token = ValidationToken(user_id=new_user.id, token=jwt_token, expires_at = datetime.utcnow()+timedelta(minutes=30))
    db.add(token)
    db.commit()

    return f"Verification link has sent to Email {credentials.email}"


def verify_email(db: Session, token):
    credential_exception = HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid link", headers={"WWW-Authenticate":"Bearer"})

    token_db = db.query(ValidationToken).filter(ValidationToken.token == token).first()

    if not token_db:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail='Invalid token or expired')
    
    data = security.validate_access_token(credential_exception=credential_exception, token=token_db.token)

    user = db.query(PendingUser).filter(PendingUser.email == data.email).first() 

    if not user:
        raise credential_exception
    
    new_user = Users(username=user.username, password_hash=user.password_hash, email=user.email)
    db.add(new_user)
    db.delete(user)
    db.commit()
    db.refresh(new_user)

    return {'Msg': "Email Verfied Successfully"}