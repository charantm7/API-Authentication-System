import re
from fastapi import Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import Optional, Tuple

from app.models.models import Users
from app.utils import utils
from app.database.psql_connection import get_db


def get_user( db: Session, username: Optional[str] = None, email: Optional[str] = None) -> Optional[Users]:

    """Returns the user information if exists in DB else None"""
    if username:
        query = db.query(Users).filter(Users.username == username)

    if email: 
        query = db.query(Users).filter(Users.email == email)

    return query.first()


def is_strong_password(password: str) -> Tuple[bool, str]:
    
    """
    Check the strenght of the password
    
    It returns Tuple(bool, str) -> True, "Reason"
    """

    if len(password) < 8:
        return False, "Password must be atleast 8 characters long!"
    
    if not re.search(r'[a-z]', password):
        return False, "Password must contain atleast one lowercase letter!"
    
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain atleast one uppercase letter!"

    if not re.search(r'[\d]', password):
        return False, "Password must contain atleast one digit!"

    if not re.search(r'[!@#$%^&*(),.?\":{}|<>]', password):
        return False, "password must contain atleast one Special characters!"
    
    return True, "Strong Password"

    
def get_current_user(token: str = Depends(utils.oauth2_scheme) , db: Session = Depends(get_db)):

    credential_exception = HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Could not validate credentials", headers={"WWW-Authenticate":"Bearer"})

    data = utils.validate_access_token(credential_exception, token)
    
    user = get_user(db=db, username=data.username)

    if not user:
        raise credential_exception

    return user