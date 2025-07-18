import re
from sqlalchemy.orm import Session
from typing import Optional, Tuple

from app.models.models import Users
from app.models.models import Users


def get_user( db: Session, username: str, email: str) -> Optional[Users]:

    """Returns the user information if exists in DB else None"""
    return db.query(Users).filter(
        (Users.username == username) | (Users.email == email)
    ).first()


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

    
