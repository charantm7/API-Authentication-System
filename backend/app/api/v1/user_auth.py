from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.schemas.auth_schema import SignUp, UserResponse
from app.database.psql_connection import get_db
from app.dependency import get_user, is_strong_password
from app.models.models import Users
from app.utils import utils

router = APIRouter()

# User SignUp Endpoint
@router.post('/signup', response_model=UserResponse)
async def user_signup(credentials: SignUp, db: Session = Depends(get_db)):

    user = get_user(db, credentials.username, credentials.email)
    if user:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Username or Email already exists!.")
    
    # check for strong password
    is_valid, message = is_strong_password(credentials.password_hash)

    if not is_valid:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"{message}")

    # storing hashed password
    credentials.password_hash = utils.hash_password(credentials.password_hash)

    new_user = Users(**credentials.dict())
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return new_user


