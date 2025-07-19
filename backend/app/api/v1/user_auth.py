from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from fastapi.security import OAuth2PasswordRequestForm

from app.schemas.auth_schema import Login, SignUp, UserResponse, TokenResponse
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


# User Login Endpoint
@router.post('/login', response_model=TokenResponse)
async def user_login(credentials: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    """
    Login Function to API

    - User input (email, password)
    - Validate for user exists in the Database and verify Password 
    - Creates access token 
    """

    user = get_user(db=db, email=credentials.username)
    if not user or not utils.verify_password(credentials.password, user.password_hash):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='Invalid Credentials!')

    jwt_token = utils.create_access_token({'username':user.username})

    
    return {'access_token': jwt_token, 'token_type': 'Bearer'}