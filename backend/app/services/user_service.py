
from datetime import datetime, timedelta
from typing import Optional

from fastapi import Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.utils import security
from app.utils import security
from app.services import email_service
from app.database.psql_connection import get_db
from app.models.models import Users, PendingUser, ValidationToken, PasswordResetToken

# get user via username and email function
def get_user( db: Session, username: Optional[str] = None, email: Optional[str] = None) -> Optional[Users]:
    """Returns the user information if exists in DB else None"""

    if username:
        query = db.query(Users).filter(Users.username == username)

    if email: 
        query = db.query(Users).filter(Users.email == email)

    return query.first()

# get user in pending verification via username or email
def get_user_inpending( db: Session, username: Optional[str] = None, email: Optional[str] = None) -> Optional[PendingUser]:

    """Returns the user information if exists in DB else None"""
    if username:
        query = db.query(PendingUser).filter(PendingUser.username == username)

    if email: 
        query = db.query(PendingUser).filter(PendingUser.email == email)

    return query.first()


# get current user via token validation through headers
def get_current_user(token: str = Depends(security.oauth2_scheme) , db: Session = Depends(get_db)):

    """
    This function get current user after login 
    
    - Gets the token from header.
    - Send token for validation and return token data.
    - Through token data gets email and query the email to get user.
    
    """
    credential_exception = HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Could not validate credentials", headers={"WWW-Authenticate":"Bearer"})

    data = security.validate_access_token(credential_exception, token)
    
    user = get_user(db=db, email=data.email)

    if not user:
        raise credential_exception

    return user


# create user via credentials
async def create_user_account(credentials, db: Session):

    """
    This function creates new user via credential 

    - gets credentials and checks for user exists.
    - Checks for pending user if exists delete them with its token.
    - checks password strength.
    - checks for password conformation.
    - creates jwt token, email included. 
    - Sends the verification link to the email.
    - Hash the password and creates a pending user.
    - stores the jwt token with relation to the pending user id.
    """
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

    is_valid, message = security.is_strong_password(credentials.password_hash)

    if not is_valid:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"{message}")

    if credentials.password_hash != credentials.confirm_password:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Both field should be same")

    jwt_token = security.create_access_token({'email':credentials.email})

    await email_service.send_account_verification_email(credentials.email, jwt_token)

    credentials.password_hash = security.hash_password(credentials.password_hash)

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


# Verify the email via token sent through query
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


# sends the verification email to reset password
async def forget_password(credentials, db: Session):
    user = db.query(Users).filter(Users.email == credentials.email).first()

    reset_token = db.query(PasswordResetToken).filter(PasswordResetToken.user_id == user.id).first()

    if reset_token:
        db.delete(reset_token)
        db.commit()

    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='User not found! Please Signup.')

    pending_user = db.query(PendingUser).filter(PendingUser.email == credentials.email).first()

    if pending_user:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="You'r not verified your account! Please signup")
    

    jwt_token = security.create_access_token({'email':credentials.email})

    await email_service.send_reset_password_link(to_email=credentials.email, token=jwt_token)

    token = PasswordResetToken(user_id=user.id, token=jwt_token, expires_at = datetime.utcnow()+timedelta(minutes=30))
    db.add(token)
    db.commit()

    return {'msg':f'Password reset link sent to email {credentials.email}'}


# verify the link and reset password
def verify_and_reset_password(credentials,token, db: Session):

    credential_exception = HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid link", headers={"WWW-Authenticate":"Bearer"})

    valid_token = db.query(PasswordResetToken).filter(PasswordResetToken.token == token).first()

    if not valid_token:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail='Link Expired or Invalid link')
    
    token_data = security.validate_access_token(credential_exception=credential_exception, token=valid_token.token)

    user = get_user(email=token_data.email, db=db)

    if not user:
        raise credential_exception
    
    if credentials.password != credentials.confirm_password:
        raise HTTPException(status_code=status.HTTP_406_NOT_ACCEPTABLE, detail=f"Please enter same password for both fields")
    
    is_valid, message = security.is_strong_password(credentials.password)

    if not is_valid:
        raise HTTPException(status_code=status.HTTP_406_NOT_ACCEPTABLE, detail=message)

    user.password_hash = security.hash_password(credentials.confirm_password)
    db.commit()
    
    db.delete(valid_token)
    db.commit()

    return {'msg':'Password reset successfull'}


# user login / creates the token via email
def user_login(db, credentials):

    """
    Login Function to API

    - User input (email, password)
    - Validate for user exists in the Database and verify Password 
    - Creates access token 
    """
    user = get_user(db=db, email=credentials.username)

    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='Invalid Credentials!')

    if user.provider != "credentials":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Please login using {user.provider.title()}")

    if not security.verify_password(credentials.password, user.password_hash):

        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='Invalid Credentials!')

    access_token = security.create_access_token({'email':user.email})
    refresh_token = security.create_refresh_token({'email':user.email})
    
    return {'access_token': access_token,'refresh_token': refresh_token, 'token_type': 'Bearer'}
