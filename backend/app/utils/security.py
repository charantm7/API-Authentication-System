
import jwt
import re
from fastapi import Depends , HTTPException
from passlib.context import CryptContext
from jose import ExpiredSignatureError, JWTError
from starlette.middleware.sessions import SessionMiddleware
from fastapi.responses import JSONResponse, RedirectResponse
from typing import Tuple
from datetime import datetime, timedelta, timezone
from fastapi.security import OAuth2PasswordBearer
from authlib.integrations.starlette_client import OAuth

from app.core.config import settings
from app.schemas import auth_schema

SECRETE_KEY = settings.SECRETE_KEY
ALGORITHM = settings.ALGORITHM
TOKEN_EXPIRATION_TIME = settings.TOKEN_EXPIRATION_TIME

pwd_context = CryptContext(schemes=['bcrypt'], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl='/v1/api/auth/login')

oauth = OAuth()
oauth.register(
    name="API_Authentication_System",
    client_id = settings.GOOGLE_CLIENT_ID,
    client_secret = settings.GOOGLE_CLIENT_SECRETE,
    authorize_url = "https://accounts.google.com/o/oauth2/auth",
    authorize_params = None,
    access_token_url = "https://accounts.google.com/o/oauth2/token",
    access_token_params = None,
    refresh_token_url = None,
    authorize_state = settings.SECRETE_KEY,
    redirect_uri = "http://127.0.0.1:8000/auth",
    jwks_uri="https://www.googleapis.com/oauth2/v3/certs",
    client_kwargs={"scope": "openid profile email"},
)

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plane_password, hash_password) -> bool:
    return pwd_context.verify(plane_password, hash_password)

# create access token
def create_access_token(data: dict) -> str:
    """
    Create the JWT access token

    - Encode the User data (id, username, etc)
    - Encode the Secrete key and the Algorithm
    """

    to_encode = data.copy()
    expire_time = datetime.now(timezone.utc) + timedelta(minutes=TOKEN_EXPIRATION_TIME)

    to_encode.update({'exp':expire_time})
    jwt_encode = jwt.encode(to_encode, SECRETE_KEY, algorithm=ALGORITHM)

    return jwt_encode

# Verify access token
def validate_access_token(credential_exception, token):

    if not token:
        credential_exception

    try:
        payload = jwt.decode(token, SECRETE_KEY, algorithms=[ALGORITHM])
        email = payload.get('email')

        if not email:
            raise credential_exception
        
        token_data = auth_schema.TokenData(email=email)
        return token_data

    except ExpiredSignatureError:
        raise credential_exception
    
    except JWTError:
        raise credential_exception

    
    

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
