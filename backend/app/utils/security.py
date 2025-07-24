
import jwt
import re
from fastapi import Depends , HTTPException, status
from passlib.context import CryptContext
from jose import JWTError
from jwt.exceptions import ExpiredSignatureError
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
REFRESH_TOKEN_EXPIRATION_DAY = settings.REFRESH_TOKEN_EXPIRATION_DAY
REFRESH_TOKEN_SECRETE_KEY = settings.REFRESH_TOKEN_SECRETE_KEY


pwd_context = CryptContext(schemes=['bcrypt'], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl='/v1/api/auth/login')

oauth = OAuth()

# Google auth registeration
oauth.register(
    name='google',
    client_id=settings.GOOGLE_CLIENT_ID,
    client_secret=settings.GOOGLE_CLIENT_SECRETE,
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={
        'scope': 'openid email profile',
        'prompt': 'consent'
    }
)

# Github auth registeration
oauth.register(
    name='github',
    client_id=settings.GITHUB_CLIENT_ID,
    client_secret=settings.GITHUB_CLIENT_SECRETE,
    access_token_url='https://github.com/login/oauth/access_token',
    authorize_url='https://github.com/login/oauth/authorize',
    api_base_url='https://api.github.com/',
    client_kwargs={
        'scope': 'user:email read:user',
    },
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

# create refresh token 
def create_refresh_token(data: dict) -> str:

    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRATION_DAY)

    to_encode.update({'exp':expire})

    refresh_token = jwt.encode(to_encode, REFRESH_TOKEN_SECRETE_KEY, algorithm=ALGORITHM)

    return refresh_token

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
    
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    
# verify refresh token and create new access token
def validate_refresh_token(token):

    credential_exception = HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Could not validate credentials", headers={"WWW-Authenticate":"Bearer"})

    if not token:
            raise credential_exception
    try:

        payload = jwt.decode(token.refresh_token.encode('utf-8'), REFRESH_TOKEN_SECRETE_KEY, algorithms=[ALGORITHM])

        email = payload.get('email')
        if not email:
            raise credential_exception
        
        token_data = auth_schema.TokenData(email=email)

        expire = datetime.utcnow() + timedelta(minutes=TOKEN_EXPIRATION_TIME)
        to_encode = {'email':token_data.email, 'exp':expire}

        access_token = jwt.encode(to_encode, SECRETE_KEY, algorithm=ALGORITHM)

        return {'access_token': access_token, 'token_type': 'Bearer'}
    
    except ExpiredSignatureError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))

    except JWTError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
        
# check for password strength
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
