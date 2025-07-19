
from re import I
import jwt
from jwt.exceptions import InvalidTokenError
from fastapi import Depends
from passlib.context import CryptContext
from datetime import datetime, timedelta, timezone
from fastapi.security import OAuth2PasswordBearer

from app.core.config import Token
from app.schemas import auth_schema

SECRETE_KEY = Token.SECRETE_KEY
ALGORITHM = Token.ALGORITHM
TOKEN_EXPIRATION_TIME = Token.TOKEN_EXPIRATION_TIME

pwd_context = CryptContext(schemes=['bcrypt'], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl='/v1/api/auth/login')

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

    try:
        payload = jwt.decode(token, SECRETE_KEY, algorithms=[ALGORITHM])
        username = payload.get('username')

        if not username:
            raise credential_exception
        
        token_data = auth_schema.TokenData(username=username)
        return token_data

    except InvalidTokenError:
        raise credential_exception
    

