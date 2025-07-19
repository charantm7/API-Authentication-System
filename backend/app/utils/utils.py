import jwt
from passlib.context import CryptContext
from datetime import datetime, timedelta, timezone

from app.core.config import Token

SECRETE_KEY = Token.SECRETE_KEY
ALGORITHM = Token.ALGORITHM
TOKEN_EXPIRATION_TIME = Token.TOKEN_EXPIRATION_TIME

pwd_context = CryptContext(schemes=['bcrypt'], deprecated="auto")

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