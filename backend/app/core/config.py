from pydantic_settings import BaseSettings
from dotenv import load_dotenv

load_dotenv()

class Settings(BaseSettings):

    DB_HOST: str
    DB_PORT: int
    DB_USER: str
    DB_PASS: str
    DB_NAME: str

    class Config:
        env_file = ".env"
        extra = "ignore"
        

class JWT_Token(BaseSettings):

    SECRETE_KEY: str
    ALGORITHM: str
    TOKEN_EXPIRATION_TIME: int

    class Config:
        env_file = ".env"
        extra = "ignore"

class GoogleAuth(BaseSettings):

    GOOGLE_CLIENT_ID: str
    GOOGLE_CLIENT_SECRETE: str

settings = Settings()
Token = JWT_Token()
