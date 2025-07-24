from pydantic_core import Url
from pydantic_settings import BaseSettings
from dotenv import load_dotenv
from fastapi.templating import Jinja2Templates

load_dotenv()

templates = Jinja2Templates(directory="frontend/templates")


class Settings(BaseSettings):

    # database
    DB_HOST: str
    DB_PORT: int
    DB_USER: str
    DB_PASS: str
    DB_NAME: str

    MIDDLEWARE_SECRETE_KEY: str

    # jwt
    SECRETE_KEY: str
    ALGORITHM: str
    TOKEN_EXPIRATION_TIME: int
    REFRESH_TOKEN_EXPIRATION_DAY: int
    REFRESH_TOKEN_SECRETE_KEY: str

    # google oauth
    GOOGLE_CLIENT_ID: str
    GOOGLE_CLIENT_SECRETE: str
    REDIRECT_URL: str
    FRONTEND_URL: str

    # email
    EMAIL_FROM: str
    EMAIL_PASSWORD: str
    SMTP_SERVER: str
    SMTP_PORT:int

    class Config:
        env_file = ".env"
        extra = "ignore"
        

settings = Settings()