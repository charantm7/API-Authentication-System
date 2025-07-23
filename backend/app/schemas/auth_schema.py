from datetime import datetime
from pydantic import BaseModel, EmailStr

# JWT Token
class TokenResponse(BaseModel):

    access_token: str
    refresh_token: str
    token_type: str

class TokenData(BaseModel):

    email: EmailStr

class RefreshToken(BaseModel):

    refresh_token: str
    token_type: str = "Bearer"
    
# Authentication
class UserAuth(BaseModel):

    username: str
    email: EmailStr
    password_hash: str
    

class Login(BaseModel):

    email: EmailStr
    password_hash: str

class SignUp(UserAuth):
    confirm_password: str

class UserResponse(BaseModel):

    username: str
    email: EmailStr
    created_at: datetime
    is_active: bool

class ForgetPassword(BaseModel):

    email: EmailStr

class ResetPassword(BaseModel):

    password: str
    confirm_password: str