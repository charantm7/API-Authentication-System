from datetime import datetime
from pydantic import BaseModel, EmailStr

# JWT Token
class TokenResponse(BaseModel):

    access_token: str
    token_type: str

class TokenData(BaseModel):

    email: EmailStr
    
# Authentication
class UserAuth(BaseModel):

    username: str
    email: EmailStr
    password_hash: str

class Login(BaseModel):

    email: EmailStr
    password_hash: str

class SignUp(UserAuth):
    pass

class UserResponse(BaseModel):

    username: str
    email: EmailStr
    created_at: datetime
    is_active: bool

class ForgetPassword(BaseModel):

    email: EmailStr