from datetime import datetime
from pydantic import BaseModel, EmailStr

class UserAuth(BaseModel):

    username: str
    email: EmailStr
    password_hash: str

class SignUp(UserAuth):
    pass

class UserResponse(BaseModel):

    username: str
    email: EmailStr
    created_at: datetime
    is_active: bool