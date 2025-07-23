
from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.responses import HTMLResponse

from sqlalchemy.orm import Session

from app.utils import security
from app.database.psql_connection import get_db
from app.services import user_service
from app.schemas.auth_schema import Login, SignUp, UserResponse, TokenResponse, ForgetPassword, ResetPassword, RefreshToken

router = APIRouter()


# User SignUp Endpoint
@router.post('/signup', response_class=HTMLResponse)
async def user_signup(credentials:SignUp, db: Session = Depends(get_db)):
    return await user_service.create_user_account(credentials=credentials, db=db)

# Email Verification through token
@router.get('/verify')
async def verify_email(token: str = Query(...), db: Session = Depends(get_db) ):
    return user_service.verify_email(db=db, token=token)


# Forget password and sends reset link to email
@router.post('/forget-password')
async def forget_password(credentials: ForgetPassword, db: Session = Depends(get_db) ):
    return await user_service.forget_password(credentials=credentials, db=db)

# Verify link and reset password
@router.post('/reset-password')
async def reset_password(credentials:ResetPassword, token: str = Query(...), db: Session = Depends(get_db)):
    return user_service.verify_and_reset_password(credentials=credentials, token=token, db=db)
    
# User Login Endpoint
@router.post('/login', response_model=TokenResponse)
async def user_login(credentials: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    return user_service.user_login(credentials=credentials, db=db)
    

@router.post('/refresh')
def refresh_token(token: RefreshToken):
    return security.validate_refresh_token(token=token)
