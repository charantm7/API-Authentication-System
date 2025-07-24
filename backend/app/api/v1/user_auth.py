
import secrets

from fastapi import APIRouter, Depends, HTTPException, Query, status, Request
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.responses import HTMLResponse

from sqlalchemy.orm import Session
from authlib.integrations.httpx_client import AsyncOAuth2Client

from app.core.config import settings
from app.utils import security
from app.models.models import Users
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
    
# refresh token
@router.post('/refresh')
def refresh_token(token: RefreshToken):
    return security.validate_refresh_token(token=token)


# login wihth google 
@router.get('/v1/auth/login/google')
async def login_with_google(request: Request):
    request.session.clear()
    
    redirect_uri = "http://127.0.0.1:8000/v1/auth/google/callback"
    return await security.oauth.google.authorize_redirect(request, redirect_uri)

@router.get('/v1/auth/google/callback', response_model=TokenResponse)
async def google_callback(request: Request, db: Session = Depends(get_db)):
    try:
        token = await security.oauth.google.authorize_access_token(request)
        user_info = await security.oauth.google.parse_id_token(request, token)

        if not user_info:
            raise HTTPException(status_code=400, detail="Could not get user info from Google")


    except Exception as e:
        raise HTTPException(status_code=400, detail=f"OAuth Error: {str(e)}")

    