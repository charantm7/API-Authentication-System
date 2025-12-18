
import secrets
import httpx

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
async def user_signup(credentials: SignUp, db: Session = Depends(get_db)):
    return await user_service.create_user_account(credentials=credentials, db=db)

# Email Verification through token


@router.get('/verify')
async def verify_email(token: str = Query(...), db: Session = Depends(get_db)):
    return user_service.verify_email(db=db, token=token)


# Forget password and sends reset link to email
@router.post('/forget-password')
async def forget_password(credentials: ForgetPassword, db: Session = Depends(get_db)):
    return await user_service.forget_password(credentials=credentials, db=db)

# Verify link and reset password


@router.post('/reset-password')
async def reset_password(credentials: ResetPassword, token: str = Query(...), db: Session = Depends(get_db)):
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


@router.get('/login/google', response_model=TokenResponse)
async def login_with_google(request: Request):
    redirect_uri = "http://127.0.0.1:8000/v1/auth/google/callback"
    return await security.oauth.google.authorize_redirect(request, redirect_uri)


@router.get('/google/callback')
async def google_callback(request: Request, db: Session = Depends(get_db)):
    try:

        token = await security.oauth.google.authorize_access_token(request)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    access_token = token.get('access_token')
    userinfo = token.get('userinfo')
    iss = userinfo['iss']

    async with httpx.AsyncClient() as client:

        response = await client.get(
            "https://www.googleapis.com/oauth2/v2/userinfo",
            headers={"Authorization": f"Bearer {access_token}"}
        )

    user_info = response.json()
    email = user_info['email']
    name = user_info['name']
    user_id = user_info['id']

    if iss not in ["https://accounts.google.com", "accounts.google.com"]:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Google authentication failed.")

    if not user_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Google authentication failed.")

    user = db.query(Users).filter(Users.email == email).first()

    password = secrets.token_urlsafe(16)
    hashed_password = security.hash_password(password=password)
    if not user:

        new_user = Users(username=name, email=email,
                         provider='google', password_hash=hashed_password)
        db.add(new_user)
        db.commit()
        db.refresh(new_user)

    jwt_token = security.create_access_token({'email': email})
    refresh_token = security.create_refresh_token({'email': email})

    return {'access_token': jwt_token, 'refresh_token': refresh_token, 'token_type': 'Bearer'}


@router.get('/login/github')
async def login_with_github(request: Request):
    redirect_uri = "http://127.0.0.1:8000/v1/auth/github/callback"
    return await security.oauth.github.authorize_redirect(request, redirect_uri)


@router.get('/github/callback')
async def github_callback(request: Request):

    try:
        token = await security.oauth.github.authorize_access_token(request)
        user_data = await security.oauth.github.get('user', token=token)

        email_data = await security.oauth.github.get('user/emails', token=token)
        emails = email_data.json()
        return {'user': user_data.json(), 'email': emails}

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
