from datetime import datetime, timedelta
from fastapi import APIRouter, Depends, HTTPException, Query, status, Request, BackgroundTasks
from sqlalchemy.orm import Session
from fastapi.security import OAuth2PasswordRequestForm

from app.schemas.auth_schema import Login, SignUp, UserResponse, TokenResponse, ForgetPassword
from app.database.psql_connection import get_db
from app.services.user_service import get_user
from app.models.models import Users, PendingUser, ValidationToken, PasswordResetToken
from app.utils import security
from app.services import user_service, email_service

router = APIRouter()

# User SignUp Endpoint
@router.post('/signup')
async def user_signup(credentials: SignUp,  db: Session = Depends(get_db)):
    return await user_service.create_user_account(credentials=credentials, db=db)

# Email Verification 
@router.get('/verify')
async def verify_email(token: str = Query(...), db: Session = Depends(get_db) ):
    return user_service.verify_email(db=db, token=token)


# Forget password
@router.post('/forget-password')
async def forget_password(credential: ForgetPassword, db: Session = Depends(get_db) ):
    
    user = db.query(Users).filter(Users.email == credential.email).first()

    reset_token = db.query(PasswordResetToken).filter(PasswordResetToken.user_id == user.id).first()

    if reset_token:
        db.delete(reset_token)
        db.commit()

    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='User not found! Please Signup.')

    pending_user = db.query(PendingUser).filter(PendingUser.email == credential.email).first()

    if pending_user:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="You'r not verified your account! Please signup")
    

    jwt_token = security.create_access_token({'email':credential.email})

    await email_service.send_reset_password_link(to_email=credential.email, token=jwt_token)

    user = db.query(Users).filter(Users.email == credential.email).first()

    token = PasswordResetToken(user_id=user.id, token=jwt_token, expires_at = datetime.utcnow()+timedelta(minutes=30))
    db.add(token)
    db.commit()

    return {'msg': f'Password reset link sent to email {credential.email}'}

    
    

# User Login Endpoint
@router.post('/login', response_model=TokenResponse)
async def user_login(request: Request,credentials: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    """
    Login Function to API

    - User input (email, password)
    - Validate for user exists in the Database and verify Password 
    - Creates access token 
    """

    # request.session.clear()
    # referer = request.headers.get('referer')
    # redirect_url = Googleauth.REDIRECT_URL
    # frontend_url = Googleauth.FRONTEND_URL
    # request.session["login_redirect"] = frontend_url

    # return await utils.oauth.API_Authentication_System.authorize_redirect

    user = get_user(db=db, email=credentials.username)
    if not user or not security.verify_password(credentials.password, user.password_hash):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='Invalid Credentials!')

    jwt_token = security.create_access_token({'username':user.username})

    
    return {'access_token': jwt_token, 'token_type': 'Bearer'}