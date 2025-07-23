from datetime import datetime, timedelta
from fastapi import APIRouter, Depends, HTTPException, Query, status, Request, Form
from sqlalchemy.orm import Session
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles

from app.schemas.auth_schema import Login, SignUp, UserResponse, TokenResponse, ForgetPassword, ResetPassword
from app.database.psql_connection import get_db
from app.services.user_service import get_user
from app.models.models import Users, PendingUser, ValidationToken, PasswordResetToken
from app.utils import security
from app.services import user_service, email_service
from app.core.config import templates


router = APIRouter()


# render templates
@router.get('/signup')
def get_signup(request: Request):
    return templates.TemplateResponse('signup.html', {"request": request})

@router.get('/signin')
def get_signup(request: Request):
    return templates.TemplateResponse('signin.html', {"request": request})

# User SignUp Endpoint
@router.post('/signup', response_class=HTMLResponse)
async def user_signup(request: Request,username: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),confirm_password: str = Form(...),   db: Session = Depends(get_db)):

    credentials = SignUp(username=username, email=email, password_hash=password, confirm_password=confirm_password)

    response = await user_service.create_user_account(credentials=credentials, db=db)

    return templates.TemplateResponse("signup.html", {"request": request,
            "message": f"{response}",
            "message_type": "error"})

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


@router.post('/reset-password')
async def reset_password(cred:ResetPassword, token: str = Query(...), db: Session = Depends(get_db)):

    credential_exception = HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid link", headers={"WWW-Authenticate":"Bearer"})

    valid_token = db.query(PasswordResetToken).filter(PasswordResetToken.token == token).first()

    if not valid_token:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail='Link Expired or Invalid link')
    
    token_data = security.validate_access_token(credential_exception=credential_exception, token=valid_token.token)

    user = get_user(email=token_data.email, db=db)

    if not user:
        raise credential_exception
    
    if cred.password != cred.confirm_password:
        raise HTTPException(status_code=status.HTTP_406_NOT_ACCEPTABLE, detail=f"Please enter same password for both fields")
    
    is_valid, message = security.is_strong_password(cred.password)

    if not is_valid:
        raise HTTPException(status_code=status.HTTP_406_NOT_ACCEPTABLE, detail=message)

    
    hashed_password = security.hash_password(cred.confirm_password)

    user.password_hash = hashed_password
    db.commit()
    
    
    db.delete(valid_token)
    db.commit()

    return {'msg':'Password reset successfull'}
    
    

# User Login Endpoint
@router.post('/login', response_model=TokenResponse)
async def user_login(credentials: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
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

    jwt_token = security.create_access_token({'email':user.email})

    
    return {'access_token': jwt_token, 'token_type': 'Bearer'}