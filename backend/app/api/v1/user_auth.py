from fastapi import APIRouter, Depends, HTTPException, Query, status, Request, BackgroundTasks
from sqlalchemy.orm import Session
from fastapi.security import OAuth2PasswordRequestForm

from app.schemas.auth_schema import Login, SignUp, UserResponse, TokenResponse
from app.database.psql_connection import get_db
from app.services.user_service import get_user
from app.models.models import Users, PendingUser
from app.utils import security
from app.services import user_service

router = APIRouter()

# User SignUp Endpoint
@router.post('/signup')
async def user_signup(credentials: SignUp,  db: Session = Depends(get_db)):

    return await user_service.create_user_account(credentials=credentials, db=db)

@router.get('/verify')
async def verify_email(token: str = Query(...), db: Session = Depends(get_db) ):

    credential_exception = HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid link", headers={"WWW-Authenticate":"Bearer"})
    
    data = security.validate_access_token(credential_exception=credential_exception, token=token)

    user = db.query(PendingUser).filter(PendingUser.username == data.username).first()

    if not user:
        raise credential_exception
    
    new_user = Users(username=user.username, password_hash=user.password_hash, email=user.email)
    db.add(new_user)
    db.delete(user)
    db.commit()
    db.refresh(new_user)
    
    return {'MSG':'Email verified Successfull', 'User':new_user}





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