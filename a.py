from authlib.integrations.starlette_client import OAuth
from fastapi import Request, FastAPI, Depends
from sqlalchemy.orm import Session
import secrets

router = FastAPI()

oauth = OAuth()
oauth.register(
    name="google",
    client_id=settings.GOOGLE_CLIENT_ID,
    client_secret=settings.GOOGLE_CLIENT_SECRETE,
    server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
    client_kwargs={"scope": "openid email profile"},
)

@router.get("/login/google")
async def login_with_google(request: Request):
    state = secrets.token_urlsafe(16)  # generate a random state token
    redirect_uri = settings.REDIRECT_URL + "v1/auth/google/callback"
    return await oauth.google.authorize_redirect(request, redirect_uri, state=state)

@router.get("/google/callback", response_model=TokenResponse)
async def google_callback(request: Request, db: Session = Depends(get_db)):
    # token includes id_token and access_token
    token = await oauth.google.authorize_access_token(request)
    user_info = await oauth.google.parse_id_token(request, token)

    email = user_info.get('email')
    name = user_info.get('name')
    sub = user_info.get('sub')

    user = db.query(Users).filter(Users.email == email).first()

    if not user:
        password = secrets.token_urlsafe(16)
        hashed_password = security.hash_password(password=password)

        new_user = Users(
            email=email,
            username=name,
            provider="google",
            password_hash=hashed_password,
        )
        db.add(new_user)
        db.commit()
        db.refresh(new_user)

    access_token = security.create_access_token({"email": email})
    refresh_token = security.create_refresh_token({"email": email})

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "Bearer",
    }
