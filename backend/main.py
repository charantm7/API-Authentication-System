from os import name
from fastapi import FastAPI, Response, status, Depends
from contextlib import asynccontextmanager
from typing import Annotated
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware

from starlette.middleware.sessions import SessionMiddleware

from app.api import api_router as router
from app.models.models import Users
from app.core.config import settings
from app.services.user_service import get_current_user

@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Lifespan manager for API, Handles the sartup and the shutdown tasks
    """
    print("Server starting ...")
    yield
    print("Server shutdown ...")

# instance of fastapi
app = FastAPI(
    title='Authentication System',
    version="1.0",
    lifespan=lifespan
)

app.add_middleware(
    SessionMiddleware,
    secret_key=settings.SECRETE_KEY,
    same_site="lax",            
    https_only=False,
    session_cookie="auth_session",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:8000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)

app.mount("/static", StaticFiles(directory="frontend/static"), name='static')

app.include_router(router)


@app.get('/favicon.ico')
async def favicon():
    """Prevents from favicon 404 log"""
    return Response(status_code=status.HTTP_200_OK)


@app.get("/")
def health_check(current_user: Annotated[Users, Depends(get_current_user)] ):
    return current_user


