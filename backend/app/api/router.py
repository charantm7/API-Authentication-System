from fastapi import APIRouter
from .v1.user_auth import router as auth_router

api_router = APIRouter()

api_router.include_router(
    auth_router,
    prefix="/v1/auth",
    tags=['Authentication']
)


__all__ = ['api_router']