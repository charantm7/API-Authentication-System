from fastapi import FastAPI, Response, status, Depends
from contextlib import asynccontextmanager
from typing import Annotated

from app.api import api_router as router
from app.models.models import Users
from app.dependency import get_current_user

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

app.include_router(router)


@app.get('/favicon.ico')
async def favicon():
    """Prevents from favicon 404 log"""
    return Response(status_code=status.HTTP_200_OK)


@app.get("/")
def health_check(current_user: Annotated[Users, Depends(get_current_user)] ):
    return current_user


