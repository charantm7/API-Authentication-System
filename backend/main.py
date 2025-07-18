from fastapi import FastAPI, Response, status
from contextlib import asynccontextmanager

from app.api import api_router as router

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
def health_check():
    return {"Message": "Server Running"}


