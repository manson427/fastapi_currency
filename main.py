import uvicorn
from fastapi import FastAPI, Depends
from app.api.routers.user import user_router
from app.api.routers.currency import currency_router
from fastapi.middleware.cors import CORSMiddleware
from app.core.config import parse_settings


app = FastAPI()

app.include_router(user_router)
app.include_router(currency_router)


if __name__ == "__main__":
    uvicorn.run(app="main:app")#, host='api.app.localhost')
