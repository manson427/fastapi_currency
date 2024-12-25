from fastapi import APIRouter


currency_router = APIRouter(
    prefix="/currency",
    tags=["Currency"]
)


@currency_router.get("/exchange/")
async def exchange():
    pass


@currency_router.post("/list/")
async def list():
    pass
