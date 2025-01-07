from fastapi import APIRouter


currency_router = APIRouter(
    prefix="/currency",
    tags=["Currency"]
)


@currency_router.get("/exchange/")
async def exchange():
    pass


@currency_router.post("/list/")
async def show_list():
    pass


@currency_router.post("/update_list/")
async def update_list():
    pass