from pydantic import BaseModel


class Currency(BaseModel):
    name: str
    quotes: dict
    timestamp: int
