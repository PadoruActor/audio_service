from fastapi import FastAPI
from app.database import init_db
from app.endpoints import router

app = FastAPI()
app.include_router(router)

@app.on_event("startup")
async def startup():
    pass
    await init_db()