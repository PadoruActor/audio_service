from fastapi import FastAPI
from database import init_db
from endpoints import router
import asyncio

app = FastAPI()

# Подключаем роутер
app.include_router(router)

@app.on_event("startup")
async def startup():
    await init_db()