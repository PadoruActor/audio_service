from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker, declarative_base
from sqlalchemy import Column, String, Boolean, Integer, ForeignKey
from sqlalchemy import UniqueConstraint
import os

# Configuration
class Config:
    SECRET_KEY = "development-secret-key"  # Change in production!
    ALGORITHM = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES = 1440  # 24 hours
    YANDEX_CLIENT_ID = "78f8ad51b5ca4fb289ccefb21f957bb5"
    YANDEX_CLIENT_SECRET = "b6c9d88569184d07849ef1294f69bb13"
    DATABASE_URL = "postgresql+asyncpg://postgres:admin@db:5432/audio_service"
    AUDIO_STORAGE_PATH = "audio_storage"
    SUPERUSER_EMAILS = ["admin@example.com"]  # List of superuser emails

os.makedirs(Config.AUDIO_STORAGE_PATH, exist_ok=True)

Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    __table_args__ = (UniqueConstraint('email', name='unique_email'),)

    id = Column(String, primary_key=True)
    yandex_id = Column(String, unique=True, nullable=True)  # Made nullable
    username = Column(String)
    email = Column(String, unique=True, nullable=False)
    is_superuser = Column(Boolean, default=False)

class AudioFile(Base):
    __tablename__ = "audio_files"
    id = Column(Integer, primary_key=True)
    user_id = Column(String, ForeignKey("users.id"))
    file_name = Column(String, nullable=False)
    file_path = Column(String, nullable=False)

engine = create_async_engine(Config.DATABASE_URL)
async_session = sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)

async def init_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)