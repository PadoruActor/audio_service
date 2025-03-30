# main.py
from datetime import datetime, timedelta
from typing import List, Optional
import jwt
import requests
from fastapi import FastAPI, UploadFile, HTTPException, Depends, status, Query
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jwt import PyJWTError
from pydantic import BaseModel, ConfigDict
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy import Column, String, Boolean, Integer, ForeignKey, select, UniqueConstraint
from sqlalchemy.ext.declarative import declarative_base
import os
from pathlib import Path
import hashlib


# Configuration
class Config:
    SECRET_KEY = "development-secret-key"  # Change in production!
    ALGORITHM = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES = 1440  # 24 hours
    YANDEX_CLIENT_ID = "78f8ad51b5ca4fb289ccefb21f957bb5"
    YANDEX_CLIENT_SECRET = "b6c9d88569184d07849ef1294f69bb13"
    DATABASE_URL = "postgresql+asyncpg://postgres:admin@localhost:5432/audio_service"
    AUDIO_STORAGE_PATH = "./audio_storage"
    SUPERUSER_EMAILS = ["admin@example.com"]  # List of superuser emails


os.makedirs(Config.AUDIO_STORAGE_PATH, exist_ok=True)

# Database setup
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


# Models
class UserBase(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    username: str
    email: str
    is_superuser: bool = False


class Token(BaseModel):
    access_token: str
    token_type: str
    user: UserBase


class AudioFileInfo(BaseModel):
    file_name: str
    file_path: str


app = FastAPI()
security = HTTPBearer()


# Auth utilities
def create_access_token(data: dict) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=Config.ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, Config.SECRET_KEY, algorithm=Config.ALGORITHM)


async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    try:
        payload = jwt.decode(token, Config.SECRET_KEY, algorithms=[Config.ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise HTTPException(status_code=401, detail="Invalid token")

        async with async_session() as session:
            user = await session.execute(select(User).where(User.email == email))
            user = user.scalar_one_or_none()
            if user is None:
                raise HTTPException(status_code=401, detail="User not found")
            return user
    except PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid token")


async def get_current_superuser(current_user: User = Depends(get_current_user)):
    if not current_user.is_superuser:
        raise HTTPException(status_code=403, detail="Not authorized")
    return current_user


# Database initialization
async def init_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)  # Drop existing tables
        await conn.run_sync(Base.metadata.create_all)  # Recreate them


@app.on_event("startup")
async def startup():
    await init_db()
    # Create initial superusers
    async with async_session() as session:
        for email in Config.SUPERUSER_EMAILS:
            user_id = hashlib.sha256(email.encode()).hexdigest()
            existing_user = await session.execute(select(User).where(User.email == email))
            if not existing_user.scalar_one_or_none():
                superuser = User(
                    id=user_id,
                    yandex_id=f"superuser-{user_id}",  # Fake Yandex ID for superusers
                    username=email.split('@')[0],
                    email=email,
                    is_superuser=True
                )
                session.add(superuser)
        await session.commit()


# Auth endpoints
@app.get("/auth/yandex", response_model=dict)
async def get_yandex_auth_url():
    return {
        "auth_url": f"https://oauth.yandex.ru/authorize?response_type=code&client_id={Config.YANDEX_CLIENT_ID}"
    }


@app.get("/auth/yandex/callback", response_model=Token)
async def yandex_callback(code: str = Query(...)):
    try:
        # Exchange code for Yandex token
        token_data = {
            "grant_type": "authorization_code",
            "code": code,
            "client_id": Config.YANDEX_CLIENT_ID,
            "client_secret": Config.YANDEX_CLIENT_SECRET,
        }
        res = requests.post("https://oauth.yandex.ru/token", data=token_data)
        res.raise_for_status()
        yandex_token = res.json()["access_token"]

        # Get user info from Yandex
        headers = {"Authorization": f"Bearer {yandex_token}"}
        info = requests.get("https://login.yandex.ru/info", headers=headers)
        info.raise_for_status()
        user_info = info.json()

        if not user_info.get('default_email'):
            raise HTTPException(status_code=400, detail="Email is required")

        email = user_info['default_email']
        async with async_session() as session:
            # Check if user exists by email
            existing_user = await session.execute(select(User).where(User.email == email))
            existing_user = existing_user.scalar_one_or_none()

            if not existing_user:
                # Create new user
                user_id = hashlib.sha256(email.encode()).hexdigest()
                is_superuser = email in Config.SUPERUSER_EMAILS
                new_user = User(
                    id=user_id,
                    yandex_id=user_info['id'],
                    username=user_info.get('login', email.split('@')[0]),
                    email=email,
                    is_superuser=is_superuser
                )
                session.add(new_user)
                await session.commit()
                await session.refresh(new_user)
                user = new_user
            else:
                user = existing_user

            # Create JWT token
            access_token = create_access_token(data={"sub": user.email})
            return {
                "access_token": access_token,
                "token_type": "bearer",
                "user": user
            }

    except requests.RequestException as e:
        raise HTTPException(status_code=400, detail=f"Yandex authentication failed: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")


# User management
@app.get("/users/me", response_model=UserBase)
async def read_current_user(user: User = Depends(get_current_user)):
    return user


@app.delete("/users/{user_id}")
async def delete_user(
        user_id: str,
        superuser: User = Depends(get_current_superuser)
):
    async with async_session() as session:
        if user_id == superuser.id:
            raise HTTPException(status_code=400, detail="Cannot delete yourself")

        user = await session.get(User, user_id)
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        await session.delete(user)
        await session.commit()
        return {"message": "User deleted successfully"}


# Audio endpoints
@app.post("/audio")
async def upload_audio_file(
        file: UploadFile,
        user: User = Depends(get_current_user)
):
    try:
        user_dir = Path(Config.AUDIO_STORAGE_PATH) / user.id
        user_dir.mkdir(exist_ok=True)

        file_path = user_dir / file.filename
        with open(file_path, "wb") as f:
            f.write(await file.read())

        async with async_session() as session:
            audio_file = AudioFile(
                user_id=user.id,
                file_name=file.filename,
                file_path=str(file_path)
            )
            session.add(audio_file)
            await session.commit()

        return {"filename": file.filename, "filepath": str(file_path)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/audio_files", response_model=List[AudioFileInfo])
async def get_user_audio_files(user: User = Depends(get_current_user)):
    async with async_session() as session:
        result = await session.execute(
            select(AudioFile).where(AudioFile.user_id == user.id)
        )
        files = result.scalars().all()
        return [AudioFileInfo(file_name=f.file_name, file_path=f.file_path) for f in files]


@app.post("/logout")
async def logout():
    return {"message": "Successfully logged out"}