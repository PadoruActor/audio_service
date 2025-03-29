# main.py
from datetime import datetime, timedelta
from typing import List, Optional

import jwt
import requests
import secrets
from fastapi import FastAPI, UploadFile, HTTPException, Depends, status
from fastapi.security import OAuth2PasswordBearer
from jwt import PyJWTError
from pydantic import BaseModel, ConfigDict
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy import Column, String, Boolean, Integer, ForeignKey, select
from sqlalchemy.ext.declarative import declarative_base
import os
from pathlib import Path


# Configuration
class Config:
    SECRET_KEY = secrets.token_hex(32)
    ALGORITHM = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES = 30
    YANDEX_CLIENT_ID = "78f8ad51b5ca4fb289ccefb21f957bb5"
    YANDEX_CLIENT_SECRET = "b6c9d88569184d07849ef1294f69bb13"
    DATABASE_URL = "postgresql+asyncpg://postgres:admin@localhost:5432/audio_service"
    AUDIO_STORAGE_PATH = "./audio_storage"


# Create directories if they don't exist
os.makedirs(Config.AUDIO_STORAGE_PATH, exist_ok=True)

# Database setup
Base = declarative_base()


class User(Base):
    __tablename__ = "users"

    id = Column(String, primary_key=True)
    yandex_id = Column(String, unique=True, nullable=False)
    username = Column(String, nullable=False)
    email = Column(String)
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
    yandex_id: str
    username: str
    email: Optional[str] = None
    is_superuser: bool = False


class Token(BaseModel):
    access_token: str
    token_type: str


class AudioFileInfo(BaseModel):
    file_name: str
    file_path: str


# FastAPI setup
app = FastAPI()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


# Database initialization
async def init_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


@app.on_event("startup")
async def startup():
    await init_db()


# Authentication utilities
def create_access_token(data: dict, expires_delta: timedelta = None) -> str:
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=Config.ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, Config.SECRET_KEY, algorithm=Config.ALGORITHM)


async def get_current_user(token: str = Depends(oauth2_scheme)) -> UserBase:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, Config.SECRET_KEY, algorithms=[Config.ALGORITHM])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise credentials_exception

        async with async_session() as session:
            user = await session.get(User, user_id)
            if user is None:
                raise credentials_exception

            return UserBase.model_validate(user)
    except PyJWTError:
        raise credentials_exception


async def get_current_superuser(current_user: UserBase = Depends(get_current_user)) -> UserBase:
    if not current_user.is_superuser:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to perform this action",
        )
    return current_user


# API Endpoints
@app.get("/auth_url")
async def get_auth_url():
    return {
        "url": f"https://oauth.yandex.ru/authorize?response_type=code&client_id={Config.YANDEX_CLIENT_ID}"
    }


@app.get("/yandex_login", response_model=Token)
async def yandex_login(code: str):
    try:
        # Exchange code for Yandex token
        data = {
            "grant_type": "authorization_code",
            "code": code,
            "client_id": Config.YANDEX_CLIENT_ID,
            "client_secret": Config.YANDEX_CLIENT_SECRET,
        }

        res = requests.post("https://oauth.yandex.ru/token", data=data)
        res.raise_for_status()
        yandex_token = res.json()["access_token"]

        # Get user info from Yandex
        headers = {"Authorization": f"Bearer {yandex_token}"}
        info = requests.get("https://login.yandex.ru/info", headers=headers)
        info.raise_for_status()
        user_info = info.json()

        async with async_session() as session:
            # Check if user exists
            existing_user = await session.execute(
                select(User).where(User.yandex_id == user_info['id'])
            )
            existing_user = existing_user.scalar_one_or_none()

            if existing_user:
                user = existing_user
            else:
                # Create new user
                user_id = secrets.token_hex(16)
                user = User(
                    id=user_id,
                    yandex_id=user_info['id'],
                    username=user_info.get('login', 'Unknown'),
                    email=user_info.get('default_email'),
                    is_superuser=False
                )
                session.add(user)
                await session.commit()
                await session.refresh(user)

            # Create internal access token
            access_token = create_access_token(data={"sub": user.id})
            return {"access_token": access_token, "token_type": "bearer"}

    except requests.RequestException as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Yandex authentication failed: {str(e)}"
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Internal server error: {str(e)}"
        )


@app.get("/users/me", response_model=UserBase)
async def read_current_user(current_user: UserBase = Depends(get_current_user)):
    return current_user


@app.put("/users/me", response_model=UserBase)
async def update_current_user(
        update_data: dict,
        current_user: UserBase = Depends(get_current_user)
):
    async with async_session() as session:
        user = await session.get(User, current_user.id)
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        for key, value in update_data.items():
            setattr(user, key, value)

        await session.commit()
        await session.refresh(user)
        return UserBase.model_validate(user)


@app.delete("/users/{user_id}")
async def delete_user(
        user_id: str,
        current_user: UserBase = Depends(get_current_superuser)
):
    async with async_session() as session:
        user = await session.get(User, user_id)
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        await session.delete(user)
        await session.commit()
        return {"message": "User deleted successfully"}


@app.get("/audio_files", response_model=List[AudioFileInfo])
async def get_user_audio_files(
        current_user: UserBase = Depends(get_current_user)
):
    async with async_session() as session:
        result = await session.execute(
            select(AudioFile).where(AudioFile.user_id == current_user.id)
        )
        files = result.scalars().all()
        return [AudioFileInfo(file_name=f.file_name, file_path=f.file_path) for f in files]


@app.post("/audio")
async def upload_audio_file(
        file: UploadFile,
        current_user: UserBase = Depends(get_current_user)
):
    if not file:
        raise HTTPException(status_code=400, detail="No file provided")

    try:
        # Create user directory if it doesn't exist
        user_dir = Path(Config.AUDIO_STORAGE_PATH) / current_user.id
        user_dir.mkdir(exist_ok=True)

        # Save file
        file_path = user_dir / file.filename
        contents = await file.read()
        with open(file_path, "wb") as f:
            f.write(contents)

        # Save file info to DB
        async with async_session() as session:
            audio_file = AudioFile(
                user_id=current_user.id,
                file_name=file.filename,
                file_path=str(file_path)
            )
            session.add(audio_file)
            await session.commit()

        return {"filename": file.filename, "filepath": str(file_path)}
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )