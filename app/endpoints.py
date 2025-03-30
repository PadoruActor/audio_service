import hashlib
from datetime import datetime, timedelta
from pathlib import Path
from typing import List
import jwt
from jwt import PyJWTError
import requests
from fastapi import FastAPI, UploadFile, HTTPException, Depends, status, Query, APIRouter
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from database import (async_session, User, AudioFile, Config,
                     engine, init_db, Base, async_session)
from models import UserBase, Token, AudioFileInfo
from sqlalchemy import select

router = APIRouter()
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

@router.on_event("startup")
async def startup():
    await init_db()
    async with async_session() as session:
        for email in Config.SUPERUSER_EMAILS:
            user_id = hashlib.sha256(email.encode()).hexdigest()
            existing_user = await session.execute(select(User).where(User.email == email))
            if not existing_user.scalar_one_or_none():
                superuser = User(
                    id=user_id,
                    yandex_id=f"superuser-{user_id}",
                    username=email.split('@')[0],
                    email=email,
                    is_superuser=True
                )
                session.add(superuser)
        await session.commit()

# Auth endpoints
@router.get("/auth/yandex", response_model=dict)
async def get_yandex_auth_url():
    return {
        "auth_url": f"https://oauth.yandex.ru/authorize?response_type=code&client_id={Config.YANDEX_CLIENT_ID}"
    }

@router.get("/auth/yandex/callback", response_model=Token)
async def yandex_callback(code: str = Query(...)):
    try:
        token_data = {
            "grant_type": "authorization_code",
            "code": code,
            "client_id": Config.YANDEX_CLIENT_ID,
            "client_secret": Config.YANDEX_CLIENT_SECRET,
        }
        res = requests.post("https://oauth.yandex.ru/token", data=token_data)
        res.raise_for_status()
        yandex_token = res.json()["access_token"]

        headers = {"Authorization": f"Bearer {yandex_token}"}
        info = requests.get("https://login.yandex.ru/info", headers=headers)
        info.raise_for_status()
        user_info = info.json()

        if not user_info.get('default_email'):
            raise HTTPException(status_code=400, detail="Email is required")

        email = user_info['default_email']
        async with async_session() as session:
            existing_user = await session.execute(select(User).where(User.email == email))
            existing_user = existing_user.scalar_one_or_none()

            if not existing_user:
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
@router.get("/users/me", response_model=UserBase)
async def read_current_user(user: User = Depends(get_current_user)):
    return user

@router.delete("/users/{user_id}")
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
@router.post("/audio")
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

@router.get("/audio_files", response_model=List[AudioFileInfo])
async def get_user_audio_files(user: User = Depends(get_current_user)):
    async with async_session() as session:
        result = await session.execute(
            select(AudioFile).where(AudioFile.user_id == user.id)
        )
        files = result.scalars().all()
        return [AudioFileInfo(file_name=f.file_name, file_path=f.file_path) for f in files]

@router.post("/logout")
async def logout():
    return {"message": "Successfully logged out"}