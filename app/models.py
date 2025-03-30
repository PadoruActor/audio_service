from pydantic import BaseModel, ConfigDict

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