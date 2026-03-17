from pydantic import BaseModel
from typing import List, Optional
from uuid import UUID


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    user_id: Optional[int] = None
    org_id: Optional[str] = None
    role: Optional[str] = None


class UserCreate(BaseModel):
    email: str
    password: str


class UserResponse(BaseModel):
    id: int
    org_id: UUID
    email: str
    role: str

    class Config:
        from_attributes = True


class APIKeyCreateRequest(BaseModel):
    name: str
    permissions: List[str]


class APIKeyCreateResponse(BaseModel):
    id: int
    org_id: str
    key: str
    permissions: List[str]


class APIKeyListItem(BaseModel):
    id: int
    org_id: str
    permissions: List[str]
    last_used: Optional[str] = None
