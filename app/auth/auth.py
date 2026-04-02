from __future__ import annotations
from datetime import datetime, timedelta
from typing import Optional
from jose import JWTError, jwt
from fastapi import Cookie, HTTPException, Request
from fastapi.responses import RedirectResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.config import settings
from app.database.models import User, UserRole


def create_access_token(data: dict) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def decode_token(token: str) -> Optional[dict]:
    try:
        return jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
    except JWTError:
        return None


async def get_current_user(
    request: Request,
    db: AsyncSession,
) -> Optional[User]:
    token = request.cookies.get("access_token")
    if not token:
        return None
    payload = decode_token(token)
    if not payload:
        return None
    username: str = payload.get("sub")
    if not username:
        return None
    result = await db.execute(select(User).where(User.username == username))
    user = result.scalar_one_or_none()
    return user


async def require_auth(request: Request, db: AsyncSession) -> User:
    user = await get_current_user(request, db)
    if user is None:
        raise HTTPException(status_code=401, detail="Non authentifié")
    if user.is_locked:
        raise HTTPException(status_code=403, detail="Compte verrouillé")
    return user


async def require_roles(request: Request, db: AsyncSession, *roles: UserRole) -> User:
    user = await require_auth(request, db)
    if user.role not in roles:
        raise HTTPException(status_code=403, detail="Accès interdit")
    return user