from __future__ import annotations
from fastapi import APIRouter, Request, Form, Depends, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func as sqlfunc, and_
from datetime import datetime, timedelta
import re

from app.database.connection import get_db
from app.database.models import User, Patient, Consultation, SecurityEvent, Alert, UserRole
from app.auth.auth import require_auth, require_roles
from app.auth.password_utils import hash_password
from app.events.event_manager import event_manager
from app.events.event_types import EventType

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")


@router.get("/admin/dashboard", response_class=HTMLResponse)
async def admin_dashboard(request: Request, db: AsyncSession = Depends(get_db)):
    """Tableau de bord directeur"""
    user = await require_roles(request, db, UserRole.directeur)
    
    # Stats
    total_patients = (await db.execute(select(sqlfunc.count()).select_from(Patient))).scalar() or 0
    
    total_users = (await db.execute(select(sqlfunc.count()).select_from(User))).scalar() or 0
    
    total_events = (await db.execute(select(sqlfunc.count()).select_from(SecurityEvent))).scalar() or 0
    
    result_recent_events = await db.execute(select(SecurityEvent).order_by(SecurityEvent.timestamp.desc()).limit(50))
    recent_events = result_recent_events.scalars().all()
        
    unresolved_alerts = (await db.execute(
        select(sqlfunc.count()).select_from(Alert).where(Alert.resolved == False)
    )).scalar() or 0
    
    result_recent_alerts = await db.execute(select(Alert).order_by(Alert.timestamp.desc()).limit(50))
    recent_alerts = result_recent_alerts.scalars().all()
    
    result_recent_patients = await db.execute(select(Patient).order_by(Patient.created_at.desc()).limit(5))
    recent_patients = result_recent_patients.scalars().all()
    
    return templates.TemplateResponse("admin/dashboard.html", {
        "request": request,
        "user": user,
        "total_patients": total_patients,
        "total_users": total_users,
        "total_events": total_events,
        "unresolved_alerts": unresolved_alerts,
        "recent_events": recent_events,
        "recent_alerts": recent_alerts,
        "recent_patients": recent_patients
    })


@router.get("/admin/users", response_class=HTMLResponse)
async def users_list(request: Request, db: AsyncSession = Depends(get_db)):
    """Liste des utilisateurs"""
    user = await require_roles(request, db, UserRole.directeur)
    
    result = await db.execute(select(User).order_by(User.created_at.desc()))
    users = result.scalars().all()
    
    return templates.TemplateResponse("admin/users.html", {
        "request": request,
        "user": user,
        "users": users
    })


@router.get("/admin/users/nouveau", response_class=HTMLResponse)
async def new_user_page(request: Request, db: AsyncSession = Depends(get_db)):
    """Page création utilisateur"""
    user = await require_roles(request, db, UserRole.directeur)
    return templates.TemplateResponse("admin/new_user.html", {
        "request": request,
        "user": user
    })


@router.post("/admin/users/nouveau")
async def create_user(
    request: Request,
    username: str = Form(...),
    full_name: str = Form(...),
    password: str = Form(...),
    role: str = Form(...),
    db: AsyncSession = Depends(get_db),
):
    """Créer un nouvel utilisateur"""
    creator = await require_roles(request, db, UserRole.directeur)
    ip = request.client.host
    
    # Vérifier injection SQL
    sql_patterns = [r"(\bOR\b.*=)", r"(\bAND\b.*=)", r"(--)", r"(\bDROP\b)"]
    for field in [username, full_name]:
        for pattern in sql_patterns:
            if re.search(pattern, field, re.IGNORECASE):
                raise HTTPException(status_code=400, detail="Donnée invalide")
    
    # Vérifier si username existe déjà
    result = await db.execute(select(User).where(User.username == username))
    if result.scalar_one_or_none():
        return templates.TemplateResponse("admin/new_user.html", {
            "request": request,
            "user": creator,
            "error": "Ce nom d'utilisateur existe déjà"
        })
    
    # Créer utilisateur
    new_user = User(
        username=username,
        full_name=full_name,
        password_hash=hash_password(password),
        role=UserRole(role),
        created_by=creator.username
    )
    
    db.add(new_user)
    await db.commit()
    
    await event_manager.emit(EventType.USER_CREATED, {
        "username": creator.username,
        "ip": ip,
        "description": f"Utilisateur {username} créé par {creator.username}"
    })
    
    return RedirectResponse(url="/admin/users", status_code=303)

@router.post("/admin/users/{user_id}/toggle-lock")
async def toggle_lock_user(user_id: int, request: Request, db: AsyncSession = Depends(get_db)):
    admin = await require_roles(request, db, UserRole.directeur)
    result = await db.execute(select(User).where(User.id == user_id))
    u = result.scalar_one_or_none()
    if not u: raise HTTPException(status_code=404)
    u.is_locked = not u.is_locked
    if not u.is_locked: u.failed_attempts = 0
    await db.commit()
    return RedirectResponse(url="/admin/users", status_code=303)