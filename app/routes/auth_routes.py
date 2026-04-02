from __future__ import annotations
from fastapi import APIRouter, Request, Form, Depends, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from datetime import datetime
import re

from app.database.connection import get_db
from app.database.models import User, UserRole
from app.auth.auth import create_access_token, decode_token, require_auth, get_current_user
from app.auth.password_utils import hash_password, verify_password
from app.events.event_manager import event_manager
from app.events.event_types import EventType

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")


@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    """Page de connexion"""
    return templates.TemplateResponse("login.html", {"request": request})


@router.post("/login")
async def login_submit(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    db: AsyncSession = Depends(get_db),
):
    """Traitement de la connexion"""
    ip = request.client.host
    
    # Détection injection SQL
    sql_patterns = [r"(\bOR\b.*=)", r"(\bAND\b.*=)", r"(--)", r"(;)", r"(\bDROP\b)", r"(\bUNION\b)", r"(\bSELECT\b)"]
    for pattern in sql_patterns:
        if re.search(pattern, username, re.IGNORECASE) or re.search(pattern, password, re.IGNORECASE):
            await event_manager.emit(EventType.SQL_INJECTION, {
                "username": username,
                "ip": ip,
                "description": f"Tentative injection SQL dans le formulaire de login",
                "payload": f"username={username[:50]}"
            })
            return templates.TemplateResponse("login.html", {
                "request": request,
                "error": "Connexion échouée"
            })
    
    # Vérifier utilisateur
    result = await db.execute(select(User).where(User.username == username))
    user = result.scalar_one_or_none()
    
    if not user:
        await event_manager.emit(EventType.LOGIN_UNKNOWN_USER, {
            "username": username,
            "ip": ip,
            "description": f"Tentative de connexion avec un utilisateur inexistant"
        })
        return templates.TemplateResponse("login.html", {
            "request": request,
            "error": "Identifiant ou mot de passe incorrect"
        })
    
    # Vérifier si verrouillé
    if user.is_locked:
        await event_manager.emit(EventType.LOGIN_LOCKED, {
            "username": username,
            "ip": ip,
            "description": f"Tentative de connexion sur un compte verrouillé"
        })
        return templates.TemplateResponse("login.html", {
            "request": request,
            "error": "Compte verrouillé. Contactez l'administrateur."
        })
    
    # Vérifier mot de passe
    if not verify_password(password, user.password_hash):
        await event_manager.emit(EventType.LOGIN_FAILED, {
            "username": username,
            "ip": ip,
            "description": f"Échec d'authentification"
        })
        return templates.TemplateResponse("login.html", {
            "request": request,
            "error": "Identifiant ou mot de passe incorrect"
        })
    
    # Connexion réussie
    role_val = user.role.value if hasattr(user.role, 'value') else user.role
    token = create_access_token({"sub": user.username, "role": role_val})
    await event_manager.emit(EventType.LOGIN_SUCCESS, {
        "username": user.username,
        "ip": ip,
        "description": f"Connexion réussie",
        "user_id": user.id
    })
    
    # Redirection selon le rôle
    if user.role == UserRole.directeur:
        redirect_url = "/admin/dashboard"
    elif user.role == UserRole.security:
        redirect_url = "/security/dashboard"
    elif user.role == UserRole.infirmier:
        redirect_url = "/dashboard/infirmier"
    else:
        redirect_url = "/dashboard"
    
    response = RedirectResponse(url=redirect_url, status_code=303)
    response.set_cookie(key="access_token", value=token, httponly=True, max_age=60*60*24*7)
    return response


@router.get("/logout")
async def logout(request: Request, db: AsyncSession = Depends(get_db)):
    """Déconnexion"""
    user = await get_current_user(request, db)
    if user:
        ip = request.client.host
        await event_manager.emit(EventType.LOGOUT, {
            "username": user.username,
            "ip": ip,
            "description": "Déconnexion utilisateur"
        })
    
    response = RedirectResponse(url="/login", status_code=303)
    response.delete_cookie("access_token")
    return response


@router.get("/change-password", response_class=HTMLResponse)
async def change_password_page(request: Request, db: AsyncSession = Depends(get_db)):
    """Page de modification du mot de passe"""
    user = await require_auth(request, db)
    return templates.TemplateResponse("change_password.html", {
        "request": request,
        "user": user
    })


@router.post("/change-password")
async def change_password_submit(
    request: Request,
    current_password: str = Form(...),
    new_password: str = Form(...),
    confirm_password: str = Form(...),
    db: AsyncSession = Depends(get_db),
):
    """Traitement de la modification du mot de passe"""
    user = await require_auth(request, db)
    ip = request.client.host
    
    # Vérifier mot de passe actuel
    if not verify_password(current_password, user.password_hash):
        return templates.TemplateResponse("change_password.html", {
            "request": request,
            "user": user,
            "error": "Mot de passe actuel incorrect"
        })
    
    # Vérifier confirmation
    if new_password != confirm_password:
        return templates.TemplateResponse("change_password.html", {
            "request": request,
            "user": user,
            "error": "Les nouveaux mots de passe ne correspondent pas"
        })
    
    # Vérifier complexité
    if len(new_password) < 8:
        return templates.TemplateResponse("change_password.html", {
            "request": request,
            "user": user,
            "error": "Le mot de passe doit contenir au moins 8 caractères"
        })
    
    # Mettre à jour
    user.password_hash = hash_password(new_password)
    await db.commit()
    
    await event_manager.emit(EventType.PASSWORD_CHANGED, {
        "username": user.username,
        "ip": ip,
        "description": "Mot de passe modifié avec succès"
    })
    
    return templates.TemplateResponse("change_password.html", {
        "request": request,
        "user": user,
        "success": "Mot de passe modifié avec succès"
    })