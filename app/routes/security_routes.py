from __future__ import annotations
from fastapi import APIRouter, Request, Depends, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func as sqlfunc, text
from datetime import datetime
import json

from app.database.connection import get_db
from app.database.models import User, SecurityEvent, Alert, UserRole, Severity
from app.auth.auth import require_auth, require_roles
from app.services.ws_manager import ws_manager
from app.events.event_manager import event_manager
from app.events.event_types import EventType

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")


@router.get("/security/dashboard", response_class=HTMLResponse)
async def security_dashboard(request: Request, db: AsyncSession = Depends(get_db)):
    """Tableau de bord sécurité"""
    user = await require_roles(request, db, UserRole.security, UserRole.directeur)
    
    # Stats globale
    total_events = (await db.execute(select(sqlfunc.count(SecurityEvent.id)))).scalar() or 0
    
    critical_events = (await db.execute(
        select(sqlfunc.count(SecurityEvent.id)).where(SecurityEvent.severity == Severity.critical)
    )).scalar() or 0
    
    unresolved = (await db.execute(
        select(sqlfunc.count(Alert.id)).where(Alert.resolved == False)
    )).scalar() or 0
    
    locked_users = (await db.execute(
        select(sqlfunc.count(User.id)).where(User.is_locked == True)
    )).scalar() or 0
    
    # Répartition par sévérité en une seule requête
    severity_result = await db.execute(
        select(SecurityEvent.severity, sqlfunc.count(SecurityEvent.id))
        .group_by(SecurityEvent.severity)
    )
    severity_counts = {}
    for row in severity_result.all():
        sev, count = row
        key = sev.value if hasattr(sev, 'value') else sev
        severity_counts[key] = count
    
    # Événements récents
    result_events = await db.execute(
        select(SecurityEvent).order_by(SecurityEvent.timestamp.desc()).limit(100)
    )
    recent_events = result_events.scalars().all()
    
    # Alertes récentes
    result_alerts = await db.execute(
        select(Alert).order_by(Alert.timestamp.desc()).limit(50)
    )
    recent_alerts = result_alerts.scalars().all()
    
    return templates.TemplateResponse("security/dashboard.html", {
        "request": request,
        "user": user,
        "total_events": total_events,
        "critical_events": critical_events,
        "unresolved": unresolved,
        "locked_users": locked_users,
        "severity_counts": severity_counts,
        "recent_events": recent_events,
        "recent_alerts": recent_alerts
    })


@router.websocket("/ws/alerts")
async def websocket_alerts(websocket: WebSocket):
    """WebSocket pour les alertes en temps réel"""
    await ws_manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            # Keep-alive ping
            if data == "ping":
                await websocket.send_text(json.dumps({"type": "ping"}))
    except WebSocketDisconnect:
        await ws_manager.disconnect(websocket)


@router.post("/security/alerts/{alert_id}/resolve")
async def resolve_alert(alert_id: int, request: Request, db: AsyncSession = Depends(get_db)):
    """Résoudre une alerte"""
    user = await require_auth(request, db)
    
    if user.role not in [UserRole.security, UserRole.directeur]:
        raise HTTPException(status_code=403, detail="Accès réservé")
    
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()
    
    if not alert:
        raise HTTPException(status_code=404, detail="Alerte non trouvée")
    
    alert.resolved = True
    alert.resolved_at = datetime.utcnow()
    alert.resolved_by = user.username
    
    await db.commit()
    
    return RedirectResponse(url="/security/dashboard", status_code=303)


@router.post("/security/users/{user_id}/toggle-lock")
async def security_toggle_lock(user_id: int, request: Request, db: AsyncSession = Depends(get_db)):
    """Verrouiller ou déverrouiller un compte (SOC)"""
    user_sec = await require_roles(request, db, UserRole.security, UserRole.directeur)
    
    result = await db.execute(select(User).where(User.id == user_id))
    u = result.scalar_one_or_none()
    if not u:
        raise HTTPException(status_code=404, detail="Utilisateur non trouvé")
        
    # On ne peut pas se verrouiller soi-même via cette route
    if u.id == user_sec.id:
        raise HTTPException(status_code=400, detail="Action impossible sur soi-même")
        
    u.is_locked = not u.is_locked
    action = "verrouillé" if u.is_locked else "déverrouillé"
    if not u.is_locked:
        u.failed_attempts = 0
        
    await db.commit()
    
    # Émettre un événement de sécurité car une action manuelle a été prise
    await event_manager.emit(
        EventType.LOGIN_LOCKED if u.is_locked else EventType.PASSWORD_CHANGED,
        {
            "username": u.username,
            "ip": request.client.host,
            "description": f"Compte {action} manuellement par {user_sec.username}",
            "operator": user_sec.username
        }
    )
    
    return RedirectResponse(url="/security/users", status_code=303)


@router.get("/security/users", response_class=HTMLResponse)
async def security_users_list(request: Request, db: AsyncSession = Depends(get_db)):
    """Liste des comptes pour gestion SOC"""
    user = await require_roles(request, db, UserRole.security, UserRole.directeur)
    
    result = await db.execute(select(User).order_by(User.created_at.desc()))
    users = result.scalars().all()
    
    return templates.TemplateResponse("security/users.html", {
        "request": request,
        "user": user,
        "users": users
    })


@router.get("/api/stats")
async def get_stats(db: AsyncSession = Depends(get_db)):
    """API pour récupérer les stats (fallback si WS mort)"""
    result = await db.execute(text("SELECT COUNT(*) FROM security_events"))
    total_events = result.scalar()
    
    result = await db.execute(text("SELECT COUNT(*) FROM alerts WHERE resolved = false"))
    unresolved_alerts = result.scalar()
    
    result = await db.execute(text("SELECT COUNT(*) FROM users WHERE is_locked = true"))
    locked_users = result.scalar()
    
    return {
        "total_events": total_events,
        "unresolved_alerts": unresolved_alerts,
        "locked_users": locked_users
    }