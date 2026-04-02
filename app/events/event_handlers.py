"""
Event Handlers — logique de traitement des événements de sécurité.
Chaque handler :
  1. Persiste l'événement en base (security_events)
  2. Génère une alerte si nécessaire (alerts)
  3. Broadcast l'alerte via WebSocket
  4. Journalise dans le fichier log
"""
from __future__ import annotations
import logging
from datetime import datetime
from collections import defaultdict
from typing import Dict, Any, List, Tuple
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func as sqlfunc

from app.database.connection import AsyncSessionLocal
from app.database.models import SecurityEvent, Alert, Severity, AlertLevel, User
from app.events.event_types import EventType, EVENT_SEVERITY, EVENT_ALERT_LEVEL
from app.services.logging_service import log_security_event
from app.config import settings

# On garde le logger standard pour les logs internes du module si besoin
logger = logging.getLogger("security")

# ─── Compteurs en mémoire (rate limiters) ─────────────────────────────────────
# Structure: {username: [(timestamp, count)]}
_failed_login_tracker: Dict[str, List[datetime]] = defaultdict(list)
# Structure: {ip: [(timestamp, username)]}
_ip_username_tracker: Dict[str, List[Tuple[datetime, str]]] = defaultdict(list)
# Structure: {username: [timestamp]}
_sensitive_reads_tracker: Dict[str, List[datetime]] = defaultdict(list)


async def _persist_event(
    event_type: EventType,
    data: Dict[str, Any],
    severity: str,
    action_taken: str = "",
) -> int:
    """Persiste l'événement en base et renvoie l'id."""
    async with AsyncSessionLocal() as db:
        event = SecurityEvent(
            timestamp=datetime.utcnow(),
            username=data.get("username"),
            ip_address=data.get("ip"),
            event_type=event_type.value,
            severity=severity,
            description=data.get("description", ""),
            status="detected",
            action_taken=action_taken,
        )
        db.add(event)
        await db.commit()
        await db.refresh(event)
        
        # Diffusion en temps réel
        from app.services.ws_manager import ws_manager
        await ws_manager.broadcast_event({
            "id": event.id,
            "timestamp": event.timestamp.isoformat(),
            "event_type": event.event_type,
            "username": event.username,
            "ip": event.ip_address,
            "severity": event.severity.value if hasattr(event.severity, 'value') else event.severity,
            "description": event.description
        })
        
        return event.id


async def _create_alert(level: str, message: str, source_event_id: int):
    """Crée une alerte en base et la diffuse via WebSocket."""
    from app.services.ws_manager import ws_manager

    async with AsyncSessionLocal() as db:
        alert = Alert(
            timestamp=datetime.utcnow(),
            alert_level=level,
            source_event_id=source_event_id,
            message=message,
            resolved=False,
        )
        db.add(alert)
        await db.commit()
        await db.refresh(alert)

    # Broadcast immédiat
    await ws_manager.broadcast_alert({
        "id": alert.id,
        "timestamp": alert.timestamp.isoformat(),
        "alert_level": level,
        "message": message,
        "source_event_id": source_event_id,
        "resolved": False,
    })
    return alert.id


# ─── Handler global : journalisation fichier ──────────────────────────────────

async def handle_log_all(event_type: EventType, data: Dict[str, Any]):
    """Journalise tous les événements dans le fichier log via le service dédié."""
    severity = EVENT_SEVERITY.get(event_type, "low")
    
    # On extrait les données utiles pour le logging
    username = data.get("username", "?")
    ip = data.get("ip", "?")
    description = data.get("description", "")
    
    # On passe le reste en kwargs pour le logging structuré
    kwargs = {k: v for k, v in data.items() if k not in ["username", "ip", "description", "event_type"]}
    
    log_security_event(
        event_type=event_type,
        username=username,
        ip=ip,
        severity=severity,
        description=description,
        **kwargs
    )


# ─── Handlers spécifiques ──────────────────────────────────────────────────────

async def handle_login_success(event_type: EventType, data: Dict[str, Any]):
    severity = EVENT_SEVERITY.get(event_type, "low")
    await _persist_event(event_type, data, severity, "Session ouverte")


async def handle_login_failed(event_type: EventType, data: Dict[str, Any]):
    """
    Règle 1 : 3 échecs en < 2 min → alerte moyenne + verrouillage.
    Règle 5 : même IP, plusieurs usernames → alerte énumération.
    """
    username = data.get("username", "?")
    ip = data.get("ip", "?")
    now = datetime.utcnow()

    # Nettoyage fenêtre temporelle (2 min)
    window = settings.FAILED_ATTEMPTS_WINDOW
    _failed_login_tracker[username] = [
        t for t in _failed_login_tracker[username]
        if (now - t).total_seconds() < window
    ]
    _failed_login_tracker[username].append(now)

    count = len(_failed_login_tracker[username])
    data["description"] = (
        f"Échec connexion pour '{username}' depuis {ip} "
        f"({count} tentative(s) sur {window}s)"
    )

    severity = EVENT_SEVERITY.get(event_type, "medium")
    event_id = await _persist_event(event_type, data, severity)

    if count >= settings.MAX_FAILED_ATTEMPTS:
        # Verrouillage du compte
        await _lock_user(username)
        lock_severity = EVENT_SEVERITY.get(EventType.LOGIN_LOCKED, "high")
        lock_event_id = await _persist_event(
            EventType.LOGIN_LOCKED,
            {**data, "description": f"Compte '{username}' verrouillé après {count} échecs"},
            lock_severity,
            "Compte verrouillé"
        )
        await _create_alert(
            "medium",
            f"🔒 Brute-force détecté : compte '{username}' verrouillé après {count} tentatives depuis {ip}",
            lock_event_id
        )
        _failed_login_tracker[username].clear()

    # Règle 5 : énumération IP
    _ip_username_tracker[ip] = [
        (t, u) for t, u in _ip_username_tracker[ip]
        if (now - t).total_seconds() < 300
    ]
    _ip_username_tracker[ip].append((now, username))
    unique_users = {u for _, u in _ip_username_tracker[ip]}
    if len(unique_users) >= 5:
        enum_severity = EVENT_SEVERITY.get(EventType.IP_ENUMERATION, "high")
        enum_event_id = await _persist_event(
            EventType.IP_ENUMERATION,
            {**data, "description": f"IP {ip} a tenté {len(unique_users)} comptes différents"},
            enum_severity,
            "IP surveillée"
        )
        await _create_alert(
            "high",
            f"🕵️ Énumération d'identifiants depuis {ip} — {len(unique_users)} comptes testés",
            enum_event_id
        )
        _ip_username_tracker[ip].clear()


async def handle_login_unknown(event_type: EventType, data: Dict[str, Any]):
    severity = EVENT_SEVERITY.get(event_type, "medium")
    await _persist_event(event_type, data, severity, "")


async def handle_access_denied(event_type: EventType, data: Dict[str, Any]):
    severity = EVENT_SEVERITY.get(event_type, "high")
    event_id = await _persist_event(event_type, data, severity, "Requête rejetée 403")
    await _create_alert(
        "low",
        f"🚫 Accès refusé : {data.get('username','?')} → {data.get('path','?')} depuis {data.get('ip','?')}",
        event_id
    )


async def handle_sql_injection(event_type: EventType, data: Dict[str, Any]):
    severity = EVENT_SEVERITY.get(event_type, "critical")
    event_id = await _persist_event(event_type, data, severity, "Requête bloquée")
    await _create_alert(
        "high",
        f"💉 Injection SQL détectée depuis {data.get('ip','?')} | Payload: {data.get('payload','?')[:80]}",
        event_id
    )


async def handle_privilege_escalation(event_type: EventType, data: Dict[str, Any]):
    severity = EVENT_SEVERITY.get(event_type, "critical")
    event_id = await _persist_event(event_type, data, severity, "Tentative bloquée")
    await _create_alert(
        "high",
        f"⬆️ Tentative d'élévation de privilège : {data.get('username','?')} → {data.get('path','?')}",
        event_id
    )


async def handle_rate_limit(event_type: EventType, data: Dict[str, Any]):
    severity = EVENT_SEVERITY.get(event_type, "medium")
    event_id = await _persist_event(event_type, data, severity, "IP throttlée")
    await _create_alert(
        "medium",
        f"⚡ Taux de requêtes anormal depuis {data.get('ip','?')} ({data.get('count','?')} req/min)",
        event_id
    )


async def handle_sensitive_data_read(event_type: EventType, data: Dict[str, Any]):
    """
    Règle 4 : >20 consultations en <1 min → alerte critique.
    """
    username = data.get("username", "?")
    now = datetime.utcnow()

    _sensitive_reads_tracker[username] = [
        t for t in _sensitive_reads_tracker[username]
        if (now - t).total_seconds() < 60
    ]
    _sensitive_reads_tracker[username].append(now)
    count = len(_sensitive_reads_tracker[username])

    data["description"] = (
        f"Lecture données sensibles par '{username}' ({count} en 60s)"
    )
    severity = EVENT_SEVERITY.get(event_type, "medium")
    event_id = await _persist_event(event_type, data, severity)

    if count >= settings.SENSITIVE_DATA_THRESHOLD:
        mass_severity = EVENT_SEVERITY.get(EventType.SENSITIVE_DATA_MASS_READ, "critical")
        mass_id = await _persist_event(
            EventType.SENSITIVE_DATA_MASS_READ,
            {**data, "description": f"Exfiltration massive par '{username}': {count} dossiers/min"},
            mass_severity,
            "Session auditée"
        )
        await _create_alert(
            "critical",
            f"🚨 EXFILTRATION MASSIVE : '{username}' a consulté {count} dossiers en moins d'une minute !",
            mass_id
        )
        _sensitive_reads_tracker[username].clear()


async def handle_ooh_access(event_type: EventType, data: Dict[str, Any]):
    severity = EVENT_SEVERITY.get(event_type, "high")
    event_id = await _persist_event(event_type, data, severity, "Accès hors horaires enregistré")
    await _create_alert(
        "medium",
        f"🕐 Accès hors horaires ({data.get('hour','?')}h) par '{data.get('username','?')}'",
        event_id
    )


async def handle_suspicious_url(event_type: EventType, data: Dict[str, Any]):
    severity = EVENT_SEVERITY.get(event_type, "high")
    event_id = await _persist_event(event_type, data, severity, "Requête rejetée")
    await _create_alert(
        "medium",
        f"🔍 URL suspecte accédée depuis {data.get('ip','?')} : {data.get('path','?')}",
        event_id
    )


async def handle_generic(event_type: EventType, data: Dict[str, Any]):
    severity = EVENT_SEVERITY.get(event_type, "low")
    alert_level = EVENT_ALERT_LEVEL.get(event_type)
    event_id = await _persist_event(event_type, data, severity)
    if alert_level:
        await _create_alert(alert_level, data.get("description", ""), event_id)


# ─── Helpers ──────────────────────────────────────────────────────────────────

async def _lock_user(username: str):
    from sqlalchemy import update
    async with AsyncSessionLocal() as db:
        await db.execute(
            update(User)
            .where(User.username == username)
            .values(is_locked=True, failed_attempts=0)
        )
        await db.commit()


# ─── Enregistrement des handlers ──────────────────────────────────────────────

def register_handlers(event_manager):
    from app.events.event_types import EventType as ET

    event_manager.on_any(handle_log_all)

    event_manager.on(ET.LOGIN_SUCCESS, handle_login_success)
    event_manager.on(ET.LOGIN_FAILED, handle_login_failed)
    event_manager.on(ET.LOGIN_UNKNOWN_USER, handle_login_unknown)
    event_manager.on(ET.ACCESS_DENIED, handle_access_denied)
    event_manager.on(ET.PRIVILEGE_ESCALATION, handle_privilege_escalation)
    event_manager.on(ET.SQL_INJECTION, handle_sql_injection)
    event_manager.on(ET.RATE_LIMIT_EXCEEDED, handle_rate_limit)
    event_manager.on(ET.SENSITIVE_DATA_READ, handle_sensitive_data_read)
    event_manager.on(ET.SENSITIVE_DATA_MASS_READ, handle_sensitive_data_read)
    event_manager.on(ET.OOH_ACCESS, handle_ooh_access)
    event_manager.on(ET.SUSPICIOUS_URL, handle_suspicious_url)
    event_manager.on(ET.IP_ENUMERATION, handle_generic)
    event_manager.on(ET.UNAUTHORIZED_PATIENT_ACCESS, handle_generic)