from __future__ import annotations
from fastapi import APIRouter, Request, Form, Depends, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_
from datetime import datetime
import re

from app.database.connection import get_db
from app.database.models import Patient, Consultation, User, NiveauConfidentialite, Sexe, UserRole
from app.auth.auth import require_auth, require_roles
from app.events.event_manager import event_manager
from app.events.event_types import EventType

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")


async def check_sql_injection(value: str, request: Request, username: str):
    """Vérifier les tentatives d'injection SQL"""
    if not value:
        return False
    sql_patterns = [
        r"(\bOR\b.*=)", r"(\bAND\b.*=)", r"(--)", r"(\bDROP\b)",
        r"(\bUNION\b)", r"(\bSELECT\b)", r"(\bINSERT\b)", r"(\bDELETE\b)",
        r"(\bUPDATE\b)", r"(\bEXEC\b)", r"(\bTRUNCATE\b)"
    ]
    for pattern in sql_patterns:
        if re.search(pattern, value, re.IGNORECASE):
            await event_manager.emit(EventType.SQL_INJECTION, {
                "username": username,
                "ip": request.client.host,
                "description": f"Tentative injection SQL détectée",
                "payload": value[:100]
            })
            return True
    return False


@router.get("/dashboard")
async def dashboard_redirect(request: Request, db: AsyncSession = Depends(get_db)):
    """Rediriger vers le dashboard selon le rôle"""
    user = await require_auth(request, db)
    
    if user.role == UserRole.directeur:
        return RedirectResponse(url="/admin/dashboard", status_code=303)
    elif user.role == UserRole.security:
        return RedirectResponse(url="/security/dashboard", status_code=303)
    else:
        return RedirectResponse(url="/dashboard/infirmier", status_code=303)


@router.get("/dashboard/infirmier", response_class=HTMLResponse)
async def infirmier_dashboard(request: Request, db: AsyncSession = Depends(get_db)):
    """Tableau de bord infirmier"""
    from sqlalchemy import func as sqlfunc
    from sqlalchemy.orm import joinedload
    
    user = await require_auth(request, db)
    if user.role != UserRole.infirmier:
        raise HTTPException(status_code=403, detail="Accès réservé aux infirmiers")
    
    # Stats
    today_start = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
    
    today_cons = (await db.execute(
        select(sqlfunc.count(Consultation.id)).where(
            and_(Consultation.infirmier_id == user.id, Consultation.date_visite >= today_start)
        )
    )).scalar() or 0
    
    total_cons = (await db.execute(
        select(sqlfunc.count(Consultation.id)).where(Consultation.infirmier_id == user.id)
    )).scalar() or 0
    
    total_patients = (await db.execute(select(sqlfunc.count(Patient.id)))).scalar() or 0
    
    # Consultations récentes avec chargement des patients en une fois
    result = await db.execute(
        select(Consultation)
        .options(joinedload(Consultation.patient))
        .where(Consultation.infirmier_id == user.id)
        .order_by(Consultation.date_visite.desc())
        .limit(5)
    )
    consultations = result.scalars().all()
    
    recent_consultations = []
    for cons in consultations:
        recent_consultations.append({"consultation": cons, "patient": cons.patient})
    
    return templates.TemplateResponse("infirmier/dashboard.html", {
        "request": request,
        "user": user,
        "today_cons": today_cons,
        "total_cons": total_cons,
        "total_patients": total_patients,
        "recent_consultations": recent_consultations
    })


@router.get("/patients", response_class=HTMLResponse)
async def patients_list(request: Request, db: AsyncSession = Depends(get_db)):
    """Liste des patients"""
    user = await require_roles(request, db, UserRole.infirmier, UserRole.directeur)
    
    result = await db.execute(select(Patient).order_by(Patient.created_at.desc()))
    patients = result.scalars().all()
    
    return templates.TemplateResponse("patients/list.html", {
        "request": request,
        "user": user,
        "patients": patients
    })


@router.get("/patients/nouveau", response_class=HTMLResponse)
async def new_patient_page(request: Request, db: AsyncSession = Depends(get_db)):
    """Page nouveau patient"""
    user = await require_roles(request, db, UserRole.infirmier, UserRole.directeur)
    
    return templates.TemplateResponse("patients/new.html", {
        "request": request,
        "user": user
    })


@router.post("/patients/nouveau")
async def create_patient(
    request: Request,
    nom: str = Form(...),
    prenom: str = Form(...),
    date_naissance: str = Form(...),
    sexe: str = Form(...),
    adresse: str = Form(None),
    telephone: str = Form(None),
    db: AsyncSession = Depends(get_db),
):
    """Créer un nouveau patient"""
    user = await require_auth(request, db)
    ip = request.client.host
    
    # Vérifier injection SQL
    for field in [nom, prenom, adresse, telephone]:
        if await check_sql_injection(field, request, user.username):
            raise HTTPException(status_code=400, detail="Donnée invalide détectée")
    
    patient = Patient(
        nom=nom.upper(),
        prenom=prenom.capitalize(),
        date_naissance=date_naissance,
        sexe=Sexe(sexe),
        adresse=adresse,
        telephone=telephone
    )
    
    db.add(patient)
    await db.commit()
    
    await event_manager.emit(EventType.PATIENT_CREATED, {
        "username": user.username,
        "ip": ip,
        "description": f"Patient {prenom} {nom} créé"
    })
    
    return RedirectResponse(url="/patients", status_code=303)


@router.get("/patients/{patient_id}", response_class=HTMLResponse)
async def patient_detail(patient_id: int, request: Request, db: AsyncSession = Depends(get_db)):
    """Dossier patient"""
    user = await require_roles(request, db, UserRole.infirmier, UserRole.directeur)
    
    # Vérifier injection
    if await check_sql_injection(str(patient_id), request, user.username):
        raise HTTPException(status_code=400, detail="ID invalide")
    
    result = await db.execute(select(Patient).where(Patient.id == patient_id))
    patient = result.scalar_one_or_none()
    
    if not patient:
        raise HTTPException(status_code=404, detail="Patient non trouvé")
    
    # Historique consultations
    from sqlalchemy.orm import joinedload
    result = await db.execute(
        select(Consultation)
        .options(joinedload(Consultation.infirmier))
        .where(Consultation.patient_id == patient_id)
        .order_by(Consultation.date_visite.desc())
    )
    consultations = result.scalars().all()
    
    # Tracker lecture donnée sensible
    await event_manager.emit(EventType.SENSITIVE_DATA_READ, {
        "username": user.username,
        "ip": request.client.host,
        "description": f"Consultation dossier patient {patient.nom} {patient.prenom}"
    })
    
    return templates.TemplateResponse("patients/detail.html", {
        "request": request,
        "user": user,
        "patient": patient,
        "consultations": consultations
    })


@router.get("/patients/{patient_id}/consultation", response_class=HTMLResponse)
async def consultation_page(patient_id: int, request: Request, db: AsyncSession = Depends(get_db)):
    """Page de consultation pour un patient"""
    user = await require_roles(request, db, UserRole.infirmier)
    
    result = await db.execute(select(Patient).where(Patient.id == patient_id))
    patient = result.scalar_one_or_none()
    
    if not patient:
        raise HTTPException(status_code=404, detail="Patient non trouvé")
    
    return templates.TemplateResponse("patients/consultation.html", {
        "request": request,
        "user": user,
        "patient": patient
    })


@router.post("/patients/{patient_id}/consultation")
async def create_consultation(
    patient_id: int,
    request: Request,
    poids: float = Form(None),
    tension_arterielle: str = Form(None),
    temperature: float = Form(None),
    frequence_cardiaque: int = Form(None),
    saturation_o2: float = Form(None),
    diagnostic: str = Form(...),
    traitement: str = Form(...),
    observations: str = Form(None),
    niveau_confidentialite: str = Form("normal"),
    db: AsyncSession = Depends(get_db),
):
    """Enregistrer une consultation"""
    user = await require_roles(request, db, UserRole.infirmier)
    ip = request.client.host
    
    # Vérifier injection SQL
    for field in [diagnostic, traitement, observations]:
        if await check_sql_injection(field or "", request, user.username):
            raise HTTPException(status_code=400, detail="Donnée invalide détectée")
    
    consultation = Consultation(
        patient_id=patient_id,
        infirmier_id=user.id,
        poids=poids,
        tension_arterielle=tension_arterielle,
        temperature=temperature,
        frequence_cardiaque=frequence_cardiaque,
        saturation_o2=saturation_o2,
        diagnostic=diagnostic,
        traitement=traitement,
        observations=observations,
        niveau_confidentialite=NiveauConfidentialite(niveau_confidentialite)
    )
    
    db.add(consultation)
    await db.commit()
    
    await event_manager.emit(EventType.CONSULTATION_CREATED, {
        "username": user.username,
        "ip": ip,
        "description": f"Consultation créée pour patient #{patient_id}"
    })
    
    return RedirectResponse(url=f"/patients/{patient_id}", status_code=303)