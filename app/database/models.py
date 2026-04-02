from datetime import datetime
from sqlalchemy import (
    Column, Integer, String, Boolean, DateTime, Text,
    ForeignKey, Enum as SAEnum, Float, func
)
from sqlalchemy.orm import relationship
import enum
from app.database.connection import Base


class UserRole(str, enum.Enum):
    directeur = "directeur"
    security = "security"
    infirmier = "infirmier"


class Severity(str, enum.Enum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class AlertLevel(str, enum.Enum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class Sexe(str, enum.Enum):
    M = "M"
    F = "F"


class NiveauConfidentialite(str, enum.Enum):
    normal = "normal"
    confidentiel = "confidentiel"
    secret = "secret"


# ─── Users ───────────────────────────────────────────────────────────────────

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, nullable=False, index=True)
    full_name = Column(String(100), nullable=False)
    password_hash = Column(String(255), nullable=False)
    role = Column(SAEnum(UserRole, name='user_role', native_enum=True), nullable=False)
    is_locked = Column(Boolean, default=False)
    failed_attempts = Column(Integer, default=0)
    last_failed_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    created_by = Column(String(50), nullable=True)

    consultations = relationship("Consultation", back_populates="infirmier",
                                  foreign_keys="Consultation.infirmier_id")


# ─── Patients ─────────────────────────────────────────────────────────────────

class Patient(Base):
    __tablename__ = "patients"

    id = Column(Integer, primary_key=True, index=True)
    nom = Column(String(100), nullable=False)
    prenom = Column(String(100), nullable=False)
    date_naissance = Column(String(20), nullable=False)
    sexe = Column(SAEnum(Sexe, name='sexe_type', native_enum=True), nullable=False)
    adresse = Column(Text, nullable=True)
    telephone = Column(String(20), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    consultations = relationship("Consultation", back_populates="patient",
                                  cascade="all, delete-orphan")


# ─── Consultations (Dossier patient) ─────────────────────────────────────────

class Consultation(Base):
    __tablename__ = "consultations"

    id = Column(Integer, primary_key=True, index=True)
    patient_id = Column(Integer, ForeignKey("patients.id"), nullable=False)
    infirmier_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    date_visite = Column(DateTime, default=datetime.utcnow)
    poids = Column(Float, nullable=True)           # kg
    tension_arterielle = Column(String(20), nullable=True)  # ex: 120/80
    temperature = Column(Float, nullable=True)     # °C
    frequence_cardiaque = Column(Integer, nullable=True)   # bpm
    saturation_o2 = Column(Float, nullable=True)   # %
    diagnostic = Column(Text, nullable=False)
    traitement = Column(Text, nullable=False)
    observations = Column(Text, nullable=True)
    niveau_confidentialite = Column(SAEnum(NiveauConfidentialite, name='confidentialite_level', native_enum=True),
                                     default=NiveauConfidentialite.normal)
    created_at = Column(DateTime, default=datetime.utcnow)

    patient = relationship("Patient", back_populates="consultations")
    infirmier = relationship("User", back_populates="consultations",
                              foreign_keys=[infirmier_id])


# ─── Security Events ──────────────────────────────────────────────────────────

class SecurityEvent(Base):
    __tablename__ = "security_events"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    username = Column(String(100), nullable=True)
    ip_address = Column(String(45), nullable=True)
    event_type = Column(String(80), nullable=False, index=True)
    severity = Column(SAEnum(Severity, name='severity_level', native_enum=True), nullable=False, index=True)
    description = Column(Text, nullable=False)
    status = Column(String(50), default="detected")
    action_taken = Column(Text, nullable=True)

    alerts = relationship("Alert", back_populates="source_event")


# ─── Alerts ───────────────────────────────────────────────────────────────────

class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    alert_level = Column(SAEnum(AlertLevel, name='alert_level', native_enum=True), nullable=False, index=True)
    source_event_id = Column(Integer, ForeignKey("security_events.id"), nullable=True)
    message = Column(Text, nullable=False)
    resolved = Column(Boolean, default=False)
    resolved_at = Column(DateTime, nullable=True)
    resolved_by = Column(String(50), nullable=True)

    source_event = relationship("SecurityEvent", back_populates="alerts")