from __future__ import annotations
from enum import Enum


class EventType(str, Enum):
    # ── Authentification
    LOGIN_SUCCESS = "login_success"
    LOGIN_FAILED = "login_failed"
    LOGIN_LOCKED = "login_locked"
    LOGIN_UNKNOWN_USER = "login_unknown_user"
    LOGOUT = "logout"
    PASSWORD_CHANGED = "password_changed"

    # ── Autorisation
    ACCESS_DENIED = "access_denied"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    UNAUTHORIZED_PATIENT_ACCESS = "unauthorized_patient_access"

    # ── Attaques
    SQL_INJECTION = "sql_injection_attempt"
    BRUTE_FORCE = "brute_force_detected"
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"
    IP_ENUMERATION = "ip_enumeration"
    SUSPICIOUS_URL = "suspicious_url"
    SPECIAL_CHARS_INPUT = "special_chars_input"

    # ── Données sensibles
    SENSITIVE_DATA_READ = "sensitive_data_read"
    SENSITIVE_DATA_MASS_READ = "sensitive_data_mass_read"
    UNAUTHORIZED_MODIFICATION = "unauthorized_modification"

    # ── Applicatifs
    OOH_ACCESS = "out_of_hours_access"      # Out-of-hours
    USER_CREATED = "user_created"
    PATIENT_CREATED = "patient_created"
    CONSULTATION_CREATED = "consultation_created"


# Mapping EventType → Severity
EVENT_SEVERITY = {
    EventType.LOGIN_SUCCESS: "low",
    EventType.LOGIN_FAILED: "medium",
    EventType.LOGIN_LOCKED: "high",
    EventType.LOGIN_UNKNOWN_USER: "medium",
    EventType.LOGOUT: "low",
    EventType.PASSWORD_CHANGED: "medium",
    EventType.ACCESS_DENIED: "high",
    EventType.PRIVILEGE_ESCALATION: "critical",
    EventType.UNAUTHORIZED_PATIENT_ACCESS: "critical",
    EventType.SQL_INJECTION: "critical",
    EventType.BRUTE_FORCE: "critical",
    EventType.RATE_LIMIT_EXCEEDED: "medium",
    EventType.IP_ENUMERATION: "high",
    EventType.SUSPICIOUS_URL: "high",
    EventType.SPECIAL_CHARS_INPUT: "medium",
    EventType.SENSITIVE_DATA_READ: "medium",
    EventType.SENSITIVE_DATA_MASS_READ: "critical",
    EventType.UNAUTHORIZED_MODIFICATION: "critical",
    EventType.OOH_ACCESS: "high",
    EventType.USER_CREATED: "low",
    EventType.PATIENT_CREATED: "low",
    EventType.CONSULTATION_CREATED: "low",
}

# Which events trigger alerts and at what level
EVENT_ALERT_LEVEL = {
    EventType.ACCESS_DENIED: "low",
    EventType.LOGIN_FAILED: None,          # handled dynamically (after 3 fails)
    EventType.BRUTE_FORCE: "medium",
    EventType.LOGIN_LOCKED: "medium",
    EventType.SQL_INJECTION: "high",
    EventType.PRIVILEGE_ESCALATION: "high",
    EventType.SUSPICIOUS_URL: "medium",
    EventType.RATE_LIMIT_EXCEEDED: "medium",
    EventType.IP_ENUMERATION: "high",
    EventType.SENSITIVE_DATA_MASS_READ: "critical",
    EventType.UNAUTHORIZED_MODIFICATION: "critical",
    EventType.OOH_ACCESS: "medium",
    EventType.UNAUTHORIZED_PATIENT_ACCESS: "high",
}