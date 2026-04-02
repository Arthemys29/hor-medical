"""
Logging Service - Service utilitaire pour la journalisation structurée.
Centralise la configuration et l'utilisation du logging pour toute l'application.
"""
from __future__ import annotations
import logging
import sys
import os
from pathlib import Path
from typing import Optional, Any, Dict


class SecurityLogger:
    """Logger spécialisé pour les événements de sécurité"""
    
    # Mapping des sévérités applicatives vers les niveaux de logging standard
    LEVEL_MAPPING = {
        "low": logging.INFO,
        "medium": logging.WARNING,
        "high": logging.ERROR,
        "critical": logging.CRITICAL
    }
    
    def __init__(self, name: str = "security", log_file: Optional[str] = "logs/security.log"):
        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging.DEBUG)
        
        # Éviter de rajouter des handlers si déjà présents
        if not self.logger.handlers:
            # Format des logs structuré et lisible
            formatter = logging.Formatter(
                '%(asctime)s | %(levelname)-8s | [%(name)s] | %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S'
            )
            
            # Handler console
            console_handler = logging.StreamHandler(sys.stdout)
            console_handler.setLevel(logging.INFO)
            console_handler.setFormatter(formatter)
            self.logger.addHandler(console_handler)
            
            # Handler fichier
            if log_file:
                log_path = Path(log_file)
                log_path.parent.mkdir(parents=True, exist_ok=True)
                file_handler = logging.FileHandler(log_file, encoding='utf-8')
                file_handler.setLevel(logging.DEBUG)
                file_handler.setFormatter(formatter)
                self.logger.addHandler(file_handler)
    
    def log_event(self, event_type: str, username: str, ip: str, 
                  severity: str, description: str, **kwargs):
        """Journaliser un événement de sécurité de manière structurée"""
        level = self.LEVEL_MAPPING.get(severity.lower(), logging.INFO)
        
        # Préparation des infos additionnelles
        extra_info = ""
        if kwargs:
            extra_info = " | " + " | ".join(f"{k}={v}" for k, v in kwargs.items() if v is not None)
        
        message = (
            f"EVENT={event_type.upper()} | USER={username} | IP={ip} | "
            f"SEVERITY={severity.upper()} | DESC={description}"
            f"{extra_info}"
        )
        
        self.logger.log(level, message)
    
    def info(self, message: str, **kwargs):
        self.log_event("INFO", "system", "127.0.0.1", "low", message, **kwargs)
    
    def warning(self, message: str, **kwargs):
        self.log_event("WARNING", "system", "127.0.0.1", "medium", message, **kwargs)
    
    def error(self, message: str, **kwargs):
        self.log_event("ERROR", "system", "127.0.0.1", "high", message, **kwargs)
    
    def critical(self, message: str, **kwargs):
        self.log_event("CRITICAL", "system", "127.0.0.1", "critical", message, **kwargs)


# Instance globale unique
_security_logger: Optional[SecurityLogger] = None


def get_security_logger() -> SecurityLogger:
    """Obtenir l'instance unique du logger de sécurité"""
    global _security_logger
    if _security_logger is None:
        _security_logger = SecurityLogger()
    return _security_logger


def log_security_event(event_type: str, username: str, ip: str,
                       severity: str, description: str, **kwargs):
    """Fonction utilitaire principale pour journaliser un événement de sécurité"""
    logger = get_security_logger()
    # On supporte aussi le passage direct d'un EventType
    event_str = event_type.value if hasattr(event_type, 'value') else str(event_type)
    logger.log_event(event_str, username, ip, severity, description, **kwargs)