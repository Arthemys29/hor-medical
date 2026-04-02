"""
Logging Service - Service utilitaire pour la journalisation structurée.
Centralise la configuration et l'utilisation du logging pour toute l'application.
"""
from __future__ import annotations
import logging
import sys
from pathlib import Path
from typing import Optional


class SecurityLogger:
    """Logger spécialisé pour les événements de sécurité"""
    
    def __init__(self, name: str = "security", log_file: Optional[str] = None):
        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging.INFO)
        
        # Format des logs
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        
        # Handler console
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging.INFO)
        console_handler.setFormatter(formatter)
        self.logger.addHandler(console_handler)
        
        # Handler fichier (si spécifié)
        if log_file:
            log_path = Path(log_file)
            log_path.parent.mkdir(parents=True, exist_ok=True)
            file_handler = logging.FileHandler(log_file, encoding='utf-8')
            file_handler.setLevel(logging.DEBUG)
            file_handler.setFormatter(formatter)
            self.logger.addHandler(file_handler)
    
    def log_event(self, event_type: str, username: str, ip: str, 
                  severity: str, description: str, **kwargs):
        """Journaliser un événement de sécurité"""
        level = getattr(logging, severity.upper(), logging.INFO)
        
        extra_info = " | ".join(f"{k}={v}" for k, v in kwargs.items() if v)
        message = (
            f"[{event_type.upper()}] user={username} | ip={ip} | "
            f"severity={severity} | {description}"
            f"{f' | {extra_info}' if extra_info else ''}"
        )
        
        self.logger.log(level, message)
    
    def info(self, message: str, **kwargs):
        """Log niveau INFO"""
        self.log_event("INFO", "system", "localhost", "info", message, **kwargs)
    
    def warning(self, message: str, **kwargs):
        """Log niveau WARNING"""
        self.log_event("WARNING", "system", "localhost", "warning", message, **kwargs)
    
    def error(self, message: str, **kwargs):
        """Log niveau ERROR"""
        self.log_event("ERROR", "system", "localhost", "error", message, **kwargs)
    
    def critical(self, message: str, **kwargs):
        """Log niveau CRITICAL"""
        self.log_event("CRITICAL", "system", "localhost", "critical", message, **kwargs)
    
    def security_event(self, event_type: str, username: str, ip: str,
                       severity: str, description: str, **kwargs):
        """Alias pour log_event avec nom plus explicite"""
        self.log_event(event_type, username, ip, severity, description, **kwargs)


# Instance globale
_security_logger: Optional[SecurityLogger] = None


def get_security_logger(log_file: str = "logs/security.log") -> SecurityLogger:
    """Obtenir ou créer le logger de sécurité"""
    global _security_logger
    if _security_logger is None:
        _security_logger = SecurityLogger(log_file=log_file)
    return _security_logger


def log_security_event(event_type: str, username: str, ip: str,
                       severity: str, description: str, **kwargs):
    """Fonction utilitaire pour logger rapidement un événement"""
    logger = get_security_logger()
    logger.security_event(event_type, username, ip, severity, description, **kwargs)