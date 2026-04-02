"""
Security Service - Services utilitaires pour la sécurité.
Fournit des fonctions de validation, détection et protection.
"""
from __future__ import annotations
import re
from typing import Optional, Dict, List
from datetime import datetime, timedelta


class SecurityValidator:
    """Service de validation et détection des attaques"""
    
    # Patterns SQL Injection
    SQL_INJECTION_PATTERNS = [
        r"(\bOR\b\s+\d+\s*=\s*\d+)",           # OR 1=1
        r"(\bAND\b\s+\d+\s*=\s*\d+)",          # AND 1=1
        r"(--\s*$)",                            # Commentaire SQL
        r"(;\s*DROP\s+TABLE)",                 # DROP TABLE
        r"(\bUNION\b\s+\bSELECT\b)",           # UNION SELECT
        r"(\bSELECT\b.*\bFROM\b)",             # SELECT FROM
        r"(\bINSERT\b\s+\bINTO\b)",            # INSERT INTO
        r"(\bDELETE\b\s+\bFROM\b)",            # DELETE FROM
        r"(\bUPDATE\b.*\bSET\b)",              # UPDATE SET
        r"(\bEXEC\b\s*\()",                    # EXEC()
        r"(\bTRUNCATE\b\s+\bTABLE\b)",         # TRUNCATE TABLE
        r"('|\s*=\s*')",                       # Quotes
        r"(\bDECLARE\b\s+@\w+)",               # DECLARE @variable
        r"(\bWAITFOR\b\s+\bDELAY\b)",          # WAITFOR DELAY
        r"(\bBENCHMARK\b\s*\()",               # BENCHMARK()
        r"(\bSLEEP\b\s*\()",                   # SLEEP()
    ]
    
    # Patterns XSS
    XSS_PATTERNS = [
        r"<script[^>]*>",                      # <script>
        r"</script>",                          # </script>
        r"javascript:",                        # javascript:
        r"on\w+\s*=",                          # onclick=, onload=, etc.
        r"<iframe[^>]*>",                      # <iframe>
        r"<object[^>]*>",                      # <object>
        r"<embed[^>]*>",                       # <embed>
        r"<img[^>]+onerror",                   # <img onerror
    ]
    
    # Patterns Path Traversal
    PATH_TRAVERSAL_PATTERNS = [
        r"\.\./",                              # ../
        r"\.\.\\",                             # ..\
        r"%2e%2e%2f",                          # URL encoded ../
        r"%252e%252e%252f",                    # Double URL encoded
        r"\.\.%2f",                            # ..%2f
        r"%2e%2e/",                            # %2e%2e/
    ]
    
    @classmethod
    def check_sql_injection(cls, value: str) -> bool:
        """
        Vérifier si une valeur contient des motifs d'injection SQL
        Returns: True si injection détectée
        """
        if not value:
            return False
        
        for pattern in cls.SQL_INJECTION_PATTERNS:
            if re.search(pattern, value, re.IGNORECASE):
                return True
        return False
    
    @classmethod
    def check_xss(cls, value: str) -> bool:
        """
        Vérifier si une valeur contient des motifs XSS
        Returns: True si XSS détecté
        """
        if not value:
            return False
        
        for pattern in cls.XSS_PATTERNS:
            if re.search(pattern, value, re.IGNORECASE):
                return True
        return False
    
    @classmethod
    def check_path_traversal(cls, path: str) -> bool:
        """
        Vérifier si un chemin contient des motifs de traversal
        Returns: True si traversal détecté
        """
        if not path:
            return False
        
        for pattern in cls.PATH_TRAVERSAL_PATTERNS:
            if re.search(pattern, path, re.IGNORECASE):
                return True
        return False
    
    @classmethod
    def sanitize_input(cls, value: str) -> str:
        """
        Nettoyer une entrée utilisateur
        Supprime les caractères dangereux
        """
        if not value:
            return ""
        
        # Échapper les caractères spéciaux HTML
        value = value.replace("<", "&lt;")
        value = value.replace(">", "&gt;")
        value = value.replace("'", "''")
        value = value.replace("\"", "\\\"")
        
        return value.strip()
    
    @classmethod
    def validate_username(cls, username: str) -> bool:
        """Valider un nom d'utilisateur (alphanumérique + underscore)"""
        if not username or len(username) < 3 or len(username) > 50:
            return False
        return bool(re.match(r'^[a-zA-Z0-9_]+$', username))
    
    @classmethod
    def validate_password_strength(cls, password: str) -> Dict[str, any]:
        """
        Valider la force d'un mot de passe
        Returns: dict avec score et détails
        """
        score = 0
        details = {
            'length': len(password) >= 8,
            'uppercase': bool(re.search(r'[A-Z]', password)),
            'lowercase': bool(re.search(r'[a-z]', password)),
            'numbers': bool(re.search(r'[0-9]', password)),
            'special': bool(re.search(r'[^A-Za-z0-9]', password)),
        }
        
        score = sum(details.values())
        
        strength = 'Faible'
        if score >= 5:
            strength = 'Excellent'
        elif score >= 4:
            strength = 'Bon'
        elif score >= 3:
            strength = 'Moyen'
        
        return {
            'score': score,
            'strength': strength,
            'details': details,
            'valid': score >= 3
        }
    
    @classmethod
    def is_out_of_hours(cls, hour: int, start_hour: int = 6, end_hour: int = 22) -> bool:
        """Vérifier si l'heure est en dehors des heures normales"""
        return hour < start_hour or hour >= end_hour
    
    @classmethod
    def get_current_hour(cls) -> int:
        """Obtenir l'heure actuelle"""
        return datetime.now().hour


# Instance globale pour usage rapide
security_validator = SecurityValidator()


# Fonctions utilitaires rapides
def check_sql_injection(value: str) -> bool:
    """Vérifier rapidement une injection SQL"""
    return SecurityValidator.check_sql_injection(value)


def check_xss(value: str) -> bool:
    """Vérifier rapidement une attaque XSS"""
    return SecurityValidator.check_xss(value)


def validate_password(password: str) -> Dict[str, any]:
    """Valider rapidement un mot de passe"""
    return SecurityValidator.validate_password_strength(password)