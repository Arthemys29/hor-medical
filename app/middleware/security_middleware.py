from __future__ import annotations
import re
import time
from collections import defaultdict
from typing import Dict, List, Tuple
from fastapi import Request, HTTPException
from fastapi.responses import HTMLResponse
from starlette.middleware.base import BaseHTTPMiddleware
from app.events.event_manager import event_manager
from app.events.event_types import EventType
import logging

logger = logging.getLogger("security")


class SecurityMiddleware(BaseHTTPMiddleware):
    """Middleware de sécurité pour détecter les attaques"""
    
    def __init__(self, app):
        super().__init__(app)
        # Rate limiting: {ip: [(timestamp, count)]}
        self._rate_limit_tracker: Dict[str, List[Tuple[float, int]]] = defaultdict(list)
    
    async def dispatch(self, request: Request, call_next):
        ip = request.client.host if request.client else "unknown"
        path = request.url.path
        
        # 1. Détection injection SQL dans les paramètres URL
        query_params = str(request.query_params)
        if self._check_sql_injection(query_params):
            await event_manager.emit(EventType.SQL_INJECTION, {
                "username": "anonymous",
                "ip": ip,
                "description": f"Injection SQL détectée dans les paramètres URL",
                "payload": query_params[:200],
                "path": path
            })
            return HTMLResponse(
                status_code=400,
                content=self._error_page("Requête suspecte détectée", "Une tentative d'injection SQL a été bloquée.")
            )
        
        # 2. Rate limiting
        if not await self._check_rate_limit(ip, request):
            await event_manager.emit(EventType.RATE_LIMIT_EXCEEDED, {
                "username": "anonymous",
                "ip": ip,
                "description": f"Rate limit dépassé - {request.method} {path}",
                "count": len(self._rate_limit_tracker[ip])
            })
            return HTMLResponse(
                status_code=429,
                content=self._error_page("Trop de requêtes", "Veuillez ralentir vos requêtes.")
            )
        
        # 3. URLs suspectes (scan de chemin)
        suspicious_patterns = [
            r"\.\./", r"%2e%2e/", r"\.\.%2f", r"%252e",  # Path traversal
            r"/wp-admin", r"/phpmyadmin", r"/\.php",  # CMS/admin scan externe
            r"/\.env", r"/\.git", r"/config\.",  # Fichier sensibles
            r"<script>", r"%3Cscript", r"javascript:",  # XSS
        ]
        for pattern in suspicious_patterns:
            if re.search(pattern, path, re.IGNORECASE):
                await event_manager.emit(EventType.SUSPICIOUS_URL, {
                    "username": "anonymous",
                    "ip": ip,
                    "description": f"URL suspecte accédée: {path}",
                    "path": path
                })
                break
        
        # Continuer vers le handler
        response = await call_next(request)
        return response
    
    def _check_sql_injection(self, value: str) -> bool:
        """Vérifier les motifs d'injection SQL"""
        if not value:
            return False
        
        sql_patterns = [
            r"(\bOR\b\s+\d+\s*=\s*\d+)",
            r"(\bAND\b\s+\d+\s*=\s*\d+)",
            r"(--\s*$)",
            r"(;\s*DROP\s+TABLE)",
            r"(\bUNION\b\s+\bSELECT\b)",
            r"(\bSELECT\b.*\bFROM\b)",
            r"(\bINSERT\b\s+\bINTO\b)",
            r"(\bDELETE\b\s+\bFROM\b)",
            r"(\bUPDATE\b.*\bSET\b)",
            r"(\bEXEC\b\s*\()",
            r"(\bTRUNCATE\b\s+\bTABLE\b)",
            r"('|\s*=\s*')",
        ]
        
        for pattern in sql_patterns:
            if re.search(pattern, value, re.IGNORECASE):
                return True
        return False
    
    async def _check_rate_limit(self, ip: str, request: Request) -> bool:
        """Vérifier le rate limiting (100 req/min)"""
        now = time.time()
        window = 60  # secondes
        max_requests = 100
        
        # Nettoyer anciennes entrées
        self._rate_limit_tracker[ip] = [
            (ts, cnt) for ts, cnt in self._rate_limit_tracker[ip]
            if now - ts < window
        ]
        
        # Ajouter nouvelle requête
        self._rate_limit_tracker[ip].append((now, 1))
        
        return len(self._rate_limit_tracker[ip]) <= max_requests
    
    def _error_page(self, title: str, message: str) -> str:
        """Page d'erreur personnalisée"""
        return f"""
        <!DOCTYPE html>
        <html lang="fr">
        <head>
            <meta charset="UTF-8">
            <title>{title}</title>
            <style>
                body {{ font-family: 'Segoe UI', sans-serif; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
                       min-height: 100vh; display: flex; align-items: center; justify-content: center; margin: 0; }}
                .card {{ background: white; padding: 40px; border-radius: 20px; box-shadow: 0 20px 60px rgba(0,0,0,0.3); 
                        text-align: center; max-width: 500px; }}
                h1 {{ color: #333; margin-bottom: 10px; }}
                p {{ color: #666; line-height: 1.6; }}
                .icon {{ font-size: 64px; margin-bottom: 20px; }}
            </style>
        </head>
        <body>
            <div class="card">
                <div class="icon">🚫</div>
                <h1>{title}</h1>
                <p>{message}</p>
            </div>
        </body>
        </html>
        """