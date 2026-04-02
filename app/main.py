from __future__ import annotations
from fastapi import FastAPI, Request, Depends
from fastapi.exceptions import HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
import logging
import os

from app.routes import auth_routes, patient_routes, admin_routes, security_routes
from app.middleware.security_middleware import SecurityMiddleware
from app.events.event_manager import event_manager
from app.events.event_handlers import register_handlers
from app.database.connection import init_db, get_db
from app.auth.auth import require_auth
from app.database.models import User, UserRole

# Configuration du logging
os.makedirs('logs', exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/security.log'),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)

app = FastAPI(title="Secure Medical Monitor - Hôpital", version="1.0.0")

# Middleware
app.add_middleware(SecurityMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Inclusion des routes
app.include_router(auth_routes.router)
app.include_router(patient_routes.router)
app.include_router(admin_routes.router)
app.include_router(security_routes.router)

# Enregistrement des handlers
register_handlers(event_manager)

# Templates avec debug activé pour afficher les erreurs détaillées
templates = Jinja2Templates(directory="app/templates")
templates.env.auto_reload = True  # Recharge automatique des templates
templates.env.globals['debug'] = True  # Active le mode debug


@app.get("/", response_class=HTMLResponse)
async def root(request: Request, db: AsyncSession = Depends(get_db)):
    """Redirection vers login ou dashboard"""
    from app.auth.auth import decode_token
    
    token = request.cookies.get("access_token")
    if token:
        payload = decode_token(token)
        if payload:
            username = payload.get("sub")
            if username:
                result = await db.execute(select(User).where(User.username == username))
                user = result.scalar_one_or_none()
                if user and not user.is_locked:
                    # Rediriger selon le rôle
                    if user.role == UserRole.directeur:
                        return RedirectResponse(url="/admin/dashboard", status_code=303)
                    elif user.role == UserRole.security:
                        return RedirectResponse(url="/security/dashboard", status_code=303)
                    elif user.role == UserRole.infirmier:
                        return RedirectResponse(url="/dashboard/infirmier", status_code=303)
    
    return RedirectResponse(url="/login", status_code=303)


@app.exception_handler(401)
async def unauthorized_handler(request: Request, exc: HTTPException):
    """Erreur 401 - Non authentifié"""
    return HTMLResponse(
        status_code=401,
        content=error_page_html("401 - Non authentifié", "Veuillez vous connecter pour accéder à cette ressource.")
    )


@app.exception_handler(403)
async def forbidden_handler(request: Request, exc: HTTPException):
    """Erreur 403 - Accès interdit"""
    return HTMLResponse(
        status_code=403,
        content=error_page_html("403 - Accès interdit", "Vous n'avez pas les autorisations nécessaires.")
    )


@app.exception_handler(404)
async def not_found_handler(request: Request, exc: HTTPException):
    """Erreur 404 - Page non trouvée"""
    return HTMLResponse(
        status_code=404,
        content=error_page_html("404 - Page non trouvée", "La page demandée n'existe pas.")
    )


def error_page_html(title: str, message: str) -> str:
    """Générateur de pages d'erreur"""
    return f"""
    <!DOCTYPE html>
    <html lang="fr">
    <head>
        <meta charset="UTF-8">
        <title>{title}</title>
        <style>
            body {{ 
                font-family: 'Segoe UI', system-ui, sans-serif; 
                background: linear-gradient(135deg, #f0f7ff 0%, #e8f4fd 100%);
                min-height: 100vh; 
                display: flex; 
                align-items: center; 
                justify-content: center; 
                margin: 0; 
            }}
            .card {{ 
                background: white; 
                padding: 50px; 
                border-radius: 20px; 
                box-shadow: 0 20px 60px rgba(0,0,0,0.15); 
                text-align: center; 
                max-width: 500px; 
            }}
            h1 {{ color: #1e293b; margin-bottom: 15px; font-size: 2em; }}
            p {{ color: #64748b; line-height: 1.6; font-size: 1.1em; }}
            .icon {{ 
                width: 80px; height: 80px; 
                margin: 0 auto 25px;
                background: linear-gradient(135deg, #1558a0, #1d6fb8);
                border-radius: 50%;
                display: flex;
                align-items: center;
                justify-content: center;
                color: white;
                font-size: 40px;
            }}
            .btn {{
                display: inline-block;
                margin-top: 25px;
                padding: 12px 30px;
                background: linear-gradient(135deg, #1558a0, #1d6fb8);
                color: white;
                text-decoration: none;
                border-radius: 12px;
                font-weight: 600;
                transition: all 0.2s;
            }}
            .btn:hover {{ transform: translateY(-2px); box-shadow: 0 8px 20px rgba(21,88,160,0.4); }}
        </style>
    </head>
    <body>
        <div class="card">
            <div class="icon">🔒</div>
            <h1>{title}</h1>
            <p>{message}</p>
            <a href="/" class="btn">Retour</a>
        </div>
    </body>
    </html>
    """


@app.on_event("startup")
async def startup_event():
    """Initialisation de la base de données au démarrage"""
    logger.info("Initialisation de la base de données...")
    await init_db()
    logger.info("Application démarrée avec succès")


@app.on_event("shutdown")
async def shutdown_event():
    logger.info("Application arrêtée")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)