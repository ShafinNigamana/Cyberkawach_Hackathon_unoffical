"""
Modular API Routers for Cyber Fraud Guardian.
"""

from backend.routes.analysis import analysis_router
from backend.routes.auth import auth_router
from backend.routes.incidents import incidents_router
from backend.routes.tools import tools_router
from backend.routes.verification import verification_router

__all__ = [
    "analysis_router",
    "auth_router",
    "incidents_router",
    "tools_router",
    "verification_router",
]
