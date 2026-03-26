"""
manager/api/routers.py — Top-level API router aggregating all sub-routers.
"""

from fastapi import APIRouter

from manager.api.auth     import router as auth_router
from manager.api.stream   import router as stream_router
from manager.api.sessions import router as sessions_router
from manager.api.events   import router as events_router
from manager.api.sensors  import router as sensors_router
from manager.api.health   import router as health_router
from manager.api.iocs      import router as iocs_router
from manager.api.attackers import router as attackers_router
from manager.api.admin.users        import router as users_router
from manager.api.admin.system       import router as system_router
from manager.api.admin.smtp         import router as smtp_router
from manager.api.admin.siem         import router as siem_router
from manager.api.admin.audit        import router as audit_router
from manager.api.admin.alert_rules  import router as alert_rules_router
from manager.api.admin.llm_config   import router as llm_config_router
from manager.api.reports            import router as reports_router
from manager.api.search             import router as search_router
from manager.api.llm                import router as llm_router

api_router = APIRouter()

api_router.include_router(auth_router)
api_router.include_router(stream_router)
api_router.include_router(sessions_router)
api_router.include_router(events_router)
api_router.include_router(sensors_router)
api_router.include_router(health_router)
api_router.include_router(iocs_router)
api_router.include_router(attackers_router)
api_router.include_router(system_router,       prefix="/admin")
api_router.include_router(users_router,        prefix="/admin")
api_router.include_router(smtp_router,         prefix="/admin")
api_router.include_router(siem_router,         prefix="/admin")
api_router.include_router(audit_router,        prefix="/admin")
api_router.include_router(alert_rules_router,  prefix="/admin")
api_router.include_router(llm_config_router,   prefix="/admin")
api_router.include_router(reports_router)
api_router.include_router(search_router)
api_router.include_router(llm_router)
