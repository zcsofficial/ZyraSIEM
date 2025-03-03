import asyncio
import aiohttp
import logging
from fastapi import FastAPI, Request, Depends
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from typing import Dict, Any, Optional
import uvicorn
from contextlib import asynccontextmanager

# Setup logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# FastAPI app
app = FastAPI(title="Zyra SIEM Dashboard", version="1.0.0")

# Templates
templates = Jinja2Templates(directory="templates")

# Configuration
API_BASE_URL = "http://localhost:5000/api/v1"
WS_URL = "ws://localhost:5000/ws/dashboard"

# Session manager
class SessionManager:
    def __init__(self):
        self.session = None

    async def get_session(self):
        if self.session is None or self.session.closed:
            self.session = aiohttp.ClientSession()
            logger.info("Initialized aiohttp session")
        return self.session

    async def close(self):
        if self.session and not self.session.closed:
            await self.session.close()
            logger.info("Closed aiohttp session")

session_mgr = SessionManager()

@asynccontextmanager
async def lifespan(app: FastAPI):
    await session_mgr.get_session()
    yield
    await session_mgr.close()

app = FastAPI(lifespan=lifespan)

# Dependency
async def get_http_session():
    return await session_mgr.get_session()

# API fetcher
async def fetch_api(endpoint: str, params: Dict[str, Any] = None, session: aiohttp.ClientSession = Depends(get_http_session)) -> Dict:
    url = f"{API_BASE_URL}/{endpoint}"
    # Filter out None values from params
    if params:
        params = {k: v for k, v in params.items() if v is not None}
    try:
        async with session.get(url, params=params) as response:
            if response.status != 200:
                logger.error(f"API call failed: {url} - Status: {response.status}")
                return {}
            return await response.json()
    except Exception as e:
        logger.error(f"Error fetching {url}: {e}")
        return {}

# Routes
@app.get("/", response_class=HTMLResponse)
async def dashboard(
    request: Request,
    session: aiohttp.ClientSession = Depends(get_http_session),
    search: Optional[str] = None,
    sort_by: str = "timestamp",
    sort_order: str = "desc",
    severity: Optional[str] = None,
    source: Optional[str] = None
):
    params = {"search": search, "sort_by": sort_by, "sort_order": sort_order, "severity": severity, "source": source}
    data = await fetch_api("dashboard", params=params, session=session)
    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "data": data or {"total_agents": 0, "total_logs": 0, "total_alerts": 0, "recent_alerts": []},
        "ws_url": WS_URL,
        "search": search,
        "sort_by": sort_by,
        "sort_order": sort_order,
        "severity": severity,
        "source": source
    })

@app.get("/alerts", response_class=HTMLResponse)
async def alerts(
    request: Request,
    limit: int = 100,
    offset: int = 0,
    search: Optional[str] = None,
    sort_by: str = "timestamp",
    sort_order: str = "desc",
    severity: Optional[str] = None,
    session: aiohttp.ClientSession = Depends(get_http_session)
):
    params = {"limit": limit, "offset": offset, "search": search, "sort_by": sort_by, "sort_order": sort_order, "severity": severity}
    data = await fetch_api("alerts", params=params, session=session)
    return templates.TemplateResponse("alerts.html", {"request": request, "data": data or {"alerts": [], "total": 0, "limit": limit, "offset": offset}})

@app.get("/logs", response_class=HTMLResponse)
async def logs(
    request: Request,
    limit: int = 100,
    offset: int = 0,
    search: Optional[str] = None,
    sort_by: str = "timestamp",
    sort_order: str = "desc",
    severity: Optional[str] = None,
    source: Optional[str] = None,
    session: aiohttp.ClientSession = Depends(get_http_session)
):
    params = {"limit": limit, "offset": offset, "search": search, "sort_by": sort_by, "sort_order": sort_order, "severity": severity, "source": source}
    data = await fetch_api("logs", params=params, session=session)
    return templates.TemplateResponse("logs.html", {"request": request, "data": data or {"logs": [], "total": 0, "limit": limit, "offset": offset}})

@app.get("/agents", response_class=HTMLResponse)
async def agents(
    request: Request,
    limit: int = 100,
    offset: int = 0,
    sort_by: str = "last_updated",
    sort_order: str = "desc",
    session: aiohttp.ClientSession = Depends(get_http_session)
):
    params = {"limit": limit, "offset": offset, "sort_by": sort_by, "sort_order": sort_order}
    data = await fetch_api("agents", params=params, session=session)
    return templates.TemplateResponse("agents.html", {"request": request, "data": data or {"agents": [], "total": 0, "limit": limit, "offset": offset}})

@app.get("/agent/{agent_id}", response_class=HTMLResponse)
async def agent(request: Request, agent_id: str, session: aiohttp.ClientSession = Depends(get_http_session)):
    data = await fetch_api(f"agent/{agent_id}", session=session)
    return templates.TemplateResponse("agent.html", {"request": request, "data": data or {"agent": {}, "logs": [], "alerts": []}, "agent_id": agent_id})

@app.get("/malware", response_class=HTMLResponse)
async def malware(
    request: Request,
    limit: int = 100,
    offset: int = 0,
    sort_by: str = "timestamp",
    sort_order: str = "desc",
    session: aiohttp.ClientSession = Depends(get_http_session)
):
    params = {"limit": limit, "offset": offset, "sort_by": sort_by, "sort_order": sort_order}
    data = await fetch_api("malware", params=params, session=session)
    return templates.TemplateResponse("malware.html", {"request": request, "data": data or {"malware": [], "total": 0, "limit": limit, "offset": offset}})

if __name__ == "__main__":
    logger.info("Starting FastAPI server with uvicorn...")
    uvicorn.run(app, host="0.0.0.0", port=5001, log_level="info")