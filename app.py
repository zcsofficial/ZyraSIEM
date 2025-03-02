from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, Response
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
import aiohttp
import asyncio
import logging
from cachetools import TTLCache
from typing import Dict, Any
import uvicorn

# Setup logging with detailed traceback
logging.basicConfig(
    filename="webui.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    filemode="a"
)
logger = logging.getLogger()
handler = logging.StreamHandler()
handler.setLevel(logging.INFO)
formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
handler.setFormatter(formatter)
logger.addHandler(handler)

# FastAPI app
app = FastAPI(title="Zyra SIEM Web UI", version="1.0.0")
templates = Jinja2Templates(directory="templates")

# API base URL
API_BASE_URL = "http://localhost:5000/api/v1"

# Cache setup (TTL of 60 seconds)
cache = TTLCache(maxsize=100, ttl=60)

# Async HTTP client session
async def fetch_api_data(session: aiohttp.ClientSession, endpoint: str, params: Dict = None) -> Dict[str, Any]:
    try:
        async with session.get(f"{API_BASE_URL}/{endpoint}", params=params) as response:
            if response.status == 200:
                data = await response.json()
                logger.debug(f"Fetched data from {endpoint}: {data}")
                return data
            else:
                logger.warning(f"Failed to fetch {endpoint}: Status {response.status}")
                return {}
    except Exception as e:
        logger.error(f"Error fetching {endpoint}: {e}", exc_info=True)
        return {}

# Dashboard page
@app.get("/", response_class=HTMLResponse)
async def dashboard():
    try:
        async with aiohttp.ClientSession() as session:
            tasks = []

            # Total agents
            if "total_agents" not in cache:
                tasks.append(fetch_api_data(session, "devices", {"limit": 1000}))
            else:
                tasks.append(asyncio.ensure_future(asyncio.to_thread(lambda: {"total": cache["total_agents"]})))

            # Total logs
            log_types = ["system_metrics", "dns_queries", "network", "system_logs", "security_logs", "processes", "registry_changes"]
            if "total_logs" not in cache:
                for log_type in log_types:
                    tasks.append(fetch_api_data(session, f"logs/{log_type}", {"limit": 1}))
            else:
                tasks.append(asyncio.ensure_future(asyncio.to_thread(lambda: {"total": cache["total_logs"]})))

            # Total alerts
            if "total_alerts" not in cache:
                tasks.append(fetch_api_data(session, "alerts", {"limit": 1}))
            else:
                tasks.append(asyncio.ensure_future(asyncio.to_thread(lambda: {"total": cache["total_alerts"]})))

            # Latest 10 alerts
            tasks.append(fetch_api_data(session, "alerts", {"sort_by": "timestamp", "sort_order": "desc", "limit": 10}))

            # Latest 10 logs
            for log_type in log_types:
                tasks.append(fetch_api_data(session, f"logs/{log_type}", {"sort_by": "timestamp", "sort_order": "desc", "limit": 10}))

            results = await asyncio.gather(*tasks)

            # Process results
            offset = 0
            total_agents_data = results[offset]
            total_agents = total_agents_data.get("total", 0)
            cache["total_agents"] = total_agents
            offset += 1

            total_logs = 0
            if "total_logs" not in cache:
                for i in range(len(log_types)):
                    logs_data = results[offset + i]
                    total_logs += logs_data.get("total", 0)
                cache["total_logs"] = total_logs
            else:
                total_logs = results[offset]["total"]
            offset += len(log_types)

            total_alerts_data = results[offset]
            total_alerts = total_alerts_data.get("total", 0)
            cache["total_alerts"] = total_alerts
            offset += 1

            latest_alerts = results[offset].get("alerts", [])
            offset += 1

            latest_logs = []
            for i in range(len(log_types)):
                logs_data = results[offset + i]
                log_type = log_types[i]
                if logs_data and log_type in logs_data:
                    for log in logs_data[log_type]:
                        log["log_type"] = log_type
                        latest_logs.append(log)
            latest_logs = sorted(latest_logs, key=lambda x: x.get("timestamp", ""), reverse=True)[:10]

            return templates.TemplateResponse(
                "dashboard.html",
                {
                    "request": {},
                    "total_agents": total_agents,
                    "total_logs": total_logs,
                    "total_alerts": total_alerts,
                    "latest_alerts": latest_alerts,
                    "latest_logs": latest_logs
                }
            )
    except Exception as e:
        logger.error(f"Error rendering dashboard: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal Server Error")

# Agents list page
@app.get("/agents", response_class=HTMLResponse)
async def agents_list():
    try:
        async with aiohttp.ClientSession() as session:
            devices_data = await fetch_api_data(session, "devices", {"limit": 1000})
            agents = devices_data.get("devices", [])
            return templates.TemplateResponse(
                "agents.html",
                {"request": {}, "agents": agents}
            )
    except Exception as e:
        logger.error(f"Error rendering agents list: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal Server Error")

# Agent details page
@app.get("/agents/{agent_id}", response_class=HTMLResponse)
async def agent_details(agent_id: str):
    try:
        async with aiohttp.ClientSession() as session:
            tasks = [
                fetch_api_data(session, f"agents/{agent_id}/device"),
                fetch_api_data(session, f"agents/{agent_id}/alerts", {"limit": 10}),
            ]
            log_types = ["system_metrics", "dns_queries", "network", "system_logs", "security_logs", "processes", "registry_changes"]
            for log_type in log_types:
                tasks.append(fetch_api_data(session, f"agents/{agent_id}/logs/{log_type}", {"limit": 10}))

            results = await asyncio.gather(*tasks)

            device_data = results[0].get("devices", [{}])[0] if results[0] else {}
            latest_alerts = results[1].get("alerts", [])
            latest_logs = []
            offset = 2
            for log_type in log_types:
                logs_data = results[offset]
                if logs_data and log_type in logs_data:
                    for log in logs_data[log_type]:
                        log["log_type"] = log_type
                        latest_logs.append(log)
                offset += 1
            latest_logs = sorted(latest_logs, key=lambda x: x.get("timestamp", ""), reverse=True)[:10]

            return templates.TemplateResponse(
                "agent_details.html",
                {
                    "request": {},
                    "agent_id": agent_id,
                    "device": device_data,
                    "latest_alerts": latest_alerts,
                    "latest_logs": latest_logs
                }
            )
    except Exception as e:
        logger.error(f"Error rendering agent details for {agent_id}: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal Server Error")

# Logs by type page
@app.get("/logs/{log_type}", response_class=HTMLResponse)
async def logs_by_type(log_type: str):
    try:
        async with aiohttp.ClientSession() as session:
            logs_data = await fetch_api_data(session, f"logs/{log_type}", {"limit": 50})
            logs = logs_data.get(log_type, []) if logs_data else []
            return templates.TemplateResponse(
                "logs.html",
                {"request": {}, "log_type": log_type, "logs": logs}
            )
    except Exception as e:
        logger.error(f"Error rendering logs for {log_type}: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal Server Error")

# Agent logs by type page
@app.get("/agents/{agent_id}/logs/{log_type}", response_class=HTMLResponse)
async def agent_logs_by_type(agent_id: str, log_type: str):
    try:
        async with aiohttp.ClientSession() as session:
            logs_data = await fetch_api_data(session, f"agents/{agent_id}/logs/{log_type}", {"limit": 50})
            logs = logs_data.get(log_type, []) if logs_data else []
            return templates.TemplateResponse(
                "logs.html",
                {"request": {}, "log_type": log_type, "logs": logs, "agent_id": agent_id}
            )
    except Exception as e:
        logger.error(f"Error rendering logs for agent {agent_id}, type {log_type}: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal Server Error")

# Alerts page
@app.get("/alerts", response_class=HTMLResponse)
async def alerts_list():
    try:
        async with aiohttp.ClientSession() as session:
            alerts_data = await fetch_api_data(session, "alerts", {"limit": 50})
            alerts = alerts_data.get("alerts", []) if alerts_data else []
            return templates.TemplateResponse(
                "alerts.html",
                {"request": {}, "alerts": alerts}
            )
    except Exception as e:
        logger.error(f"Error rendering alerts list: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal Server Error")

# Agent alerts page
@app.get("/agents/{agent_id}/alerts", response_class=HTMLResponse)
async def agent_alerts(agent_id: str):
    try:
        async with aiohttp.ClientSession() as session:
            alerts_data = await fetch_api_data(session, f"agents/{agent_id}/alerts", {"limit": 50})
            alerts = alerts_data.get("alerts", []) if alerts_data else []
            return templates.TemplateResponse(
                "alerts.html",
                {"request": {}, "alerts": alerts, "agent_id": agent_id}
            )
    except Exception as e:
        logger.error(f"Error rendering alerts for agent {agent_id}: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal Server Error")

@app.get("/favicon.ico")
async def favicon():
    return Response(status_code=204)

# Run the server
if __name__ == "__main__":
    logger.info("Starting FastAPI web UI with Uvicorn...")
    print("Starting FastAPI web UI with Uvicorn...")
    uvicorn.run(app, host="0.0.0.0", port=5001, log_level="info")