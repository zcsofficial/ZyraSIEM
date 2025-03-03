import asyncio
import logging
from fastapi import FastAPI, Query, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pymongo import MongoClient, DESCENDING, ASCENDING, IndexModel, TEXT
from pymongo.errors import ConnectionFailure
from typing import List, Dict, Any, Optional
from urllib.parse import quote
import uvicorn
from contextlib import asynccontextmanager
from bson import ObjectId
from tenacity import retry, stop_after_attempt, wait_exponential

# Setup logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s", filename="server.log")
logger = logging.getLogger(__name__)

# MongoDB connection
DB_PASSWORD = "Hacker@66202"
ENCODED_PASSWORD = quote(DB_PASSWORD)
MONGO_URI = f"mongodb+srv://zyraadmin:{ENCODED_PASSWORD}@zyrasiemcluster.8ydms.mongodb.net/?retryWrites=true&w=majority&appName=ZyraSiemCluster"

mongo_client = None
db = None

# Retry decorator for MongoDB connection
@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=4, max=10))
async def connect_to_mongo():
    global mongo_client, db
    mongo_client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=20000)
    mongo_client.admin.command('ping')  # Test connection
    db = mongo_client["zyra_siem"]
    return db

# Lifespan handler
@asynccontextmanager
async def lifespan(app: FastAPI):
    global mongo_client, db
    try:
        await connect_to_mongo()
        if db is not None:
            db.logs.create_indexes([
                IndexModel([("agent_id", ASCENDING), ("timestamp", DESCENDING)]),
                IndexModel([("system_metrics.cpu_percent", DESCENDING)]),
                IndexModel([("$**", TEXT)], name="text_index")  # For search
            ])
            db.alerts.create_indexes([
                IndexModel([("agent_id", ASCENDING), ("timestamp", DESCENDING)]),
                IndexModel([("severity", ASCENDING)])
            ])
            db.device_info.create_indexes([
                IndexModel([("agent_id", ASCENDING), ("last_updated", DESCENDING)], unique=True)
            ])
            logger.info("MongoDB connected and indexes created")
    except ConnectionFailure as e:
        logger.error(f"MongoDB connection failed: {e}. Running without database.")
        db = None

    yield

    if mongo_client:
        mongo_client.close()
    logger.info("MongoDB connection closed")

# FastAPI app
app = FastAPI(title="Zyra SIEM Server", version="1.0.0", lifespan=lifespan)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Helper functions
def convert_objectid(data: Any) -> Any:
    if isinstance(data, ObjectId):
        return str(data)
    elif isinstance(data, list):
        return [convert_objectid(item) for item in data]
    elif isinstance(data, dict):
        return {key: convert_objectid(value) for key, value in data.items()}
    return data

async def fetch_data(collection, query: Dict, sort: List, limit: int, offset: int) -> Dict:
    if collection is not None:
        try:
            total = await asyncio.to_thread(collection.count_documents, query)
            data = await asyncio.to_thread(lambda: list(collection.find(query).sort(sort).skip(offset).limit(limit)))
            return {"total": total, "data": [convert_objectid(d) for d in data], "limit": limit, "offset": offset}
        except Exception as e:
            logger.error(f"Error fetching data from MongoDB: {e}")
    return {"total": 0, "data": [], "limit": limit, "offset": offset}

def apply_filters(query: Dict, search: Optional[str] = None, filters: Dict = None) -> Dict:
    if search:
        query["$text"] = {"$search": search}
    if filters:
        for key, value in filters.items():
            if value:  # Only add non-None filters
                query[key] = value
    return query

def apply_sort(sort_by: str = "timestamp", sort_order: str = "desc") -> List:
    order = DESCENDING if sort_order.lower() == "desc" else ASCENDING
    return [(sort_by, order)]

# API Endpoints
@app.get("/api/v1/dashboard")
async def get_dashboard_data():
    if db is None:
        return {
            "total_agents": 0, "total_logs": 0, "total_alerts": 0,
            "recent_alerts": []  # Changed to alerts
        }

    tasks = [
        fetch_data(db.device_info, {}, [("last_updated", DESCENDING)], 1000, 0),
        fetch_data(db.logs, {}, [("timestamp", DESCENDING)], 1000, 0),
        fetch_data(db.alerts, {}, [("timestamp", DESCENDING)], 1000, 0)
    ]
    agents, logs, alerts = await asyncio.gather(*tasks)

    recent_alerts = []
    for alert in alerts["data"][:8]:  # Show recent alerts instead of logs
        severity = alert.get("severity", "low")
        recent_alerts.append({
            "timestamp": alert.get("timestamp", "N/A"),
            "source": alert.get("agent_id", "Unknown"),
            "event": alert.get("type", "Unknown"),
            "severity": severity,
            "status": "Open" if severity in ["high", "critical"] else "Resolved"  # Simple status logic
        })

    return {
        "total_agents": agents["total"],
        "total_logs": logs["total"],
        "total_alerts": alerts["total"],
        "recent_alerts": recent_alerts
    }

@app.get("/api/v1/logs")
async def get_logs(
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    search: Optional[str] = Query(None),
    sort_by: str = Query("timestamp"),
    sort_order: str = Query("desc"),
    severity: Optional[str] = Query(None),
    source: Optional[str] = Query(None)
):
    if db is None:
        return {"logs": [], "total": 0, "limit": limit, "offset": offset}

    query = {}
    filters = {"severity": severity, "agent_id": source}
    query = apply_filters(query, search, filters)
    sort = apply_sort(sort_by, sort_order)

    result = await fetch_data(db.logs, query, sort, limit, offset)
    logs = []
    for log in result["data"]:
        source = log.get("agent_id", "Unknown")
        event_type = next((k for k in log.keys() if k not in ["agent_id", "timestamp", "_id"]), "Unknown")
        severity = "low"
        if "system_metrics" in log and log["system_metrics"].get("cpu_percent", 0) > 90:
            severity = "high"
        logs.append({
            "timestamp": log.get("timestamp", "N/A"),
            "source": source,
            "event": event_type.capitalize().replace("_", " "),
            "severity": severity,
            "status": "Open"
        })
    return {"logs": logs, "total": result["total"], "limit": limit, "offset": offset}

@app.get("/api/v1/alerts")
async def get_alerts(
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    search: Optional[str] = Query(None),
    sort_by: str = Query("timestamp"),
    sort_order: str = Query("desc"),
    severity: Optional[str] = Query(None)
):
    if db is None:
        return {"alerts": [], "total": 0, "limit": limit, "offset": offset}

    query = {}
    filters = {"severity": severity}
    query = apply_filters(query, search, filters)
    sort = apply_sort(sort_by, sort_order)

    result = await fetch_data(db.alerts, query, sort, limit, offset)
    alerts = []
    for alert in result["data"]:
        severity = alert.get("severity", "low")
        alerts.append({
            "timestamp": alert.get("timestamp", "N/A"),
            "source": alert.get("agent_id", "Unknown"),
            "event": alert.get("type", "Unknown"),
            "severity": severity,
            "status": "Open" if severity in ["high", "critical"] else "Resolved",
            "details": alert.get("details", "N/A")
        })
    return {"alerts": alerts, "total": result["total"], "limit": limit, "offset": offset}

@app.get("/api/v1/agents")
async def get_agents(
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    sort_by: str = Query("last_updated"),
    sort_order: str = Query("desc")
):
    if db is None:
        return {"agents": [], "total": 0, "limit": limit, "offset": offset}

    sort = apply_sort(sort_by, sort_order)
    result = await fetch_data(db.device_info, {}, sort, limit, offset)
    return {"agents": result["data"], "total": result["total"], "limit": limit, "offset": offset}

@app.get("/api/v1/agent/{agent_id}")
async def get_agent(agent_id: str):
    if db is None:
        return {"agent": {}, "logs": [], "alerts": []}

    tasks = [
        fetch_data(db.device_info, {"agent_id": agent_id}, [("last_updated", DESCENDING)], 1, 0),
        fetch_data(db.logs, {"agent_id": agent_id}, [("timestamp", DESCENDING)], 100, 0),
        fetch_data(db.alerts, {"agent_id": agent_id}, [("timestamp", DESCENDING)], 100, 0)
    ]
    device, logs, alerts = await asyncio.gather(*tasks)

    agent_logs = []
    for log in logs["data"]:
        source = log.get("agent_id", "Unknown")
        event_type = next((k for k in log.keys() if k not in ["agent_id", "timestamp", "_id"]), "Unknown")
        severity = "low"
        if "system_metrics" in log and log["system_metrics"].get("cpu_percent", 0) > 90:
            severity = "high"
        agent_logs.append({
            "timestamp": log.get("timestamp", "N/A"),
            "source": source,
            "event": event_type.capitalize().replace("_", " "),
            "severity": severity,
            "status": "Open"
        })

    agent_alerts = []
    for alert in alerts["data"]:
        severity = alert.get("severity", "low")
        agent_alerts.append({
            "timestamp": alert.get("timestamp", "N/A"),
            "source": alert.get("agent_id", "Unknown"),
            "event": alert.get("type", "Unknown"),
            "severity": severity,
            "status": "Open" if severity in ["high", "critical"] else "Resolved",
            "details": alert.get("details", "N/A")
        })

    return {
        "agent": device["data"][0] if device["data"] else {},
        "logs": agent_logs,
        "alerts": agent_alerts
    }

@app.get("/api/v1/malware")
async def get_malware(
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    sort_by: str = Query("timestamp"),
    sort_order: str = Query("desc")
):
    if db is None:
        return {"malware": [], "total": 0, "limit": limit, "offset": offset}

    query = {"type": "Malware Detected"}
    sort = apply_sort(sort_by, sort_order)
    result = await fetch_data(db.alerts, query, sort, limit, offset)
    malware = []
    for alert in result["data"]:
        severity = alert.get("severity", "low")
        malware.append({
            "timestamp": alert.get("timestamp", "N/A"),
            "source": alert.get("agent_id", "Unknown"),
            "severity": severity,
            "details": alert.get("details", "N/A")
        })
    return {"malware": malware, "total": result["total"], "limit": limit, "offset": offset}

@app.websocket("/ws/dashboard")
async def websocket_dashboard(websocket: WebSocket):
    await websocket.accept()
    connected = True
    while connected:
        try:
            data = await get_dashboard_data()
            await websocket.send_json(data)
            await asyncio.sleep(2)
        except WebSocketDisconnect:
            logger.info("WebSocket disconnected")
            connected = False
        except Exception as e:
            logger.error(f"WebSocket error: {e}")
            connected = False
    await websocket.close()

if __name__ == "__main__":
    logger.info("Starting FastAPI server...")
    uvicorn.run(app, host="0.0.0.0", port=5000, log_level="info")