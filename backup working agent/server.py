from fastapi import FastAPI, Query, HTTPException, Depends
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pymongo import MongoClient, DESCENDING, ASCENDING
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
from datetime import datetime
import logging
from urllib.parse import quote
import asyncio
import uvicorn
import json
from bson import ObjectId

# Setup logging
logging.basicConfig(
    filename="server.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    filemode="a"
)
logger = logging.getLogger()

# MongoDB connection with URL-encoded password
DB_PASSWORD = "Hacker@66202"
ENCODED_PASSWORD = quote(DB_PASSWORD)
MONGO_URI = f"mongodb+srv://zyraadmin:{ENCODED_PASSWORD}@zyrasiemcluster.8ydms.mongodb.net/?retryWrites=true&w=majority&appName=ZyraSiemCluster"
mongo_client = MongoClient(MONGO_URI)
db = mongo_client["zyra_siem"]

# FastAPI app with CORS
app = FastAPI(title="Zyra SIEM Server", version="1.0.0")

# CORS configuration
origins = [
    "http://localhost",
    "http://localhost:3000",
    "https://your-frontend-domain.com",
    "*"
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Pydantic models
class FilterParams(BaseModel):
    field: str
    value: Any

class DataResponse(BaseModel):
    total: int
    limit: int
    offset: int
    data: List[Dict[str, Any]]

# Dependency for parsing filters
def get_filters(filters: Optional[str] = Query(None, description="Filters as JSON string, e.g., '[{\"field\":\"agent_id\",\"value\":\"550e...\"}]'")) -> Optional[List[FilterParams]]:
    if filters:
        try:
            filter_list = json.loads(filters)
            return [FilterParams(**f) for f in filter_list]
        except Exception as e:
            logger.error(f"Error parsing filters: {e}")
            raise HTTPException(status_code=400, detail="Invalid filters format")
    return None

# Helper function to convert ObjectId to string
def convert_objectid(data: Any) -> Any:
    if isinstance(data, ObjectId):
        return str(data)
    elif isinstance(data, list):
        return [convert_objectid(item) for item in data]
    elif isinstance(data, dict):
        return {key: convert_objectid(value) for key, value in data.items()}
    return data

# Helper functions
def apply_filters(query: Dict, filters: List[FilterParams] = None) -> Dict:
    if filters:
        for f in filters:
            query[f.field] = f.value
    return query

def apply_sort(sort_by: str = "timestamp", sort_order: str = "desc") -> List:
    order = DESCENDING if sort_order.lower() == "desc" else ASCENDING
    return [(sort_by, order)]

def apply_search(query: Dict, search: str = None) -> Dict:
    if search:
        query["$text"] = {"$search": search}
    return query

async def fetch_data(collection, query: Dict, sort: List, limit: int, offset: int) -> Dict:
    try:
        total = await asyncio.to_thread(collection.count_documents, query)
        data = await asyncio.to_thread(
            lambda: list(collection.find(query).sort(sort).skip(offset).limit(limit))
        )
        # Convert ObjectId to string in the result
        converted_data = convert_objectid(data)
        return {
            "total": total,
            "data": converted_data,
            "limit": limit,
            "offset": offset
        }
    except Exception as e:
        logger.error(f"Error fetching data: {e}\n{traceback.format_exc()}")
        raise HTTPException(status_code=500, detail=str(e))

# Generic endpoint handler
async def get_endpoint_data(
    collection,
    endpoint_name: str,
    search: Optional[str] = None,
    filters: List[FilterParams] = Depends(get_filters),
    sort_by: str = "timestamp",
    sort_order: str = "desc",
    limit: int = 100,
    offset: int = 0
):
    query = apply_filters({}, filters)
    query = apply_search(query, search)
    sort = apply_sort(sort_by, sort_order)
    result = await fetch_data(collection, query, sort, limit, offset)
    logger.info(f"Fetched {len(result['data'])} {endpoint_name} with query: {query}")
    return JSONResponse(content={endpoint_name: result["data"], "total": result["total"], "limit": limit, "offset": offset})

# API Endpoints for each log type
@app.get("/api/v1/logs/system_metrics")
async def get_system_metrics(
    search: Optional[str] = Query(None, description="Search system metrics"),
    filters: List[FilterParams] = Depends(get_filters),
    sort_by: str = Query("timestamp", description="Field to sort by"),
    sort_order: str = Query("desc", description="Sort order: asc or desc"),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0)
):
    """Fetch system metrics logs."""
    return await get_endpoint_data(db.logs, "system_metrics", search, filters, sort_by, sort_order, limit, offset)

@app.get("/api/v1/logs/dns_queries")
async def get_dns_queries(
    search: Optional[str] = Query(None, description="Search DNS queries"),
    filters: List[FilterParams] = Depends(get_filters),
    sort_by: str = Query("timestamp", description="Field to sort by"),
    sort_order: str = Query("desc", description="Sort order: asc or desc"),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0)
):
    """Fetch DNS queries logs."""
    return await get_endpoint_data(db.logs, "dns_queries", search, filters, sort_by, sort_order, limit, offset)

@app.get("/api/v1/logs/network")
async def get_network(
    search: Optional[str] = Query(None, description="Search network logs"),
    filters: List[FilterParams] = Depends(get_filters),
    sort_by: str = Query("timestamp", description="Field to sort by"),
    sort_order: str = Query("desc", description="Sort order: asc or desc"),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0)
):
    """Fetch network logs."""
    return await get_endpoint_data(db.logs, "network", search, filters, sort_by, sort_order, limit, offset)

@app.get("/api/v1/logs/system_logs")
async def get_system_logs(
    search: Optional[str] = Query(None, description="Search system logs"),
    filters: List[FilterParams] = Depends(get_filters),
    sort_by: str = Query("timestamp", description="Field to sort by"),
    sort_order: str = Query("desc", description="Sort order: asc or desc"),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0)
):
    """Fetch system event logs."""
    return await get_endpoint_data(db.logs, "system_logs", search, filters, sort_by, sort_order, limit, offset)

@app.get("/api/v1/logs/security_logs")
async def get_security_logs(
    search: Optional[str] = Query(None, description="Search security logs"),
    filters: List[FilterParams] = Depends(get_filters),
    sort_by: str = Query("timestamp", description="Field to sort by"),
    sort_order: str = Query("desc", description="Sort order: asc or desc"),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0)
):
    """Fetch security event logs."""
    return await get_endpoint_data(db.logs, "security_logs", search, filters, sort_by, sort_order, limit, offset)

@app.get("/api/v1/logs/processes")
async def get_processes(
    search: Optional[str] = Query(None, description="Search processes logs"),
    filters: List[FilterParams] = Depends(get_filters),
    sort_by: str = Query("timestamp", description="Field to sort by"),
    sort_order: str = Query("desc", description="Sort order: asc or desc"),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0)
):
    """Fetch processes logs."""
    return await get_endpoint_data(db.logs, "processes", search, filters, sort_by, sort_order, limit, offset)

@app.get("/api/v1/logs/registry_changes")
async def get_registry_changes(
    search: Optional[str] = Query(None, description="Search registry changes logs"),
    filters: List[FilterParams] = Depends(get_filters),
    sort_by: str = Query("timestamp", description="Field to sort by"),
    sort_order: str = Query("desc", description="Sort order: asc or desc"),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0)
):
    """Fetch registry changes logs."""
    return await get_endpoint_data(db.logs, "registry_changes", search, filters, sort_by, sort_order, limit, offset)

@app.get("/api/v1/alerts")
async def get_alerts(
    search: Optional[str] = Query(None, description="Search alerts"),
    filters: List[FilterParams] = Depends(get_filters),
    sort_by: str = Query("timestamp", description="Field to sort by"),
    sort_order: str = Query("desc", description="Sort order: asc or desc"),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0)
):
    """Fetch alerts."""
    return await get_endpoint_data(db.alerts, "alerts", search, filters, sort_by, sort_order, limit, offset)

@app.get("/api/v1/devices")
async def get_devices(
    search: Optional[str] = Query(None, description="Search devices"),
    filters: List[FilterParams] = Depends(get_filters),
    sort_by: str = Query("last_updated", description="Field to sort by"),
    sort_order: str = Query("desc", description="Sort order: asc or desc"),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0)
):
    """Fetch devices."""
    return await get_endpoint_data(db.device_info, "devices", search, filters, sort_by, sort_order, limit, offset)

@app.get("/api/v1/commands", response_model=Dict[str, Any])
async def get_command():
    """Send commands to agents."""
    try:
        command = {"action": "list_processes"}
        logger.info("Command requested: list_processes")
        return JSONResponse(content=command)
    except Exception as e:
        logger.error(f"Error in command endpoint: {e}\n{traceback.format_exc()}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/v1/commands/result", response_model=Dict[str, Any])
async def receive_command_result(result: Dict[str, Any]):
    """Receive results from agent commands."""
    try:
        logger.info(f"Received command result: {result}")
        return {"status": "success", "message": "Result received"}
    except Exception as e:
        logger.error(f"Error receiving command result: {e}\n{traceback.format_exc()}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/v1/analytics", response_model=Dict[str, Any])
async def get_analytics():
    """Fetch analytics (e.g., alert counts by severity)."""
    try:
        pipeline = [
            {"$group": {"_id": "$severity", "count": {"$sum": 1}}},
            {"$sort": {"count": -1}}
        ]
        analytics = await asyncio.to_thread(lambda: list(db.alerts.aggregate(pipeline)))
        # Convert ObjectId in analytics if present
        converted_analytics = convert_objectid(analytics)
        result = {"analytics": converted_analytics}
        logger.info(f"Fetched analytics: {result}")
        return JSONResponse(content=result)
    except Exception as e:
        logger.error(f"Error fetching analytics: {e}\n{traceback.format_exc()}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/v1/get_vt_api_key", response_model=Dict[str, str])
async def get_vt_api_key():
    """Provide VirusTotal API key to agents."""
    try:
        vt_api_key = "your_virustotal_api_key_here"  # Replace with your actual key
        logger.info("VirusTotal API key requested")
        return {"api_key": vt_api_key}
    except Exception as e:
        logger.error(f"Error providing VT API key: {e}\n{traceback.format_exc()}")
        raise HTTPException(status_code=500, detail=str(e))

# Run the server
if __name__ == "__main__":
    logger.info("Starting FastAPI server...")
    print("Starting FastAPI server...")
    uvicorn.run(app, host="0.0.0.0", port=5000, log_level="info")