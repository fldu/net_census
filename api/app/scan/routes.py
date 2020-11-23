from fastapi import APIRouter, HTTPException, Query
from typing import Optional
from pydantic import BaseModel
from .scan import Scan
from .tasks import task_scan

scan = APIRouter()

class IpRangeScan(BaseModel):
    ip_range: str = Query(None, regex = "^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)/((?:[0-9])|(?:[1-2][0-9])|(?:3[0-2]))$")
    rate: str = Query(None, regex = "^\d{1,4}$")
    port: str = Query(None, regex = "^()([1-9]|[1-5]?[0-9]{2,4}|6[1-4][0-9]{3}|65[1-4][0-9]{2}|655[1-2][0-9]|6553[1-5])$")

class IpScan(BaseModel):
    ip: Optional[str] = Query(None, regex = "^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$")
    port: Optional[str] = Query(None, regex = "^()([1-9]|[1-5]?[0-9]{2,4}|6[1-4][0-9]{3}|65[1-4][0-9]{2}|655[1-2][0-9]|6553[1-5])$")

@scan.post("/", status_code=200)
async def scan_post(input: IpRangeScan):
    r = task_scan.delay(input.ip_range, input.rate, input.port)
    return {"id": r.id, 'status': 'queued'}

@scan.get("/", status_code=200)
async def scan_get(input: IpScan):
    r = Scan(
        ip = input.ip,
        port = input.port
    )
    r_value = r.retrieve()
    return r_value