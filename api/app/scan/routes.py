from fastapi import APIRouter, HTTPException, Query
from typing import Optional
from pydantic import BaseModel
from .scan import Scan
from .tasks import task_scan

scan = APIRouter()

class IpRangeScan(BaseModel):
    ip_range: str = Query(None, regex = "^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)/((?:[0-9])|(?:[1-2][0-9])|(?:3[0-2]))$")
    rate: str = Query(None, regex = "\d{1,4}")

class IpScan(BaseModel):
    ip: str = Query(None, regex = "^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$")

@scan.post("/", status_code=200)
async def scan_post(input: IpRangeScan):
    r = task_scan.delay(input.ip_range, input.rate)
    return {"id": r.id, 'status': 'queued'}

@scan.get("/", status_code=200)
async def scan_get(input: IpScan):
    r = Scan(
        ip = input.ip
    )
    r_value_timestamp = r.retrieve_ip()
    if r_value_timestamp is False:
        return {input.ip: "error"}
    else:
        return {input.ip: r_value_timestamp}