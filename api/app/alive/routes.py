from fastapi import APIRouter, HTTPException, Query
from typing import Optional
from pydantic import BaseModel
from .alive import Alive
from .tasks import *

alive = APIRouter()

class IpRange(BaseModel):
    ip_range: str = Query(None, regex = "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/((?:[0-9])|(?:[1-2][0-9])|(?:3[0-2]))")

class Ip(BaseModel):
    ip: str = Query(None, regex = "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")

@alive.post("/ping", status_code=200)
async def alive_ping_post(input: IpRange):
    r = task_alive_ping.delay(input.ip_range)
    return {"id": r.id, 'status': 'queued'}

@alive.get("/", status_code=200)
async def alive_get(input: Ip):
    r = Alive(
        ip = input.ip
    )
    r_value_timestamp = r.retrieve_ip()
    if r_value_timestamp is False:
        return {input.ip: "error"}
    else:
        return {input.ip: r_value_timestamp}