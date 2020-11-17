from fastapi import FastAPI
from alive.routes import alive
from scan.routes import scan

api = FastAPI()

"""
@api.on_event("startup")
async def startup():
    await database.connect()

@api.on_event("shutdown")
async def shutdown():
    await database.disconnect()
"""

api.include_router(alive, prefix="/alive")
api.include_router(scan, prefix="/scan")