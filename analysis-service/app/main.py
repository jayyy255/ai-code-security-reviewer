from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.routers.analyze import router as scan_router
from app.routers.health import router as health_router

app = FastAPI(
    title="AI Code Security Reviewer - Analysis Engine",
    version="2.0.0",
    description="Multi-mode static analysis, secret scanning, malware status, prompt injection defense, and grounded AI advisories."
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
async def root():
    return {
        "service": "scanner-service",
        "status": "running",
        "version": "2.0.0",
        "modes": ["paste", "upload", "commit"]
    }

app.include_router(health_router)
app.include_router(scan_router)