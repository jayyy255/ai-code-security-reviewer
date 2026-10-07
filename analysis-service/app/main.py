from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
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

@app.exception_handler(RuntimeError)
async def scanner_failure(request: Request, exc: RuntimeError):
    return JSONResponse(status_code=503, content={"detail": str(exc)})
