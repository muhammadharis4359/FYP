import logging
import os
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from app.database import Base, engine
from app.routers import scans

logging.basicConfig(level=logging.INFO)

app = FastAPI(
    title="AI-Powered Bug Bounty Recon & Exploit Mapper",
    description="Phase 3 (Recon) + Phase 4 (Vulnerability Scanning) API",
    version="0.1.0",
)

# Enable CORS for local web dashboards and tooling
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_origin_regex=".*",
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


from app.db_migrate import auto_migrate

# Auto-add backend/bin to PATH so local CLI security binaries are discovered
BIN_DIR = Path(__file__).resolve().parent.parent / "bin"
if BIN_DIR.exists():
    os.environ["PATH"] = str(BIN_DIR) + os.pathsep + os.environ.get("PATH", "")


@app.on_event("startup")
def on_startup():
    auto_migrate()


@app.get("/api/health", tags=["system"])
def api_health():
    return {
        "status": "ok",
        "message": "Recon & Exploit Mapper API is online",
        "version": "0.1.0",
    }


app.include_router(scans.router, tags=["scans"])

# Locate and mount frontend if available
BASE_DIR = Path(__file__).resolve().parent.parent.parent
FRONTEND_DIR = BASE_DIR / "frontend"

if FRONTEND_DIR.exists() and (FRONTEND_DIR / "index.html").exists():
    if (FRONTEND_DIR / "css").exists():
        app.mount("/css", StaticFiles(directory=str(FRONTEND_DIR / "css")), name="css")
    if (FRONTEND_DIR / "js").exists():
        app.mount("/js", StaticFiles(directory=str(FRONTEND_DIR / "js")), name="js")

    @app.get("/", include_in_schema=False)
    def serve_frontend_root():
        return FileResponse(str(FRONTEND_DIR / "index.html"))
else:
    @app.get("/")
    def root():
        return {
            "status": "ok",
            "message": "Recon & Exploit Mapper API is running. Interactive docs at /docs",
        }



