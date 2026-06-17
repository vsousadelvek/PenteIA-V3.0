# Example: How to integrate the evasion router into your FastAPI app

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from evasion import router as evasion_router

app = FastAPI(
    title="PenteIA - Evasion Module",
    description="Evasion techniques for penetration testing",
    version="1.0.0"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include the evasion router
app.include_router(evasion_router)


# Root endpoint
@app.get("/")
async def root():
    return {
        "message": "PenteIA Evasion Module",
        "version": "1.0.0",
        "endpoints": {
            "techniques": "GET /api/evasion/techniques",
            "test": "POST /api/evasion/test",
            "payloads_upload": "POST /api/evasion/payloads",
            "payloads_list": "GET /api/evasion/payloads",
            "payloads_download": "GET /api/evasion/payloads/{payload_id}/download",
            "payloads_delete": "DELETE /api/evasion/payloads/{payload_id}",
            "execute": "POST /api/evasion/execute"
        }
    }


# Health check
@app.get("/health")
async def health():
    return {"status": "healthy"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
