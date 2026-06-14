param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("backend", "frontend", "both")]
    [string]$Mode = "both"
)

$BackendPath = "E:\cyber\PenteIA-V3.0"
$FrontendPath = "E:\cyber\PenteIA-V3.0\frontend"

function Start-Backend {
    Write-Host "`n✅ Iniciando Backend (FastAPI)..." -ForegroundColor Green
    Write-Host "URL: http://localhost:8000" -ForegroundColor Cyan
    Write-Host "Docs: http://localhost:8000/docs" -ForegroundColor Cyan
    Set-Location $BackendPath
    & python -m uvicorn app_fastapi_v2:app --host 0.0.0.0 --port 8000 --reload
}

function Start-Frontend {
    Write-Host "`n✅ Iniciando Frontend (React + Vite)..." -ForegroundColor Green
    Write-Host "URL: http://localhost:5173" -ForegroundColor Cyan
    Set-Location $FrontendPath
    & npm run dev
}

switch ($Mode) {
    "backend" { Start-Backend }
    "frontend" { Start-Frontend }
    "both" {
        Write-Host "`n╔════════════════════════════════════════╗" -ForegroundColor Yellow
        Write-Host "║   PenteIA v4.0 - Startup Script        ║" -ForegroundColor Yellow
        Write-Host "║   Red Team Platform - Multi-User Lab   ║" -ForegroundColor Yellow
        Write-Host "╚════════════════════════════════════════╝`n" -ForegroundColor Yellow

        Write-Host "Abrindo 2 terminais..." -ForegroundColor Cyan

        # Terminal 1: Backend
        Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$BackendPath'; Write-Host '📦 Backend iniciando...'; python -m uvicorn app_fastapi_v2:app --host 0.0.0.0 --port 8000 --reload"

        Start-Sleep -Seconds 3

        # Terminal 2: Frontend
        Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$FrontendPath'; Write-Host '⚛️  Frontend iniciando...'; npm run dev"

        Write-Host "`n✅ Ambos os serviços iniciados!`n" -ForegroundColor Green
        Write-Host "Backend:  http://localhost:8000" -ForegroundColor Cyan
        Write-Host "Frontend: http://localhost:5173" -ForegroundColor Cyan
        Write-Host "`nDocs API: http://localhost:8000/docs" -ForegroundColor Cyan
    }
}
