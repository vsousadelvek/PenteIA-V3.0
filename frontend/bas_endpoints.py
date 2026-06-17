from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel
from models import Playbook, Simulation, User
from database import get_db
from auth import get_current_user

router = APIRouter(prefix="/api/bas", tags=["BAS"])


# Pydantic Models
class PlaybookCreate(BaseModel):
    name: str
    techniques: int
    severity: str
    description: Optional[str] = None


class PlaybookUpdate(BaseModel):
    name: Optional[str] = None
    techniques: Optional[int] = None
    severity: Optional[str] = None
    description: Optional[str] = None


class PlaybookResponse(BaseModel):
    id: int
    user_id: int
    name: str
    techniques: int
    severity: str
    description: Optional[str]
    created_at: datetime

    class Config:
        from_attributes = True


class SimulationExecute(BaseModel):
    playbook_id: int
    target: str


class SimulationResults(BaseModel):
    status: str
    score: float


class SimulationResponse(BaseModel):
    id: int
    user_id: int
    playbook_id: int
    target: str
    status: str
    score: float
    date: datetime

    class Config:
        from_attributes = True


# POST /api/bas/playbooks - Criar playbook
@router.post("/playbooks", response_model=PlaybookResponse, status_code=status.HTTP_201_CREATED)
async def create_playbook(
    playbook_data: PlaybookCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Criar um novo playbook BAS"""
    new_playbook = Playbook(
        user_id=current_user.id,
        name=playbook_data.name,
        techniques=playbook_data.techniques,
        severity=playbook_data.severity,
        description=playbook_data.description,
    )

    db.add(new_playbook)
    db.commit()
    db.refresh(new_playbook)

    return new_playbook


# GET /api/bas/playbooks - Listar playbooks do usuário
@router.get("/playbooks", response_model=List[PlaybookResponse])
async def list_playbooks(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Listar todos os playbooks do usuário autenticado"""
    playbooks = db.query(Playbook).filter(Playbook.user_id == current_user.id).all()
    return playbooks


# PUT /api/bas/playbooks/{playbook_id} - Editar playbook
@router.put("/playbooks/{playbook_id}", response_model=PlaybookResponse)
async def update_playbook(
    playbook_id: int,
    playbook_data: PlaybookUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Editar um playbook existente"""
    playbook = (
        db.query(Playbook)
        .filter(Playbook.id == playbook_id, Playbook.user_id == current_user.id)
        .first()
    )

    if not playbook:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Playbook não encontrado",
        )

    if playbook_data.name is not None:
        playbook.name = playbook_data.name
    if playbook_data.techniques is not None:
        playbook.techniques = playbook_data.techniques
    if playbook_data.severity is not None:
        playbook.severity = playbook_data.severity
    if playbook_data.description is not None:
        playbook.description = playbook_data.description

    db.commit()
    db.refresh(playbook)

    return playbook


# DELETE /api/bas/playbooks/{playbook_id} - Deletar playbook
@router.delete("/playbooks/{playbook_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_playbook(
    playbook_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Deletar um playbook"""
    playbook = (
        db.query(Playbook)
        .filter(Playbook.id == playbook_id, Playbook.user_id == current_user.id)
        .first()
    )

    if not playbook:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Playbook não encontrado",
        )

    db.delete(playbook)
    db.commit()

    return None


# POST /api/bas/execute - Executar playbook e iniciar simulação
@router.post("/execute", response_model=SimulationResponse, status_code=status.HTTP_201_CREATED)
async def execute_playbook(
    execution_data: SimulationExecute,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Executar um playbook e iniciar simulação BAS"""
    playbook = (
        db.query(Playbook)
        .filter(Playbook.id == execution_data.playbook_id, Playbook.user_id == current_user.id)
        .first()
    )

    if not playbook:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Playbook não encontrado",
        )

    new_simulation = Simulation(
        user_id=current_user.id,
        playbook_id=execution_data.playbook_id,
        target=execution_data.target,
        status="em_execução",
        score=0.0,
        date=datetime.utcnow(),
    )

    db.add(new_simulation)
    db.commit()
    db.refresh(new_simulation)

    return new_simulation


# GET /api/bas/simulations - Listar simulações do usuário
@router.get("/simulations", response_model=List[SimulationResponse])
async def list_simulations(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Listar todas as simulações do usuário autenticado"""
    simulations = (
        db.query(Simulation).filter(Simulation.user_id == current_user.id).all()
    )
    return simulations


# GET /api/bas/simulations/{simulation_id} - Detalhes da simulação
@router.get("/simulations/{simulation_id}", response_model=SimulationResponse)
async def get_simulation(
    simulation_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Obter detalhes de uma simulação específica"""
    simulation = (
        db.query(Simulation)
        .filter(Simulation.id == simulation_id, Simulation.user_id == current_user.id)
        .first()
    )

    if not simulation:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Simulação não encontrada",
        )

    return simulation


# POST /api/bas/simulations/{simulation_id}/results - Salvar resultados da simulação
@router.post("/simulations/{simulation_id}/results", response_model=SimulationResponse)
async def save_simulation_results(
    simulation_id: int,
    results_data: SimulationResults,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Salvar resultados de uma simulação"""
    simulation = (
        db.query(Simulation)
        .filter(Simulation.id == simulation_id, Simulation.user_id == current_user.id)
        .first()
    )

    if not simulation:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Simulação não encontrada",
        )

    simulation.status = results_data.status
    simulation.score = results_data.score

    db.commit()
    db.refresh(simulation)

    return simulation
