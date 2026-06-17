from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from datetime import datetime
from pydantic import BaseModel
from typing import List

from auth import (
    LoginRequest,
    TokenResponse,
    get_current_user,
    hash_password,
    verify_password,
    create_access_token,
)
from database import get_db
from models import User, Listener, Beacon

router = APIRouter(prefix="/api/c2", tags=["c2"])


class ListenerCreate(BaseModel):
    name: str
    host: str
    port: int
    protocol: str


class ListenerResponse(BaseModel):
    id: int
    user_id: int
    name: str
    host: str
    port: int
    protocol: str
    status: str
    created_at: datetime

    class Config:
        from_attributes = True


class BeaconRegister(BaseModel):
    hostname: str
    ip: str
    user: str


class BeaconResponse(BaseModel):
    id: int
    user_id: int
    hostname: str
    ip: str
    user: str
    last_seen: datetime
    status: str
    created_at: datetime

    class Config:
        from_attributes = True


class CommandRequest(BaseModel):
    command: str


class CommandResponse(BaseModel):
    output: str


class BeaconStatusUpdate(BaseModel):
    status: str


@router.post("/login", response_model=TokenResponse)
async def login(request: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == request.username).first()

    if not user or not verify_password(request.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Usuário ou senha inválidos",
        )

    access_token = create_access_token(data={"sub": user.username})

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "expires_in": 30 * 60,
    }


@router.get("/listeners", response_model=List[ListenerResponse])
async def get_listeners(
    current_user: User = Depends(get_current_user), db: Session = Depends(get_db)
):
    listeners = (
        db.query(Listener)
        .filter(Listener.user_id == current_user.id)
        .all()
    )
    return listeners


@router.post("/listeners", response_model=ListenerResponse)
async def create_listener(
    listener_data: ListenerCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    new_listener = Listener(
        user_id=current_user.id,
        name=listener_data.name,
        host=listener_data.host,
        port=listener_data.port,
        protocol=listener_data.protocol,
        status="ativo",
    )

    db.add(new_listener)
    db.commit()
    db.refresh(new_listener)

    return new_listener


@router.delete("/listeners/{listener_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_listener(
    listener_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    listener = (
        db.query(Listener)
        .filter(
            Listener.id == listener_id, Listener.user_id == current_user.id
        )
        .first()
    )

    if not listener:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Listener não encontrado",
        )

    db.delete(listener)
    db.commit()


@router.get("/beacons", response_model=List[BeaconResponse])
async def get_beacons(
    current_user: User = Depends(get_current_user), db: Session = Depends(get_db)
):
    beacons = (
        db.query(Beacon)
        .filter(Beacon.user_id == current_user.id)
        .all()
    )
    return beacons


@router.post("/beacons", response_model=BeaconResponse)
async def register_beacon(
    beacon_data: BeaconRegister,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    new_beacon = Beacon(
        user_id=current_user.id,
        hostname=beacon_data.hostname,
        ip=beacon_data.ip,
        user=beacon_data.user,
        status="conectado",
        last_seen=datetime.utcnow(),
    )

    db.add(new_beacon)
    db.commit()
    db.refresh(new_beacon)

    return new_beacon


@router.post(
    "/beacons/{beacon_id}/command", response_model=CommandResponse
)
async def send_command_to_beacon(
    beacon_id: int,
    command_request: CommandRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    beacon = (
        db.query(Beacon)
        .filter(
            Beacon.id == beacon_id, Beacon.user_id == current_user.id
        )
        .first()
    )

    if not beacon:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Beacon não encontrado",
        )

    if beacon.status != "conectado":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Beacon não está conectado",
        )

    beacon.last_seen = datetime.utcnow()
    db.commit()

    output = f"Comando executado: {command_request.command}"

    return {"output": output}


@router.put("/beacons/{beacon_id}", response_model=BeaconResponse)
async def update_beacon_status(
    beacon_id: int,
    status_update: BeaconStatusUpdate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    beacon = (
        db.query(Beacon)
        .filter(
            Beacon.id == beacon_id, Beacon.user_id == current_user.id
        )
        .first()
    )

    if not beacon:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Beacon não encontrado",
        )

    beacon.status = status_update.status
    beacon.last_seen = datetime.utcnow()
    db.commit()
    db.refresh(beacon)

    return beacon
