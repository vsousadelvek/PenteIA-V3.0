"""
ext_router_billing.py — PenteIA V4.0
Endpoints de billing: PIX via CredPix, assinaturas, horas extras, status de plano.
"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from auth import get_current_user
from models import User, PixDeposit
from pydantic import BaseModel
from typing import Optional
from datetime import datetime, timedelta
import uuid

billing_router = APIRouter()

try:
    from credpix_engine import create_pix, verify_pix
    _HAS_CREDPIX = True
except ImportError:
    _HAS_CREDPIX = False

try:
    from subscription_engine import (
        PLANS, EXTRA_PACKS,
        get_user_billing_status, activate_plan, add_extra_hours,
        can_start_attack, open_session, close_session,
    )
    _HAS_SUB = True
except ImportError:
    _HAS_SUB = False


def _get_db():
    from database import SessionLocal
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ── Status e planos ──────────────────────────────────────────────────────────

@billing_router.get("/billing/status", tags=["Billing"])
async def billing_status(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(_get_db),
):
    if not _HAS_SUB:
        raise HTTPException(503, "subscription_engine não disponível")
    return get_user_billing_status(current_user, db)


@billing_router.get("/billing/plans", tags=["Billing"])
async def billing_plans():
    if not _HAS_SUB:
        raise HTTPException(503, "subscription_engine não disponível")
    return {"plans": PLANS, "extra_packs": EXTRA_PACKS}


# ── Assinar plano via PIX ────────────────────────────────────────────────────

class SubscribeRequest(BaseModel):
    plan: str  # researcher | pro | business


@billing_router.post("/billing/subscribe", tags=["Billing"])
async def billing_subscribe(
    req: SubscribeRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(_get_db),
):
    if not _HAS_CREDPIX or not _HAS_SUB:
        raise HTTPException(503, "Billing não disponível")
    plan = PLANS.get(req.plan)
    if not plan or plan["price_brl"] == 0:
        raise HTTPException(400, f"Plano inválido: {req.plan}")

    amount = plan["price_brl"]
    try:
        pix = create_pix(amount, str(current_user.id))
    except Exception as e:
        raise HTTPException(502, f"Erro ao gerar PIX: {e}")

    deposit = PixDeposit(
        id=str(uuid.uuid4()),
        user_id=current_user.id,
        deposit_type="subscription",
        plan_type=req.plan,
        extra_pack=None,
        amount_brl=amount,
        minutes_granted=plan["minutes"],
        external_id=pix["external_id"],
        qr_code=pix["qr_code"],
        status="pending",
        expires_at=datetime.utcnow() + timedelta(minutes=30),
    )
    db.add(deposit)
    db.commit()

    return {
        "deposit_id": deposit.id,
        "plan": req.plan,
        "plan_label": plan["label"],
        "amount_brl": amount,
        "qr_code": pix["qr_code"],
        "external_id": pix["external_id"],
        "expires_at": deposit.expires_at.isoformat(),
        "message": (
            f"PIX gerado com sucesso! Pague R${amount} para ativar o plano "
            f"{plan['label']} por 30 dias."
        ),
    }


# ── Comprar horas extras via PIX ─────────────────────────────────────────────

class ExtraHoursRequest(BaseModel):
    pack: str  # 5h | 15h


@billing_router.post("/billing/extra-hours", tags=["Billing"])
async def billing_extra_hours(
    req: ExtraHoursRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(_get_db),
):
    if not _HAS_CREDPIX or not _HAS_SUB:
        raise HTTPException(503, "Billing não disponível")
    pack = EXTRA_PACKS.get(req.pack)
    if not pack:
        raise HTTPException(400, f"Pacote inválido: {req.pack}. Use: 5h | 15h")

    plan_type = current_user.plan_type or "free"
    if plan_type == "free":
        raise HTTPException(
            403,
            "Horas extras são exclusivas para assinantes. Assine um plano primeiro."
        )

    amount = pack["price_brl"]
    try:
        pix = create_pix(amount, str(current_user.id))
    except Exception as e:
        raise HTTPException(502, f"Erro ao gerar PIX: {e}")

    deposit = PixDeposit(
        id=str(uuid.uuid4()),
        user_id=current_user.id,
        deposit_type="extra_hours",
        plan_type=None,
        extra_pack=req.pack,
        amount_brl=amount,
        minutes_granted=pack["minutes"],
        external_id=pix["external_id"],
        qr_code=pix["qr_code"],
        status="pending",
        expires_at=datetime.utcnow() + timedelta(minutes=30),
    )
    db.add(deposit)
    db.commit()

    return {
        "deposit_id": deposit.id,
        "pack": req.pack,
        "pack_label": pack["label"],
        "minutes": pack["minutes"],
        "amount_brl": amount,
        "qr_code": pix["qr_code"],
        "external_id": pix["external_id"],
        "expires_at": deposit.expires_at.isoformat(),
        "message": f"PIX gerado! Pague R${amount} para adicionar {pack['label']}.",
    }


# ── Status de depósito (polling do frontend) ─────────────────────────────────

@billing_router.get("/billing/deposit/{deposit_id}", tags=["Billing"])
async def billing_deposit_status(
    deposit_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(_get_db),
):
    deposit = db.query(PixDeposit).filter(
        PixDeposit.id == deposit_id,
        PixDeposit.user_id == current_user.id,
    ).first()
    if not deposit:
        raise HTTPException(404, "Depósito não encontrado")
    return {
        "deposit_id": deposit.id,
        "status": deposit.status,
        "amount_brl": deposit.amount_brl,
        "deposit_type": deposit.deposit_type,
        "plan_type": deposit.plan_type,
        "extra_pack": deposit.extra_pack,
        "minutes_granted": deposit.minutes_granted,
        "confirmed_at": deposit.confirmed_at.isoformat() if deposit.confirmed_at else None,
    }


# ── Histórico de depósitos ───────────────────────────────────────────────────

@billing_router.get("/billing/deposits", tags=["Billing"])
async def billing_deposits(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(_get_db),
):
    deposits = (
        db.query(PixDeposit)
        .filter(PixDeposit.user_id == current_user.id)
        .order_by(PixDeposit.created_at.desc())
        .limit(30)
        .all()
    )
    return {
        "deposits": [
            {
                "id": d.id,
                "type": d.deposit_type,
                "plan": d.plan_type,
                "pack": d.extra_pack,
                "amount_brl": d.amount_brl,
                "minutes": d.minutes_granted,
                "status": d.status,
                "created_at": d.created_at.isoformat(),
                "confirmed_at": d.confirmed_at.isoformat() if d.confirmed_at else None,
            }
            for d in deposits
        ]
    }


# ── Admin: ajuste manual de plano ────────────────────────────────────────────

class AdminSetPlanRequest(BaseModel):
    user_id: str
    plan: str
    days: Optional[int] = 30


@billing_router.post("/admin/billing/set-plan", tags=["Admin Billing"])
async def admin_set_plan(
    req: AdminSetPlanRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(_get_db),
):
    if not current_user.is_admin:
        raise HTTPException(403, "Acesso restrito a administradores")
    if not _HAS_SUB:
        raise HTTPException(503, "subscription_engine não disponível")

    target = db.query(User).filter(User.id == req.user_id).first()
    if not target:
        raise HTTPException(404, "Usuário não encontrado")

    plan = PLANS.get(req.plan)
    if not plan:
        raise HTTPException(400, f"Plano inválido: {req.plan}")

    target.plan_type = req.plan
    target.plan_expires_at = datetime.utcnow() + timedelta(days=req.days) if req.plan != "free" else None
    target.minutes_quota = plan["minutes"]
    target.minutes_used = 0
    db.commit()

    return {
        "user_id": req.user_id,
        "plan": req.plan,
        "expires_at": target.plan_expires_at.isoformat() if target.plan_expires_at else None,
        "message": f"Plano {plan['label']} ativado por {req.days} dias.",
    }
