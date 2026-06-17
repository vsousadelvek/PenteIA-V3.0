"""
subscription_engine.py — PenteIA V4.0
Lógica de planos, cota de tempo, limite de ataques simultâneos.
"""
from __future__ import annotations
from datetime import datetime, timedelta
from sqlalchemy.orm import Session

# ---------------------------------------------------------------------------
# Planos e pacotes
# ---------------------------------------------------------------------------

PLANS: dict = {
    "free": {
        "label": "Free",
        "minutes": 10,        # total vitalício (não mensal)
        "concurrent": 1,
        "monthly": False,
        "price_brl": 0,
        "description": "10 minutos de ataque vitalícios",
    },
    "researcher": {
        "label": "Researcher",
        "minutes": 1200,      # 20h/mês
        "concurrent": 2,
        "monthly": True,
        "price_brl": 49,
        "description": "20 horas de ataque por mês, 2 simultâneos",
    },
    "pro": {
        "label": "Pro",
        "minutes": 4800,      # 80h/mês
        "concurrent": 5,
        "monthly": True,
        "price_brl": 149,
        "description": "80 horas de ataque por mês, 5 simultâneos",
    },
    "business": {
        "label": "Business",
        "minutes": None,      # ilimitado
        "concurrent": 15,
        "monthly": True,
        "price_brl": 499,
        "description": "Tempo ilimitado, 15 simultâneos",
    },
}

EXTRA_PACKS: dict = {
    "5h":  {"minutes": 300,  "price_brl": 19, "label": "+5 horas"},
    "15h": {"minutes": 900,  "price_brl": 49, "label": "+15 horas"},
}

RENEWAL_DAYS = 30

# ---------------------------------------------------------------------------
# Limites de força de ataque por plano
# ---------------------------------------------------------------------------
# free: suficiente pra derrubar um servidor simples (VPS pequena, app de teste)
# Os limites são caps — o usuário pode pedir menos, nunca mais.

ATTACK_LIMITS: dict = {
    "free": {
        "max_threads":     50,
        "max_pps":         1_000,
        "max_duration":    60,      # segundos
        "max_connections": 300,     # Slowloris
        "max_workers":     20,      # recon / BAS workers
    },
    "researcher": {
        "max_threads":     200,
        "max_pps":         10_000,
        "max_duration":    300,
        "max_connections": 2_000,
        "max_workers":     100,
    },
    "pro": {
        "max_threads":     500,
        "max_pps":         50_000,
        "max_duration":    600,
        "max_connections": 5_000,
        "max_workers":     300,
    },
    "business": {
        "max_threads":     1_000,
        "max_pps":         200_000,
        "max_duration":    3_600,
        "max_connections": 10_000,
        "max_workers":     1_000,
    },
}


def get_attack_limits(user) -> dict:
    """Retorna os caps de força de ataque para o usuário (considera expiração)."""
    plan_type = user.plan_type or "free"
    now = datetime.utcnow()
    if plan_type != "free" and user.plan_expires_at and user.plan_expires_at < now:
        plan_type = "free"
    return ATTACK_LIMITS.get(plan_type) or ATTACK_LIMITS["free"]


def clamp_attack_params(user, **kwargs) -> dict:
    """
    Clamp parâmetros de ataque aos limites do plano.
    Aceita: threads, pps, duration, connections, workers.
    Retorna dict com os valores clampeados.
    """
    limits = get_attack_limits(user)
    mapping = {
        "threads":     "max_threads",
        "pps":         "max_pps",
        "duration":    "max_duration",
        "connections": "max_connections",
        "workers":     "max_workers",
    }
    result = {}
    for param, limit_key in mapping.items():
        if param in kwargs and kwargs[param] is not None:
            result[param] = min(int(kwargs[param]), limits[limit_key])
    return result


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def get_plan(plan_type: str) -> dict:
    return PLANS.get(plan_type) or PLANS["free"]


def _active_sessions_count(user_id: str, db: Session) -> int:
    from models import UsageSession
    return db.query(UsageSession).filter(
        UsageSession.user_id == user_id,
        UsageSession.ended_at == None,  # noqa: E711
    ).count()


# ---------------------------------------------------------------------------
# Gate de acesso
# ---------------------------------------------------------------------------

def can_start_attack(user, db: Session) -> tuple[bool, str]:
    """
    Verifica se o usuário pode iniciar um novo ataque.
    Retorna (permitido: bool, motivo: str).
    """
    plan_type = user.plan_type or "free"
    plan = get_plan(plan_type)
    now = datetime.utcnow()

    # Plano pago expirado → trata como free
    if plan_type != "free" and user.plan_expires_at and user.plan_expires_at < now:
        plan_type = "free"
        plan = get_plan("free")

    # Verificação de cota de tempo (business = ilimitado)
    if plan["minutes"] is not None:
        quota = user.minutes_quota if user.minutes_quota is not None else plan["minutes"]
        used = user.minutes_used or 0
        if used >= quota:
            if plan_type == "free":
                return False, (
                    "Seus 10 minutos gratuitos foram utilizados. "
                    "Assine um plano via PIX para continuar."
                )
            return False, (
                f"Cota mensal esgotada ({quota // 60}h usadas). "
                "Adicione horas extras via PIX ou aguarde a renovação."
            )

    # Verificação de ataques simultâneos
    active = _active_sessions_count(user.id, db)
    if active >= plan["concurrent"]:
        return False, (
            f"Limite de {plan['concurrent']} ataque(s) simultâneo(s) atingido. "
            "Aguarde um terminar ou faça upgrade do plano."
        )

    return True, "ok"


# ---------------------------------------------------------------------------
# Sessões de uso
# ---------------------------------------------------------------------------

def open_session(user_id: str, session_type: str, db: Session, reference_id: str = None) -> str:
    """Abre uma UsageSession (ataque iniciado). Retorna session_id."""
    from models import UsageSession
    import uuid
    session = UsageSession(
        id=str(uuid.uuid4()),
        user_id=user_id,
        session_type=session_type,
        started_at=datetime.utcnow(),
        reference_id=reference_id,
    )
    db.add(session)
    db.commit()
    return session.id


def close_session(session_id: str, db: Session) -> int:
    """
    Fecha uma UsageSession e desconta minutos da cota do usuário.
    Retorna minutos cobrados (mínimo 1).
    """
    from models import UsageSession, User
    session = db.query(UsageSession).filter(UsageSession.id == session_id).first()
    if not session or session.ended_at:
        return 0

    now = datetime.utcnow()
    session.ended_at = now
    elapsed = max(1, int((now - session.started_at).total_seconds() / 60))
    session.minutes_billed = elapsed

    user = db.query(User).filter(User.id == session.user_id).first()
    if user:
        plan = get_plan(user.plan_type or "free")
        if plan["minutes"] is not None:  # business não conta
            user.minutes_used = (user.minutes_used or 0) + elapsed

    db.commit()
    return elapsed


def close_session_by_ref(reference_id: str, session_type: str, db: Session) -> int:
    """Fecha sessão pelo reference_id (simulation_id, job_id, etc.)."""
    from models import UsageSession
    session = db.query(UsageSession).filter(
        UsageSession.reference_id == reference_id,
        UsageSession.session_type == session_type,
        UsageSession.ended_at == None,  # noqa: E711
    ).first()
    if not session:
        return 0
    return close_session(session.id, db)


# ---------------------------------------------------------------------------
# Ativação de plano e horas extras
# ---------------------------------------------------------------------------

def activate_plan(user, plan_type: str, db: Session):
    """Ativa ou renova assinatura. Renova a partir do vencimento atual se ainda ativo."""
    plan = PLANS.get(plan_type)
    if not plan or plan["price_brl"] == 0:
        raise ValueError(f"Plano inválido para ativação: {plan_type}")

    now = datetime.utcnow()
    current_expiry = user.plan_expires_at

    if current_expiry and current_expiry > now and user.plan_type == plan_type:
        # Renovação antes do vencimento — estende
        user.plan_expires_at = current_expiry + timedelta(days=RENEWAL_DAYS)
    else:
        # Novo plano ou upgrade
        user.plan_expires_at = now + timedelta(days=RENEWAL_DAYS)
        user.minutes_used = 0  # reset ao trocar/iniciar plano

    user.plan_type = plan_type
    user.minutes_quota = plan["minutes"]
    db.commit()


def add_extra_hours(user, pack_key: str, db: Session) -> int:
    """Adiciona horas extras de um pacote PIX. Retorna minutos adicionados."""
    pack = EXTRA_PACKS.get(pack_key)
    if not pack:
        raise ValueError(f"Pacote inválido: {pack_key}")
    user.minutes_quota = (user.minutes_quota or 0) + pack["minutes"]
    db.commit()
    return pack["minutes"]


# ---------------------------------------------------------------------------
# Status do usuário
# ---------------------------------------------------------------------------

def get_user_billing_status(user, db: Session) -> dict:
    """Retorna status completo de billing para o usuário."""
    plan_type = user.plan_type or "free"
    plan = get_plan(plan_type)
    now = datetime.utcnow()

    plan_active = True
    days_left = None
    if plan_type != "free" and user.plan_expires_at:
        plan_active = user.plan_expires_at > now
        days_left = max(0, (user.plan_expires_at - now).days)

    quota = user.minutes_quota if user.minutes_quota is not None else plan["minutes"]
    used = user.minutes_used or 0
    unlimited = quota is None

    limits = get_attack_limits(user)
    return {
        "plan": plan_type,
        "plan_label": plan["label"],
        "plan_active": plan_active,
        "plan_expires_at": user.plan_expires_at.isoformat() if user.plan_expires_at else None,
        "days_left": days_left,
        "minutes_quota": quota,
        "minutes_used": used,
        "minutes_remaining": None if unlimited else max(0, quota - used),
        "hours_remaining": None if unlimited else round(max(0, quota - used) / 60, 1),
        "unlimited": unlimited,
        "max_concurrent": plan["concurrent"],
        "active_attacks": _active_sessions_count(user.id, db),
        "price_brl": plan["price_brl"],
        "attack_limits": limits,
    }
