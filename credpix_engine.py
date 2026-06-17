"""
credpix_engine.py — PenteIA V4.0
CredPix Finance — integração PIX para pagamentos de assinatura e horas extras.
API docs: credpix.finance/api
"""
import httpx

_BASE = "https://credpix.finance/api"
_TOKEN = "45a74a8c9d4e0971d38681f3b722e287"


def create_pix(amount_brl: int, pagador_id: str) -> dict:
    """
    Gera cobrança PIX via CredPix.
    amount_brl: valor inteiro em reais (mínimo R$10).
    pagador_id: identificador do pagador (user.id).
    Retorna {"external_id": str, "qr_code": str}.
    """
    if amount_brl < 10:
        raise ValueError(f"Valor mínimo é R$10, recebido R${amount_brl}")
    params = {
        "tokenuser": _TOKEN,
        "valor": int(amount_brl),
        "chatidpagador": str(pagador_id),
    }
    with httpx.Client(timeout=30) as client:
        r = client.get(f"{_BASE}/create.php", params=params)
        r.raise_for_status()
        data = r.json() if r.text.strip() else {}

    status = str(data.get("Status", "")).lower()
    if status not in ("success", "ok"):
        raise RuntimeError(f"CredPix recusou cobrança: {data}")

    return {
        "external_id": data.get("IDPagamento", ""),
        "qr_code": data.get("CopiaeCola", ""),
    }


def verify_pix(external_id: str) -> str:
    """
    Verifica status de pagamento PIX.
    Retorna "confirmed" | "pending" | "expired".
    Nunca lança exceção — retorna "pending" em caso de erro (retry conservador).
    """
    params = {"tokenuser": _TOKEN, "IDPagamento": external_id}
    try:
        with httpx.Client(timeout=30) as client:
            r = client.get(f"{_BASE}/verificar.php", params=params)
            r.raise_for_status()
            data = r.json() if r.text.strip() else {}
        raw = str(data.get("payment_status", "")).lower()
        if "aprovado" in raw:
            return "confirmed"
        if "expirado" in raw:
            return "expired"
        return "pending"
    except Exception:
        return "pending"
