"""
scheduler_engine.py — PenteIA V4.0
Scheduled/continuous BAS automation using APScheduler.
Allows simulations to run automatically on cron schedules.
"""
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from datetime import datetime
import uuid
import logging

logger = logging.getLogger("penteia.scheduler")

_scheduler = BackgroundScheduler(daemon=True)
_scheduler.start()

# In-memory job registry: job_id -> metadata
_JOBS: dict = {}

def _run_simulation(user_id: str, playbook_id: str, target: str, job_id: str):
    """Execute a BAS simulation for a scheduled job."""
    try:
        from database import SessionLocal
        from models import Simulation, Playbook
        from bas_engine import run_simulation_sync

        db = SessionLocal()
        try:
            pb = db.query(Playbook).filter(Playbook.id == playbook_id, Playbook.user_id == user_id).first()
            if not pb:
                logger.warning(f"Scheduled job {job_id}: playbook {playbook_id} not found")
                return

            sim_id = str(uuid.uuid4())
            sim = Simulation(
                id=sim_id,
                target=target,
                playbook_id=playbook_id,
                user_id=user_id,
                status="running",
                score=0.0,
            )
            db.add(sim)
            db.commit()

            # Run simulation (use existing BAS engine if available)
            try:
                results = run_simulation_sync(playbook_id, target, user_id, db)
                sim.status = "completed"
                sim.score = results.get("score", 0.0)
                sim.results = results
            except Exception as e:
                sim.status = "completed"
                sim.score = 0.0
                sim.results = {"error": str(e), "techniques": []}

            db.commit()

            if job_id in _JOBS:
                _JOBS[job_id]["last_run"] = datetime.utcnow().isoformat()
                _JOBS[job_id]["last_sim_id"] = sim_id
                _JOBS[job_id]["run_count"] = _JOBS[job_id].get("run_count", 0) + 1

            logger.info(f"Scheduled job {job_id} completed: sim {sim_id}, score {sim.score}")
        finally:
            db.close()
    except Exception as e:
        logger.error(f"Scheduled job {job_id} error: {e}")


def create_schedule(job_id: str, user_id: str, playbook_id: str, target: str,
                    cron_expr: str, name: str, enabled: bool = True) -> dict:
    """Create or update a scheduled BAS job."""
    parts = cron_expr.strip().split()
    if len(parts) != 5:
        raise ValueError(f"Invalid cron expression: {cron_expr} (need 5 fields: min hour day month weekday)")

    minute, hour, day, month, day_of_week = parts
    trigger = CronTrigger(
        minute=minute, hour=hour, day=day,
        month=month, day_of_week=day_of_week,
    )

    # Remove old job if exists
    if job_id in _JOBS:
        try:
            _scheduler.remove_job(job_id)
        except Exception:
            pass

    meta = {
        "job_id": job_id,
        "user_id": user_id,
        "playbook_id": playbook_id,
        "target": target,
        "cron": cron_expr,
        "name": name,
        "enabled": enabled,
        "created_at": datetime.utcnow().isoformat(),
        "last_run": None,
        "last_sim_id": None,
        "run_count": 0,
    }
    _JOBS[job_id] = meta

    if enabled:
        _scheduler.add_job(
            _run_simulation,
            trigger=trigger,
            id=job_id,
            args=[user_id, playbook_id, target, job_id],
            replace_existing=True,
            misfire_grace_time=3600,
        )

    return meta


def delete_schedule(job_id: str, user_id: str) -> bool:
    """Delete a scheduled job. Returns True if found and deleted."""
    job = _JOBS.get(job_id)
    if not job or job.get("user_id") != user_id:
        return False
    try:
        _scheduler.remove_job(job_id)
    except Exception:
        pass
    del _JOBS[job_id]
    return True


def toggle_schedule(job_id: str, user_id: str, enabled: bool) -> dict:
    """Pause or resume a scheduled job."""
    job = _JOBS.get(job_id)
    if not job or job.get("user_id") != user_id:
        raise KeyError(f"Job {job_id} not found")

    job["enabled"] = enabled
    if enabled:
        try:
            _scheduler.resume_job(job_id)
        except Exception:
            # Re-add if not found
            parts = job["cron"].strip().split()
            minute, hour, day, month, dow = parts
            trigger = CronTrigger(minute=minute, hour=hour, day=day, month=month, day_of_week=dow)
            _scheduler.add_job(
                _run_simulation, trigger=trigger, id=job_id,
                args=[job["user_id"], job["playbook_id"], job["target"], job_id],
                replace_existing=True, misfire_grace_time=3600,
            )
    else:
        try:
            _scheduler.pause_job(job_id)
        except Exception:
            pass

    return job


def list_schedules(user_id: str) -> list:
    """List all schedules for a user."""
    jobs = [j for j in _JOBS.values() if j.get("user_id") == user_id]
    for job in jobs:
        try:
            apjob = _scheduler.get_job(job["job_id"])
            job["next_run"] = apjob.next_run_time.isoformat() if apjob and apjob.next_run_time else None
        except Exception:
            job["next_run"] = None
    return jobs


def get_schedule(job_id: str, user_id: str) -> dict | None:
    """Get a single schedule."""
    job = _JOBS.get(job_id)
    if not job or job.get("user_id") != user_id:
        return None
    return job


# Common cron presets for UI
CRON_PRESETS = [
    {"label": "Diário às 02:00",     "cron": "0 2 * * *"},
    {"label": "Semanal (Segunda 03:00)", "cron": "0 3 * * 1"},
    {"label": "Quinzenal",           "cron": "0 2 1,15 * *"},
    {"label": "Mensal (dia 1)",       "cron": "0 1 1 * *"},
    {"label": "A cada 6 horas",      "cron": "0 */6 * * *"},
    {"label": "Personalizado",        "cron": ""},
]
