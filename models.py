from sqlalchemy import Column, Integer, String, DateTime, Float, JSON, ForeignKey, Boolean, LargeBinary
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from datetime import datetime
import uuid

Base = declarative_base()

class User(Base):
    __tablename__ = "users"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    username = Column(String, unique=True, index=True, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    password_hash = Column(String, nullable=False)
    is_admin = Column(Boolean, default=False, server_default='0')
    role = Column(String, default="user", server_default="'user'")
    credits = Column(Integer, default=0, server_default='0')  # legado — não usado
    status = Column(String, default="active", server_default="'active'")
    plan_type = Column(String, default="free", server_default="'free'")
    plan_expires_at = Column(DateTime, nullable=True)
    minutes_quota = Column(Integer, nullable=True, default=10)
    minutes_used = Column(Integer, default=0, server_default='0')
    # NOTE: SQLite does NOT add new columns to existing tables via create_all.
    # Fresh installs get this automatically. Existing installs must run:
    #   ALTER TABLE users ADD COLUMN org_id TEXT;
    org_id = Column(String, nullable=True, default=None)
    created_at = Column(DateTime, default=datetime.utcnow)

    listeners = relationship("Listener", back_populates="user", cascade="all, delete-orphan")
    beacons = relationship("Beacon", back_populates="user_rel", cascade="all, delete-orphan")
    playbooks = relationship("Playbook", back_populates="user", cascade="all, delete-orphan")
    simulations = relationship("Simulation", back_populates="user", cascade="all, delete-orphan")
    reports = relationship("Report", back_populates="user", cascade="all, delete-orphan")
    payloads = relationship("Payload", back_populates="user", cascade="all, delete-orphan")
    penteia_agents = relationship("PenteiaAgent", back_populates="owner", cascade="all, delete-orphan")

class Organization(Base):
    __tablename__ = "organizations"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String, nullable=False)
    slug = Column(String, unique=True, index=True, nullable=False)
    owner_user_id = Column(String, ForeignKey("users.id"), nullable=False)
    plan = Column(String, default="starter")  # starter, professional, enterprise, mssp
    max_users = Column(Integer, default=5)
    max_simulations = Column(Integer, default=100)
    settings = Column(JSON, default={})
    white_label_name = Column(String, default="")
    white_label_logo = Column(String, default="")
    created_at = Column(DateTime, default=datetime.utcnow)

    users = relationship("User", foreign_keys="User.org_id", primaryjoin="Organization.id == User.org_id", lazy="dynamic")


class ApiKey(Base):
    __tablename__ = "api_keys"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String, ForeignKey("users.id"), nullable=False)
    name = Column(String, nullable=False)
    key_hash = Column(String, unique=True, nullable=False)
    key_prefix = Column(String, nullable=False)  # first 12 chars for display: "pk_live_a3f8"
    enabled = Column(Boolean, default=True)
    last_used = Column(DateTime, nullable=True)
    requests_count = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.utcnow)

    user = relationship("User")


class SSOConfig(Base):
    __tablename__ = "sso_configs"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    provider = Column(String, nullable=False)  # azure, google, okta, generic
    client_id = Column(String, nullable=False)
    client_secret_enc = Column(String, nullable=False)  # encrypted or plain for now
    extra_config = Column(JSON, default={})  # tenant_id, domain, etc.
    enabled = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class Listener(Base):
    __tablename__ = "listeners"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String, ForeignKey("users.id"), nullable=False)
    name = Column(String, nullable=False)
    host = Column(String, nullable=False)
    port = Column(Integer, nullable=False)
    protocol = Column(String, nullable=False)
    status = Column(String, default="inactive")
    created_at = Column(DateTime, default=datetime.utcnow)

    user = relationship("User", back_populates="listeners")

class Beacon(Base):
    __tablename__ = "beacons"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String, ForeignKey("users.id"), nullable=False)
    hostname = Column(String, nullable=False)
    ip = Column(String, nullable=False)
    user = Column(String, nullable=False)
    last_seen = Column(DateTime, default=datetime.utcnow)
    status = Column(String, default="idle")
    created_at = Column(DateTime, default=datetime.utcnow)

    user_rel = relationship("User", back_populates="beacons")

class Playbook(Base):
    __tablename__ = "playbooks"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String, ForeignKey("users.id"), nullable=False)
    name = Column(String, nullable=False)
    techniques = Column(Integer, default=0)
    severity = Column(String, nullable=False)
    description = Column(String, default="")
    created_at = Column(DateTime, default=datetime.utcnow)

    user = relationship("User", back_populates="playbooks")
    simulations = relationship("Simulation", back_populates="playbook", cascade="all, delete-orphan")

class Simulation(Base):
    __tablename__ = "simulations"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String, ForeignKey("users.id"), nullable=False)
    playbook_id = Column(String, ForeignKey("playbooks.id"), nullable=False)
    target = Column(String, nullable=False)
    status = Column(String, default="pending")
    score = Column(Float, default=0.0)
    date = Column(DateTime, default=datetime.utcnow)
    results = Column(JSON, default={})

    user = relationship("User", back_populates="simulations")
    playbook = relationship("Playbook", back_populates="simulations")

class Report(Base):
    __tablename__ = "reports"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String, ForeignKey("users.id"), nullable=False)
    title = Column(String, nullable=False)
    type = Column(String, nullable=False)
    format = Column(String, nullable=False)
    content = Column(LargeBinary, nullable=True)
    json_data = Column(JSON, default={})
    created_at = Column(DateTime, default=datetime.utcnow)

    user = relationship("User", back_populates="reports")

class Payload(Base):
    __tablename__ = "payloads"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String, ForeignKey("users.id"), nullable=False)
    name = Column(String, nullable=False)
    type = Column(String, nullable=False)
    size = Column(String, nullable=False)
    content = Column(LargeBinary, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    user = relationship("User", back_populates="payloads")


class PenteiaAgent(Base):
    __tablename__ = "penteia_agents"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String, ForeignKey("users.id"), nullable=False)
    hostname = Column(String, nullable=False)
    ip = Column(String, default="")
    os_info = Column(String, default="")
    username = Column(String, default="")
    python_version = Column(String, default="")
    agent_token = Column(String, nullable=True)  # API key for agent auth
    last_seen = Column(DateTime, default=datetime.utcnow)
    status = Column(String, default="active")  # active, lost
    created_at = Column(DateTime, default=datetime.utcnow)

    owner = relationship("User", back_populates="penteia_agents")
    tasks = relationship("AgentTask", back_populates="agent", cascade="all, delete-orphan")


class AgentTask(Base):
    __tablename__ = "agent_tasks"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    agent_id = Column(String, ForeignKey("penteia_agents.id"), nullable=False)
    technique = Column(String, nullable=False)
    status = Column(String, default="pending")  # pending, running, completed, failed
    result = Column(JSON, default={})
    created_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)

    agent = relationship("PenteiaAgent", back_populates="tasks")


class ScheduledScan(Base):
    __tablename__ = "scheduled_scans"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String, ForeignKey("users.id"), nullable=False)
    playbook_id = Column(String, ForeignKey("playbooks.id"), nullable=False)
    target = Column(String, nullable=False)
    interval = Column(String, nullable=False)  # "daily" / "weekly" / "monthly"
    next_run = Column(DateTime, nullable=True)
    last_run = Column(DateTime, nullable=True)
    enabled = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    user = relationship("User")
    playbook = relationship("Playbook")


class WebhookConfig(Base):
    __tablename__ = "webhook_configs"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String, ForeignKey("users.id"), nullable=False)
    name = Column(String, nullable=False)
    url = Column(String, nullable=False)
    events = Column(JSON, default=["simulation_complete"])
    secret = Column(String, nullable=True)
    enabled = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    user = relationship("User")


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String, nullable=True)
    module = Column(String, nullable=False)
    action = Column(String, nullable=False)
    details = Column(String, default="")
    created_at = Column(DateTime, default=datetime.utcnow)


class Campaign(Base):
    __tablename__ = "campaigns"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String, ForeignKey("users.id"), nullable=False)
    status = Column(String, default="pending")
    config = Column(JSON, default={})
    results = Column(JSON, default={})
    report = Column(JSON, default={})
    started_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)

    user = relationship("User")


class Notification(Base):
    __tablename__ = "notifications"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String, ForeignKey("users.id"), nullable=False)
    title = Column(String, nullable=False)
    message = Column(String, nullable=False)
    type = Column(String, default="info")  # info, warning, critical, success
    read = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    user = relationship("User")


class CloudReconResult(Base):
    __tablename__ = "cloud_recon_results"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String, ForeignKey("users.id"), nullable=False)
    host = Column(String, nullable=False)
    company_name = Column(String, default="")
    status = Column(String, default="running")
    cloud_provider = Column(String, default="")
    results = Column(JSON, default={})
    created_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)

    user = relationship("User")


class PhishingCampaign(Base):
    __tablename__ = "phishing_campaigns"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String, ForeignKey("users.id"), nullable=False)
    name = Column(String, nullable=False)
    subject = Column(String, nullable=False)
    sender_name = Column(String, default="IT Security")
    sender_email = Column(String, default="security@company.com")
    body_template = Column(String, default="")
    landing_url = Column(String, default="")
    status = Column(String, default="draft")  # draft, active, completed
    total_targets = Column(Integer, default=0)
    opened = Column(Integer, default=0)
    clicked = Column(Integer, default=0)
    credentials_harvested = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)

    user = relationship("User")
    targets = relationship("PhishingTarget", back_populates="campaign", cascade="all, delete-orphan")


class PhishingTarget(Base):
    __tablename__ = "phishing_targets"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    campaign_id = Column(String, ForeignKey("phishing_campaigns.id"), nullable=False)
    email = Column(String, nullable=False)
    name = Column(String, default="")
    department = Column(String, default="")
    opened = Column(Boolean, default=False)
    clicked = Column(Boolean, default=False)
    credential_harvested = Column(Boolean, default=False)
    opened_at = Column(DateTime, nullable=True)
    clicked_at = Column(DateTime, nullable=True)
    harvested_at = Column(DateTime, nullable=True)
    ip_address = Column(String, default="")
    user_agent = Column(String, default="")
    created_at = Column(DateTime, default=datetime.utcnow)

    campaign = relationship("PhishingCampaign", back_populates="targets")


class SOCValidation(Base):
    __tablename__ = "soc_validations"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String, ForeignKey("users.id"), nullable=False)
    simulation_id = Column(String, ForeignKey("simulations.id"), nullable=True)
    siem_type = Column(String, default="wazuh")
    siem_url = Column(String, default="")
    total_techniques = Column(Integer, default=0)
    detected = Column(Integer, default=0)
    not_detected = Column(Integer, default=0)
    detection_rate_pct = Column(Float, default=0.0)
    results = Column(JSON, default=[])
    status = Column(String, default="completed")
    created_at = Column(DateTime, default=datetime.utcnow)

    user = relationship("User")


class RemediationTicket(Base):
    __tablename__ = "remediation_tickets"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String, ForeignKey("users.id"), nullable=False)
    simulation_id = Column(String, nullable=True)
    technique_id = Column(String, nullable=False)
    title = Column(String, nullable=False)
    description = Column(String, default="")
    severity = Column(String, default="Medium")
    cvss = Column(Float, default=0.0)
    status = Column(String, default="open")  # open, in_progress, resolved, verified
    assignee = Column(String, default="")
    due_date = Column(DateTime, nullable=True)
    remediation_steps = Column(String, default="")
    compliance = Column(JSON, default=[])
    external_ticket_id = Column(String, default="")
    external_system = Column(String, default="")
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow)
    resolved_at = Column(DateTime, nullable=True)

    user = relationship("User")


class PixDeposit(Base):
    """Registro de pagamentos PIX via CredPix (assinaturas e horas extras)."""
    __tablename__ = "pix_deposits"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String, ForeignKey("users.id"), nullable=False)
    deposit_type = Column(String, nullable=False)   # subscription | extra_hours
    plan_type = Column(String, nullable=True)        # researcher | pro | business
    extra_pack = Column(String, nullable=True)       # 5h | 15h
    amount_brl = Column(Integer, nullable=False)
    minutes_granted = Column(Integer, nullable=True)
    external_id = Column(String, nullable=True)      # IDPagamento CredPix
    qr_code = Column(String, nullable=True)          # CopiaeCola PIX
    status = Column(String, default="pending")       # pending | confirmed | expired
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=True)     # PIX expira em 30min
    confirmed_at = Column(DateTime, nullable=True)

    user = relationship("User")


class UsageSession(Base):
    """Rastreamento de tempo real de ataques ativos."""
    __tablename__ = "usage_sessions"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String, ForeignKey("users.id"), nullable=False)
    session_type = Column(String, nullable=False)   # bas | ddos | recon | ad | cloud | phishing | execution
    started_at = Column(DateTime, default=datetime.utcnow)
    ended_at = Column(DateTime, nullable=True)
    minutes_billed = Column(Integer, nullable=True)
    reference_id = Column(String, nullable=True)    # simulation_id ou job_id

    user = relationship("User")


class BenchmarkEntry(Base):
    """Opt-in anonymous benchmark submission — stores client BAS scores per sector."""
    __tablename__ = "benchmark_entries"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    sector = Column(String, nullable=False, index=True)
    score = Column(Float, nullable=False)
    techniques_total = Column(Integer, default=0)
    techniques_passed = Column(Integer, default=0)
    simulation_id = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
