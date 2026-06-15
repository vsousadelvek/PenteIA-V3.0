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
    credits = Column(Integer, default=0, server_default='0')
    status = Column(String, default="active", server_default="'active'")
    created_at = Column(DateTime, default=datetime.utcnow)

    listeners = relationship("Listener", back_populates="user", cascade="all, delete-orphan")
    beacons = relationship("Beacon", back_populates="user_rel", cascade="all, delete-orphan")
    playbooks = relationship("Playbook", back_populates="user", cascade="all, delete-orphan")
    simulations = relationship("Simulation", back_populates="user", cascade="all, delete-orphan")
    reports = relationship("Report", back_populates="user", cascade="all, delete-orphan")
    payloads = relationship("Payload", back_populates="user", cascade="all, delete-orphan")
    penteia_agents = relationship("PenteiaAgent", back_populates="owner", cascade="all, delete-orphan")

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
