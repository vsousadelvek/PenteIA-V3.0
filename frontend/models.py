from datetime import datetime
from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey, Float, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship

Base = declarative_base()


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    username = Column(String(50), unique=True, nullable=False, index=True)
    email = Column(String(120), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    listeners = relationship("Listener", back_populates="user", cascade="all, delete-orphan")
    beacons = relationship("Beacon", back_populates="user", cascade="all, delete-orphan")
    playbooks = relationship("Playbook", back_populates="user", cascade="all, delete-orphan")
    simulations = relationship("Simulation", back_populates="user", cascade="all, delete-orphan")
    reports = relationship("Report", back_populates="user", cascade="all, delete-orphan")
    payloads = relationship("Payload", back_populates="user", cascade="all, delete-orphan")


class Listener(Base):
    __tablename__ = "listeners"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    name = Column(String(100), nullable=False)
    host = Column(String(255), nullable=False)
    port = Column(Integer, nullable=False)
    protocol = Column(String(20), nullable=False)
    status = Column(String(20), default="ativo", index=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    user = relationship("User", back_populates="listeners")


class Beacon(Base):
    __tablename__ = "beacons"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    hostname = Column(String(255), nullable=False)
    ip = Column(String(45), nullable=False, index=True)
    user = Column(String(100), nullable=False)
    last_seen = Column(DateTime, default=datetime.utcnow)
    status = Column(String(20), default="conectado", index=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    user_rel = relationship("User", back_populates="beacons")


class Playbook(Base):
    __tablename__ = "playbooks"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    name = Column(String(200), nullable=False)
    techniques = Column(Text, nullable=False)
    severity = Column(String(20), nullable=False)
    description = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)

    user = relationship("User", back_populates="playbooks")
    simulations = relationship("Simulation", back_populates="playbook", cascade="all, delete-orphan")


class Simulation(Base):
    __tablename__ = "simulations"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    playbook_id = Column(Integer, ForeignKey("playbooks.id"), nullable=False, index=True)
    target = Column(String(255), nullable=False)
    status = Column(String(20), default="pendente", index=True)
    score = Column(Float, default=0.0)
    date = Column(DateTime, default=datetime.utcnow)

    user = relationship("User", back_populates="simulations")
    playbook = relationship("Playbook", back_populates="simulations")


class Report(Base):
    __tablename__ = "reports"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    title = Column(String(255), nullable=False)
    type = Column(String(50), nullable=False)
    format = Column(String(20), nullable=False)
    content = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    user = relationship("User", back_populates="reports")


class Payload(Base):
    __tablename__ = "payloads"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    name = Column(String(200), nullable=False)
    type = Column(String(50), nullable=False)
    size = Column(Integer, nullable=False)
    content = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    user = relationship("User", back_populates="payloads")
