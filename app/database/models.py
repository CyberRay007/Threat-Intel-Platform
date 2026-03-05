# app/database/models.py
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, JSON, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from datetime import datetime

Base = declarative_base()

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    password_hash = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    scans = relationship("Scan", back_populates="user")


class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    target_url = Column(String, nullable=False)
    status = Column(String, default="pending")  # pending, running, completed
    created_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)

    user = relationship("User", back_populates="scans")
    result = relationship("ScanResult", uselist=False, back_populates="scan")


class ScanResult(Base):
    __tablename__ = "scan_results"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False, index=True)
    # intelligence scores
    structural_score = Column(Integer, default=0)
    vt_score = Column(Integer, default=0)
    ioc_score = Column(Integer, default=0)
    risk_score = Column(Integer, default=0)
    # legacy/backwards fields
    domain_score = Column(Integer, default=0)
    structure_score = Column(Integer, default=0)
    behavior_score = Column(Integer, default=0)
    exploit_score = Column(Integer, default=0)
    total_score = Column(Integer, default=0)
    risk_level = Column(String, default="low")  # low, medium, high, critical
    details = Column(JSON, default={})
    # additional data
    signals_json = Column(JSON, default={})
    vt_raw_json = Column(JSON, default={})
    summary = Column(Text, default="")

    scan = relationship("Scan", back_populates="result")


class ThreatActor(Base):
    __tablename__ = "threat_actor"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    description = Column(Text)
    first_seen = Column(DateTime)
    last_seen = Column(DateTime)

    iocs = relationship("IOC", back_populates="threat_actor")


class FileScan(Base):
    __tablename__ = "file_scans"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    filename = Column(String, nullable=False)
    sha256 = Column(String, nullable=False, index=True)
    vt_score = Column(Integer, default=0)
    risk_score = Column(Integer, default=0)
    vt_raw_json = Column(JSON, default={})
    status = Column(String, default="pending")
    created_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)

    user = relationship("User")


class IOC(Base):
    __tablename__ = "ioc"

    id = Column(Integer, primary_key=True, index=True)
    type = Column(String, nullable=False)
    value = Column(String, nullable=False, index=True)
    threat_actor_id = Column(Integer, ForeignKey("threat_actor.id"))
    source = Column(String)

    threat_actor = relationship("ThreatActor", back_populates="iocs")