# app/database/models.py
from enum import Enum
from uuid import uuid4

from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, JSON, Text, UniqueConstraint, Boolean, Float
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from datetime import datetime

Base = declarative_base()
JSON_TYPE = JSON().with_variant(JSONB, "postgresql")


class Role(str, Enum):
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"
    API_CLIENT = "api_client"


class Organization(Base):
    __tablename__ = "organizations"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    name = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    users = relationship("User", back_populates="organization")

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    org_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    password_hash = Column(String, nullable=False)
    role = Column(String, default=Role.ANALYST.value, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    organization = relationship("Organization", back_populates="users")
    scans = relationship("Scan", back_populates="user")
    events = relationship("Event", back_populates="user")


class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    org_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    target_url = Column(String, nullable=False)
    status = Column(String, default="pending")  # pending, running, completed
    # Week 3 aligned aggregate fields kept on scans for quick retrieval
    structural_score = Column(Integer, default=0)
    vt_score = Column(Integer, default=0)
    feed_intel_score = Column(Integer, default=0)
    historical_score = Column(Integer, default=0)
    risk_score = Column(Integer, default=0)
    signals = Column(JSON_TYPE, default=dict)
    vt_response = Column(JSON_TYPE, default=dict)
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
    feed_intel_score = Column(Integer, default=0)
    historical_score = Column(Integer, default=0)
    risk_score = Column(Integer, default=0)
    # legacy/backwards fields
    domain_score = Column(Integer, default=0)
    structure_score = Column(Integer, default=0)
    behavior_score = Column(Integer, default=0)
    exploit_score = Column(Integer, default=0)
    total_score = Column(Integer, default=0)
    risk_level = Column(String, default="low")  # low, medium, high, critical
    details = Column(JSON_TYPE, default=dict)
    # additional data
    signals_json = Column(JSON_TYPE, default=dict)
    vt_raw_json = Column(JSON_TYPE, default=dict)
    # Week 3 canonical names (kept alongside legacy names)
    signals = Column(JSON_TYPE, default=dict)
    vt_response = Column(JSON_TYPE, default=dict)
    summary = Column(Text, default="")

    scan = relationship("Scan", back_populates="result")


class ThreatActor(Base):
    __tablename__ = "threat_actors"

    id = Column(Integer, primary_key=True, index=True)
    org_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False, index=True)
    name = Column(String, nullable=False, unique=True, index=True)
    description = Column(Text)
    origin = Column(String)  # country / region attribution
    aliases = Column(JSON_TYPE, default=list)
    first_seen = Column(DateTime)
    last_seen = Column(DateTime)
    created_at = Column(DateTime, default=datetime.utcnow)

    iocs = relationship("IOC", back_populates="threat_actor")
    campaigns = relationship("Campaign", back_populates="threat_actor")
    ioc_relationships = relationship("IOCRelationship", back_populates="threat_actor")


class FileScan(Base):
    __tablename__ = "file_scans"

    id = Column(Integer, primary_key=True, index=True)
    org_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    filename = Column(String, nullable=False)
    sha256 = Column(String, nullable=False, index=True)
    vt_score = Column(Integer, default=0)
    risk_score = Column(Integer, default=0)
    vt_raw_json = Column(JSON_TYPE, default=dict)
    status = Column(String, default="pending")
    created_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)

    user = relationship("User")


class IOC(Base):
    __tablename__ = "ioc"
    __table_args__ = (UniqueConstraint("type", "value", name="uq_ioc_type_value"),)

    id = Column(Integer, primary_key=True, index=True)
    org_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False, index=True)
    type = Column(String, nullable=False)
    value = Column(String, nullable=False, index=True)
    threat_actor_id = Column(Integer, ForeignKey("threat_actors.id"), nullable=True)
    source = Column(String)
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)
    confidence = Column(Float, default=0.5)
    source_reliability = Column(Float, default=0.5)

    threat_actor = relationship("ThreatActor", back_populates="iocs")
    relationships = relationship("IOCRelationship", back_populates="ioc")
    outgoing_graph_relationships = relationship(
        "IOCGraphRelationship",
        foreign_keys="IOCGraphRelationship.source_ioc_id",
        back_populates="source_ioc",
    )
    incoming_graph_relationships = relationship(
        "IOCGraphRelationship",
        foreign_keys="IOCGraphRelationship.target_ioc_id",
        back_populates="target_ioc",
    )


class Event(Base):
    __tablename__ = "events"

    id = Column(Integer, primary_key=True, index=True)
    org_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    source = Column(String, nullable=False, default="api")
    domain = Column(String, nullable=True, index=True)
    url = Column(String, nullable=True, index=True)
    ip = Column(String, nullable=True, index=True)
    file_hash = Column(String, nullable=True, index=True)
    raw_event = Column(JSON_TYPE, default=dict)
    alert_id = Column(Integer, ForeignKey("alerts.id"), nullable=True, index=True)
    event_type = Column(String, nullable=False, default="generic")
    extracted_observables = Column(JSON_TYPE, default=dict)
    matched_iocs = Column(JSON_TYPE, default=dict)
    status = Column(String, nullable=False, default="processed")
    created_at = Column(DateTime, default=datetime.utcnow)

    user = relationship("User", back_populates="events")
    alert = relationship("Alert", back_populates="events")


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    org_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False, index=True)
    fingerprint = Column(String, unique=True, index=True, nullable=False)
    observable_type = Column(String, nullable=False)
    observable_value = Column(String, nullable=False)
    severity = Column(String, nullable=False, default="low")
    title = Column(String, nullable=False)
    description = Column(Text, default="")
    matched_count = Column(Integer, default=0)
    status = Column(String, nullable=False, default="open")
    assigned_to = Column(Integer, ForeignKey("users.id"), nullable=True, index=True)
    first_seen_at = Column(DateTime, default=datetime.utcnow)
    last_seen_at = Column(DateTime, default=datetime.utcnow)
    occurrence_count = Column(Integer, default=1)
    created_at = Column(DateTime, default=datetime.utcnow)

    events = relationship("Event", back_populates="alert")


class MalwareFamily(Base):
    __tablename__ = "malware_families"

    id = Column(Integer, primary_key=True, index=True)
    org_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False, index=True)
    name = Column(String, nullable=False, unique=True, index=True)
    family_type = Column(String)  # ransomware, trojan, worm, spyware, etc.
    description = Column(Text)
    aliases = Column(JSON_TYPE, default=list)
    created_at = Column(DateTime, default=datetime.utcnow)

    ioc_relationships = relationship("IOCRelationship", back_populates="malware_family")


class Campaign(Base):
    __tablename__ = "campaigns"

    id = Column(Integer, primary_key=True, index=True)
    org_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False, index=True)
    name = Column(String, nullable=False, unique=True, index=True)
    description = Column(Text)
    threat_actor_id = Column(Integer, ForeignKey("threat_actors.id"), nullable=True, index=True)
    first_seen = Column(DateTime)
    last_seen = Column(DateTime)
    created_at = Column(DateTime, default=datetime.utcnow)

    threat_actor = relationship("ThreatActor", back_populates="campaigns")
    ioc_relationships = relationship("IOCRelationship", back_populates="campaign")


class IOCRelationship(Base):
    """Links an IOC to a threat actor, malware family, or campaign."""
    __tablename__ = "ioc_relationships"
    __table_args__ = (
        UniqueConstraint(
            "ioc_id", "relationship_type", "related_entity_type", "related_entity_id",
            name="uq_ioc_relationship",
        ),
    )

    id = Column(Integer, primary_key=True, index=True)
    org_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False, index=True)
    ioc_id = Column(Integer, ForeignKey("ioc.id"), nullable=False, index=True)
    relationship_type = Column(String, nullable=False)  # e.g. associated_with, used_by, part_of
    # Denormalised entity discriminator — mirrors the nullable FK that is set
    related_entity_type = Column(String, nullable=False)  # threat_actor | malware_family | campaign
    related_entity_id = Column(Integer, nullable=False)
    # Nullable FKs — only one is populated depending on related_entity_type
    threat_actor_id = Column(Integer, ForeignKey("threat_actors.id"), nullable=True, index=True)
    malware_family_id = Column(Integer, ForeignKey("malware_families.id"), nullable=True, index=True)
    campaign_id = Column(Integer, ForeignKey("campaigns.id"), nullable=True, index=True)
    source = Column(String)
    confidence = Column(Integer, default=50)  # 0-100
    created_at = Column(DateTime, default=datetime.utcnow)

    ioc = relationship("IOC", back_populates="relationships")
    threat_actor = relationship("ThreatActor", back_populates="ioc_relationships")
    malware_family = relationship("MalwareFamily", back_populates="ioc_relationships")
    campaign = relationship("Campaign", back_populates="ioc_relationships")


class IOCGraphRelationship(Base):
    """IOC-to-IOC relationships for graph investigation queries."""

    __tablename__ = "ioc_graph_relationships"
    __table_args__ = (
        UniqueConstraint(
            "source_ioc_id",
            "target_ioc_id",
            "relationship_type",
            name="uq_ioc_graph_relationship",
        ),
    )

    id = Column(Integer, primary_key=True, index=True)
    org_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False, index=True)
    source_ioc_id = Column(Integer, ForeignKey("ioc.id"), nullable=False, index=True)
    target_ioc_id = Column(Integer, ForeignKey("ioc.id"), nullable=False, index=True)
    relationship_type = Column(String, nullable=False)
    confidence = Column(Integer, default=50)
    created_at = Column(DateTime, default=datetime.utcnow)

    source_ioc = relationship("IOC", foreign_keys=[source_ioc_id], back_populates="outgoing_graph_relationships")
    target_ioc = relationship("IOC", foreign_keys=[target_ioc_id], back_populates="incoming_graph_relationships")


class DetectionRule(Base):
    __tablename__ = "detection_rules"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False, unique=True, index=True)
    description = Column(Text, default="")
    rule_type = Column(String, nullable=False, index=True)
    severity = Column(String, nullable=False, default="low")
    enabled = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)


class APIKey(Base):
    __tablename__ = "api_keys"

    id = Column(Integer, primary_key=True, index=True)
    org_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False, index=True)
    key_hash = Column(String, nullable=False, unique=True, index=True)
    permissions = Column(JSON_TYPE, default=list)
    last_used = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class IOCTag(Base):
    __tablename__ = "ioc_tags"
    __table_args__ = (UniqueConstraint("ioc_id", "tag", name="uq_ioc_tag"),)

    id = Column(Integer, primary_key=True, index=True)
    org_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False, index=True)
    ioc_id = Column(Integer, ForeignKey("ioc.id"), nullable=False, index=True)
    tag = Column(String, nullable=False, index=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class AlertHistory(Base):
    __tablename__ = "alert_history"

    id = Column(Integer, primary_key=True, index=True)
    org_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False, index=True)
    alert_id = Column(Integer, ForeignKey("alerts.id"), nullable=False, index=True)
    action = Column(String, nullable=False)
    performed_by = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    details = Column(JSON_TYPE, default=dict)
    timestamp = Column(DateTime, default=datetime.utcnow)