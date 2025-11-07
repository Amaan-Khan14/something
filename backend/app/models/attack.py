from sqlalchemy import Column, Integer, String, Float, DateTime, Text, Boolean, Index
from sqlalchemy.sql import func
from .database import Base


class Attack(Base):
    """Model for storing detected attacks"""
    __tablename__ = "attacks"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime(timezone=True), server_default=func.now(), index=True)
    source_ip = Column(String(45), index=True)  # IPv6 support
    dest_ip = Column(String(45))
    dest_port = Column(Integer)
    url = Column(Text, nullable=False)
    method = Column(String(10))  # GET, POST, etc.
    attack_type = Column(String(100), index=True)  # SQL Injection, XSS, etc.
    attack_subtype = Column(String(100))  # union-based, blind, etc.
    success_status = Column(Boolean, default=False, index=True)
    severity = Column(String(20), index=True)  # Critical, High, Medium, Low
    confidence_score = Column(Float)  # 0-100
    raw_request = Column(Text)
    detection_method = Column(String(50))  # pattern, ml, heuristic, hybrid
    user_agent = Column(Text)
    referer = Column(Text)

    # Indexes for common queries
    __table_args__ = (
        Index('idx_timestamp_attack_type', 'timestamp', 'attack_type'),
        Index('idx_source_ip_timestamp', 'source_ip', 'timestamp'),
        Index('idx_severity_timestamp', 'severity', 'timestamp'),
    )

    def to_dict(self):
        """Convert model to dictionary"""
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "source_ip": self.source_ip,
            "dest_ip": self.dest_ip,
            "dest_port": self.dest_port,
            "url": self.url,
            "method": self.method,
            "attack_type": self.attack_type,
            "attack_subtype": self.attack_subtype,
            "success_status": self.success_status,
            "severity": self.severity,
            "confidence_score": self.confidence_score,
            "raw_request": self.raw_request,
            "detection_method": self.detection_method,
            "user_agent": self.user_agent,
            "referer": self.referer,
        }
