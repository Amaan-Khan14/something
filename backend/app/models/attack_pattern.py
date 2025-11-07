from sqlalchemy import Column, Integer, String, Text, Float
from .database import Base


class AttackPattern(Base):
    """Model for storing attack detection patterns"""
    __tablename__ = "attack_patterns"

    id = Column(Integer, primary_key=True, index=True)
    pattern_id = Column(String(100), unique=True, index=True)
    attack_type = Column(String(100), index=True)
    attack_subtype = Column(String(100))
    regex_pattern = Column(Text)
    description = Column(Text)
    severity = Column(String(20))
    confidence_weight = Column(Float, default=1.0)
    enabled = Column(Integer, default=1)

    def to_dict(self):
        """Convert model to dictionary"""
        return {
            "id": self.id,
            "pattern_id": self.pattern_id,
            "attack_type": self.attack_type,
            "attack_subtype": self.attack_subtype,
            "regex_pattern": self.regex_pattern,
            "description": self.description,
            "severity": self.severity,
            "confidence_weight": self.confidence_weight,
            "enabled": bool(self.enabled),
        }
