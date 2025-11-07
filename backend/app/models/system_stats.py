from sqlalchemy import Column, Integer, String, DateTime, Float
from sqlalchemy.sql import func
from .database import Base


class SystemStats(Base):
    """Model for storing aggregate system statistics"""
    __tablename__ = "system_stats"

    id = Column(Integer, primary_key=True, index=True)
    stat_type = Column(String(50), index=True)  # daily, hourly, total
    stat_key = Column(String(100))  # attack_type, source_ip, etc.
    stat_value = Column(String(200))
    count = Column(Integer, default=0)
    percentage = Column(Float, default=0.0)
    timestamp = Column(DateTime(timezone=True), server_default=func.now(), index=True)
    period_start = Column(DateTime(timezone=True))
    period_end = Column(DateTime(timezone=True))

    def to_dict(self):
        """Convert model to dictionary"""
        return {
            "id": self.id,
            "stat_type": self.stat_type,
            "stat_key": self.stat_key,
            "stat_value": self.stat_value,
            "count": self.count,
            "percentage": self.percentage,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "period_start": self.period_start.isoformat() if self.period_start else None,
            "period_end": self.period_end.isoformat() if self.period_end else None,
        }
