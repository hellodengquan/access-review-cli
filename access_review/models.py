from datetime import datetime
from enum import Enum
from typing import Optional, List
from pydantic import BaseModel, Field, ConfigDict


class PermissionStatus(str, Enum):
    ACTIVE = "active"
    EXPIRED = "expired"
    REVOKED = "revoked"
    PENDING_REVIEW = "pending_review"


class ReviewResult(str, Enum):
    APPROVED = "approved"
    REVOKE_RECOMMENDED = "revoke_recommended"
    ESCALATED = "escalated"
    PENDING = "pending"


class AnomalyType(str, Enum):
    OVER_PRIVILEGED = "over_privileged"
    UNUSED_LONG_TERM = "unused_long_term"
    EXPIRED_ACCESS = "expired_access"
    SUSPICIOUS_PATTERN = "suspicious_pattern"


class UserPermission(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    id: str
    username: str
    email: str
    department: str
    role: str
    resource: str
    permission_level: str
    granted_date: datetime
    last_used_date: Optional[datetime] = None
    expiry_date: Optional[datetime] = None
    status: PermissionStatus = PermissionStatus.ACTIVE
    granted_by: Optional[str] = None
    description: Optional[str] = None
    tags: List[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=datetime.now)
    updated_at: datetime = Field(default_factory=datetime.now)


class ReviewRecord(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    id: str
    permission_id: str
    reviewer: str
    review_date: datetime
    result: ReviewResult
    comments: Optional[str] = None
    anomaly_types: List[AnomalyType] = Field(default_factory=list)
    follow_up_date: Optional[datetime] = None
    created_at: datetime = Field(default_factory=datetime.now)


class AnomalyReport(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    id: str
    permission_id: str
    anomaly_type: AnomalyType
    severity: str
    description: str
    detected_date: datetime
    resolved: bool = False
    resolved_date: Optional[datetime] = None
    resolution_notes: Optional[str] = None


class ReviewCycle(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    id: str
    name: str
    quarter: str
    year: int
    start_date: datetime
    end_date: Optional[datetime] = None
    status: str = "in_progress"
    description: Optional[str] = None
    created_at: datetime = Field(default_factory=datetime.now)
