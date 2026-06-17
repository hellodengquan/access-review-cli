from datetime import datetime
from enum import Enum
from typing import Optional, List, Union, Type, TypeVar
from pydantic import BaseModel, Field, ConfigDict, field_validator

from .dtutils import utcnow, ensure_utc, parse_iso_datetime


E = TypeVar("E", bound=Enum)


def _coerce_enum(value: Union[str, E, None], enum_cls: Type[E]) -> Optional[E]:
    if value is None:
        return None
    if isinstance(value, enum_cls):
        return value
    if isinstance(value, str):
        try:
            return enum_cls(value.lower())
        except ValueError:
            valid = ", ".join(e.value for e in enum_cls)
            raise ValueError(
                f"非法值 '{value}'，允许的值为: {valid}"
            ) from None
    raise ValueError(f"不支持的类型: {type(value)}")


def _coerce_enum_list(values: Union[List[str], List[E], None], enum_cls: Type[E]) -> List[E]:
    if values is None:
        return []
    result = []
    for v in values:
        result.append(_coerce_enum(v, enum_cls))
    return result


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


class SeverityLevel(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    CRITICAL = "critical"


def _coerce_utc(v: Optional[Union[datetime, str]]) -> Optional[datetime]:
    if v is None:
        return v
    if isinstance(v, str):
        return parse_iso_datetime(v)
    return ensure_utc(v)


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
    created_at: datetime = Field(default_factory=utcnow)
    updated_at: datetime = Field(default_factory=utcnow)

    @field_validator(
        "granted_date", "last_used_date", "expiry_date",
        "created_at", "updated_at", mode="before",
    )
    @classmethod
    def _coerce_utc_field(cls, v: Optional[Union[datetime, str]]) -> Optional[datetime]:
        return _coerce_utc(v)

    @field_validator("status", mode="before")
    @classmethod
    def _coerce_status(cls, v: Union[str, PermissionStatus, None]) -> PermissionStatus:
        if v is None:
            return PermissionStatus.ACTIVE
        return _coerce_enum(v, PermissionStatus)


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
    created_at: datetime = Field(default_factory=utcnow)

    @field_validator(
        "review_date", "follow_up_date", "created_at", mode="before",
    )
    @classmethod
    def _coerce_utc_field(cls, v: Optional[Union[datetime, str]]) -> Optional[datetime]:
        return _coerce_utc(v)

    @field_validator("result", mode="before")
    @classmethod
    def _coerce_result(cls, v: Union[str, ReviewResult]) -> ReviewResult:
        result = _coerce_enum(v, ReviewResult)
        if result is None:
            raise ValueError("result 不能为空")
        return result

    @field_validator("anomaly_types", mode="before")
    @classmethod
    def _coerce_anomaly_types(cls, v: Optional[Union[List[str], List[AnomalyType]]]) -> List[AnomalyType]:
        return _coerce_enum_list(v, AnomalyType)


class AnomalyReport(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    id: str
    permission_id: str
    anomaly_type: AnomalyType
    severity: SeverityLevel
    description: str
    detected_date: datetime
    resolved: bool = False
    resolved_date: Optional[datetime] = None
    resolution_notes: Optional[str] = None

    @field_validator("detected_date", "resolved_date", mode="before")
    @classmethod
    def _coerce_utc_field(cls, v: Optional[Union[datetime, str]]) -> Optional[datetime]:
        return _coerce_utc(v)

    @field_validator("anomaly_type", mode="before")
    @classmethod
    def _coerce_anomaly_type(cls, v: Union[str, AnomalyType]) -> AnomalyType:
        result = _coerce_enum(v, AnomalyType)
        if result is None:
            raise ValueError("anomaly_type 不能为空")
        return result

    @field_validator("severity", mode="before")
    @classmethod
    def _coerce_severity(cls, v: Union[str, SeverityLevel]) -> SeverityLevel:
        result = _coerce_enum(v, SeverityLevel)
        if result is None:
            raise ValueError("severity 不能为空")
        return result


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
    created_at: datetime = Field(default_factory=utcnow)

    @field_validator("start_date", "end_date", "created_at", mode="before")
    @classmethod
    def _coerce_utc_field(cls, v: Optional[Union[datetime, str]]) -> Optional[datetime]:
        return _coerce_utc(v)
