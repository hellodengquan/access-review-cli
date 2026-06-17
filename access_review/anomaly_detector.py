from datetime import datetime, timedelta
from typing import List, Dict, Any, Tuple
from collections import defaultdict

from .models import (
    UserPermission,
    AnomalyReport,
    AnomalyType,
    SeverityLevel,
    PermissionStatus,
)
from .storage import Storage
from .dtutils import utcnow

MAX_UNUSED_DAYS = 365 * 3
MIN_UNUSED_DAYS = 1


class AnomalyDetector:
    def __init__(self, storage: Storage, unused_days: int = 90, high_risk_roles=None, high_risk_resources=None):
        self.storage = storage
        if not isinstance(unused_days, int):
            raise ValueError(f"unused_days 必须是整数，当前类型: {type(unused_days)}")
        if unused_days < MIN_UNUSED_DAYS or unused_days > MAX_UNUSED_DAYS:
            raise ValueError(
                f"unused_days 必须在 {MIN_UNUSED_DAYS} 到 {MAX_UNUSED_DAYS} 天之间，"
                f"当前值: {unused_days}"
            )
        self.unused_days = unused_days
        self.high_risk_roles = high_risk_roles or ["admin", "superuser", "root", "owner"]
        self.high_risk_resources = high_risk_resources or ["production", "prod", "database", "db", "pii"]

    def detect_all(self) -> List[AnomalyReport]:
        permissions = self.storage.list_permissions()
        active_permissions = [p for p in permissions if p.status == PermissionStatus.ACTIVE]

        anomalies = []
        anomalies.extend(self.detect_unused_permissions(active_permissions))
        anomalies.extend(self.detect_expired_permissions(active_permissions))
        anomalies.extend(self.detect_over_privileged(active_permissions))
        anomalies.extend(self.detect_suspicious_patterns(active_permissions))

        for anomaly in anomalies:
            self.storage.save_anomaly(anomaly)

        return anomalies

    def detect_unused_permissions(self, permissions: List[UserPermission]) -> List[AnomalyReport]:
        anomalies = []
        now = utcnow()
        threshold_date = now - timedelta(days=self.unused_days)

        for perm in permissions:
            is_unused = False
            if perm.last_used_date:
                if perm.last_used_date < threshold_date:
                    is_unused = True
            else:
                if perm.granted_date < threshold_date:
                    is_unused = True

            if is_unused:
                days_unused = (now - (perm.last_used_date or perm.granted_date)).days
                anomaly = AnomalyReport(
                    id=Storage.generate_id(),
                    permission_id=perm.id,
                    anomaly_type=AnomalyType.UNUSED_LONG_TERM,
                    severity=SeverityLevel.MEDIUM,
                    description=f"权限已超过 {days_unused} 天未使用",
                    detected_date=now,
                )
                anomalies.append(anomaly)

        return anomalies

    def detect_expired_permissions(self, permissions: List[UserPermission]) -> List[AnomalyReport]:
        anomalies = []
        now = utcnow()

        for perm in permissions:
            if perm.expiry_date and perm.expiry_date < now:
                days_expired = (now - perm.expiry_date).days
                anomaly = AnomalyReport(
                    id=Storage.generate_id(),
                    permission_id=perm.id,
                    anomaly_type=AnomalyType.EXPIRED_ACCESS,
                    severity=SeverityLevel.HIGH,
                    description=f"权限已过期 {days_expired} 天，应立即收回",
                    detected_date=now,
                )
                anomalies.append(anomaly)

        return anomalies

    def detect_over_privileged(self, permissions: List[UserPermission]) -> List[AnomalyReport]:
        anomalies = []
        now = utcnow()
        perm_counts: Dict[Tuple[str, str], int] = defaultdict(int)

        for perm in permissions:
            key = (perm.username, perm.department)
            perm_counts[key] += 1

        for perm in permissions:
            key = (perm.username, perm.department)
            count = perm_counts[key]
            role_lower = perm.role.lower()
            resource_lower = perm.resource.lower()
            perm_level_lower = perm.permission_level.lower()

            is_high_risk = False
            risk_reasons = []

            if any(hr in role_lower for hr in self.high_risk_roles):
                is_high_risk = True
                risk_reasons.append(f"高危角色: {perm.role}")

            if any(hr in resource_lower for hr in self.high_risk_resources):
                is_high_risk = True
                risk_reasons.append(f"高危资源: {perm.resource}")

            if perm_level_lower in ["write", "admin", "owner", "full"]:
                is_high_risk = True
                risk_reasons.append(f"高权限级别: {perm.permission_level}")

            if count > 10:
                is_high_risk = True
                risk_reasons.append(f"权限数量过多: {count} 个")

            if is_high_risk:
                severity = SeverityLevel.HIGH if len(risk_reasons) >= 2 else SeverityLevel.MEDIUM
                anomaly = AnomalyReport(
                    id=Storage.generate_id(),
                    permission_id=perm.id,
                    anomaly_type=AnomalyType.OVER_PRIVILEGED,
                    severity=severity,
                    description="潜在越权风险: " + "; ".join(risk_reasons),
                    detected_date=now,
                )
                anomalies.append(anomaly)

        return anomalies

    def detect_suspicious_patterns(self, permissions: List[UserPermission]) -> List[AnomalyReport]:
        anomalies = []
        now = utcnow()
        thirty_days_ago = now - timedelta(days=30)

        recent_high_risk = [
            p for p in permissions
            if p.granted_date > thirty_days_ago
            and p.status == PermissionStatus.ACTIVE
        ]

        dept_perms: Dict[str, List[UserPermission]] = defaultdict(list)
        for perm in recent_high_risk:
            dept_perms[perm.department].append(perm)

        for dept, perms in dept_perms.items():
            if len(perms) >= 5:
                for perm in perms:
                    anomaly = AnomalyReport(
                        id=Storage.generate_id(),
                        permission_id=perm.id,
                        anomaly_type=AnomalyType.SUSPICIOUS_PATTERN,
                        severity=SeverityLevel.MEDIUM,
                        description=f"部门 {dept} 近期 ({len(perms)} 个) 权限授予异常集中",
                        detected_date=now,
                    )
                    anomalies.append(anomaly)

        return anomalies

    def get_summary(self, unresolved_only: bool = True) -> Dict[str, Any]:
        anomalies = self.storage.list_anomalies(unresolved_only=unresolved_only)
        permissions = self.storage.list_permissions()
        active_perms = [p for p in permissions if p.status == PermissionStatus.ACTIVE]

        by_type: Dict[str, int] = defaultdict(int)
        by_severity: Dict[str, int] = defaultdict(int)
        affected_permission_ids = set()

        for anomaly in anomalies:
            by_type[anomaly.anomaly_type.value] += 1
            by_severity[anomaly.severity.value] += 1
            affected_permission_ids.add(anomaly.permission_id)

        high_risk_perms = [
            p for p in active_perms
            if p.id in affected_permission_ids
            and any(a.severity == SeverityLevel.HIGH for a in anomalies if a.permission_id == p.id)
        ]

        return {
            "total_anomalies": len(anomalies),
            "by_type": dict(by_type),
            "by_severity": dict(by_severity),
            "affected_permissions": len(affected_permission_ids),
            "total_active_permissions": len(active_perms),
            "high_risk_count": len(high_risk_perms),
            "unused_threshold_days": self.unused_days,
        }

    def get_revoke_candidates(self) -> List[Dict[str, Any]]:
        anomalies = self.storage.list_anomalies(unresolved_only=True)
        permissions = self.storage.list_permissions()
        perm_map = {p.id: p for p in permissions}

        candidates = []
        for anomaly in anomalies:
            perm = perm_map.get(anomaly.permission_id)
            if not perm or perm.status != PermissionStatus.ACTIVE:
                continue

            if anomaly.anomaly_type in [AnomalyType.EXPIRED_ACCESS, AnomalyType.UNUSED_LONG_TERM]:
                candidates.append({
                    "permission": perm,
                    "anomaly": anomaly,
                    "priority": "critical" if anomaly.severity == SeverityLevel.HIGH else "normal",
                })

        candidates.sort(key=lambda x: (x["priority"] != "critical", x["anomaly"].detected_date))
        return candidates

    def mark_resolved(self, anomaly_id: str, notes: str) -> bool:
        anomaly = self.storage.load_anomaly(anomaly_id)
        if not anomaly:
            return False

        anomaly.resolved = True
        anomaly.resolved_date = utcnow()
        anomaly.resolution_notes = notes
        self.storage.save_anomaly(anomaly)
        return True
