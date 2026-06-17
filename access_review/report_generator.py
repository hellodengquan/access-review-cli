from datetime import datetime
from typing import List, Dict, Any, Optional
from pathlib import Path
import csv
import json
from collections import defaultdict

from .models import UserPermission, ReviewRecord, AnomalyReport, ReviewCycle, AnomalyType
from .storage import Storage


class ReportGenerator:
    def __init__(self, storage: Storage):
        self.storage = storage

    def generate_review_summary(self, cycle: Optional[ReviewCycle] = None) -> Dict[str, Any]:
        permissions = self.storage.list_permissions()
        reviews = self.storage.list_reviews()
        anomalies = self.storage.list_anomalies(unresolved_only=True)

        if cycle:
            reviews = [
                r for r in reviews
                if cycle.start_date <= r.review_date <= (cycle.end_date or datetime.now())
            ]

        total_perms = len(permissions)
        active_perms = [p for p in permissions if p.status == "active"]
        reviewed_perm_ids = set(r.permission_id for r in reviews)
        reviewed_perms = [p for p in active_perms if p.id in reviewed_perm_ids]
        unreviewed_perms = [p for p in active_perms if p.id not in reviewed_perm_ids]

        approved = [r for r in reviews if r.result == "approved"]
        to_revoke = [r for r in reviews if r.result == "revoke_recommended"]
        escalated = [r for r in reviews if r.result == "escalated"]

        by_department: Dict[str, Dict[str, Any]] = defaultdict(lambda: {
            "total": 0, "reviewed": 0, "approved": 0, "to_revoke": 0, "anomalies": 0
        })

        perm_reviews_map = defaultdict(list)
        for r in reviews:
            perm_reviews_map[r.permission_id].append(r)

        for perm in active_perms:
            dept = perm.department
            by_department[dept]["total"] += 1
            if perm.id in reviewed_perm_ids:
                by_department[dept]["reviewed"] += 1
                perm_reviews = perm_reviews_map.get(perm.id, [])
                if any(r.result == "approved" for r in perm_reviews):
                    by_department[dept]["approved"] += 1
                if any(r.result == "revoke_recommended" for r in perm_reviews):
                    by_department[dept]["to_revoke"] += 1

        anomaly_perm_ids = set(a.permission_id for a in anomalies)
        for perm in active_perms:
            if perm.id in anomaly_perm_ids:
                by_department[perm.department]["anomalies"] += 1

        return {
            "generated_at": datetime.now().isoformat(),
            "cycle": cycle.model_dump(mode="json") if cycle else None,
            "summary": {
                "total_permissions": total_perms,
                "active_permissions": len(active_perms),
                "reviewed_count": len(reviewed_perms),
                "unreviewed_count": len(unreviewed_perms),
                "review_progress": f"{len(reviewed_perms)}/{len(active_perms)}" if active_perms else "0/0",
                "review_progress_pct": round(len(reviewed_perms) / len(active_perms) * 100, 1) if active_perms else 0,
                "approved_count": len(approved),
                "revoke_recommended_count": len(to_revoke),
                "escalated_count": len(escalated),
                "total_anomalies": len(anomalies),
            },
            "by_department": dict(by_department),
            "anomalies": [a.model_dump(mode="json") for a in anomalies],
            "to_revoke_list": [
                {
                    "permission": self.storage.load_permission(r.permission_id).model_dump(mode="json")
                    if self.storage.load_permission(r.permission_id) else None,
                    "review": r.model_dump(mode="json"),
                }
                for r in to_revoke
            ],
        }

    def generate_revoke_list(self) -> List[Dict[str, Any]]:
        reviews = self.storage.list_reviews()
        to_revoke_reviews = [r for r in reviews if r.result == "revoke_recommended"]

        seen_permissions = set()
        result = []
        for review in to_revoke_reviews:
            perm = self.storage.load_permission(review.permission_id)
            if perm and perm.status != "revoked" and perm.id not in seen_permissions:
                seen_permissions.add(perm.id)
                result.append({
                    "permission_id": perm.id,
                    "username": perm.username,
                    "email": perm.email,
                    "department": perm.department,
                    "role": perm.role,
                    "resource": perm.resource,
                    "permission_level": perm.permission_level,
                    "granted_date": perm.granted_date.isoformat(),
                    "reviewer": review.reviewer,
                    "review_date": review.review_date.isoformat(),
                    "review_comments": review.comments or "",
                })
        return result

    def export_to_csv(self, data: List[Dict[str, Any]], output_path: Path, default_headers: Optional[List[str]] = None) -> None:
        if not data:
            if default_headers:
                with open(output_path, "w", newline="", encoding="utf-8-sig") as f:
                    writer = csv.DictWriter(f, fieldnames=default_headers)
                    writer.writeheader()
            return

        fieldnames = list(data[0].keys())
        with open(output_path, "w", newline="", encoding="utf-8-sig") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(data)

    def export_revoke_list_csv(self, output_path: Path) -> int:
        revoke_list = self.generate_revoke_list()
        default_headers = [
            "permission_id", "username", "email", "department", "role",
            "resource", "permission_level", "granted_date", "reviewer",
            "review_date", "review_comments"
        ]
        self.export_to_csv(revoke_list, output_path, default_headers=default_headers)
        return len(revoke_list)

    def export_permission_list_csv(self, output_path: Path, status: Optional[str] = None) -> int:
        permissions = self.storage.list_permissions()
        if status:
            permissions = [p for p in permissions if p.status == status]

        data = [
            {
                "id": p.id,
                "username": p.username,
                "email": p.email,
                "department": p.department,
                "role": p.role,
                "resource": p.resource,
                "permission_level": p.permission_level,
                "granted_date": p.granted_date.isoformat(),
                "last_used_date": p.last_used_date.isoformat() if p.last_used_date else "",
                "expiry_date": p.expiry_date.isoformat() if p.expiry_date else "",
                "status": p.status.value if hasattr(p.status, 'value') else str(p.status),
                "granted_by": p.granted_by or "",
                "description": p.description or "",
                "tags": ",".join(p.tags),
            }
            for p in permissions
        ]
        default_headers = [
            "id", "username", "email", "department", "role",
            "resource", "permission_level", "granted_date",
            "last_used_date", "expiry_date", "status",
            "granted_by", "description", "tags"
        ]
        self.export_to_csv(data, output_path, default_headers=default_headers)
        return len(data)

    def generate_anomaly_report(self, output_path: Optional[Path] = None) -> Dict[str, Any]:
        anomalies = self.storage.list_anomalies(unresolved_only=True)
        permissions = self.storage.list_permissions()
        perm_map = {p.id: p for p in permissions}

        by_type: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        for anomaly in anomalies:
            perm = perm_map.get(anomaly.permission_id)
            by_type[anomaly.anomaly_type.value].append({
                "anomaly": anomaly.model_dump(mode="json"),
                "permission": perm.model_dump(mode="json") if perm else None,
            })

        report = {
            "generated_at": datetime.now().isoformat(),
            "total_unresolved": len(anomalies),
            "by_type": {k: v for k, v in by_type.items()},
        }

        if output_path:
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2, ensure_ascii=False)

        return report

    def generate_user_report(self, username: str) -> Dict[str, Any]:
        permissions = self.storage.list_permissions()
        user_perms = [p for p in permissions if p.username.lower() == username.lower()]
        reviews = []
        for perm in user_perms:
            reviews.extend(self.storage.get_reviews_for_permission(perm.id))
        anomalies = []
        for perm in user_perms:
            anomalies.extend(self.storage.get_anomalies_for_permission(perm.id))

        return {
            "generated_at": datetime.now().isoformat(),
            "username": username,
            "permissions": [p.model_dump(mode="json") for p in user_perms],
            "reviews": [r.model_dump(mode="json") for r in reviews],
            "anomalies": [a.model_dump(mode="json") for a in anomalies],
            "permission_count": len(user_perms),
            "active_count": len([p for p in user_perms if p.status == "active"]),
            "anomaly_count": len([a for a in anomalies if not a.resolved]),
        }
