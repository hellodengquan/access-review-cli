import json
import os
import uuid
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Type, TypeVar, Dict, Any
from rich.console import Console
from pydantic import ValidationError

from .models import (
    UserPermission,
    ReviewRecord,
    AnomalyReport,
    ReviewCycle,
)
from .dtutils import utcnow

T = TypeVar("T", UserPermission, ReviewRecord, AnomalyReport, ReviewCycle)

console = Console()


class Storage:
    def __init__(self, base_dir: Optional[Path] = None):
        if base_dir is None:
            base_dir = Path.home() / ".access_review"
        self.base_dir = base_dir
        self.data_dir = self.base_dir / "data"
        self._ensure_directories()

    def _ensure_directories(self) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        for subdir in ["permissions", "reviews", "anomalies", "cycles"]:
            (self.data_dir / subdir).mkdir(exist_ok=True)

    def _get_file_path(self, data_type: str, id: str) -> Path:
        return self.data_dir / data_type / f"{id}.json"

    def _get_dir_path(self, data_type: str) -> Path:
        return self.data_dir / data_type

    @staticmethod
    def generate_id() -> str:
        return str(uuid.uuid4())

    def save(self, obj: T, data_type: str) -> None:
        file_path = self._get_file_path(data_type, obj.id)
        obj_dict = obj.model_dump(mode="json")
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(obj_dict, f, indent=2, ensure_ascii=False)

    def load(self, id: str, data_type: str, model_class: Type[T]) -> Optional[T]:
        file_path = self._get_file_path(data_type, id)
        if not file_path.exists():
            return None
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return model_class(**data)

    def delete(self, id: str, data_type: str) -> bool:
        file_path = self._get_file_path(data_type, id)
        if file_path.exists():
            file_path.unlink()
            return True
        return False

    def list_all(self, data_type: str, model_class: Type[T]) -> List[T]:
        dir_path = self._get_dir_path(data_type)
        items = []
        for file_path in sorted(dir_path.glob("*.json")):
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            items.append(model_class(**data))
        return items

    def save_permission(self, permission: UserPermission) -> None:
        permission.updated_at = utcnow()
        self.save(permission, "permissions")

    def load_permission(self, id: str) -> Optional[UserPermission]:
        return self.load(id, "permissions", UserPermission)

    def list_permissions(self) -> List[UserPermission]:
        return self.list_all("permissions", UserPermission)

    def delete_permission(self, id: str) -> bool:
        return self.delete(id, "permissions")

    def save_review(self, review: ReviewRecord) -> None:
        self.save(review, "reviews")

    def load_review(self, id: str) -> Optional[ReviewRecord]:
        return self.load(id, "reviews", ReviewRecord)

    def list_reviews(self) -> List[ReviewRecord]:
        return self.list_all("reviews", ReviewRecord)

    def get_reviews_for_permission(self, permission_id: str) -> List[ReviewRecord]:
        reviews = self.list_reviews()
        return [r for r in reviews if r.permission_id == permission_id]

    def save_anomaly(self, anomaly: AnomalyReport) -> None:
        self.save(anomaly, "anomalies")

    def load_anomaly(self, id: str) -> Optional[AnomalyReport]:
        return self.load(id, "anomalies", AnomalyReport)

    def list_anomalies(self, unresolved_only: bool = False) -> List[AnomalyReport]:
        anomalies = self.list_all("anomalies", AnomalyReport)
        if unresolved_only:
            anomalies = [a for a in anomalies if not a.resolved]
        return anomalies

    def get_anomalies_for_permission(self, permission_id: str) -> List[AnomalyReport]:
        anomalies = self.list_anomalies()
        return [a for a in anomalies if a.permission_id == permission_id]

    def save_cycle(self, cycle: ReviewCycle) -> None:
        self.save(cycle, "cycles")

    def load_cycle(self, id: str) -> Optional[ReviewCycle]:
        return self.load(id, "cycles", ReviewCycle)

    def list_cycles(self) -> List[ReviewCycle]:
        cycles = self.list_all("cycles", ReviewCycle)
        return sorted(cycles, key=lambda c: c.created_at, reverse=True)

    def get_active_cycle(self) -> Optional[ReviewCycle]:
        cycles = self.list_cycles()
        for cycle in cycles:
            if cycle.status == "in_progress":
                return cycle
        return None

    def export_to_json(self, output_path: Path, data_type: Optional[str] = None) -> None:
        export_data: Dict[str, Any] = {}
        if data_type is None or data_type == "permissions":
            permissions = self.list_permissions()
            export_data["permissions"] = [p.model_dump(mode="json") for p in permissions]
        if data_type is None or data_type == "reviews":
            reviews = self.list_reviews()
            export_data["reviews"] = [r.model_dump(mode="json") for r in reviews]
        if data_type is None or data_type == "anomalies":
            anomalies = self.list_anomalies()
            export_data["anomalies"] = [a.model_dump(mode="json") for a in anomalies]
        if data_type is None or data_type == "cycles":
            cycles = self.list_cycles()
            export_data["cycles"] = [c.model_dump(mode="json") for c in cycles]

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(export_data, f, indent=2, ensure_ascii=False)

    @staticmethod
    def _normalize_identity(perm: UserPermission) -> str:
        if perm.email and perm.email.strip():
            return perm.email.strip().lower()
        username = perm.username.strip().lower()
        for suffix in ("_ext", "_tmp", "-ext", "-tmp", ".ext", ".tmp"):
            if username.endswith(suffix):
                username = username[: -len(suffix)]
        parts = username.split("_")
        if len(parts) >= 2 and parts[-1].isdigit():
            username = "_".join(parts[:-1])
        return username

    @staticmethod
    def _permission_business_key(perm: UserPermission, use_email: bool = True) -> tuple:
        identity = (
            Storage._normalize_identity(perm)
            if use_email
            else perm.username.lower()
        )
        return (
            identity,
            perm.resource.lower(),
            perm.role.lower(),
        )

    @staticmethod
    def _merge_permissions(target: UserPermission, source: UserPermission) -> UserPermission:
        if target.granted_date and source.granted_date:
            if source.granted_date > target.granted_date:
                target.id = source.id
                target.granted_date = source.granted_date
                target.permission_level = source.permission_level
                target.status = source.status
                target.granted_by = source.granted_by or target.granted_by
        if source.last_used_date:
            if not target.last_used_date or source.last_used_date > target.last_used_date:
                target.last_used_date = source.last_used_date
        if source.expiry_date and not target.expiry_date:
            target.expiry_date = source.expiry_date
        elif source.expiry_date and target.expiry_date:
            if source.expiry_date > target.expiry_date:
                target.expiry_date = source.expiry_date
        if not target.email and source.email:
            target.email = source.email
        if not target.department and source.department:
            target.department = source.department
        elif target.department and source.department and target.department != source.department:
            target.department = target.department + "; " + source.department
        if not target.description and source.description:
            target.description = source.description
        elif source.description and source.description not in target.description:
            target.description = target.description + "; " + source.description
        if source.tags:
            merged_tags = list(dict.fromkeys(list(target.tags) + list(source.tags)))
            target.tags = merged_tags
        return target

    def import_from_json(
        self,
        input_path: Path,
        overwrite: bool = False,
        dedupe: bool = True,
        cross_ou: bool = True,
    ) -> Dict[str, Any]:
        if not input_path.exists():
            raise FileNotFoundError(f"File not found: {input_path}")

        with open(input_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        counts = {
            "permissions": 0,
            "reviews": 0,
            "anomalies": 0,
            "cycles": 0,
            "duplicates_merged": 0,
            "cross_ou_merged": 0,
        }
        errors = []

        required_perm_fields = [
            "id", "username", "email", "department", "role",
            "resource", "permission_level", "granted_date",
        ]

        raw_perms = []
        for idx, perm_data in enumerate(data.get("permissions", [])):
            missing = [f for f in required_perm_fields if f not in perm_data]
            if missing:
                errors.append(
                    f"permissions[{idx}]: 缺少必填字段: {', '.join(missing)}"
                )
                continue
            try:
                perm = UserPermission(**perm_data)
                raw_perms.append(perm)
            except ValidationError as exc:
                errors.append(f"permissions[{idx}] (id={perm_data.get('id', '?')}): {exc}")
                continue

        if dedupe and raw_perms:
            deduped: Dict[tuple, UserPermission] = {}
            for perm in raw_perms:
                key = self._permission_business_key(perm, use_email=cross_ou)
                if key in deduped:
                    prev_dept = deduped[key].department
                    deduped[key] = self._merge_permissions(deduped[key], perm)
                    counts["duplicates_merged"] += 1
                    if cross_ou and prev_dept != deduped[key].department and ";" in deduped[key].department:
                        counts["cross_ou_merged"] += 1
                else:
                    deduped[key] = perm
            perms_to_import = list(deduped.values())
        else:
            perms_to_import = raw_perms

        if dedupe:
            existing_perms = self.list_permissions()
            existing_by_key: Dict[tuple, UserPermission] = {}
            for ep in existing_perms:
                key = self._permission_business_key(ep, use_email=cross_ou)
                existing_by_key[key] = ep

            final_perms = []
            for perm in perms_to_import:
                key = self._permission_business_key(perm, use_email=cross_ou)
                if key in existing_by_key:
                    existing = existing_by_key[key]
                    prev_dept = existing.department
                    merged = self._merge_permissions(existing.model_copy(deep=True), perm)
                    if overwrite or merged != existing:
                        final_perms.append(merged)
                        counts["duplicates_merged"] += 1
                        if cross_ou and prev_dept != merged.department and ";" in merged.department:
                            counts["cross_ou_merged"] += 1
                else:
                    final_perms.append(perm)
            perms_to_import = final_perms

        for perm in perms_to_import:
            if overwrite or not self.load_permission(perm.id):
                self.save_permission(perm)
                counts["permissions"] += 1

        required_review_fields = [
            "id", "permission_id", "reviewer", "review_date", "result",
        ]
        for idx, review_data in enumerate(data.get("reviews", [])):
            missing = [f for f in required_review_fields if f not in review_data]
            if missing:
                errors.append(
                    f"reviews[{idx}]: 缺少必填字段: {', '.join(missing)}"
                )
                continue
            try:
                review = ReviewRecord(**review_data)
            except ValidationError as exc:
                errors.append(f"reviews[{idx}] (id={review_data.get('id', '?')}): {exc}")
                continue
            existing = self.load_review(review.id)
            if overwrite or not existing:
                self.save_review(review)
                counts["reviews"] += 1

        required_anomaly_fields = [
            "id", "permission_id", "anomaly_type", "severity",
            "description", "detected_date",
        ]
        for idx, anomaly_data in enumerate(data.get("anomalies", [])):
            missing = [f for f in required_anomaly_fields if f not in anomaly_data]
            if missing:
                errors.append(
                    f"anomalies[{idx}]: 缺少必填字段: {', '.join(missing)}"
                )
                continue
            try:
                anomaly = AnomalyReport(**anomaly_data)
            except ValidationError as exc:
                errors.append(f"anomalies[{idx}] (id={anomaly_data.get('id', '?')}): {exc}")
                continue
            existing = self.load_anomaly(anomaly.id)
            if overwrite or not existing:
                self.save_anomaly(anomaly)
                counts["anomalies"] += 1

        required_cycle_fields = ["id", "name", "quarter", "year", "start_date"]
        for idx, cycle_data in enumerate(data.get("cycles", [])):
            missing = [f for f in required_cycle_fields if f not in cycle_data]
            if missing:
                errors.append(
                    f"cycles[{idx}]: 缺少必填字段: {', '.join(missing)}"
                )
                continue
            try:
                cycle = ReviewCycle(**cycle_data)
            except ValidationError as exc:
                errors.append(f"cycles[{idx}] (id={cycle_data.get('id', '?')}): {exc}")
                continue
            existing = self.load_cycle(cycle.id)
            if overwrite or not existing:
                self.save_cycle(cycle)
                counts["cycles"] += 1

        if errors:
            error_msg = "数据导入校验失败:\n" + "\n".join(errors)
            raise ValueError(error_msg)

        return counts

    def get_stats(self) -> Dict[str, Any]:
        permissions = self.list_permissions()
        reviews = self.list_reviews()
        anomalies = self.list_anomalies()
        cycles = self.list_cycles()

        active_perms = [p for p in permissions if p.status == "active"]
        expired_perms = [p for p in permissions if p.status == "expired"]
        revoked_perms = [p for p in permissions if p.status == "revoked"]
        pending_perms = [p for p in permissions if p.status == "pending_review"]

        unresolved_anomalies = [a for a in anomalies if not a.resolved]
        active_cycles = [c for c in cycles if c.status == "in_progress"]

        return {
            "total_permissions": len(permissions),
            "active_permissions": len(active_perms),
            "expired_permissions": len(expired_perms),
            "revoked_permissions": len(revoked_perms),
            "pending_review": len(pending_perms),
            "total_reviews": len(reviews),
            "total_anomalies": len(anomalies),
            "unresolved_anomalies": len(unresolved_anomalies),
            "total_cycles": len(cycles),
            "active_cycles": len(active_cycles),
        }
