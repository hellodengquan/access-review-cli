import json
import os
import getpass
import socket
import uuid
import inspect
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional
from functools import wraps

from .dtutils import utcnow


class AuditLogger:
    def __init__(self, base_dir: Optional[Path] = None):
        if base_dir is None:
            base_dir = Path(os.environ.get("ACCESS_REVIEW_HOME", Path.home() / ".access_review"))
        self.base_dir = base_dir
        self.audit_dir = self.base_dir / "audit"
        self.audit_dir.mkdir(parents=True, exist_ok=True)
        self.current_log_file = self._get_log_file()

    def _get_log_file(self) -> Path:
        today = utcnow().strftime("%Y-%m-%d")
        return self.audit_dir / f"audit_{today}.jsonl"

    def _rotate_if_needed(self) -> None:
        expected = self._get_log_file()
        if self.current_log_file != expected:
            self.current_log_file = expected

    @staticmethod
    def _get_operator() -> Dict[str, str]:
        operator = os.environ.get("ACCESS_REVIEW_OPERATOR")
        if not operator:
            try:
                operator = getpass.getuser()
            except (ImportError, OSError):
                operator = "unknown"
        return {
            "operator": operator,
            "operator_source": "env" if os.environ.get("ACCESS_REVIEW_OPERATOR") else "system",
        }

    @staticmethod
    def _get_host_info() -> Dict[str, str]:
        try:
            hostname = socket.gethostname()
        except (ImportError, OSError):
            hostname = "unknown"
        return {
            "hostname": hostname,
            "pid": str(os.getpid()),
        }

    def log(
        self,
        action: str,
        status: str = "success",
        command: Optional[str] = None,
        params: Optional[Dict[str, Any]] = None,
        result: Optional[Dict[str, Any]] = None,
        error: Optional[str] = None,
        **extra: Any,
    ) -> str:
        self._rotate_if_needed()

        entry_id = str(uuid.uuid4())
        operator_info = self._get_operator()
        host_info = self._get_host_info()

        entry: Dict[str, Any] = {
            "id": entry_id,
            "timestamp": utcnow().isoformat(),
            "action": action,
            "status": status,
            "command": command,
            "params": params or {},
            "result": result or {},
            "error": error,
            **operator_info,
            **host_info,
        }
        entry.update(extra)

        line = json.dumps(entry, ensure_ascii=False, sort_keys=False)
        try:
            with open(self.current_log_file, "a", encoding="utf-8") as f:
                f.write(line + "\n")
        except Exception:
            pass

        return entry_id

    def log_success(
        self,
        action: str,
        command: Optional[str] = None,
        params: Optional[Dict[str, Any]] = None,
        result: Optional[Dict[str, Any]] = None,
        **extra: Any,
    ) -> str:
        return self.log(
            action=action,
            status="success",
            command=command,
            params=params,
            result=result,
            **extra,
        )

    def log_failure(
        self,
        action: str,
        error: str,
        command: Optional[str] = None,
        params: Optional[Dict[str, Any]] = None,
        **extra: Any,
    ) -> str:
        return self.log(
            action=action,
            status="failure",
            command=command,
            params=params,
            error=error,
            **extra,
        )

    def query(
        self,
        action: Optional[str] = None,
        operator: Optional[str] = None,
        status: Optional[str] = None,
        start_date: Optional[str] = None,
        end_date: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []

        log_files = sorted(self.audit_dir.glob("audit_*.jsonl"))

        for log_file in log_files:
            if start_date:
                file_date = log_file.stem.replace("audit_", "")
                if file_date < start_date:
                    continue
            if end_date:
                file_date = log_file.stem.replace("audit_", "")
                if file_date > end_date:
                    continue

            try:
                with open(log_file, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            entry = json.loads(line)
                        except json.JSONDecodeError:
                            continue

                        if action and entry.get("action") != action:
                            continue
                        if operator and operator.lower() not in (entry.get("operator") or "").lower():
                            continue
                        if status and entry.get("status") != status:
                            continue

                        results.append(entry)
                        if len(results) >= limit:
                            return results
            except Exception:
                continue

        return results


_audit_logger: Optional[AuditLogger] = None


def get_audit_logger(base_dir: Optional[Path] = None) -> AuditLogger:
    global _audit_logger
    if _audit_logger is None or (base_dir is not None and _audit_logger.base_dir != base_dir):
        _audit_logger = AuditLogger(base_dir)
    return _audit_logger


def audit_command(action_name: Optional[str] = None):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            from .storage import Storage

            storage = None
            for arg in args:
                if isinstance(arg, Storage):
                    storage = arg
                    break
            if storage is None and "storage" in kwargs:
                storage = kwargs["storage"]

            base_dir = storage.base_dir if storage else None
            logger = get_audit_logger(base_dir)

            sig = inspect.signature(func)
            bound = sig.bind_partial(*args, **kwargs)
            bound.apply_defaults()
            params = {}
            for k, v in bound.arguments.items():
                if k == "storage":
                    continue
                try:
                    json.dumps(v)
                    params[k] = v
                except (TypeError, ValueError):
                    params[k] = str(v)

            action = action_name or func.__name__

            try:
                result = func(*args, **kwargs)
            except Exception as exc:
                logger.log_failure(
                    action=action,
                    error=str(exc),
                    command=None,
                    params=params,
                )
                raise

            result_summary: Dict[str, Any] = {}
            if isinstance(result, dict):
                for k in ("count", "total", "affected", "status"):
                    if k in result:
                        result_summary[k] = result[k]
                if not result_summary:
                    result_summary["type"] = "dict"
            elif result is not None:
                result_summary["result"] = str(result)[:120]

            logger.log_success(
                action=action,
                command=None,
                params=params,
                result=result_summary or None,
            )

            return result

        return wrapper

    return decorator
