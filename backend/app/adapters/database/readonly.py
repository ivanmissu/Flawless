"""Reference read-only database adapter (``cisre.infrastructure.adapter/v1``).

This module is the first non-Kubernetes acceptance sample of the Plugin-first
roadmap. It turns a product-specific, read-only telemetry transport into the
stable Resource / Evidence / Verification contracts without knowing which
database product sits behind it.

Boundaries enforced here:

* The adapter only requests section names declared in ``DATABASE_READONLY_SECTIONS``.
* The transport must declare ``read_only = True``; the adapter never calls a
  write method and has no write capability in its descriptor.
* Every section read has a deadline. Timeouts, permission errors and transport
  exceptions become typed ``collection_errors``; they never turn into "healthy".
* Transport payloads are copied through an allowlist and sensitive keys are
  removed. Error text is redacted before it leaves the adapter.
* ``verify`` re-reads the real target through the same transport. A receipt from
  an executor is treated as an audit reference only, never as recovery proof.
"""
from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Protocol, runtime_checkable

from ..contracts import (
    AdapterDescriptor,
    EvidenceBundle,
    InfrastructureResource,
    VerificationResult,
)
from ..registry import ADAPTER_REGISTRY, InfrastructureAdapterRegistry
from .spec import DATABASE_DOMAIN_SPEC


DATABASE_READONLY_ADAPTER_VERSION = "1.0.0"
REQUIRED_SECTIONS: tuple[str, ...] = tuple(DATABASE_DOMAIN_SPEC["required_evidence"])
VERIFICATION_SECTIONS: tuple[str, ...] = ("business_probe", "error_rate")
DATABASE_READONLY_SECTIONS: tuple[str, ...] = REQUIRED_SECTIONS + VERIFICATION_SECTIONS

DEFAULT_SECTION_TIMEOUT_SECONDS = 5.0
MAX_SECTION_TIMEOUT_SECONDS = 60.0

# (degraded, critical) thresholds; a value at or above a threshold is graded.
THRESHOLDS: dict[str, tuple[float, float]] = {
    "connections_percent": (85.0, 95.0),
    "replication_lag_seconds": (30.0, 120.0),
    "lock_wait_max_seconds": (30.0, 60.0),
    "waiting_sessions": (1.0, 50.0),
    "capacity_used_percent": (85.0, 95.0),
    "backup_age_hours": (24.0, 72.0),
    "slow_query_count": (10.0, 100.0),
}
# Recovery limits are deliberately as strict as the degraded thresholds above.
RECOVERY_REPLICATION_LAG_SECONDS = 30.0
RECOVERY_ERROR_RATE_PERCENT = 1.0

_SEVERITY_RANK = {"healthy": 0, "unknown": 1, "degraded": 2, "critical": 3}
_SENSITIVE_KEY_PATTERN = re.compile(
    r"(?i)(password|passwd|secret|token|api[_-]?key|private[_-]?key|credential|dsn|connection[_-]?string)"
)
_SECRET_ASSIGNMENT = re.compile(
    r"(?i)\b(password|passwd|pwd|token|secret|api[_-]?key)\s*[=:]\s*[^\s,;&'\"]+"
)
# Any URL carrying userinfo is replaced as a whole: host names inside DSNs are internal too.
_URL_WITH_USERINFO = re.compile(r"[a-zA-Z][a-zA-Z0-9+.-]*://[^\s/]*@\S*")
_SAFE_ID = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.:-]{0,95}$")
_CRITERION_SECTIONS: dict[str, tuple[str, ...]] = {
    "connectivity_recovered": ("connectivity",),
    "replication_healthy": ("replication",),
    "lock_wait_recovered": ("lock_waits",),
    "business_probe_ok": ("business_probe",),
    "error_rate_recovered": ("error_rate",),
}


def redact_message(text: object, *, limit: int = 240) -> str:
    """Remove credentials from free text before it reaches evidence or logs."""
    value = str(text)
    value = _URL_WITH_USERINFO.sub("<redacted-url>", value)
    value = _SECRET_ASSIGNMENT.sub(lambda match: f"{match.group(1)}=<redacted>", value)
    return value[:limit]


@runtime_checkable
class DatabaseTelemetryClient(Protocol):
    """Read-only transport implemented by a database product or DBA platform.

    Implementations must:

    * set ``read_only = True`` and never issue DDL, DML, configuration or
      process-control statements;
    * return only the documented section fields (see ``README.md``), using
      digests rather than raw SQL text and never credentials;
    * resolve credentials server-side from Secret, environment or workload identity.
    """

    read_only: bool
    provider: str
    engine: str

    async def list_targets(self) -> list[dict[str, Any]]: ...

    async def read_section(self, target_id: str, section: str) -> dict[str, Any]: ...


@dataclass(slots=True)
class _Read:
    section: str
    data: dict[str, Any] | None
    error: dict[str, Any] | None
    observed_at: str


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _number(data: dict[str, Any], key: str) -> float | None:
    value = data.get(key)
    if value is None or isinstance(value, bool):
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _grade(value: float, thresholds: tuple[float, float]) -> str:
    degraded, critical = thresholds
    if value >= critical:
        return "critical"
    if value >= degraded:
        return "degraded"
    return "ok"


def _strip_sensitive(value: Any, *, path: str = "section") -> tuple[Any, int]:
    """Return a copy without secret-like keys and the number of removed keys."""
    removed = 0
    if isinstance(value, dict):
        clean: dict[str, Any] = {}
        for key, item in value.items():
            if _SENSITIVE_KEY_PATTERN.search(str(key)):
                removed += 1
                continue
            cleaned, nested = _strip_sensitive(item, path=f"{path}.{key}")
            removed += nested
            clean[str(key)] = cleaned
        return clean, removed
    if isinstance(value, list):
        items = []
        for index, item in enumerate(value):
            cleaned, nested = _strip_sensitive(item, path=f"{path}[{index}]")
            removed += nested
            items.append(cleaned)
        return items, removed
    return value, 0


def _target_from(raw: Any) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise ValueError("database target must be an object")
    target_id = str(raw.get("target_id") or "")
    if not _SAFE_ID.fullmatch(target_id):
        raise ValueError("database target_id must be a stable URL-safe identifier")
    endpoint_ref = str(raw.get("endpoint_ref") or "")
    if not endpoint_ref.startswith("secret://"):
        raise ValueError(
            f"database target {target_id} endpoint_ref must be a secret:// reference, not a connection string"
        )
    raw_labels = raw.get("labels") or {}
    if not isinstance(raw_labels, dict):
        raise ValueError(f"database target {target_id} labels must be a mapping")
    labels = {
        str(key): redact_message(value, limit=120)
        for key, value in raw_labels.items()
        if not _SENSITIVE_KEY_PATTERN.search(str(key))
    }
    return {
        "target_id": target_id,
        "name": redact_message(raw.get("name") or target_id, limit=120),
        "engine": str(raw.get("engine") or "database")[:60],
        "engine_version": str(raw.get("engine_version") or "")[:60],
        "role": str(raw.get("role") or "unknown")[:40],
        "environment": str(raw.get("environment") or "unknown")[:40],
        "region": str(raw.get("region") or "external")[:60],
        "business_service": str(raw.get("business_service") or "")[:80],
        "criticality": str(raw.get("criticality") or "medium")[:20],
        "endpoint_ref": endpoint_ref,
        "labels": labels,
    }


class ReadOnlyDatabaseAdapter:
    """Database domain adapter that wraps a read-only ``DatabaseTelemetryClient``."""

    def __init__(
        self,
        client: DatabaseTelemetryClient,
        *,
        adapter_id: str = "database-readonly",
        display_name: str = "Database read-only adapter",
        version: str = DATABASE_READONLY_ADAPTER_VERSION,
        section_timeout_seconds: float = DEFAULT_SECTION_TIMEOUT_SECONDS,
    ) -> None:
        if getattr(client, "read_only", False) is not True:
            raise TypeError("database telemetry client must declare read_only=True")
        if not 0 < float(section_timeout_seconds) <= MAX_SECTION_TIMEOUT_SECONDS:
            raise ValueError(
                f"section_timeout_seconds must be within (0, {MAX_SECTION_TIMEOUT_SECONDS:g}]"
            )
        self._client = client
        self._timeout = float(section_timeout_seconds)
        self.descriptor = AdapterDescriptor(
            id=adapter_id,
            domain="database",
            display_name=display_name,
            version=version,
            provider=str(getattr(client, "provider", "custom")),
            supported_products=(str(getattr(client, "engine", "database")),),
        )
        self.descriptor.validate()

    # ------------------------------------------------------------------ discover
    async def discover(self, request: dict[str, Any]) -> list[InfrastructureResource]:
        requested_types = [str(item) for item in (request.get("resource_types") or [])]
        if requested_types and "database" not in requested_types:
            return []
        regions = {str(item) for item in (request.get("regions") or [])}
        resources: list[InfrastructureResource] = []
        for raw in await self._client.list_targets():
            target = _target_from(raw)
            if regions and target["region"] not in regions:
                continue
            resources.append(InfrastructureResource(
                id=target["target_id"],
                domain="database",
                name=target["name"],
                provider=self.descriptor.provider,
                subtype=target["engine"],
                environment=target["environment"],
                location=target["region"],
                business_service=target["business_service"],
                criticality=target["criticality"],
                endpoint_ref=target["endpoint_ref"],
                labels=target["labels"],
                facts={
                    "engine": target["engine"],
                    "engine_version": target["engine_version"],
                    "role": target["role"],
                },
            ))
        return resources

    # ------------------------------------------------------------------ evidence
    async def collect_evidence(
        self,
        resource: InfrastructureResource,
        request: dict[str, Any],
    ) -> EvidenceBundle:
        self._require_database(resource)
        requested = [str(item) for item in (request.get("evidence_types") or REQUIRED_SECTIONS)]
        sections = [item for item in dict.fromkeys(requested) if item in DATABASE_READONLY_SECTIONS]
        unsupported = [item for item in dict.fromkeys(requested) if item not in DATABASE_READONLY_SECTIONS]
        timeout = self._effective_timeout(request)

        reads = await self._read_many(resource.id, sections, timeout)
        errors: list[dict[str, Any]] = [
            {"section": item, "kind": "unsupported_section", "message": "section is not part of the database evidence contract"}
            for item in unsupported
        ]
        for item in reads.values():
            if item.error:
                errors.append(item.error)

        signals, metrics, events = self._assess(reads, sections)
        health = self._health(signals, reads, sections)
        metrics["sections_requested"] = len(sections)
        metrics["sections_collected"] = sorted(
            name for name, item in reads.items() if item.data is not None
        )
        return EvidenceBundle(
            resource_id=resource.id,
            domain="database",
            observed_at=_now(),
            health=health,
            signals=signals,
            metrics=metrics,
            events=events,
            dependencies=[],
            collection_errors=errors,
        )

    # --------------------------------------------------------------- verification
    async def verify(
        self,
        resource: InfrastructureResource,
        receipt: dict[str, Any],
        criteria: list[str],
    ) -> VerificationResult:
        self._require_database(resource)
        checked_at = _now()
        receipt = receipt or {}
        receipt_target = str(receipt.get("target_id") or receipt.get("resource_id") or resource.id)
        if receipt_target != resource.id:
            return VerificationResult(
                resource_id=resource.id,
                recovered=None,
                status="unknown",
                checked_at=checked_at,
                message="receipt target does not match the resource; readback refused",
            )
        wanted = [str(item) for item in (criteria or [])]
        if not wanted:
            return VerificationResult(
                resource_id=resource.id,
                recovered=None,
                status="unknown",
                checked_at=checked_at,
                message="no success criteria supplied; recovery cannot be proven",
            )

        needed = sorted({section for item in wanted for section in _CRITERION_SECTIONS.get(item, ())})
        reads = await self._read_many(resource.id, needed, self._timeout)
        checks: list[dict[str, Any]] = []
        for criterion in wanted:
            if criterion not in _CRITERION_SECTIONS:
                checks.append({
                    "criterion": criterion,
                    "passed": None,
                    "status": "unknown",
                    "reason": "criterion is not supported by the database adapter",
                })
                continue
            passed, reason = _CRITERION_EVALUATORS[criterion](reads)
            checks.append({
                "criterion": criterion,
                "passed": passed,
                "status": "passed" if passed is True else "failed" if passed is False else "unknown",
                "reason": reason,
                "observed_at": max(reads[name].observed_at for name in _CRITERION_SECTIONS[criterion]),
            })

        passed_count = sum(1 for item in checks if item["passed"] is True)
        failed_count = sum(1 for item in checks if item["passed"] is False)
        if failed_count:
            recovered: bool | None = False
            status = "failed"
        elif passed_count == len(checks):
            recovered = True
            status = "completed"
        else:
            recovered = None
            status = "unknown"
        return VerificationResult(
            resource_id=resource.id,
            recovered=recovered,
            status=status,
            checked_at=checked_at,
            checks=checks,
            message=f"{passed_count}/{len(checks)} criteria passed on readback; {failed_count} failed",
        )

    # ----------------------------------------------------------------- internals
    @staticmethod
    def _require_database(resource: InfrastructureResource) -> None:
        if resource.domain != "database":
            raise ValueError(f"database adapter cannot handle domain {resource.domain!r}")

    def _effective_timeout(self, request: dict[str, Any]) -> float:
        requested = request.get("deadline_seconds")
        if requested is None:
            return self._timeout
        try:
            value = float(requested)
        except (TypeError, ValueError):
            return self._timeout
        if value <= 0:
            return self._timeout
        return min(self._timeout, value, MAX_SECTION_TIMEOUT_SECONDS)

    async def _read_many(self, target_id: str, sections: list[str], timeout: float) -> dict[str, _Read]:
        results = await asyncio.gather(*(self._read(target_id, name, timeout) for name in sections))
        return {item.section: item for item in results}

    async def _read(self, target_id: str, section: str, timeout: float) -> _Read:
        if section not in DATABASE_READONLY_SECTIONS:
            raise ValueError(f"section {section!r} is not readable by the database adapter")
        observed_at = _now()
        try:
            raw = await asyncio.wait_for(self._client.read_section(target_id, section), timeout=timeout)
        except asyncio.TimeoutError:
            return _Read(section, None, {
                "section": section, "kind": "timeout", "message": f"no response within {timeout:g}s",
            }, observed_at)
        except PermissionError as exc:
            return _Read(section, None, {
                "section": section, "kind": "permission_denied",
                "message": redact_message(exc) or "permission denied",
            }, observed_at)
        except Exception as exc:  # transport failures are data, not adapter crashes
            return _Read(section, None, {
                "section": section, "kind": "client_error",
                "message": f"{type(exc).__name__}: {redact_message(exc)}",
            }, observed_at)

        if not isinstance(raw, dict):
            return _Read(section, None, {
                "section": section, "kind": "invalid_response", "message": "section payload must be an object",
            }, observed_at)
        clean, removed = _strip_sensitive(raw)
        error = None
        if removed:
            error = {
                "section": section, "kind": "redacted", "severity": "warning",
                "message": f"{removed} sensitive field(s) removed from transport payload",
            }
        return _Read(section, clean, error, observed_at)

    def _assess(
        self,
        reads: dict[str, _Read],
        sections: list[str],
    ) -> tuple[list[dict[str, Any]], dict[str, Any], list[dict[str, Any]]]:
        signals: list[dict[str, Any]] = []
        metrics: dict[str, Any] = {}
        events: list[dict[str, Any]] = []

        def signal(kind: str, section: str, value: Any, unit: str, severity: str) -> None:
            observed = reads[section].observed_at if section in reads else _now()
            signals.append({
                "type": kind, "section": section, "value": value, "unit": unit,
                "severity": severity, "observed_at": observed,
            })

        def data(section: str) -> dict[str, Any] | None:
            item = reads.get(section)
            return item.data if item else None

        connectivity = data("connectivity")
        if connectivity is not None:
            if connectivity.get("reachable") is True:
                signal("connectivity", "connectivity", True, "bool", "ok")
            elif connectivity.get("reachable") is False:
                signal("connectivity", "connectivity", False, "bool", "critical")
            else:
                signal("connectivity", "connectivity", None, "bool", "unknown")

        sessions = data("active_sessions")
        if sessions is not None:
            value = _number(sessions, "connections_percent")
            if value is not None:
                metrics["connections_percent"] = value
                signal("connections", "active_sessions", value, "percent",
                       _grade(value, THRESHOLDS["connections_percent"]))
            else:
                signal("connections", "active_sessions", None, "percent", "unknown")

        locks = data("lock_waits")
        if locks is not None:
            waiting = _number(locks, "waiting_sessions")
            max_wait = _number(locks, "max_wait_seconds")
            if waiting is not None:
                metrics["waiting_sessions"] = waiting
                signal("lock_waiters", "lock_waits", waiting, "count",
                       _grade(waiting, THRESHOLDS["waiting_sessions"]))
            else:
                signal("lock_waiters", "lock_waits", None, "count", "unknown")
            if max_wait is not None:
                metrics["lock_wait_max_seconds"] = max_wait
                signal("lock_wait", "lock_waits", max_wait, "s",
                       _grade(max_wait, THRESHOLDS["lock_wait_max_seconds"]))

        replication = data("replication")
        if replication is not None:
            replicas = _number(replication, "replica_count")
            lag = _number(replication, "lag_seconds")
            if replicas == 0:
                signal("replication_lag", "replication", None, "s", "ok")
            elif lag is not None:
                metrics["replication_lag_seconds"] = lag
                signal("replication_lag", "replication", lag, "s",
                       _grade(lag, THRESHOLDS["replication_lag_seconds"]))
            else:
                signal("replication_lag", "replication", None, "s", "unknown")

        capacity = data("capacity")
        if capacity is not None:
            used = _number(capacity, "used_percent")
            if used is not None:
                metrics["capacity_used_percent"] = used
                signal("capacity", "capacity", used, "percent",
                       _grade(used, THRESHOLDS["capacity_used_percent"]))
            else:
                signal("capacity", "capacity", None, "percent", "unknown")

        backup = data("backup_status")
        if backup is not None:
            age = _number(backup, "last_success_age_hours")
            if age is not None:
                metrics["backup_age_hours"] = age
                signal("backup_age", "backup_status", age, "h",
                       _grade(age, THRESHOLDS["backup_age_hours"]))
            else:
                signal("backup_age", "backup_status", None, "h", "unknown")

        slow = data("slow_queries")
        if slow is not None:
            count = _number(slow, "slow_query_count")
            if count is not None:
                metrics["slow_query_count"] = count
                signal("slow_queries", "slow_queries", count, "count",
                       _grade(count, THRESHOLDS["slow_query_count"]))
            else:
                signal("slow_queries", "slow_queries", None, "count", "unknown")

        role = data("instance_role")
        if role is not None:
            metrics["role"] = str(role.get("role") or "unknown")[:40]

        changes = data("recent_changes")
        if changes is not None:
            for item in (changes.get("changes") or [])[:20]:
                if not isinstance(item, dict):
                    continue
                events.append({
                    "type": "change",
                    "at": redact_message(item.get("at") or "", limit=40),
                    "kind": redact_message(item.get("kind") or "unknown", limit=40),
                    "summary": redact_message(item.get("summary") or "", limit=160),
                })

        for name in sections:
            if reads.get(name) is None or reads[name].data is None:
                signal("missing_evidence", name, None, "", "unknown")
        return signals, metrics, events

    @staticmethod
    def _health(
        signals: list[dict[str, Any]],
        reads: dict[str, _Read],
        sections: list[str],
    ) -> str:
        if not sections:
            return "unknown"
        worst = "healthy"
        for item in signals:
            severity = item["severity"]
            if severity == "ok":
                continue
            if _SEVERITY_RANK.get(severity, 1) > _SEVERITY_RANK[worst]:
                worst = severity
        if worst == "healthy" and any(reads.get(name) is None or reads[name].data is None for name in sections):
            return "unknown"
        return worst


# --------------------------------------------------------------- criteria rules
def _eval_connectivity(reads: dict[str, _Read]) -> tuple[bool | None, str]:
    item = reads["connectivity"]
    if item.data is None:
        return None, f"connectivity unavailable ({item.error['kind']})"
    reachable = item.data.get("reachable")
    if reachable is True:
        return True, "target reachable on readback"
    if reachable is False:
        return False, "target unreachable on readback"
    return None, "reachability not reported"


def _eval_replication(reads: dict[str, _Read]) -> tuple[bool | None, str]:
    item = reads["replication"]
    if item.data is None:
        return None, f"replication unavailable ({item.error['kind']})"
    replicas = _number(item.data, "replica_count")
    if replicas == 0:
        return True, "no replicas; replication not applicable"
    lag = _number(item.data, "lag_seconds")
    if lag is None:
        return None, "replica lag not reported"
    if lag <= RECOVERY_REPLICATION_LAG_SECONDS:
        return True, f"replica lag {lag:g}s within recovery limit"
    return False, f"replica lag {lag:g}s above recovery limit"


def _eval_lock_wait(reads: dict[str, _Read]) -> tuple[bool | None, str]:
    item = reads["lock_waits"]
    if item.data is None:
        return None, f"lock waits unavailable ({item.error['kind']})"
    waiting = _number(item.data, "waiting_sessions")
    if waiting is None:
        return None, "waiting sessions not reported"
    if waiting == 0:
        return True, "no waiting sessions on readback"
    return False, f"{waiting:g} sessions still waiting on locks"


def _eval_business_probe(reads: dict[str, _Read]) -> tuple[bool | None, str]:
    item = reads["business_probe"]
    if item.data is None:
        return None, f"business probe unavailable ({item.error['kind']})"
    ok = item.data.get("ok")
    if ok is True:
        return True, "business read/write probe succeeded"
    if ok is False:
        return False, "business probe failed"
    return None, "business probe result not reported"


def _eval_error_rate(reads: dict[str, _Read]) -> tuple[bool | None, str]:
    item = reads["error_rate"]
    if item.data is None:
        return None, f"error rate unavailable ({item.error['kind']})"
    ratio = _number(item.data, "ratio_percent")
    if ratio is None:
        return None, "error rate not reported"
    if ratio <= RECOVERY_ERROR_RATE_PERCENT:
        return True, f"error rate {ratio:g}% within recovery limit"
    return False, f"error rate {ratio:g}% above recovery limit"


_CRITERION_EVALUATORS = {
    "connectivity_recovered": _eval_connectivity,
    "replication_healthy": _eval_replication,
    "lock_wait_recovered": _eval_lock_wait,
    "business_probe_ok": _eval_business_probe,
    "error_rate_recovered": _eval_error_rate,
}


def register_database_adapter(
    client: DatabaseTelemetryClient,
    *,
    registry: InfrastructureAdapterRegistry = ADAPTER_REGISTRY,
    replace: bool = False,
    **kwargs: Any,
) -> ReadOnlyDatabaseAdapter:
    """Explicitly register a read-only database adapter. Import never registers."""
    adapter = ReadOnlyDatabaseAdapter(client, **kwargs)
    registry.register(adapter, replace=replace)
    return adapter
