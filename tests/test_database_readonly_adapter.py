"""Contract tests for the read-only database adapter reference implementation.

The tests use a scripted in-memory telemetry client. No vendor SDK, network
connection or credential is involved, and the client records every read so the
tests can prove the adapter only asks for declared, read-only evidence sections.
"""
import asyncio
import unittest

from backend.app.adapters import ADAPTER_REGISTRY, InfrastructureAdapterRegistry
from backend.app.adapters.contracts import (
    ADAPTER_CONTRACT_VERSION,
    InfrastructureResource,
)
from backend.app.adapters.database import (
    DATABASE_READONLY_SECTIONS,
    ReadOnlyDatabaseAdapter,
    register_database_adapter,
)
from backend.app.adapters.database.readonly import _CRITERION_SECTIONS
from backend.app.adapters.database.spec import DATABASE_DOMAIN_SPEC


HEALTHY_SECTIONS = {
    "connectivity": {"reachable": True, "server_version": "8.0"},
    "instance_role": {"role": "primary"},
    "active_sessions": {"connections_percent": 40, "active_sessions": 12},
    "slow_queries": {"slow_query_count": 0, "top_digests": []},
    "lock_waits": {"waiting_sessions": 0, "max_wait_seconds": 0},
    "replication": {"replica_count": 2, "lag_seconds": 1.5},
    "capacity": {"used_percent": 55},
    "backup_status": {"last_success_age_hours": 3},
    "recent_changes": {"changes": []},
    "business_probe": {"ok": True, "latency_ms": 12},
    "error_rate": {"ratio_percent": 0.0},
}


class ScriptedDatabaseClient:
    """Read-only fake transport. Sections can be overridden per test."""

    read_only = True
    provider = "test-dba"
    engine = "testdb"

    def __init__(self, sections=None, targets=None):
        self.sections = {**HEALTHY_SECTIONS, **(sections or {})}
        self.targets = targets if targets is not None else [{
            "target_id": "db-prod-01",
            "name": "order-db-primary",
            "engine": "testdb",
            "engine_version": "8.0",
            "role": "primary",
            "environment": "production",
            "region": "region-a",
            "business_service": "order",
            "criticality": "high",
            "endpoint_ref": "secret://cisre-adapters/test-db-prod-01",
            "labels": {"team": "dba"},
        }]
        self.reads = []

    async def list_targets(self):
        return [dict(item) for item in self.targets]

    async def read_section(self, target_id, section):
        self.reads.append((target_id, section))
        value = self.sections.get(section)
        if isinstance(value, BaseException):
            raise value
        if callable(value):
            return await value()
        return dict(value or {})


class _SlowSection:
    async def __call__(self):
        await asyncio.sleep(3600)


def _resource(client_targets=None):
    return InfrastructureResource(
        id="db-prod-01", domain="database", name="order-db-primary", provider="test-dba",
    )


def _run(coro):
    return asyncio.run(coro)


class DatabaseReadOnlyAdapterContractTests(unittest.TestCase):
    def test_contract_sections_cover_the_database_domain_spec(self):
        required = set(DATABASE_DOMAIN_SPEC["required_evidence"])
        self.assertTrue(required.issubset(set(DATABASE_READONLY_SECTIONS)))
        # Every verification criterion declared by the domain must be evaluable.
        self.assertEqual(
            set(_CRITERION_SECTIONS), set(DATABASE_DOMAIN_SPEC["verification_contract"]),
        )
        for sections in _CRITERION_SECTIONS.values():
            for section in sections:
                self.assertIn(section, DATABASE_READONLY_SECTIONS)

    def test_descriptor_is_read_only_and_matches_contract_version(self):
        adapter = ReadOnlyDatabaseAdapter(ScriptedDatabaseClient())
        descriptor = adapter.descriptor
        self.assertEqual(descriptor.contract_version, ADAPTER_CONTRACT_VERSION)
        self.assertEqual(descriptor.domain, "database")
        self.assertTrue(descriptor.read_only)
        self.assertEqual(set(descriptor.capabilities), {"discover", "collect_evidence", "verify"})
        self.assertEqual(descriptor.supported_products, ("testdb",))

    def test_client_must_declare_read_only_before_registration(self):
        client = ScriptedDatabaseClient()
        client.read_only = False
        with self.assertRaisesRegex(TypeError, "read_only=True"):
            ReadOnlyDatabaseAdapter(client)

    def test_timeout_is_bounded(self):
        with self.assertRaisesRegex(ValueError, "section_timeout_seconds"):
            ReadOnlyDatabaseAdapter(ScriptedDatabaseClient(), section_timeout_seconds=0)
        with self.assertRaisesRegex(ValueError, "section_timeout_seconds"):
            ReadOnlyDatabaseAdapter(ScriptedDatabaseClient(), section_timeout_seconds=600)


class DatabaseDiscoveryTests(unittest.TestCase):
    def test_discover_returns_safe_database_resources(self):
        adapter = ReadOnlyDatabaseAdapter(ScriptedDatabaseClient())
        resources = _run(adapter.discover({"resource_types": ["database"], "regions": []}))
        self.assertEqual(len(resources), 1)
        resource = resources[0]
        self.assertEqual(resource.id, "db-prod-01")
        self.assertEqual(resource.domain, "database")
        self.assertEqual(resource.subtype, "testdb")
        self.assertEqual(resource.facts["role"], "primary")
        self.assertEqual(resource.endpoint_ref, "secret://cisre-adapters/test-db-prod-01")
        self.assertEqual(resource.labels, {"team": "dba"})
        resource.validate()

    def test_discover_filters_by_resource_type_and_region(self):
        adapter = ReadOnlyDatabaseAdapter(ScriptedDatabaseClient())
        self.assertEqual(_run(adapter.discover({"resource_types": ["storage"]})), [])
        self.assertEqual(_run(adapter.discover({"regions": ["region-b"]})), [])
        self.assertEqual(len(_run(adapter.discover({"regions": ["region-a"]}))), 1)

    def test_discover_rejects_connection_strings_in_endpoint_ref(self):
        leaked = "mysql://dba:" + "pass" + "word-value@db.example.invalid:3306/order"
        client = ScriptedDatabaseClient(targets=[{
            "target_id": "db-bad", "name": "bad", "engine": "testdb", "endpoint_ref": leaked,
        }])
        adapter = ReadOnlyDatabaseAdapter(client)
        with self.assertRaisesRegex(ValueError, "secret:// reference") as ctx:
            _run(adapter.discover({}))
        self.assertNotIn("password-value", str(ctx.exception))

    def test_discover_strips_sensitive_labels_and_unknown_fields(self):
        client = ScriptedDatabaseClient(targets=[{
            "target_id": "db-01",
            "name": "db",
            "engine": "testdb",
            "endpoint_ref": "secret://cisre-adapters/db-01",
            "labels": {"team": "dba", "api_token": "must-not-leak"},
            "raw_password": "must-not-leak",
        }])
        resources = _run(ReadOnlyDatabaseAdapter(client).discover({}))
        self.assertEqual(resources[0].labels, {"team": "dba"})
        self.assertNotIn("raw_password", resources[0].facts)


class DatabaseEvidenceTests(unittest.TestCase):
    def _collect(self, client, **request):
        adapter = ReadOnlyDatabaseAdapter(client, section_timeout_seconds=0.2)
        bundle = _run(adapter.collect_evidence(_resource(), request))
        return bundle

    def test_healthy_target_collects_all_required_sections_read_only(self):
        client = ScriptedDatabaseClient()
        bundle = self._collect(client)
        self.assertEqual(bundle.health, "healthy")
        self.assertEqual(bundle.collection_errors, [])
        self.assertEqual(bundle.metrics["sections_collected"], sorted(DATABASE_DOMAIN_SPEC["required_evidence"]))
        bundle.public()
        # Only declared sections are ever requested from the transport.
        requested = {section for _, section in client.reads}
        self.assertTrue(requested.issubset(set(DATABASE_READONLY_SECTIONS)))
        self.assertTrue(set(DATABASE_DOMAIN_SPEC["required_evidence"]).issubset(requested))

    def test_threshold_breaches_are_graded_and_worst_wins(self):
        client = ScriptedDatabaseClient(sections={
            "active_sessions": {"connections_percent": 97, "active_sessions": 900},
            "replication": {"replica_count": 2, "lag_seconds": 45},
        })
        bundle = self._collect(client)
        self.assertEqual(bundle.health, "critical")
        severities = {item["type"]: item["severity"] for item in bundle.signals}
        self.assertEqual(severities["connections"], "critical")
        self.assertEqual(severities["replication_lag"], "degraded")

    def test_degraded_without_critical(self):
        client = ScriptedDatabaseClient(sections={"lock_waits": {"waiting_sessions": 3, "max_wait_seconds": 4}})
        self.assertEqual(self._collect(client).health, "degraded")

    def test_standalone_instance_is_not_penalised_for_missing_replica_lag(self):
        client = ScriptedDatabaseClient(sections={"replication": {"replica_count": 0, "lag_seconds": None}})
        bundle = self._collect(client)
        self.assertEqual(bundle.health, "healthy")

    def test_unreachable_target_is_critical_not_healthy(self):
        client = ScriptedDatabaseClient(sections={"connectivity": {"reachable": False}})
        self.assertEqual(self._collect(client).health, "critical")

    def test_timeout_is_partial_failure_and_never_reports_healthy(self):
        client = ScriptedDatabaseClient(sections={"lock_waits": _SlowSection()})
        bundle = self._collect(client)
        kinds = {(item["section"], item["kind"]) for item in bundle.collection_errors}
        self.assertIn(("lock_waits", "timeout"), kinds)
        # Other sections still produced evidence.
        self.assertIn("connections", {item["type"] for item in bundle.signals})
        self.assertNotEqual(bundle.health, "healthy")
        self.assertEqual(bundle.health, "unknown")

    def test_transport_errors_are_classified_and_redacted(self):
        secret_text = "pass" + "word=hunter2"
        client = ScriptedDatabaseClient(sections={
            "capacity": PermissionError(f"denied for role dba {secret_text}"),
            "backup_status": RuntimeError(
                "connect failed mysql://dba:hunter2@db.example.invalid:3306/order"
            ),
        })
        bundle = self._collect(client)
        by_section = {item["section"]: item for item in bundle.collection_errors}
        self.assertEqual(by_section["capacity"]["kind"], "permission_denied")
        self.assertEqual(by_section["backup_status"]["kind"], "client_error")
        rendered = repr(bundle.public())
        self.assertNotIn("hunter2", rendered)
        self.assertNotIn("db.example.invalid", rendered)
        self.assertIn("<redacted", rendered)

    def test_sensitive_fields_returned_by_transport_are_removed(self):
        client = ScriptedDatabaseClient(sections={
            "active_sessions": {
                "connections_percent": 30,
                "sessions": [{"user": "app", "api_token": "must-not-leak"}],
                "credential": "must-not-leak",
            },
        })
        bundle = self._collect(client)
        rendered = repr(bundle.public())
        self.assertNotIn("must-not-leak", rendered)
        redacted = [item for item in bundle.collection_errors if item["kind"] == "redacted"]
        self.assertEqual(len(redacted), 1)
        self.assertEqual(bundle.health, "healthy")

    def test_invalid_numeric_values_become_unknown_not_healthy(self):
        client = ScriptedDatabaseClient(sections={"capacity": {"used_percent": "not-a-number"}})
        bundle = self._collect(client)
        self.assertNotEqual(bundle.health, "healthy")
        capacity = next(item for item in bundle.signals if item["type"] == "capacity")
        self.assertEqual(capacity["severity"], "unknown")

    def test_requested_subset_only_reads_requested_sections(self):
        client = ScriptedDatabaseClient()
        bundle = self._collect(client, evidence_types=["connectivity", "replication"])
        self.assertEqual({section for _, section in client.reads}, {"connectivity", "replication"})
        self.assertEqual(bundle.metrics["sections_collected"], ["connectivity", "replication"])

    def test_unknown_evidence_section_is_reported_not_executed(self):
        client = ScriptedDatabaseClient()
        bundle = self._collect(client, evidence_types=["connectivity", "drop_table_users"])
        self.assertNotIn("drop_table_users", {section for _, section in client.reads})
        self.assertIn(
            ("drop_table_users", "unsupported_section"),
            {(item["section"], item["kind"]) for item in bundle.collection_errors},
        )

    def test_wrong_domain_resource_is_rejected(self):
        adapter = ReadOnlyDatabaseAdapter(ScriptedDatabaseClient())
        wrong = InfrastructureResource(id="vm-1", domain="virtual_machine", name="vm", provider="x")
        with self.assertRaisesRegex(ValueError, "database"):
            _run(adapter.collect_evidence(wrong, {}))


class DatabaseVerificationTests(unittest.TestCase):
    CRITERIA = list(DATABASE_DOMAIN_SPEC["verification_contract"])

    def _verify(self, client, criteria=None, receipt=None):
        adapter = ReadOnlyDatabaseAdapter(client, section_timeout_seconds=0.2)
        return _run(adapter.verify(
            _resource(), receipt or {"receipt_id": "change-1", "target_id": "db-prod-01"},
            criteria if criteria is not None else self.CRITERIA,
        ))

    def test_all_criteria_passing_is_completed_recovery(self):
        result = self._verify(ScriptedDatabaseClient())
        self.assertIs(result.recovered, True)
        self.assertEqual(result.status, "completed")
        self.assertTrue(all(check["passed"] is True for check in result.checks))
        self.assertEqual({check["criterion"] for check in result.checks}, set(self.CRITERIA))
        result.public()

    def test_verification_rereads_the_real_target_not_the_receipt(self):
        client = ScriptedDatabaseClient(sections={"replication": {"replica_count": 2, "lag_seconds": 600}})
        result = self._verify(client, receipt={"status": "completed", "claimed_recovered": True})
        self.assertIs(result.recovered, False)
        self.assertEqual(result.status, "failed")
        self.assertTrue(any(section == "replication" for _, section in client.reads))

    def test_missing_evidence_is_unknown_not_recovered(self):
        client = ScriptedDatabaseClient(sections={"business_probe": _SlowSection()})
        result = self._verify(client)
        self.assertIsNone(result.recovered)
        self.assertEqual(result.status, "unknown")
        probe = next(check for check in result.checks if check["criterion"] == "business_probe_ok")
        self.assertIsNone(probe["passed"])

    def test_one_failed_criterion_fails_even_if_others_are_unknown(self):
        client = ScriptedDatabaseClient(sections={
            "business_probe": _SlowSection(),
            "lock_waits": {"waiting_sessions": 5, "max_wait_seconds": 90},
        })
        result = self._verify(client)
        self.assertIs(result.recovered, False)
        self.assertEqual(result.status, "failed")

    def test_empty_or_unsupported_criteria_cannot_prove_recovery(self):
        empty = self._verify(ScriptedDatabaseClient(), criteria=[])
        self.assertIsNone(empty.recovered)
        self.assertEqual(empty.status, "unknown")
        unsupported = self._verify(ScriptedDatabaseClient(), criteria=["service_manually_marked_ok"])
        self.assertIsNone(unsupported.recovered)
        self.assertEqual(unsupported.status, "unknown")

    def test_receipt_for_other_target_is_refused_without_reading(self):
        client = ScriptedDatabaseClient()
        result = self._verify(client, receipt={"target_id": "db-other"})
        self.assertIsNone(result.recovered)
        self.assertEqual(result.status, "unknown")
        self.assertEqual(client.reads, [])

    def test_connectivity_and_error_rate_criteria(self):
        client = ScriptedDatabaseClient(sections={
            "connectivity": {"reachable": False},
            "error_rate": {"ratio_percent": 4.2},
        })
        result = self._verify(client, criteria=["connectivity_recovered", "error_rate_recovered"])
        self.assertIs(result.recovered, False)
        by_criterion = {check["criterion"]: check["passed"] for check in result.checks}
        self.assertEqual(by_criterion, {"connectivity_recovered": False, "error_rate_recovered": False})


class DatabaseRegistryIntegrationTests(unittest.TestCase):
    def test_registration_is_explicit_and_unregisterable(self):
        registry = InfrastructureAdapterRegistry()
        adapter = register_database_adapter(
            ScriptedDatabaseClient(), registry=registry, adapter_id="database-readonly-test",
        )
        self.assertIsInstance(adapter, ReadOnlyDatabaseAdapter)
        listed = registry.list(domain="database")
        self.assertEqual([item["id"] for item in listed], ["database-readonly-test"])
        resources = _run(registry.discover("database-readonly-test", {"resource_types": ["database"]}))
        self.assertEqual(resources[0]["id"], "db-prod-01")
        evidence = _run(registry.collect_evidence(
            "database-readonly-test", InfrastructureResource(
                id="db-prod-01", domain="database", name="db", provider="test-dba",
            ), {},
        ))
        self.assertEqual(evidence["domain"], "database")
        verified = _run(registry.verify(
            "database-readonly-test", InfrastructureResource(
                id="db-prod-01", domain="database", name="db", provider="test-dba",
            ), {"target_id": "db-prod-01"}, ["connectivity_recovered"],
        ))
        self.assertIs(verified["recovered"], True)
        self.assertTrue(registry.unregister("database-readonly-test"))
        self.assertEqual(registry.list(domain="database"), [])

    def test_process_wide_registry_is_not_mutated_by_default_tests(self):
        self.assertNotIn("database-readonly-test", [item["id"] for item in ADAPTER_REGISTRY.list()])


if __name__ == "__main__":
    unittest.main()
