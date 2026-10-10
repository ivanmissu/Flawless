"""Database adapter extension point and read-only reference adapter."""

from .readonly import (
    DATABASE_READONLY_SECTIONS,
    DatabaseTelemetryClient,
    ReadOnlyDatabaseAdapter,
    register_database_adapter,
)
from .spec import DATABASE_DOMAIN_SPEC

__all__ = [
    "DATABASE_DOMAIN_SPEC",
    "DATABASE_READONLY_SECTIONS",
    "DatabaseTelemetryClient",
    "ReadOnlyDatabaseAdapter",
    "register_database_adapter",
]
