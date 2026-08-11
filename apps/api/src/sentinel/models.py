import enum
import uuid
from datetime import UTC, datetime

from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    Enum,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    Uuid,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def utc_now() -> datetime:
    return datetime.now(UTC)


class Base(DeclarativeBase):
    pass


class DeviceTrust(enum.StrEnum):
    trusted = "trusted"
    unknown = "unknown"
    ignored = "ignored"
    guest = "guest"


class User(Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    username: Mapped[str] = mapped_column(String(64), unique=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    is_admin: Mapped[bool] = mapped_column(Boolean, default=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


class Session(Base):
    __tablename__ = "sessions"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    csrf_hash: Mapped[str] = mapped_column(String(64))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


class ApiToken(Base):
    __tablename__ = "api_tokens"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    name: Mapped[str] = mapped_column(String(100))
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    scopes: Mapped[str] = mapped_column(Text)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


class Device(Base):
    __tablename__ = "devices"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    display_name: Mapped[str] = mapped_column(String(100))
    hostname: Mapped[str | None] = mapped_column(String(255))
    mac_address: Mapped[str | None] = mapped_column(String(30), unique=True)
    trust: Mapped[DeviceTrust] = mapped_column(Enum(DeviceTrust), default=DeviceTrust.unknown)
    device_type: Mapped[str | None] = mapped_column(String(50))
    criticality: Mapped[str] = mapped_column(String(20), default="normal")
    notes: Mapped[str | None] = mapped_column(Text)
    monitor_port: Mapped[int | None]
    status: Mapped[str] = mapped_column(String(20), default="unknown")
    last_checked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_latency_ms: Mapped[int | None]
    last_failure_reason: Mapped[str | None] = mapped_column(String(100))
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    alerts_muted_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    alert_mute_reason: Mapped[str | None] = mapped_column(String(300))
    notifications_muted: Mapped[bool] = mapped_column(Boolean, default=False)
    addresses: Mapped[list["DeviceAddress"]] = relationship(cascade="all, delete-orphan")
    service_monitors: Mapped[list["ServiceMonitor"]] = relationship(
        back_populates="device", cascade="all, delete-orphan"
    )


class DeviceAddress(Base):
    __tablename__ = "device_addresses"
    __table_args__ = (Index("ix_device_addresses_address", "address"),)

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    device_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"))
    address: Mapped[str] = mapped_column(String(45))
    kind: Mapped[str] = mapped_column(String(10))
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


class InventorySource(Base):
    __tablename__ = "inventory_sources"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(100))
    kind: Mapped[str] = mapped_column(String(30), default="home_assistant")
    base_url: Mapped[str] = mapped_column(String(500))
    credential_encrypted: Mapped[str] = mapped_column(Text)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    last_sync_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_sync_status: Mapped[str] = mapped_column(String(30), default="never")
    last_sync_error: Mapped[str | None] = mapped_column(String(500))
    summary_json: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


class SourceDevice(Base):
    __tablename__ = "source_devices"
    __table_args__ = (
        Index("ix_source_devices_source_external", "source_id", "external_id", unique=True),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    source_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("inventory_sources.id", ondelete="CASCADE")
    )
    external_id: Mapped[str] = mapped_column(String(255))
    name: Mapped[str] = mapped_column(String(255))
    address: Mapped[str | None] = mapped_column(String(45))
    mac_address: Mapped[str | None] = mapped_column(String(30))
    manufacturer: Mapped[str | None] = mapped_column(String(100))
    model: Mapped[str | None] = mapped_column(String(100))
    area_name: Mapped[str | None] = mapped_column(String(100))
    imported_device_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("devices.id", ondelete="SET NULL")
    )
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


class NetworkIdentityEvent(Base):
    __tablename__ = "network_identity_events"
    __table_args__ = (Index("ix_network_identity_events_occurred", "occurred_at"),)

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    source_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("inventory_sources.id", ondelete="SET NULL"), index=True
    )
    source_device_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("source_devices.id", ondelete="SET NULL"), index=True
    )
    kind: Mapped[str] = mapped_column(String(30))
    name: Mapped[str] = mapped_column(String(255))
    old_value: Mapped[str | None] = mapped_column(String(255))
    new_value: Mapped[str | None] = mapped_column(String(255))
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


class ServiceMonitor(Base):
    __tablename__ = "service_monitors"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    device_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("devices.id", ondelete="SET NULL"), index=True
    )
    name: Mapped[str] = mapped_column(String(100))
    group_name: Mapped[str | None] = mapped_column(String(100), index=True)
    target_scope: Mapped[str] = mapped_column(String(20), default="internal")
    url: Mapped[str] = mapped_column(String(2048))
    expected_status: Mapped[int] = mapped_column(Integer, default=200)
    expected_text: Mapped[str | None] = mapped_column(String(500))
    timeout_seconds: Mapped[int] = mapped_column(Integer, default=5)
    verify_tls: Mapped[bool] = mapped_column(Boolean, default=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    notifications_muted: Mapped[bool] = mapped_column(Boolean, default=False)
    severity: Mapped[str] = mapped_column(String(20), default="normal")
    status: Mapped[str] = mapped_column(String(20), default="unknown")
    last_checked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_success_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    outage_started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_response_ms: Mapped[int | None] = mapped_column(Integer)
    last_status_code: Mapped[int | None] = mapped_column(Integer)
    last_failure_reason: Mapped[str | None] = mapped_column(String(500))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    device: Mapped[Device | None] = relationship(back_populates="service_monitors")
    results: Mapped[list["MonitorResult"]] = relationship(cascade="all, delete-orphan")


class MonitorResult(Base):
    __tablename__ = "monitor_results"
    __table_args__ = (Index("ix_monitor_results_monitor_checked", "monitor_id", "checked_at"),)

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    monitor_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("service_monitors.id", ondelete="CASCADE")
    )
    checked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    success: Mapped[bool] = mapped_column(Boolean)
    response_ms: Mapped[int | None] = mapped_column(Integer)
    status_code: Mapped[int | None] = mapped_column(Integer)
    failure_reason: Mapped[str | None] = mapped_column(String(500))


class Incident(Base):
    __tablename__ = "incidents"
    __table_args__ = (Index("ix_incidents_status_started", "status", "started_at"),)

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    monitor_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("service_monitors.id", ondelete="CASCADE"), index=True
    )
    device_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("devices.id", ondelete="SET NULL")
    )
    title: Mapped[str] = mapped_column(String(200))
    severity: Mapped[str] = mapped_column(String(20))
    status: Mapped[str] = mapped_column(String(20), default="open")
    summary: Mapped[str] = mapped_column(String(500))
    expected: Mapped[bool] = mapped_column(Boolean, default=False)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    recovered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    acknowledged_by: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
    events: Mapped[list["IncidentEvent"]] = relationship(cascade="all, delete-orphan")


class IncidentEvent(Base):
    __tablename__ = "incident_events"
    __table_args__ = (Index("ix_incident_events_incident_time", "incident_id", "occurred_at"),)

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    incident_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("incidents.id", ondelete="CASCADE"))
    kind: Mapped[str] = mapped_column(String(30))
    message: Mapped[str] = mapped_column(String(500))
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


class MaintenanceWindow(Base):
    __tablename__ = "maintenance_windows"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(100))
    device_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("devices.id", ondelete="CASCADE"), index=True
    )
    monitor_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("service_monitors.id", ondelete="CASCADE"), index=True
    )
    day_of_week: Mapped[int | None] = mapped_column(Integer)
    time_of_day: Mapped[str] = mapped_column(String(5))
    duration_minutes: Mapped[int] = mapped_column(Integer)
    timezone: Mapped[str] = mapped_column(String(100))
    suppress_notifications: Mapped[bool] = mapped_column(Boolean, default=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_by: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


class NotificationDelivery(Base):
    __tablename__ = "notification_deliveries"
    __table_args__ = (Index("ix_notification_deliveries_created_at", "created_at"),)

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    incident_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("incidents.id", ondelete="SET NULL"), index=True
    )
    kind: Mapped[str] = mapped_column(String(30))
    recipient: Mapped[str | None] = mapped_column(String(320))
    subject: Mapped[str] = mapped_column(String(300))
    status: Mapped[str] = mapped_column(String(20))
    provider_id: Mapped[str | None] = mapped_column(String(100))
    error: Mapped[str | None] = mapped_column(String(500))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    sent_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    dismissed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class DiscoveryRun(Base):
    __tablename__ = "discovery_runs"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    subnet: Mapped[str] = mapped_column(String(50))
    status: Mapped[str] = mapped_column(String(20), default="running")
    hosts_checked: Mapped[int] = mapped_column(Integer, default=0)
    hosts_found: Mapped[int] = mapped_column(Integer, default=0)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class DiscoveredHost(Base):
    __tablename__ = "discovered_hosts"
    __table_args__ = (Index("ix_discovered_hosts_run_address", "run_id", "address", unique=True),)

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    run_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("discovery_runs.id", ondelete="CASCADE"), index=True
    )
    address: Mapped[str] = mapped_column(String(45))
    open_ports: Mapped[str] = mapped_column(String(200))
    service_evidence: Mapped[str] = mapped_column(Text, default="[]")
    state: Mapped[str] = mapped_column(String(20), default="new")
    device_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("devices.id", ondelete="SET NULL")
    )
    discovered_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


class NetworkChange(Base):
    __tablename__ = "network_changes"
    __table_args__ = (Index("ix_network_changes_detected_at", "detected_at"),)

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    device_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("devices.id", ondelete="SET NULL"), index=True
    )
    address: Mapped[str] = mapped_column(String(45))
    kind: Mapped[str] = mapped_column(String(30))
    port: Mapped[int] = mapped_column(Integer)
    service: Mapped[str | None] = mapped_column(String(100))
    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


class VulnerabilityFinding(Base):
    __tablename__ = "vulnerability_findings"
    __table_args__ = (
        Index(
            "ix_vulnerability_address_cve_method",
            "address",
            "cve_id",
            "detection_method",
            unique=True,
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    device_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("devices.id", ondelete="SET NULL"), index=True
    )
    address: Mapped[str] = mapped_column(String(45))
    cve_id: Mapped[str] = mapped_column(String(30))
    title: Mapped[str] = mapped_column(String(300))
    description: Mapped[str] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String(20))
    cvss_score: Mapped[str | None] = mapped_column(String(10))
    known_exploited: Mapped[bool] = mapped_column(Boolean, default=False)
    required_action: Mapped[str | None] = mapped_column(Text)
    action_due: Mapped[str | None] = mapped_column(String(20))
    cpe: Mapped[str] = mapped_column(String(500))
    status: Mapped[str] = mapped_column(String(30), default="open")
    user_notes: Mapped[str | None] = mapped_column(Text)
    affected_package: Mapped[str | None] = mapped_column(String(255))
    installed_version: Mapped[str | None] = mapped_column(String(255))
    fixed_version: Mapped[str | None] = mapped_column(String(255))
    detection_method: Mapped[str] = mapped_column(String(50), default="nvd-cpe")
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


class StorageTarget(Base):
    __tablename__ = "storage_targets"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(100))
    relative_path: Mapped[str] = mapped_column(String(500), unique=True)
    large_file_bytes: Mapped[int] = mapped_column(BigInteger, default=1_073_741_824)
    old_file_days: Mapped[int] = mapped_column(Integer, default=365)
    protected_paths: Mapped[str] = mapped_column(Text, default="")
    last_scanned_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_total_bytes: Mapped[int] = mapped_column(BigInteger, default=0)
    last_file_count: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


class StorageFinding(Base):
    __tablename__ = "storage_findings"
    __table_args__ = (Index("ix_storage_findings_target_path", "target_id", "relative_path"),)

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    target_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("storage_targets.id", ondelete="CASCADE"), index=True
    )
    relative_path: Mapped[str] = mapped_column(String(1000))
    item_type: Mapped[str] = mapped_column(String(30), default="file")
    size_bytes: Mapped[int] = mapped_column(BigInteger)
    modified_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    reason: Mapped[str] = mapped_column(String(300))
    protected: Mapped[bool] = mapped_column(Boolean, default=False)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


class StorageScanJob(Base):
    __tablename__ = "storage_scan_jobs"
    __table_args__ = (Index("ix_storage_scan_jobs_created", "created_at"),)

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    target_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("storage_targets.id", ondelete="CASCADE"), index=True
    )
    status: Mapped[str] = mapped_column(String(20), default="queued")
    files_scanned: Mapped[int] = mapped_column(Integer, default=0)
    findings_count: Mapped[int] = mapped_column(Integer, default=0)
    error: Mapped[str | None] = mapped_column(String(500))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class Agent(Base):
    __tablename__ = "agents"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    device_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("devices.id", ondelete="CASCADE"), unique=True
    )
    version: Mapped[str] = mapped_column(String(40))
    executor_version: Mapped[str | None] = mapped_column(String(40))
    platform: Mapped[str] = mapped_column(String(40))
    hostname: Mapped[str | None] = mapped_column(String(255))
    os_name: Mapped[str | None] = mapped_column(String(100))
    os_version: Mapped[str | None] = mapped_column(String(100))
    kernel_version: Mapped[str | None] = mapped_column(String(100))
    credential_fingerprint: Mapped[str] = mapped_column(String(128), unique=True)
    last_heartbeat_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


class AgentEnrollment(Base):
    __tablename__ = "agent_enrollments"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    device_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("devices.id", ondelete="CASCADE"), index=True
    )
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_by: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


class AgentMetric(Base):
    __tablename__ = "agent_metrics"
    __table_args__ = (Index("ix_agent_metrics_agent_collected", "agent_id", "collected_at"),)

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    agent_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("agents.id", ondelete="CASCADE"))
    cpu_percent: Mapped[int] = mapped_column(Integer)
    memory_percent: Mapped[int] = mapped_column(Integer)
    memory_used_bytes: Mapped[int] = mapped_column(BigInteger)
    memory_total_bytes: Mapped[int] = mapped_column(BigInteger)
    disk_percent: Mapped[int] = mapped_column(Integer)
    disk_free_bytes: Mapped[int] = mapped_column(BigInteger)
    disk_total_bytes: Mapped[int] = mapped_column(BigInteger)
    uptime_seconds: Mapped[int] = mapped_column(BigInteger)
    collected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


class InstalledPackage(Base):
    __tablename__ = "installed_packages"
    __table_args__ = (Index("ix_installed_packages_agent_name", "agent_id", "name", unique=True),)

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    agent_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("agents.id", ondelete="CASCADE"))
    name: Mapped[str] = mapped_column(String(255))
    version: Mapped[str] = mapped_column(String(255))
    architecture: Mapped[str | None] = mapped_column(String(50))
    manager: Mapped[str] = mapped_column(String(30))
    source_name: Mapped[str | None] = mapped_column(String(255))
    source_version: Mapped[str | None] = mapped_column(String(255))
    candidate_version: Mapped[str | None] = mapped_column(String(255))
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


class ContainerInstance(Base):
    __tablename__ = "container_instances"
    __table_args__ = (
        Index("ix_container_instances_agent_container", "agent_id", "container_id", unique=True),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    agent_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("agents.id", ondelete="CASCADE"))
    container_id: Mapped[str] = mapped_column(String(64))
    name: Mapped[str] = mapped_column(String(255))
    image: Mapped[str] = mapped_column(String(500))
    state: Mapped[str] = mapped_column(String(30))
    health: Mapped[str | None] = mapped_column(String(30))
    status: Mapped[str] = mapped_column(String(500))
    ports: Mapped[str] = mapped_column(String(1000), default="")
    restart_count: Mapped[int] = mapped_column(Integer, default=0)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


class RemediationPlan(Base):
    __tablename__ = "remediation_plans"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    finding_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("vulnerability_findings.id", ondelete="CASCADE"), unique=True
    )
    agent_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("agents.id", ondelete="CASCADE"))
    package_name: Mapped[str] = mapped_column(String(255))
    installed_version: Mapped[str] = mapped_column(String(255))
    target_version: Mapped[str] = mapped_column(String(255))
    operation: Mapped[str] = mapped_column(String(30), default="package_upgrade")
    status: Mapped[str] = mapped_column(String(30), default="draft")
    created_by: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
    approved_by: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    dispatched_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    result_output: Mapped[str | None] = mapped_column(Text)
    result_error: Mapped[str | None] = mapped_column(String(500))


class AuditEvent(Base):
    __tablename__ = "audit_events"
    __table_args__ = (Index("ix_audit_events_created_at", "created_at"),)

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    actor_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
    action: Mapped[str] = mapped_column(String(100))
    target_type: Mapped[str | None] = mapped_column(String(50))
    target_id: Mapped[str | None] = mapped_column(String(100))
    source_address: Mapped[str | None] = mapped_column(String(45))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
