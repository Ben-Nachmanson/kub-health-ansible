#!/usr/bin/python
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: MIT

"""Self-contained Kubernetes health check module for Ansible.

Runs all kub-health checks against a Kubernetes cluster via kubeconfig.
Nothing is installed on any remote server. The module connects to the K8s
API from the Ansible control node, collects a point-in-time snapshot, runs
8 health check modules, builds a dependency graph, and correlates findings
into root-cause groups.

All API calls are read-only (list/get). Zero writes to the cluster.
"""

from __future__ import annotations

DOCUMENTATION = r"""
---
module: kub_health_check
short_description: Run Kubernetes health checks against a cluster
version_added: "1.0.0"
description:
  - Connects to a Kubernetes cluster via kubeconfig and runs comprehensive
    health checks across pods, nodes, deployments, networking, storage,
    RBAC, events, and resource utilization.
  - Correlates findings into root-cause groups using a dependency graph
    and 5 correlation strategies.
  - Completely read-only. All API calls are list/get operations.
  - Nothing is installed on the cluster or remote hosts.
options:
  kubeconfig:
    description: Path to the kubeconfig file.
    type: path
    default: ~/.kube/config
  context:
    description: Kubeconfig context to use. Defaults to current context.
    type: str
  namespace:
    description: Limit checks to a single namespace. Omit for all namespaces.
    type: str
  severity_threshold:
    description: Minimum severity to include in results.
    type: str
    default: info
    choices: [info, warning, critical]
  checks:
    description: List of check modules to run. Defaults to all.
    type: list
    elements: str
    default: [pods, nodes, resources, deployments, events, networking, storage, rbac]
requirements:
  - kubernetes (Python package, same requirement as kubernetes.core collection)
author:
  - kub-health contributors
"""

EXAMPLES = r"""
- name: Run all health checks against current context
  kub_health_check:
  register: health

- name: Check a specific cluster context
  kub_health_check:
    kubeconfig: /etc/kubernetes/admin.conf
    context: prod-cluster
  register: health

- name: Check only a single namespace
  kub_health_check:
    namespace: my-app
    severity_threshold: warning
  register: health

- name: Run only pod and node checks
  kub_health_check:
    checks:
      - pods
      - nodes
  register: health

- name: Fail playbook if critical issues found
  kub_health_check:
  register: health
  failed_when: health.summary.critical_count > 0
"""

RETURN = r"""
findings:
  description: All health check findings.
  type: list
  returned: always
  elements: dict
  sample:
    - id: "a1b2c3d4"
      category: "Pod Health"
      severity: "critical"
      resource: "Pod/default/my-pod"
      message: "container 'app' in CrashLoopBackOff (12 restarts)"
correlation_groups:
  description: Correlated root-cause groups.
  type: list
  returned: always
  elements: dict
uncorrelated_findings:
  description: Findings not associated with any root-cause group.
  type: list
  returned: always
  elements: dict
summary:
  description: Overall health summary.
  type: dict
  returned: always
  sample:
    overall_health: "critical"
    total_findings: 15
    critical_count: 3
    warning_count: 7
    info_count: 5
    node_count: 3
    pod_count: 42
    namespace_count: 5
check_results:
  description: Per-module check results.
  type: list
  returned: always
  elements: dict
report_text:
  description: Human-readable text report.
  type: str
  returned: always
"""

import logging
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any

logger = logging.getLogger("kub_health_check")


# =====================================================================
# Models (ported from kub_health/models.py)
# =====================================================================

class Severity(str, Enum):
    CRITICAL = "critical"
    WARNING = "warning"
    INFO = "info"
    OK = "ok"

    @property
    def sort_order(self) -> int:
        return {Severity.CRITICAL: 0, Severity.WARNING: 1, Severity.INFO: 2, Severity.OK: 3}[self]


class CheckCategory(str, Enum):
    PODS = "Pod Health"
    NODES = "Node Health"
    RESOURCES = "Resource Utilization"
    DEPLOYMENTS = "Deployment Status"
    EVENTS = "Events & Warnings"
    NETWORKING = "Networking"
    STORAGE = "Storage"
    RBAC = "RBAC & Security"


@dataclass(frozen=True)
class ResourceKey:
    kind: str
    name: str
    namespace: str = ""

    def __str__(self) -> str:
        if self.namespace:
            return f"{self.kind}/{self.namespace}/{self.name}"
        return f"{self.kind}/{self.name}"


@dataclass
class ClusterSnapshot:
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    pods: list[Any] = field(default_factory=list)
    nodes: list[Any] = field(default_factory=list)
    deployments: list[Any] = field(default_factory=list)
    replicasets: list[Any] = field(default_factory=list)
    statefulsets: list[Any] = field(default_factory=list)
    daemonsets: list[Any] = field(default_factory=list)
    services: list[Any] = field(default_factory=list)
    endpoints: list[Any] = field(default_factory=list)
    ingresses: list[Any] = field(default_factory=list)
    network_policies: list[Any] = field(default_factory=list)
    pvcs: list[Any] = field(default_factory=list)
    pvs: list[Any] = field(default_factory=list)
    storage_classes: list[Any] = field(default_factory=list)
    configmaps: list[Any] = field(default_factory=list)
    secrets: list[Any] = field(default_factory=list)
    service_accounts: list[Any] = field(default_factory=list)
    roles: list[Any] = field(default_factory=list)
    cluster_roles: list[Any] = field(default_factory=list)
    role_bindings: list[Any] = field(default_factory=list)
    cluster_role_bindings: list[Any] = field(default_factory=list)
    events: list[Any] = field(default_factory=list)
    namespaces: list[Any] = field(default_factory=list)
    resource_quotas: list[Any] = field(default_factory=list)
    limit_ranges: list[Any] = field(default_factory=list)
    hpas: list[Any] = field(default_factory=list)
    pod_disruption_budgets: list[Any] = field(default_factory=list)
    pod_metrics: list[Any] = field(default_factory=list)
    node_metrics: list[Any] = field(default_factory=list)


@dataclass
class Finding:
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:8])
    category: CheckCategory = CheckCategory.PODS
    severity: Severity = Severity.INFO
    resource: ResourceKey = field(default_factory=lambda: ResourceKey("Unknown", "unknown"))
    message: str = ""
    details: dict[str, Any] = field(default_factory=dict)
    remediation: str = ""
    related_resources: list[ResourceKey] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "category": self.category.value,
            "severity": self.severity.value,
            "resource": str(self.resource),
            "message": self.message,
            "details": self.details,
            "remediation": self.remediation,
            "related_resources": [str(r) for r in self.related_resources],
            "evidence": self.evidence,
        }


class DependencyType(str, Enum):
    OWNS = "owns"
    SELECTS = "selects"
    MOUNTS = "mounts"
    RUNS_ON = "runs_on"
    BINDS = "binds"
    TARGETS = "targets"
    SCALES = "scales"
    REFERENCES = "references"


@dataclass(frozen=True)
class DependencyEdge:
    source: ResourceKey
    target: ResourceKey
    dep_type: DependencyType
    metadata: dict[str, Any] = field(default_factory=dict)

    def __hash__(self) -> int:
        return hash((self.source, self.target, self.dep_type))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, DependencyEdge):
            return False
        return (self.source == other.source and self.target == other.target
                and self.dep_type == other.dep_type)


@dataclass
class DependencyGraph:
    edges: list[DependencyEdge] = field(default_factory=list)
    _adjacency: dict[ResourceKey, list[DependencyEdge]] = field(default_factory=dict, repr=False)
    _reverse: dict[ResourceKey, list[DependencyEdge]] = field(default_factory=dict, repr=False)

    def add_edge(self, edge: DependencyEdge) -> None:
        self.edges.append(edge)
        self._adjacency.setdefault(edge.source, []).append(edge)
        self._reverse.setdefault(edge.target, []).append(edge)

    def dependents_of(self, key: ResourceKey) -> list[DependencyEdge]:
        return self._reverse.get(key, [])

    def dependencies_of(self, key: ResourceKey) -> list[DependencyEdge]:
        return self._adjacency.get(key, [])

    def impact_radius(self, key: ResourceKey, visited: set[ResourceKey] | None = None) -> set[ResourceKey]:
        if visited is None:
            visited = set()
        if key in visited:
            return visited
        visited.add(key)
        for edge in self.dependents_of(key):
            self.impact_radius(edge.source, visited)
        return visited

    def dependency_chain(self, key: ResourceKey, visited: set[ResourceKey] | None = None) -> set[ResourceKey]:
        if visited is None:
            visited = set()
        if key in visited:
            return visited
        visited.add(key)
        for edge in self.dependencies_of(key):
            self.dependency_chain(edge.target, visited)
        return visited


@dataclass
class TimelineEvent:
    timestamp: datetime
    resource: ResourceKey
    event_type: str
    reason: str
    message: str
    count: int = 1
    source_component: str = ""

    def __lt__(self, other: TimelineEvent) -> bool:
        return self.timestamp < other.timestamp


@dataclass
class CorrelationGroup:
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:8])
    root_cause: Finding | None = None
    symptoms: list[Finding] = field(default_factory=list)
    affected_resources: set[ResourceKey] = field(default_factory=set)
    timeline: list[TimelineEvent] = field(default_factory=list)
    summary: str = ""

    @property
    def severity(self) -> Severity:
        if self.root_cause:
            return self.root_cause.severity
        if self.symptoms:
            return min(self.symptoms, key=lambda f: f.severity.sort_order).severity
        return Severity.OK

    @property
    def all_findings(self) -> list[Finding]:
        findings = []
        if self.root_cause:
            findings.append(self.root_cause)
        findings.extend(self.symptoms)
        return findings

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "severity": self.severity.value,
            "root_cause": self.root_cause.to_dict() if self.root_cause else None,
            "symptoms": [s.to_dict() for s in self.symptoms],
            "affected_resources": [str(r) for r in self.affected_resources],
            "summary": self.summary,
        }


@dataclass
class CheckResult:
    category: CheckCategory
    findings: list[Finding] = field(default_factory=list)
    error: str | None = None
    duration_ms: float = 0.0

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def warning_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.WARNING)

    @property
    def worst_severity(self) -> Severity:
        if not self.findings:
            return Severity.OK
        return min(self.findings, key=lambda f: f.severity.sort_order).severity

    def to_dict(self) -> dict[str, Any]:
        return {
            "category": self.category.value,
            "findings_count": len(self.findings),
            "critical_count": self.critical_count,
            "warning_count": self.warning_count,
            "worst_severity": self.worst_severity.value,
            "error": self.error,
        }


# =====================================================================
# Helpers (ported from kub_health/checks/nodes.py)
# =====================================================================

def _parse_cpu(val: str | int | float) -> float:
    s = str(val)
    if s.endswith("m"):
        return float(s[:-1]) / 1000
    if s.endswith("n"):
        return float(s[:-1]) / 1_000_000_000
    return float(s)


def _parse_memory(val: str | int | float) -> float:
    s = str(val)
    suffixes = {
        "Ki": 1024, "Mi": 1024**2, "Gi": 1024**3, "Ti": 1024**4,
        "K": 1000, "M": 1000**2, "G": 1000**3, "T": 1000**4,
        "k": 1000, "m": 0.001,
    }
    for suffix, multiplier in sorted(suffixes.items(), key=lambda x: -len(x[0])):
        if s.endswith(suffix):
            return float(s[: -len(suffix)]) * multiplier
    return float(s)


def _fmt_memory(bytes_val: float) -> str:
    if bytes_val >= 1024**3:
        return f"{bytes_val / 1024**3:.1f}Gi"
    if bytes_val >= 1024**2:
        return f"{bytes_val / 1024**2:.0f}Mi"
    return f"{bytes_val / 1024:.0f}Ki"


def _parse_resource_quantity(val: str, resource_name: str) -> float:
    if "cpu" in resource_name.lower():
        return _parse_cpu(val)
    if "memory" in resource_name.lower() or "storage" in resource_name.lower():
        return _parse_memory(val)
    try:
        return float(val)
    except (ValueError, TypeError):
        return 0


def _selector_str(selector: dict) -> str:
    return ",".join(f"{k}={v}" for k, v in selector.items())


# =====================================================================
# Snapshot Collector (ported from kub_health/collector/snapshot.py)
# =====================================================================

def _safe_list(func: Any, *args: Any, **kwargs: Any) -> list[Any]:
    try:
        result = func(*args, **kwargs)
        return result.items if hasattr(result, "items") else []
    except Exception as exc:
        logger.debug("API call %s failed: %s", getattr(func, "__name__", "?"), exc)
        return []


def collect_snapshot(api_client, namespace: str | None = None) -> ClusterSnapshot:
    """Collect a full cluster snapshot using the K8s Python client."""
    from kubernetes.client import (
        AppsV1Api, CoreV1Api, NetworkingV1Api,
        RbacAuthorizationV1Api, StorageV1Api,
    )

    snap = ClusterSnapshot()
    core = CoreV1Api(api_client)
    apps = AppsV1Api(api_client)
    net = NetworkingV1Api(api_client)
    rbac = RbacAuthorizationV1Api(api_client)
    storage = StorageV1Api(api_client)

    ns_args: dict[str, Any] = {"namespace": namespace} if namespace else {}

    def _ns_call(namespaced_fn, all_ns_fn):
        return namespaced_fn if namespace else all_ns_fn

    tasks: list[tuple[str, Any, dict[str, Any]]] = [
        ("namespaces", core.list_namespace, {}),
        ("nodes", core.list_node, {}),
        ("pods", _ns_call(core.list_namespaced_pod, core.list_pod_for_all_namespaces), ns_args),
        ("services", _ns_call(core.list_namespaced_service, core.list_service_for_all_namespaces), ns_args),
        ("endpoints", _ns_call(core.list_namespaced_endpoints, core.list_endpoints_for_all_namespaces), ns_args),
        ("configmaps", _ns_call(core.list_namespaced_config_map, core.list_config_map_for_all_namespaces), ns_args),
        ("secrets", _ns_call(core.list_namespaced_secret, core.list_secret_for_all_namespaces), ns_args),
        ("service_accounts", _ns_call(core.list_namespaced_service_account, core.list_service_account_for_all_namespaces), ns_args),
        ("events", _ns_call(core.list_namespaced_event, core.list_event_for_all_namespaces), ns_args),
        ("pvcs", _ns_call(core.list_namespaced_persistent_volume_claim, core.list_persistent_volume_claim_for_all_namespaces), ns_args),
        ("pvs", core.list_persistent_volume, {}),
        ("resource_quotas", _ns_call(core.list_namespaced_resource_quota, core.list_resource_quota_for_all_namespaces), ns_args),
        ("limit_ranges", _ns_call(core.list_namespaced_limit_range, core.list_limit_range_for_all_namespaces), ns_args),
        ("deployments", _ns_call(apps.list_namespaced_deployment, apps.list_deployment_for_all_namespaces), ns_args),
        ("replicasets", _ns_call(apps.list_namespaced_replica_set, apps.list_replica_set_for_all_namespaces), ns_args),
        ("statefulsets", _ns_call(apps.list_namespaced_stateful_set, apps.list_stateful_set_for_all_namespaces), ns_args),
        ("daemonsets", _ns_call(apps.list_namespaced_daemon_set, apps.list_daemon_set_for_all_namespaces), ns_args),
        ("ingresses", _ns_call(net.list_namespaced_ingress, net.list_ingress_for_all_namespaces), ns_args),
        ("network_policies", _ns_call(net.list_namespaced_network_policy, net.list_network_policy_for_all_namespaces), ns_args),
        ("cluster_roles", rbac.list_cluster_role, {}),
        ("cluster_role_bindings", rbac.list_cluster_role_binding, {}),
        ("roles", _ns_call(rbac.list_namespaced_role, rbac.list_role_for_all_namespaces), ns_args),
        ("role_bindings", _ns_call(rbac.list_namespaced_role_binding, rbac.list_role_binding_for_all_namespaces), ns_args),
        ("storage_classes", storage.list_storage_class, {}),
    ]

    # Optional APIs
    try:
        from kubernetes.client import AutoscalingV2Api, PolicyV1Api
        autoscaling = AutoscalingV2Api(api_client)
        policy = PolicyV1Api(api_client)
        tasks.extend([
            ("hpas", _ns_call(autoscaling.list_namespaced_horizontal_pod_autoscaler, autoscaling.list_horizontal_pod_autoscaler_for_all_namespaces), ns_args),
            ("pod_disruption_budgets", _ns_call(policy.list_namespaced_pod_disruption_budget, policy.list_pod_disruption_budget_for_all_namespaces), ns_args),
        ])
    except ImportError:
        pass

    for field_name, api_fn, api_args in tasks:
        setattr(snap, field_name, _safe_list(api_fn, **api_args))

    # Metrics (best-effort)
    try:
        from kubernetes.client import CustomObjectsApi
        custom = CustomObjectsApi(api_client)
        if namespace:
            pm = custom.list_namespaced_custom_object("metrics.k8s.io", "v1beta1", namespace, "pods")
        else:
            pm = custom.list_cluster_custom_object("metrics.k8s.io", "v1beta1", "pods")
        snap.pod_metrics = pm.get("items", [])
    except Exception:
        snap.pod_metrics = []

    try:
        from kubernetes.client import CustomObjectsApi
        custom = CustomObjectsApi(api_client)
        nm = custom.list_cluster_custom_object("metrics.k8s.io", "v1beta1", "nodes")
        snap.node_metrics = nm.get("items", [])
    except Exception:
        snap.node_metrics = []

    return snap


# =====================================================================
# Pod Health Checks (ported from kub_health/checks/pods.py)
# =====================================================================

RESTART_WARN = 5
RESTART_CRIT = 20
PENDING_WARN_MIN = 5
PENDING_CRIT_MIN = 15
UNREADY_WARN_MIN = 5


def check_pods(snap: ClusterSnapshot) -> CheckResult:
    result = CheckResult(category=CheckCategory.PODS)
    now = datetime.now(timezone.utc)

    for pod in snap.pods:
        meta = pod.metadata
        status = pod.status
        pod_key = ResourceKey("Pod", meta.name, meta.namespace)
        node_key = ResourceKey("Node", pod.spec.node_name or "unscheduled")
        phase = status.phase or "Unknown"

        if phase == "Pending":
            _check_pending(result, pod, pod_key, node_key, now)
            continue
        if phase == "Failed":
            reason = status.reason or ""
            msg = status.message or "Pod failed"
            result.findings.append(Finding(
                category=CheckCategory.PODS, severity=Severity.CRITICAL,
                resource=pod_key,
                message=f"Pod in Failed state: {reason} - {msg}",
                details={"phase": phase, "reason": reason},
                related_resources=[node_key],
                remediation="Check pod events and logs. If Evicted, review node resource pressure.",
            ))
            continue

        all_cs = []
        for cs in status.container_statuses or []:
            all_cs.append(("container", cs))
        for cs in status.init_container_statuses or []:
            all_cs.append(("init-container", cs))
        for container_kind, cs in all_cs:
            _check_container_status(result, pod_key, node_key, container_kind, cs, meta)
        _check_readiness(result, pod, pod_key, node_key, now)

    return result


def _check_pending(result, pod, pod_key, node_key, now):
    conditions = pod.status.conditions or []
    schedule_reason = ""
    schedule_msg = ""
    for cond in conditions:
        if cond.type == "PodScheduled" and cond.status == "False":
            schedule_reason = cond.reason or "Unknown"
            schedule_msg = cond.message or ""
            break

    pending_min = 0.0
    if pod.metadata.creation_timestamp:
        pending_min = (now - pod.metadata.creation_timestamp).total_seconds() / 60

    if pending_min < PENDING_WARN_MIN:
        severity = Severity.INFO
    elif pending_min < PENDING_CRIT_MIN:
        severity = Severity.WARNING
    else:
        severity = Severity.CRITICAL

    related = [node_key]
    for vol in pod.spec.volumes or []:
        if vol.persistent_volume_claim:
            related.append(ResourceKey("PVC", vol.persistent_volume_claim.claim_name, pod.metadata.namespace))

    result.findings.append(Finding(
        category=CheckCategory.PODS, severity=severity, resource=pod_key,
        message=(f"Pending for {pending_min:.0f}m - {schedule_reason}: {schedule_msg}"
                 if schedule_reason else f"Pending for {pending_min:.0f}m"),
        details={"pending_minutes": round(pending_min), "schedule_reason": schedule_reason},
        related_resources=related,
        evidence=[
            f"kubectl describe pod {pod.metadata.name} -n {pod.metadata.namespace}",
            f"kubectl get events -n {pod.metadata.namespace} --field-selector involvedObject.name={pod.metadata.name}",
        ],
        remediation="Common causes: insufficient CPU/memory, unsatisfiable node affinity, "
                    "taints without tolerations, unbound PVCs, or ResourceQuota limits reached.",
    ))


def _check_container_status(result, pod_key, node_key, container_kind, cs, meta):
    cname = cs.name
    if cs.state and cs.state.waiting:
        reason = cs.state.waiting.reason or ""
        wait_msg = cs.state.waiting.message or ""

        if reason == "CrashLoopBackOff":
            result.findings.append(Finding(
                category=CheckCategory.PODS, severity=Severity.CRITICAL, resource=pod_key,
                message=f"{container_kind} '{cname}' in CrashLoopBackOff ({cs.restart_count} restarts)",
                details={"container": cname, "container_kind": container_kind,
                         "restart_count": cs.restart_count, "image": cs.image},
                related_resources=[node_key],
                evidence=[f"kubectl logs {meta.name} -c {cname} -n {meta.namespace} --previous"],
                remediation="Check previous container logs for crash reason.",
            ))
        elif reason in ("ImagePullBackOff", "ErrImagePull", "InvalidImageName"):
            result.findings.append(Finding(
                category=CheckCategory.PODS, severity=Severity.CRITICAL, resource=pod_key,
                message=f"{container_kind} '{cname}' image pull failure: {reason}",
                details={"container": cname, "reason": reason, "image": cs.image, "message": wait_msg},
                related_resources=[node_key],
                evidence=[f"kubectl describe pod {meta.name} -n {meta.namespace}"],
                remediation="Verify image name/tag, check imagePullSecrets, ensure registry is reachable.",
            ))
        elif reason == "CreateContainerConfigError":
            result.findings.append(Finding(
                category=CheckCategory.PODS, severity=Severity.CRITICAL, resource=pod_key,
                message=f"{container_kind} '{cname}' config error: {wait_msg}",
                details={"container": cname, "reason": reason, "message": wait_msg},
                related_resources=[node_key],
                evidence=[f"kubectl describe pod {meta.name} -n {meta.namespace}"],
                remediation="A referenced ConfigMap, Secret, or ServiceAccount likely doesn't exist.",
            ))
        elif reason and reason not in ("ContainerCreating", "PodInitializing"):
            result.findings.append(Finding(
                category=CheckCategory.PODS, severity=Severity.WARNING, resource=pod_key,
                message=f"{container_kind} '{cname}' waiting: {reason} - {wait_msg}",
                details={"container": cname, "reason": reason, "message": wait_msg},
                related_resources=[node_key],
            ))

    if cs.last_state and cs.last_state.terminated:
        term = cs.last_state.terminated
        if term.reason == "OOMKilled":
            result.findings.append(Finding(
                category=CheckCategory.PODS, severity=Severity.CRITICAL, resource=pod_key,
                message=f"{container_kind} '{cname}' was OOMKilled (exit code {term.exit_code}, {cs.restart_count} restarts)",
                details={"container": cname, "exit_code": term.exit_code, "restart_count": cs.restart_count},
                related_resources=[node_key],
                evidence=[f"kubectl logs {meta.name} -c {cname} -n {meta.namespace} --previous"],
                remediation="Increase memory limits or investigate memory leaks.",
            ))
        elif term.exit_code != 0 and term.reason not in ("Completed",):
            result.findings.append(Finding(
                category=CheckCategory.PODS, severity=Severity.WARNING, resource=pod_key,
                message=f"{container_kind} '{cname}' last terminated: {term.reason} (exit {term.exit_code})",
                details={"container": cname, "reason": term.reason, "exit_code": term.exit_code, "restart_count": cs.restart_count},
                related_resources=[node_key],
            ))

    if cs.restart_count >= RESTART_WARN:
        already_crashloop = any(f.resource == pod_key and "CrashLoopBackOff" in f.message for f in result.findings)
        if not already_crashloop:
            severity = Severity.CRITICAL if cs.restart_count >= RESTART_CRIT else Severity.WARNING
            result.findings.append(Finding(
                category=CheckCategory.PODS, severity=severity, resource=pod_key,
                message=f"{container_kind} '{cname}' has {cs.restart_count} restarts",
                details={"container": cname, "restart_count": cs.restart_count},
                related_resources=[node_key],
                evidence=[f"kubectl logs {meta.name} -c {cname} -n {meta.namespace} --previous"],
                remediation="Investigate container restart history.",
            ))


def _check_readiness(result, pod, pod_key, node_key, now):
    if pod.status.phase != "Running":
        return
    for cond in pod.status.conditions or []:
        if cond.type == "Ready" and cond.status == "False":
            unready_min = 0.0
            if cond.last_transition_time:
                unready_min = (now - cond.last_transition_time).total_seconds() / 60
            if unready_min < UNREADY_WARN_MIN:
                continue
            severity = Severity.WARNING if unready_min < 30 else Severity.CRITICAL
            result.findings.append(Finding(
                category=CheckCategory.PODS, severity=severity, resource=pod_key,
                message=f"Pod running but not Ready for {unready_min:.0f}m ({cond.reason or 'unknown reason'})",
                details={"unready_minutes": round(unready_min), "reason": cond.reason or ""},
                related_resources=[node_key],
                evidence=[f"kubectl describe pod {pod.metadata.name} -n {pod.metadata.namespace}"],
                remediation="Check readiness probe configuration.",
            ))
            break


# =====================================================================
# Node Health Checks (ported from kub_health/checks/nodes.py)
# =====================================================================

ALLOC_WARN_PCT = 80
ALLOC_CRIT_PCT = 95


def check_nodes(snap: ClusterSnapshot) -> CheckResult:
    result = CheckResult(category=CheckCategory.NODES)
    now = datetime.now(timezone.utc)

    node_pods: dict[str, list] = {}
    for pod in snap.pods:
        node = pod.spec.node_name or ""
        if node:
            node_pods.setdefault(node, []).append(pod)

    node_metrics_map: dict[str, dict] = {}
    for nm in snap.node_metrics:
        name = nm.get("metadata", {}).get("name", "")
        if name:
            node_metrics_map[name] = nm

    for node in snap.nodes:
        name = node.metadata.name
        node_key = ResourceKey("Node", name)
        _check_node_conditions(result, node, node_key, now)

        if node.spec.unschedulable:
            result.findings.append(Finding(
                category=CheckCategory.NODES, severity=Severity.WARNING, resource=node_key,
                message="Node is cordoned (unschedulable)",
                evidence=[f"kubectl describe node {name}"],
                remediation=f"If intentional (maintenance), no action. Otherwise: kubectl uncordon {name}",
            ))

        taints = node.spec.taints or []
        for taint in taints:
            if taint.effect == "NoExecute" and taint.key not in ("node.kubernetes.io/not-ready", "node.kubernetes.io/unreachable"):
                result.findings.append(Finding(
                    category=CheckCategory.NODES, severity=Severity.WARNING, resource=node_key,
                    message=f"NoExecute taint: {taint.key}={taint.value or ''}",
                    details={"taint_key": taint.key, "effect": "NoExecute"},
                    evidence=[f"kubectl describe node {name} | grep -A5 Taints"],
                    remediation="NoExecute taints evict existing pods. Verify intentional.",
                ))

        _check_node_allocation(result, node, node_key, node_pods.get(name, []))

        metrics = node_metrics_map.get(name)
        if metrics:
            _check_node_metrics(result, node, node_key, metrics)

    return result


def _check_node_conditions(result, node, node_key, now):
    conditions = node.status.conditions or []
    has_ready = False
    for cond in conditions:
        if cond.type == "Ready":
            has_ready = True
            if cond.status != "True":
                not_ready_min = 0.0
                if cond.last_transition_time:
                    not_ready_min = (now - cond.last_transition_time).total_seconds() / 60
                result.findings.append(Finding(
                    category=CheckCategory.NODES, severity=Severity.CRITICAL, resource=node_key,
                    message=f"Node NotReady for {not_ready_min:.0f}m ({cond.reason or 'unknown'})",
                    details={"not_ready_minutes": round(not_ready_min), "reason": cond.reason or ""},
                    evidence=[f"kubectl describe node {node.metadata.name}"],
                    remediation="Check kubelet status, network connectivity, and system resources.",
                ))
        elif cond.type in ("MemoryPressure", "DiskPressure", "PIDPressure") and cond.status == "True":
            result.findings.append(Finding(
                category=CheckCategory.NODES, severity=Severity.CRITICAL, resource=node_key,
                message=f"Node under {cond.type}: {cond.message or cond.reason or ''}",
                details={"condition": cond.type, "reason": cond.reason or ""},
                evidence=[f"kubectl describe node {node.metadata.name}"],
            ))
        elif cond.type == "NetworkUnavailable" and cond.status == "True":
            result.findings.append(Finding(
                category=CheckCategory.NODES, severity=Severity.CRITICAL, resource=node_key,
                message=f"Node network unavailable: {cond.message or cond.reason or ''}",
                evidence=[f"kubectl describe node {node.metadata.name}"],
                remediation="Check the CNI plugin status on this node.",
            ))
    if not has_ready:
        result.findings.append(Finding(
            category=CheckCategory.NODES, severity=Severity.CRITICAL, resource=node_key,
            message="Node has no Ready condition - unusual state",
        ))


def _check_node_allocation(result, node, node_key, pods):
    allocatable = node.status.allocatable or {}
    alloc_cpu = _parse_cpu(allocatable.get("cpu", "0"))
    alloc_mem = _parse_memory(allocatable.get("memory", "0"))
    if alloc_cpu == 0 or alloc_mem == 0:
        return

    req_cpu = 0.0
    req_mem = 0.0
    for pod in pods:
        if pod.status.phase in ("Succeeded", "Failed"):
            continue
        for container in pod.spec.containers or []:
            resources = container.resources
            if resources and resources.requests:
                req_cpu += _parse_cpu(resources.requests.get("cpu", "0"))
                req_mem += _parse_memory(resources.requests.get("memory", "0"))

    cpu_pct = (req_cpu / alloc_cpu) * 100 if alloc_cpu else 0
    mem_pct = (req_mem / alloc_mem) * 100 if alloc_mem else 0

    if cpu_pct >= ALLOC_CRIT_PCT:
        severity = Severity.CRITICAL
    elif cpu_pct >= ALLOC_WARN_PCT:
        severity = Severity.WARNING
    else:
        severity = None
    if severity:
        result.findings.append(Finding(
            category=CheckCategory.NODES, severity=severity, resource=node_key,
            message=f"CPU allocation at {cpu_pct:.0f}% ({req_cpu:.1f} / {alloc_cpu:.1f} cores requested)",
            details={"requested_cpu_cores": round(req_cpu, 2), "allocatable_cpu_cores": round(alloc_cpu, 2),
                     "allocation_pct": round(cpu_pct, 1), "pod_count": len(pods)},
            remediation="High CPU allocation. Consider adding nodes or right-sizing requests.",
        ))

    if mem_pct >= ALLOC_CRIT_PCT:
        severity = Severity.CRITICAL
    elif mem_pct >= ALLOC_WARN_PCT:
        severity = Severity.WARNING
    else:
        severity = None
    if severity:
        result.findings.append(Finding(
            category=CheckCategory.NODES, severity=severity, resource=node_key,
            message=f"Memory allocation at {mem_pct:.0f}% ({_fmt_memory(req_mem)} / {_fmt_memory(alloc_mem)} requested)",
            details={"requested_memory_bytes": int(req_mem), "allocatable_memory_bytes": int(alloc_mem),
                     "allocation_pct": round(mem_pct, 1), "pod_count": len(pods)},
            remediation="High memory allocation. Consider adding nodes or reducing requests.",
        ))


def _check_node_metrics(result, node, node_key, metrics):
    usage = metrics.get("usage", {})
    allocatable = node.status.allocatable or {}
    if not usage:
        return

    actual_cpu = _parse_cpu(usage.get("cpu", "0"))
    alloc_cpu = _parse_cpu(allocatable.get("cpu", "0"))
    actual_mem = _parse_memory(usage.get("memory", "0"))
    alloc_mem = _parse_memory(allocatable.get("memory", "0"))

    if alloc_cpu > 0:
        pct = (actual_cpu / alloc_cpu) * 100
        if pct >= 90:
            result.findings.append(Finding(
                category=CheckCategory.NODES, severity=Severity.CRITICAL, resource=node_key,
                message=f"Actual CPU usage at {pct:.0f}% ({actual_cpu:.1f} / {alloc_cpu:.1f} cores)",
                remediation="Node is CPU-saturated. Workloads will be throttled.",
            ))
    if alloc_mem > 0:
        pct = (actual_mem / alloc_mem) * 100
        if pct >= 90:
            result.findings.append(Finding(
                category=CheckCategory.NODES, severity=Severity.CRITICAL, resource=node_key,
                message=f"Actual memory usage at {pct:.0f}% ({_fmt_memory(actual_mem)} / {_fmt_memory(alloc_mem)})",
                remediation="Node is near memory exhaustion. OOM kills are likely.",
            ))


# =====================================================================
# Resource Utilization Checks (ported from kub_health/checks/resources.py)
# =====================================================================

def check_resources(snap: ClusterSnapshot) -> CheckResult:
    result = CheckResult(category=CheckCategory.RESOURCES)

    # Missing requests/limits
    for pod in snap.pods:
        if pod.status.phase in ("Succeeded", "Failed"):
            continue
        if pod.metadata.namespace in ("kube-system", "kube-public", "kube-node-lease"):
            continue
        pod_key = ResourceKey("Pod", pod.metadata.name, pod.metadata.namespace)
        for container in pod.spec.containers or []:
            resources = container.resources
            has_requests = resources and resources.requests
            has_limits = resources and resources.limits
            missing = []
            if not has_requests:
                missing.append("requests")
            else:
                if not resources.requests.get("cpu"):
                    missing.append("cpu request")
                if not resources.requests.get("memory"):
                    missing.append("memory request")
            if not has_limits:
                missing.append("limits")
            else:
                if not resources.limits.get("cpu"):
                    missing.append("cpu limit")
                if not resources.limits.get("memory"):
                    missing.append("memory limit")
            if missing:
                result.findings.append(Finding(
                    category=CheckCategory.RESOURCES, severity=Severity.WARNING, resource=pod_key,
                    message=f"Container '{container.name}' missing: {', '.join(missing)}",
                    details={"container": container.name, "missing": missing},
                    remediation="Set resource requests and limits for predictable scheduling and limits.",
                ))

    # ResourceQuota checks
    for quota in snap.resource_quotas:
        meta = quota.metadata
        rk = ResourceKey("ResourceQuota", meta.name, meta.namespace)
        status = quota.status or None
        if not status or not status.hard or not status.used:
            continue
        for resource_name, hard_val in (status.hard or {}).items():
            used_val = (status.used or {}).get(resource_name, "0")
            hard_num = _parse_resource_quantity(hard_val, resource_name)
            used_num = _parse_resource_quantity(used_val, resource_name)
            if hard_num == 0:
                continue
            pct = (used_num / hard_num) * 100
            if pct >= 95:
                sev = Severity.CRITICAL
            elif pct >= 80:
                sev = Severity.WARNING
            else:
                continue
            result.findings.append(Finding(
                category=CheckCategory.RESOURCES, severity=sev, resource=rk,
                message=f"ResourceQuota '{resource_name}' at {pct:.0f}% ({used_val} / {hard_val})",
                details={"resource": resource_name, "used": used_val, "hard": hard_val, "usage_pct": round(pct, 1)},
                evidence=[f"kubectl describe resourcequota {meta.name} -n {meta.namespace}"],
                remediation=f"Namespace '{meta.namespace}' is running out of '{resource_name}' quota.",
            ))

    # LimitRange defaults
    for lr in snap.limit_ranges:
        meta = lr.metadata
        rk = ResourceKey("LimitRange", meta.name, meta.namespace)
        for limit in lr.spec.limits or []:
            if limit.type == "Container":
                default_limits = limit.default or {}
                cpu_limit = default_limits.get("cpu", "")
                if cpu_limit and _parse_cpu(cpu_limit) <= 0.1:
                    result.findings.append(Finding(
                        category=CheckCategory.RESOURCES, severity=Severity.INFO, resource=rk,
                        message=f"LimitRange default CPU limit is very low: {cpu_limit}",
                        remediation="Containers without explicit limits will be constrained to this default.",
                    ))

    # Request/limit ratio checks
    for pod in snap.pods:
        if pod.status.phase in ("Succeeded", "Failed"):
            continue
        if pod.metadata.namespace in ("kube-system",):
            continue
        pod_key = ResourceKey("Pod", pod.metadata.name, pod.metadata.namespace)
        for container in pod.spec.containers or []:
            resources = container.resources
            if not resources or not resources.requests or not resources.limits:
                continue
            req_cpu = _parse_cpu(resources.requests.get("cpu", "0"))
            lim_cpu = _parse_cpu(resources.limits.get("cpu", "0"))
            req_mem = _parse_memory(resources.requests.get("memory", "0"))
            lim_mem = _parse_memory(resources.limits.get("memory", "0"))
            if req_cpu > 0 and lim_cpu > 0 and lim_cpu / req_cpu > 10:
                result.findings.append(Finding(
                    category=CheckCategory.RESOURCES, severity=Severity.INFO, resource=pod_key,
                    message=f"Container '{container.name}' CPU limit is {lim_cpu/req_cpu:.0f}x its request",
                    details={"container": container.name, "ratio": round(lim_cpu / req_cpu, 1)},
                    remediation="Large request/limit gaps create unpredictable burst behavior.",
                ))
            if req_mem > 0 and lim_mem > 0 and lim_mem / req_mem > 5:
                result.findings.append(Finding(
                    category=CheckCategory.RESOURCES, severity=Severity.INFO, resource=pod_key,
                    message=f"Container '{container.name}' memory limit is {lim_mem/req_mem:.0f}x its request",
                    details={"container": container.name, "ratio": round(lim_mem / req_mem, 1)},
                    remediation="Large memory request/limit gap risks OOM.",
                ))

    # Actual vs requested (metrics)
    if snap.pod_metrics:
        metrics_map: dict[str, dict] = {}
        for pm in snap.pod_metrics:
            name = pm.get("metadata", {}).get("name", "")
            ns = pm.get("metadata", {}).get("namespace", "")
            if name:
                metrics_map[f"{ns}/{name}"] = pm
        for pod in snap.pods:
            if pod.status.phase != "Running":
                continue
            key = f"{pod.metadata.namespace}/{pod.metadata.name}"
            pm = metrics_map.get(key)
            if not pm:
                continue
            pod_key = ResourceKey("Pod", pod.metadata.name, pod.metadata.namespace)
            containers_usage = {c["name"]: c.get("usage", {}) for c in pm.get("containers", [])}
            for container in pod.spec.containers or []:
                usage = containers_usage.get(container.name, {})
                if not usage:
                    continue
                resources = container.resources
                if not resources or not resources.requests:
                    continue
                actual_cpu = _parse_cpu(usage.get("cpu", "0"))
                req_cpu = _parse_cpu(resources.requests.get("cpu", "0"))
                if req_cpu > 0 and actual_cpu / req_cpu < 0.1 and req_cpu >= 0.1:
                    result.findings.append(Finding(
                        category=CheckCategory.RESOURCES, severity=Severity.INFO, resource=pod_key,
                        message=f"Container '{container.name}' using only {actual_cpu/req_cpu*100:.0f}% of CPU request",
                        remediation="Consider reducing CPU request to free capacity.",
                    ))

    return result


# =====================================================================
# Deployment / StatefulSet / DaemonSet Checks (ported from kub_health/checks/deployments.py)
# =====================================================================

def check_deployments(snap: ClusterSnapshot) -> CheckResult:
    result = CheckResult(category=CheckCategory.DEPLOYMENTS)
    now = datetime.now(timezone.utc)

    # Deployments
    for dep in snap.deployments:
        meta, spec, status = dep.metadata, dep.spec, dep.status
        rk = ResourceKey("Deployment", meta.name, meta.namespace)
        desired = spec.replicas if spec.replicas is not None else 1
        ready = status.ready_replicas or 0
        available = status.available_replicas or 0
        updated = status.updated_replicas or 0
        total = status.replicas or 0

        if desired == 0:
            continue
        if ready == 0 and desired > 0:
            result.findings.append(Finding(
                category=CheckCategory.DEPLOYMENTS, severity=Severity.CRITICAL, resource=rk,
                message=f"No ready replicas (0/{desired})",
                details={"desired": desired, "ready": ready, "available": available},
                evidence=[f"kubectl rollout status deployment/{meta.name} -n {meta.namespace}"],
                remediation="Check pod status for this deployment.",
            ))
            continue
        if ready < desired:
            severity = Severity.WARNING if ready > desired // 2 else Severity.CRITICAL
            result.findings.append(Finding(
                category=CheckCategory.DEPLOYMENTS, severity=severity, resource=rk,
                message=f"Degraded: {ready}/{desired} replicas ready",
                details={"desired": desired, "ready": ready, "available": available, "updated": updated},
                evidence=[f"kubectl rollout status deployment/{meta.name} -n {meta.namespace}"],
                remediation="Some replicas are not ready.",
            ))
        if updated < desired or total > desired:
            for cond in status.conditions or []:
                if cond.type == "Progressing" and cond.status == "False":
                    result.findings.append(Finding(
                        category=CheckCategory.DEPLOYMENTS, severity=Severity.CRITICAL, resource=rk,
                        message=f"Rollout stuck: {cond.reason or 'unknown'} - {cond.message or ''}",
                        details={"reason": cond.reason or "", "updated": updated, "desired": desired},
                        evidence=[f"kubectl rollout status deployment/{meta.name} -n {meta.namespace}"],
                        remediation=f"Consider rolling back: kubectl rollout undo deployment/{meta.name} -n {meta.namespace}",
                    ))
                    break

    # StatefulSets
    for sts in snap.statefulsets:
        meta, spec, status = sts.metadata, sts.spec, sts.status
        rk = ResourceKey("StatefulSet", meta.name, meta.namespace)
        desired = spec.replicas if spec.replicas is not None else 1
        ready = status.ready_replicas or 0
        if desired == 0:
            continue
        if ready == 0 and desired > 0:
            result.findings.append(Finding(
                category=CheckCategory.DEPLOYMENTS, severity=Severity.CRITICAL, resource=rk,
                message=f"StatefulSet has no ready replicas (0/{desired})",
                details={"desired": desired, "ready": ready},
                remediation="StatefulSets roll out sequentially; a single bad pod blocks the rollout.",
            ))
        elif ready < desired:
            result.findings.append(Finding(
                category=CheckCategory.DEPLOYMENTS, severity=Severity.WARNING, resource=rk,
                message=f"StatefulSet degraded: {ready}/{desired} replicas ready",
                details={"desired": desired, "ready": ready},
            ))

    # DaemonSets
    for ds in snap.daemonsets:
        meta, status = ds.metadata, ds.status
        rk = ResourceKey("DaemonSet", meta.name, meta.namespace)
        desired = status.desired_number_scheduled or 0
        ready = status.number_ready or 0
        misscheduled = status.number_misscheduled or 0
        if desired == 0:
            continue
        if ready < desired:
            missing = desired - ready
            severity = Severity.WARNING if missing <= desired // 4 else Severity.CRITICAL
            result.findings.append(Finding(
                category=CheckCategory.DEPLOYMENTS, severity=severity, resource=rk,
                message=f"DaemonSet missing pods on {missing}/{desired} nodes ({ready} ready)",
                details={"desired": desired, "ready": ready, "missing": missing},
                remediation="Check node taints/tolerations and pod status on affected nodes.",
            ))
        if misscheduled > 0:
            result.findings.append(Finding(
                category=CheckCategory.DEPLOYMENTS, severity=Severity.WARNING, resource=rk,
                message=f"DaemonSet has {misscheduled} mis-scheduled pods",
                details={"misscheduled": misscheduled},
            ))

    # Stale ReplicaSets
    deploy_revisions: dict[str, int] = {}
    for rs in snap.replicasets:
        if not rs.metadata.owner_references:
            continue
        for owner in rs.metadata.owner_references:
            if owner.kind == "Deployment":
                rev = int(rs.metadata.annotations.get("deployment.kubernetes.io/revision", "0"))
                key = f"{rs.metadata.namespace}/{owner.name}"
                deploy_revisions[key] = max(deploy_revisions.get(key, 0), rev)
    for rs in snap.replicasets:
        if not rs.metadata.owner_references:
            continue
        if (rs.status.replicas or 0) == 0:
            continue
        for owner in rs.metadata.owner_references:
            if owner.kind == "Deployment":
                rev = int(rs.metadata.annotations.get("deployment.kubernetes.io/revision", "0"))
                key = f"{rs.metadata.namespace}/{owner.name}"
                latest = deploy_revisions.get(key, 0)
                if rev < latest and rev > 0:
                    result.findings.append(Finding(
                        category=CheckCategory.DEPLOYMENTS, severity=Severity.INFO,
                        resource=ResourceKey("ReplicaSet", rs.metadata.name, rs.metadata.namespace),
                        message=f"Old ReplicaSet (rev {rev}, latest {latest}) still has {rs.status.replicas} replicas",
                        details={"revision": rev, "latest_revision": latest, "deployment": owner.name},
                        related_resources=[ResourceKey("Deployment", owner.name, rs.metadata.namespace)],
                    ))

    return result


# =====================================================================
# Events & Warnings Checks (ported from kub_health/checks/events.py)
# =====================================================================

HIGH_COUNT_WARN = 10
HIGH_COUNT_CRIT = 50
CRITICAL_REASONS = {
    "FailedScheduling", "FailedMount", "FailedAttachVolume", "FailedCreate",
    "Unhealthy", "BackOff", "Evicted", "OOMKilling", "NodeNotReady",
    "Rebooted", "SystemOOM", "FreeDiskSpaceFailed", "EvictionThresholdMet", "NetworkNotReady",
}
NOISE_REASONS = {"Pulling", "Pulled", "Scheduled", "Started", "Created", "SuccessfulCreate", "Killing"}


def check_events(snap: ClusterSnapshot) -> CheckResult:
    result = CheckResult(category=CheckCategory.EVENTS)
    now = datetime.now(timezone.utc)

    event_groups: dict[str, list] = defaultdict(list)
    warning_events = []
    for event in snap.events:
        if event.type == "Normal" and event.reason in NOISE_REASONS:
            continue
        obj = event.involved_object
        key = f"{obj.kind}/{obj.namespace or ''}/{obj.name}:{event.reason}"
        event_groups[key].append(event)
        if event.type == "Warning":
            warning_events.append(event)

    # High-frequency events
    for key, events in event_groups.items():
        total_count = sum(e.count or 1 for e in events)
        if total_count < HIGH_COUNT_WARN:
            continue
        sample = events[0]
        obj = sample.involved_object
        rk = ResourceKey(obj.kind or "Unknown", obj.name or "unknown", obj.namespace or "")
        severity = Severity.CRITICAL if total_count >= HIGH_COUNT_CRIT else Severity.WARNING
        latest = max(events, key=lambda e: e.last_timestamp or e.metadata.creation_timestamp or now)
        result.findings.append(Finding(
            category=CheckCategory.EVENTS, severity=severity, resource=rk,
            message=f"Event '{sample.reason}' occurred {total_count} times: {(latest.message or '')[:200]}",
            details={"reason": sample.reason, "total_count": total_count, "event_type": sample.type},
            evidence=[f"kubectl get events -n {obj.namespace or 'default'} --field-selector involvedObject.name={obj.name}"],
        ))

    # Critical warning events (low count but important)
    for event in warning_events:
        if event.reason not in CRITICAL_REASONS:
            continue
        if (event.count or 1) >= HIGH_COUNT_WARN:
            continue
        obj = event.involved_object
        rk = ResourceKey(obj.kind or "Unknown", obj.name or "unknown", obj.namespace or "")
        count = event.count or 1
        event_time = event.last_timestamp or event.metadata.creation_timestamp
        age_min = (now - event_time).total_seconds() / 60 if event_time else 0
        if age_min > 30:
            continue
        result.findings.append(Finding(
            category=CheckCategory.EVENTS, severity=Severity.WARNING, resource=rk,
            message=f"{event.reason} ({count}x, {age_min:.0f}m ago): {(event.message or '')[:200]}",
            details={"reason": event.reason, "count": count, "age_minutes": round(age_min)},
            evidence=[f"kubectl describe {obj.kind.lower()} {obj.name} -n {obj.namespace or 'default'}"],
        ))

    return result


# =====================================================================
# Networking Checks (ported from kub_health/checks/networking.py)
# =====================================================================

def check_networking(snap: ClusterSnapshot) -> CheckResult:
    result = CheckResult(category=CheckCategory.NETWORKING)

    # Services with no endpoints
    ep_map: dict[str, int] = {}
    for ep in snap.endpoints:
        key = f"{ep.metadata.namespace}/{ep.metadata.name}"
        ready_count = sum(len(subset.addresses or []) for subset in ep.subsets or [])
        ep_map[key] = ready_count

    for svc in snap.services:
        meta = svc.metadata
        svc_key = ResourceKey("Service", meta.name, meta.namespace)
        if svc.spec.type == "ExternalName" or svc.spec.cluster_ip == "None" or not svc.spec.selector:
            continue
        ep_key = f"{meta.namespace}/{meta.name}"
        if ep_map.get(ep_key, 0) == 0:
            result.findings.append(Finding(
                category=CheckCategory.NETWORKING, severity=Severity.CRITICAL, resource=svc_key,
                message="Service has no ready endpoints - traffic will fail",
                details={"type": svc.spec.type, "selector": dict(svc.spec.selector)},
                evidence=[f"kubectl get endpoints {meta.name} -n {meta.namespace}",
                          f"kubectl get pods -l {_selector_str(svc.spec.selector)} -n {meta.namespace}"],
                remediation="No pods match this service's selector, or matching pods aren't ready.",
            ))

    # Selector mismatch detection
    pod_labels: dict[str, list[dict[str, str]]] = {}
    for pod in snap.pods:
        if pod.status.phase in ("Succeeded", "Failed"):
            continue
        ns = pod.metadata.namespace
        labels = dict(pod.metadata.labels or {})
        pod_labels.setdefault(ns, []).append(labels)

    for svc in snap.services:
        if not svc.spec.selector or svc.spec.type == "ExternalName":
            continue
        meta = svc.metadata
        selector = dict(svc.spec.selector)
        ns_pods = pod_labels.get(meta.namespace, [])
        matching = sum(1 for labels in ns_pods if all(labels.get(k) == v for k, v in selector.items()))
        if matching == 0:
            svc_key = ResourceKey("Service", meta.name, meta.namespace)
            already = any(f.resource == svc_key and "no ready endpoints" in f.message.lower() for f in result.findings)
            if not already:
                result.findings.append(Finding(
                    category=CheckCategory.NETWORKING, severity=Severity.WARNING, resource=svc_key,
                    message=f"Selector {selector} matches 0 running pods in namespace",
                    remediation="Check labels on pods or correct the service selector.",
                ))

    # Port mismatch detection
    for svc in snap.services:
        if not svc.spec.selector or svc.spec.type == "ExternalName":
            continue
        meta = svc.metadata
        selector = dict(svc.spec.selector)
        for pod in snap.pods:
            if pod.metadata.namespace != meta.namespace or pod.status.phase in ("Succeeded", "Failed"):
                continue
            pod_labels_dict = dict(pod.metadata.labels or {})
            if not all(pod_labels_dict.get(k) == v for k, v in selector.items()):
                continue
            container_ports = set()
            for container in pod.spec.containers or []:
                for cp in container.ports or []:
                    container_ports.add((cp.container_port, cp.protocol or "TCP"))
                    if cp.name:
                        container_ports.add((cp.name, cp.protocol or "TCP"))
            for sp in svc.spec.ports or []:
                target = sp.target_port
                protocol = sp.protocol or "TCP"
                match_key = (target, protocol) if isinstance(target, int) else (str(target), protocol)
                if match_key not in container_ports and container_ports:
                    svc_key = ResourceKey("Service", meta.name, meta.namespace)
                    result.findings.append(Finding(
                        category=CheckCategory.NETWORKING, severity=Severity.WARNING, resource=svc_key,
                        message=f"Service port {sp.port} targets port {target} which isn't exposed by matching pods",
                        remediation="The service's targetPort doesn't match any containerPort.",
                    ))
            break

    # Ingress checks
    svc_set = {f"{s.metadata.namespace}/{s.metadata.name}" for s in snap.services}
    for ing in snap.ingresses:
        meta = ing.metadata
        rk = ResourceKey("Ingress", meta.name, meta.namespace)
        for rule in ing.spec.rules or []:
            if not rule.http:
                continue
            for path in rule.http.paths or []:
                if path.backend and path.backend.service:
                    svc_ref = f"{meta.namespace}/{path.backend.service.name}"
                    if svc_ref not in svc_set:
                        result.findings.append(Finding(
                            category=CheckCategory.NETWORKING, severity=Severity.CRITICAL, resource=rk,
                            message=f"Ingress references non-existent service '{path.backend.service.name}'",
                            related_resources=[ResourceKey("Service", path.backend.service.name, meta.namespace)],
                            remediation="Create the service or fix the ingress backend reference.",
                        ))
        for tls in ing.spec.tls or []:
            if tls.secret_name:
                secret_exists = any(
                    s.metadata.name == tls.secret_name and s.metadata.namespace == meta.namespace
                    for s in snap.secrets
                )
                if not secret_exists:
                    result.findings.append(Finding(
                        category=CheckCategory.NETWORKING, severity=Severity.WARNING, resource=rk,
                        message=f"TLS secret '{tls.secret_name}' not found",
                        remediation="Create the TLS secret or use cert-manager.",
                    ))

    # NetworkPolicy checks
    for np in snap.network_policies:
        rk = ResourceKey("NetworkPolicy", np.metadata.name, np.metadata.namespace)
        spec = np.spec
        policy_types = spec.policy_types or []
        if "Ingress" in policy_types and not spec.ingress:
            result.findings.append(Finding(
                category=CheckCategory.NETWORKING, severity=Severity.INFO, resource=rk,
                message="Default-deny ingress policy - all inbound traffic blocked for matched pods",
                remediation="Ensure other NetworkPolicies allow required traffic.",
            ))
        if "Egress" in policy_types and not spec.egress:
            result.findings.append(Finding(
                category=CheckCategory.NETWORKING, severity=Severity.WARNING, resource=rk,
                message="Default-deny egress policy - all outbound traffic blocked. May break DNS.",
                remediation="Ensure DNS (port 53 to kube-dns) is explicitly allowed.",
            ))

    return result


# =====================================================================
# Storage Checks (ported from kub_health/checks/storage.py)
# =====================================================================

def check_storage(snap: ClusterSnapshot) -> CheckResult:
    result = CheckResult(category=CheckCategory.STORAGE)
    sc_names = {sc.metadata.name for sc in snap.storage_classes}

    # PVC checks
    for pvc in snap.pvcs:
        meta = pvc.metadata
        rk = ResourceKey("PVC", meta.name, meta.namespace)
        phase = pvc.status.phase or "Unknown"
        if phase == "Bound":
            continue
        if phase == "Pending":
            sc_name = pvc.spec.storage_class_name or ""
            message = "PVC stuck in Pending state"
            remediation = "Check provisioner status, available capacity, and access mode compatibility."
            if sc_name and sc_name not in sc_names:
                message = f"PVC pending - StorageClass '{sc_name}' does not exist"
                remediation = f"Create StorageClass '{sc_name}' or change the PVC's storageClassName."
            elif not sc_name and not snap.storage_classes:
                message = "PVC pending - no StorageClass specified and none exist in cluster"
                remediation = "Create a StorageClass or specify one on the PVC."
            result.findings.append(Finding(
                category=CheckCategory.STORAGE, severity=Severity.CRITICAL, resource=rk,
                message=message,
                details={"phase": phase, "storage_class": sc_name},
                evidence=[f"kubectl describe pvc {meta.name} -n {meta.namespace}"],
                remediation=remediation,
            ))
        elif phase == "Lost":
            result.findings.append(Finding(
                category=CheckCategory.STORAGE, severity=Severity.CRITICAL, resource=rk,
                message="PVC is in Lost state - underlying PV was deleted",
                evidence=[f"kubectl describe pvc {meta.name} -n {meta.namespace}"],
                remediation="The PV was removed. Data may be lost. Recreate or restore from backup.",
            ))

    # PV checks
    for pv in snap.pvs:
        meta = pv.metadata
        rk = ResourceKey("PV", meta.name)
        phase = pv.status.phase or "Unknown"
        if phase in ("Bound", "Available"):
            continue
        if phase == "Released":
            result.findings.append(Finding(
                category=CheckCategory.STORAGE, severity=Severity.WARNING, resource=rk,
                message=f"PV is Released (reclaim: {pv.spec.persistent_volume_reclaim_policy or 'Delete'}) - not usable",
                evidence=[f"kubectl describe pv {meta.name}"],
                remediation="Delete the PV if data is unneeded, or clear claimRef to reuse.",
            ))
        elif phase == "Failed":
            result.findings.append(Finding(
                category=CheckCategory.STORAGE, severity=Severity.CRITICAL, resource=rk,
                message="PV is in Failed state",
                evidence=[f"kubectl describe pv {meta.name}"],
                remediation="Check the storage backend and provisioner logs.",
            ))

    # StorageClass checks
    if not snap.storage_classes and snap.pvcs:
        result.findings.append(Finding(
            category=CheckCategory.STORAGE, severity=Severity.WARNING,
            resource=ResourceKey("StorageClass", "(none)"),
            message="No StorageClasses defined but PVCs exist - dynamic provisioning unavailable",
            remediation="Create a StorageClass for your storage backend.",
        ))
    defaults = [sc for sc in snap.storage_classes
                if (sc.metadata.annotations or {}).get("storageclass.kubernetes.io/is-default-class") == "true"]
    if len(defaults) > 1:
        result.findings.append(Finding(
            category=CheckCategory.STORAGE, severity=Severity.WARNING,
            resource=ResourceKey("StorageClass", "(multiple-defaults)"),
            message=f"Multiple default StorageClasses: {[d.metadata.name for d in defaults]}",
            remediation="Only one StorageClass should be the default.",
        ))

    # Pod volume reference checks
    pvc_set = {f"{p.metadata.namespace}/{p.metadata.name}" for p in snap.pvcs}
    cm_set = {f"{c.metadata.namespace}/{c.metadata.name}" for c in snap.configmaps}
    secret_set = {f"{s.metadata.namespace}/{s.metadata.name}" for s in snap.secrets}
    for pod in snap.pods:
        if pod.status.phase in ("Succeeded", "Failed"):
            continue
        meta = pod.metadata
        pod_key = ResourceKey("Pod", meta.name, meta.namespace)
        for vol in pod.spec.volumes or []:
            if vol.persistent_volume_claim:
                ref = f"{meta.namespace}/{vol.persistent_volume_claim.claim_name}"
                if ref not in pvc_set:
                    result.findings.append(Finding(
                        category=CheckCategory.STORAGE, severity=Severity.CRITICAL, resource=pod_key,
                        message=f"References non-existent PVC '{vol.persistent_volume_claim.claim_name}'",
                        related_resources=[ResourceKey("PVC", vol.persistent_volume_claim.claim_name, meta.namespace)],
                        remediation="Create the PVC or fix the volume reference.",
                    ))
            if vol.config_map:
                ref = f"{meta.namespace}/{vol.config_map.name}"
                if ref not in cm_set and not (vol.config_map.optional or False):
                    result.findings.append(Finding(
                        category=CheckCategory.STORAGE, severity=Severity.WARNING, resource=pod_key,
                        message=f"References non-existent ConfigMap '{vol.config_map.name}'",
                        related_resources=[ResourceKey("ConfigMap", vol.config_map.name, meta.namespace)],
                        remediation="Create the ConfigMap or the pod won't start.",
                    ))
            if vol.secret:
                ref = f"{meta.namespace}/{vol.secret.secret_name}"
                if ref not in secret_set and not (vol.secret.optional or False):
                    result.findings.append(Finding(
                        category=CheckCategory.STORAGE, severity=Severity.WARNING, resource=pod_key,
                        message=f"References non-existent Secret '{vol.secret.secret_name}'",
                        related_resources=[ResourceKey("Secret", vol.secret.secret_name, meta.namespace)],
                        remediation="Create the Secret or the pod won't start.",
                    ))

    return result


# =====================================================================
# RBAC & Security Checks (ported from kub_health/checks/rbac.py)
# =====================================================================

DANGEROUS_CAPABILITIES = {
    "SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "NET_RAW",
    "SYS_MODULE", "DAC_OVERRIDE", "SYS_RAWIO", "MKNOD",
}


def check_rbac(snap: ClusterSnapshot) -> CheckResult:
    result = CheckResult(category=CheckCategory.RBAC)
    system_subjects = {"system:masters", "system:kube-scheduler", "system:kube-controller-manager", "system:kube-proxy"}

    # cluster-admin bindings
    for crb in snap.cluster_role_bindings:
        if not crb.role_ref or crb.role_ref.name != "cluster-admin":
            continue
        for subject in crb.subjects or []:
            subject_name = subject.name or ""
            if subject_name in system_subjects or subject_name.startswith("system:"):
                continue
            result.findings.append(Finding(
                category=CheckCategory.RBAC, severity=Severity.WARNING,
                resource=ResourceKey("ClusterRoleBinding", crb.metadata.name),
                message=f"cluster-admin bound to {subject.kind} '{subject_name}'"
                        + (f" in namespace '{subject.namespace}'" if subject.namespace else ""),
                evidence=[f"kubectl describe clusterrolebinding {crb.metadata.name}"],
                remediation="Use more specific roles (principle of least privilege).",
            ))

    # Wildcard roles
    for role in snap.cluster_roles:
        if role.metadata.name.startswith("system:"):
            continue
        rk = ResourceKey("ClusterRole", role.metadata.name)
        for rule in role.rules or []:
            verbs = rule.verbs or []
            resources = rule.resources or []
            if "*" in verbs and "*" in resources:
                result.findings.append(Finding(
                    category=CheckCategory.RBAC, severity=Severity.WARNING, resource=rk,
                    message="ClusterRole has wildcard permissions (all verbs on all resources)",
                    evidence=[f"kubectl describe clusterrole {role.metadata.name}"],
                    remediation="Scope down to specific resources and verbs.",
                ))
                break
            if "secrets" in resources and ("get" in verbs or "list" in verbs or "*" in verbs):
                result.findings.append(Finding(
                    category=CheckCategory.RBAC, severity=Severity.INFO, resource=rk,
                    message="ClusterRole can read secrets across the cluster",
                    remediation="Consider namespace-scoped Roles instead.",
                ))

    # Pod security
    for pod in snap.pods:
        if pod.status.phase in ("Succeeded", "Failed"):
            continue
        if pod.metadata.namespace in ("kube-system", "kube-public", "kube-node-lease"):
            continue
        pod_key = ResourceKey("Pod", pod.metadata.name, pod.metadata.namespace)
        pod_sc = pod.spec.security_context

        if pod.spec.host_network:
            result.findings.append(Finding(
                category=CheckCategory.RBAC, severity=Severity.WARNING, resource=pod_key,
                message="Pod uses hostNetwork - can see all node network traffic",
                remediation="Remove hostNetwork unless absolutely required.",
            ))
        if pod.spec.host_pid:
            result.findings.append(Finding(
                category=CheckCategory.RBAC, severity=Severity.WARNING, resource=pod_key,
                message="Pod uses hostPID - can see all node processes",
                remediation="hostPID is a significant security risk.",
            ))

        for container in pod.spec.containers or []:
            sc = container.security_context
            if sc and sc.privileged:
                result.findings.append(Finding(
                    category=CheckCategory.RBAC, severity=Severity.CRITICAL, resource=pod_key,
                    message=f"Container '{container.name}' is privileged - full node access",
                    remediation="Use specific capabilities instead of privileged mode.",
                ))

            run_as_root = False
            if sc and sc.run_as_user == 0:
                run_as_root = True
            elif sc and sc.run_as_non_root is True:
                run_as_root = False
            elif pod_sc and pod_sc.run_as_non_root is True:
                run_as_root = False
            elif not sc or sc.run_as_user is None:
                if not (pod_sc and pod_sc.run_as_non_root):
                    run_as_root = True
            if run_as_root:
                result.findings.append(Finding(
                    category=CheckCategory.RBAC, severity=Severity.INFO, resource=pod_key,
                    message=f"Container '{container.name}' may run as root (no runAsNonRoot set)",
                    remediation="Set securityContext.runAsNonRoot: true.",
                ))

            if sc and sc.capabilities and sc.capabilities.add:
                dangerous = set(sc.capabilities.add) & DANGEROUS_CAPABILITIES
                if dangerous:
                    result.findings.append(Finding(
                        category=CheckCategory.RBAC, severity=Severity.WARNING, resource=pod_key,
                        message=f"Container '{container.name}' has dangerous capabilities: {sorted(dangerous)}",
                        remediation="Remove unless the workload specifically requires them.",
                    ))

    # Default service account usage
    for pod in snap.pods:
        if pod.status.phase in ("Succeeded", "Failed"):
            continue
        if pod.metadata.namespace in ("kube-system", "kube-public", "kube-node-lease"):
            continue
        sa_name = pod.spec.service_account_name or "default"
        if sa_name != "default":
            continue
        if pod.spec.automount_service_account_token is False:
            continue
        pod_key = ResourceKey("Pod", pod.metadata.name, pod.metadata.namespace)
        result.findings.append(Finding(
            category=CheckCategory.RBAC, severity=Severity.INFO, resource=pod_key,
            message="Using 'default' service account with auto-mounted token",
            remediation="Create a dedicated service account for this workload.",
        ))

    return result


# =====================================================================
# Dependency Graph Builder (ported from kub_health/correlator/dependency_graph.py)
# =====================================================================

def build_dependency_graph(snap: ClusterSnapshot) -> DependencyGraph:
    graph = DependencyGraph()

    # Pod -> Node
    for pod in snap.pods:
        if pod.spec.node_name:
            graph.add_edge(DependencyEdge(
                source=ResourceKey("Pod", pod.metadata.name, pod.metadata.namespace),
                target=ResourceKey("Node", pod.spec.node_name),
                dep_type=DependencyType.RUNS_ON,
            ))

    # ReplicaSet -> Deployment
    for rs in snap.replicasets:
        for owner in rs.metadata.owner_references or []:
            if owner.kind == "Deployment":
                graph.add_edge(DependencyEdge(
                    source=ResourceKey("Deployment", owner.name, rs.metadata.namespace),
                    target=ResourceKey("ReplicaSet", rs.metadata.name, rs.metadata.namespace),
                    dep_type=DependencyType.OWNS,
                ))

    # Pod -> ReplicaSet / StatefulSet / DaemonSet
    for pod in snap.pods:
        for owner in pod.metadata.owner_references or []:
            if owner.kind in ("ReplicaSet", "StatefulSet", "DaemonSet"):
                graph.add_edge(DependencyEdge(
                    source=ResourceKey(owner.kind, owner.name, pod.metadata.namespace),
                    target=ResourceKey("Pod", pod.metadata.name, pod.metadata.namespace),
                    dep_type=DependencyType.OWNS,
                ))

    # Service -> Pods
    for svc in snap.services:
        if not svc.spec.selector:
            continue
        selector = dict(svc.spec.selector)
        svc_key = ResourceKey("Service", svc.metadata.name, svc.metadata.namespace)
        for pod in snap.pods:
            if pod.metadata.namespace != svc.metadata.namespace:
                continue
            pod_labels = dict(pod.metadata.labels or {})
            if all(pod_labels.get(k) == v for k, v in selector.items()):
                graph.add_edge(DependencyEdge(
                    source=svc_key,
                    target=ResourceKey("Pod", pod.metadata.name, pod.metadata.namespace),
                    dep_type=DependencyType.SELECTS,
                ))

    # Ingress -> Service
    for ing in snap.ingresses:
        ing_key = ResourceKey("Ingress", ing.metadata.name, ing.metadata.namespace)
        for rule in ing.spec.rules or []:
            if not rule.http:
                continue
            for path in rule.http.paths or []:
                if path.backend and path.backend.service:
                    graph.add_edge(DependencyEdge(
                        source=ing_key,
                        target=ResourceKey("Service", path.backend.service.name, ing.metadata.namespace),
                        dep_type=DependencyType.REFERENCES,
                    ))

    # Pod -> PVC
    for pod in snap.pods:
        pod_key = ResourceKey("Pod", pod.metadata.name, pod.metadata.namespace)
        for vol in pod.spec.volumes or []:
            if vol.persistent_volume_claim:
                graph.add_edge(DependencyEdge(
                    source=pod_key,
                    target=ResourceKey("PVC", vol.persistent_volume_claim.claim_name, pod.metadata.namespace),
                    dep_type=DependencyType.MOUNTS,
                ))

    # Pod -> ConfigMap / Secret
    for pod in snap.pods:
        pod_key = ResourceKey("Pod", pod.metadata.name, pod.metadata.namespace)
        ns = pod.metadata.namespace
        for vol in pod.spec.volumes or []:
            if vol.config_map:
                graph.add_edge(DependencyEdge(
                    source=pod_key, target=ResourceKey("ConfigMap", vol.config_map.name, ns),
                    dep_type=DependencyType.MOUNTS,
                ))
            if vol.secret:
                graph.add_edge(DependencyEdge(
                    source=pod_key, target=ResourceKey("Secret", vol.secret.secret_name, ns),
                    dep_type=DependencyType.MOUNTS,
                ))
        for container in pod.spec.containers or []:
            for env in container.env or []:
                if env.value_from:
                    if env.value_from.config_map_key_ref:
                        graph.add_edge(DependencyEdge(
                            source=pod_key,
                            target=ResourceKey("ConfigMap", env.value_from.config_map_key_ref.name, ns),
                            dep_type=DependencyType.MOUNTS,
                        ))
                    if env.value_from.secret_key_ref:
                        graph.add_edge(DependencyEdge(
                            source=pod_key,
                            target=ResourceKey("Secret", env.value_from.secret_key_ref.name, ns),
                            dep_type=DependencyType.MOUNTS,
                        ))
            for env_from in container.env_from or []:
                if env_from.config_map_ref:
                    graph.add_edge(DependencyEdge(
                        source=pod_key,
                        target=ResourceKey("ConfigMap", env_from.config_map_ref.name, ns),
                        dep_type=DependencyType.MOUNTS,
                    ))
                if env_from.secret_ref:
                    graph.add_edge(DependencyEdge(
                        source=pod_key,
                        target=ResourceKey("Secret", env_from.secret_ref.name, ns),
                        dep_type=DependencyType.MOUNTS,
                    ))

    # HPA -> workload
    for hpa in snap.hpas:
        target = hpa.spec.scale_target_ref
        if target:
            graph.add_edge(DependencyEdge(
                source=ResourceKey("HPA", hpa.metadata.name, hpa.metadata.namespace),
                target=ResourceKey(target.kind, target.name, hpa.metadata.namespace),
                dep_type=DependencyType.SCALES,
            ))

    # NetworkPolicy -> Pods
    for np in snap.network_policies:
        np_key = ResourceKey("NetworkPolicy", np.metadata.name, np.metadata.namespace)
        selector = {}
        if np.spec.pod_selector and np.spec.pod_selector.match_labels:
            selector = dict(np.spec.pod_selector.match_labels)
        for pod in snap.pods:
            if pod.metadata.namespace != np.metadata.namespace:
                continue
            pod_labels = dict(pod.metadata.labels or {})
            if not selector or all(pod_labels.get(k) == v for k, v in selector.items()):
                graph.add_edge(DependencyEdge(
                    source=np_key,
                    target=ResourceKey("Pod", pod.metadata.name, pod.metadata.namespace),
                    dep_type=DependencyType.TARGETS,
                ))

    # RoleBinding -> Role + ServiceAccount
    for rb in snap.role_bindings:
        rb_key = ResourceKey("RoleBinding", rb.metadata.name, rb.metadata.namespace)
        if rb.role_ref:
            role_kind = rb.role_ref.kind
            role_ns = rb.metadata.namespace if role_kind == "Role" else ""
            graph.add_edge(DependencyEdge(
                source=rb_key, target=ResourceKey(role_kind, rb.role_ref.name, role_ns),
                dep_type=DependencyType.BINDS,
            ))
        for subject in rb.subjects or []:
            if subject.kind == "ServiceAccount":
                graph.add_edge(DependencyEdge(
                    source=rb_key,
                    target=ResourceKey("ServiceAccount", subject.name, subject.namespace or rb.metadata.namespace),
                    dep_type=DependencyType.BINDS,
                ))

    return graph


# =====================================================================
# Timeline Builder (ported from kub_health/correlator/timeline.py)
# =====================================================================

def build_timeline(snap: ClusterSnapshot) -> list[TimelineEvent]:
    timeline: list[TimelineEvent] = []
    for event in snap.events:
        obj = event.involved_object
        rk = ResourceKey(obj.kind or "Unknown", obj.name or "unknown", obj.namespace or "")
        ts = event.last_timestamp or event.event_time or event.metadata.creation_timestamp
        if ts is None:
            continue
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        source_component = ""
        if event.source:
            source_component = event.source.component or ""
        timeline.append(TimelineEvent(
            timestamp=ts, resource=rk, event_type=event.type or "Normal",
            reason=event.reason or "", message=event.message or "",
            count=event.count or 1, source_component=source_component,
        ))
    timeline.sort()
    return timeline


def events_for_resource(timeline: list[TimelineEvent], key: ResourceKey) -> list[TimelineEvent]:
    return [e for e in timeline if e.resource == key]


# =====================================================================
# Correlation Engine (ported from kub_health/correlator/engine.py)
# =====================================================================

def correlate_findings(
    check_results: list[CheckResult],
    graph: DependencyGraph,
    timeline: list[TimelineEvent],
) -> tuple[list[CorrelationGroup], list[Finding]]:
    all_findings: list[Finding] = []
    for cr in check_results:
        all_findings.extend(cr.findings)
    if not all_findings:
        return [], []

    findings_by_resource: dict[ResourceKey, list[Finding]] = defaultdict(list)
    for f in all_findings:
        findings_by_resource[f.resource].append(f)

    groups: list[CorrelationGroup] = []
    claimed: set[str] = set()

    _correlate_node_issues(groups, claimed, findings_by_resource, graph, timeline)
    _correlate_deployment_issues(groups, claimed, findings_by_resource, graph, timeline)
    _correlate_storage_issues(groups, claimed, findings_by_resource, graph, timeline)
    _correlate_service_issues(groups, claimed, findings_by_resource, graph, timeline)
    _correlate_config_issues(groups, claimed, findings_by_resource, graph, timeline)

    uncorrelated = [f for f in all_findings if f.id not in claimed]
    return groups, uncorrelated


def _correlate_node_issues(groups, claimed, findings_by_resource, graph, timeline):
    node_findings = {
        rk: findings for rk, findings in findings_by_resource.items()
        if rk.kind == "Node" and any(f.severity in (Severity.CRITICAL, Severity.WARNING) for f in findings)
    }
    for node_key, node_issues in node_findings.items():
        pod_edges = [e for e in graph.dependents_of(node_key)
                     if e.dep_type == DependencyType.RUNS_ON and e.source.kind == "Pod"]
        symptoms: list[Finding] = []
        affected: set[ResourceKey] = {node_key}
        for edge in pod_edges:
            affected.add(edge.source)
            for f in findings_by_resource.get(edge.source, []):
                if f.id not in claimed:
                    symptoms.append(f)
        if not symptoms:
            continue
        root = max(node_issues, key=lambda f: -f.severity.sort_order)
        group = CorrelationGroup(
            root_cause=root, symptoms=symptoms, affected_resources=affected,
            timeline=events_for_resource(timeline, node_key)[-20:],
            summary=f"Node '{node_key.name}' issue ({root.message}) affecting {len(symptoms)} pod(s).",
        )
        groups.append(group)
        claimed.add(root.id)
        for s in symptoms:
            claimed.add(s.id)
        for nf in node_issues:
            claimed.add(nf.id)


def _correlate_deployment_issues(groups, claimed, findings_by_resource, graph, timeline):
    for rk, findings in list(findings_by_resource.items()):
        if rk.kind not in ("Deployment", "StatefulSet", "DaemonSet"):
            continue
        unclaimed_findings = [f for f in findings if f.id not in claimed]
        if not unclaimed_findings:
            continue
        owned_resources = graph.dependency_chain(rk)
        pod_findings: list[Finding] = []
        affected: set[ResourceKey] = {rk}
        for res in owned_resources:
            affected.add(res)
            for f in findings_by_resource.get(res, []):
                if f.id not in claimed:
                    pod_findings.append(f)
        if not pod_findings and len(unclaimed_findings) <= 1:
            continue
        root = max(unclaimed_findings, key=lambda f: -f.severity.sort_order)
        symptoms = [f for f in pod_findings if f.id != root.id]
        events = events_for_resource(timeline, rk)
        for res in owned_resources:
            if res.kind == "Pod":
                events.extend(events_for_resource(timeline, res)[-5:])
        events.sort()
        group = CorrelationGroup(
            root_cause=root, symptoms=symptoms, affected_resources=affected,
            timeline=events[-20:],
            summary=f"{rk.kind} '{rk.name}' in {rk.namespace}: {root.message}. {len(symptoms)} related finding(s).",
        )
        groups.append(group)
        claimed.add(root.id)
        for s in symptoms:
            claimed.add(s.id)
        for f in unclaimed_findings:
            claimed.add(f.id)


def _correlate_storage_issues(groups, claimed, findings_by_resource, graph, timeline):
    pvc_findings = {
        rk: findings for rk, findings in findings_by_resource.items()
        if rk.kind == "PVC" and any(f.id not in claimed for f in findings)
    }
    for pvc_key, pvc_issues in pvc_findings.items():
        unclaimed = [f for f in pvc_issues if f.id not in claimed]
        if not unclaimed:
            continue
        pod_edges = [e for e in graph.dependents_of(pvc_key)
                     if e.dep_type == DependencyType.MOUNTS and e.source.kind == "Pod"]
        symptoms: list[Finding] = []
        affected: set[ResourceKey] = {pvc_key}
        for edge in pod_edges:
            affected.add(edge.source)
            for f in findings_by_resource.get(edge.source, []):
                if f.id not in claimed:
                    symptoms.append(f)
        if not symptoms and len(unclaimed) <= 1:
            continue
        root = max(unclaimed, key=lambda f: -f.severity.sort_order)
        group = CorrelationGroup(
            root_cause=root, symptoms=symptoms, affected_resources=affected,
            timeline=events_for_resource(timeline, pvc_key)[-10:],
            summary=f"PVC '{pvc_key.name}' in {pvc_key.namespace}: {root.message}. {len(symptoms)} pod(s) affected.",
        )
        groups.append(group)
        claimed.add(root.id)
        for s in symptoms:
            claimed.add(s.id)
        for f in unclaimed:
            claimed.add(f.id)


def _correlate_service_issues(groups, claimed, findings_by_resource, graph, timeline):
    svc_findings = {
        rk: findings for rk, findings in findings_by_resource.items()
        if rk.kind == "Service" and any(f.id not in claimed for f in findings)
    }
    for svc_key, svc_issues in svc_findings.items():
        unclaimed = [f for f in svc_issues if f.id not in claimed]
        if not unclaimed:
            continue
        pod_edges = [e for e in graph.dependencies_of(svc_key)
                     if e.dep_type == DependencyType.SELECTS and e.target.kind == "Pod"]
        symptoms: list[Finding] = []
        affected: set[ResourceKey] = {svc_key}
        for edge in pod_edges:
            affected.add(edge.target)
            for f in findings_by_resource.get(edge.target, []):
                if f.id not in claimed:
                    symptoms.append(f)
        ing_edges = [e for e in graph.dependents_of(svc_key) if e.source.kind == "Ingress"]
        for edge in ing_edges:
            affected.add(edge.source)
            for f in findings_by_resource.get(edge.source, []):
                if f.id not in claimed:
                    symptoms.append(f)
        if not symptoms:
            continue
        if symptoms and any(s.severity == Severity.CRITICAL for s in symptoms):
            root = max(symptoms, key=lambda f: -f.severity.sort_order)
            all_symptoms = [f for f in unclaimed if f.id != root.id] + [s for s in symptoms if s.id != root.id]
        else:
            root = max(unclaimed, key=lambda f: -f.severity.sort_order)
            all_symptoms = symptoms
        group = CorrelationGroup(
            root_cause=root, symptoms=all_symptoms, affected_resources=affected,
            timeline=events_for_resource(timeline, svc_key)[-10:],
            summary=f"Service '{svc_key.name}' in {svc_key.namespace}: {root.message}. {len(all_symptoms)} related.",
        )
        groups.append(group)
        claimed.add(root.id)
        for s in all_symptoms:
            claimed.add(s.id)
        for f in unclaimed:
            claimed.add(f.id)


def _correlate_config_issues(groups, claimed, findings_by_resource, graph, timeline):
    missing_refs: dict[ResourceKey, list[Finding]] = defaultdict(list)
    for rk, findings in findings_by_resource.items():
        for f in findings:
            if f.id in claimed:
                continue
            for related in f.related_resources:
                if related.kind in ("ConfigMap", "Secret"):
                    missing_refs[related].append(f)
    for ref_key, ref_findings in missing_refs.items():
        if len(ref_findings) < 2:
            continue
        root = Finding(
            category=ref_findings[0].category, severity=Severity.CRITICAL,
            resource=ref_key,
            message=f"{ref_key.kind} '{ref_key.name}' is missing or inaccessible, affecting {len(ref_findings)} pod(s)",
            remediation=f"Create the {ref_key.kind} '{ref_key.name}' in namespace '{ref_key.namespace}'.",
        )
        group = CorrelationGroup(
            root_cause=root, symptoms=ref_findings,
            affected_resources={ref_key} | {f.resource for f in ref_findings},
            summary=f"Missing {ref_key.kind} '{ref_key.name}' in {ref_key.namespace} causing {len(ref_findings)} failure(s).",
        )
        groups.append(group)
        for f in ref_findings:
            claimed.add(f.id)


# =====================================================================
# Report Text Generator
# =====================================================================

def generate_report_text(
    cluster_name: str,
    context_name: str,
    snap: ClusterSnapshot,
    check_results: list[CheckResult],
    correlation_groups: list[CorrelationGroup],
    uncorrelated: list[Finding],
) -> str:
    lines = [
        f"# Kubernetes Cluster Investigation: {cluster_name}",
        f"Context: {context_name}",
        f"Timestamp: {snap.timestamp.isoformat()}",
        f"Nodes: {len(snap.nodes)} | Pods: {len(snap.pods)} | Namespaces: {len(snap.namespaces)}",
        "",
    ]

    total = sum(len(r.findings) for r in check_results)
    crits = sum(r.critical_count for r in check_results)
    warns = sum(r.warning_count for r in check_results)
    infos = total - crits - warns

    lines.append(f"## Summary: {total} findings ({crits} critical, {warns} warning, {infos} info)")
    lines.append("")

    if correlation_groups:
        lines.append("## Root Cause Analysis")
        for i, group in enumerate(correlation_groups, 1):
            lines.append(f"\n### Issue #{i} [{group.severity.value.upper()}]")
            if group.root_cause:
                lines.append(f"Root Cause: {group.root_cause.resource} - {group.root_cause.message}")
            if group.symptoms:
                lines.append(f"Symptoms ({len(group.symptoms)}):")
                for s in group.symptoms[:10]:
                    lines.append(f"  - {s.resource}: {s.message}")
            if group.affected_resources:
                lines.append(f"Blast radius: {len(group.affected_resources)} resources affected")

    if uncorrelated:
        lines.append("\n## Additional Findings")
        for f in sorted(uncorrelated, key=lambda x: x.severity.sort_order):
            lines.append(f"- [{f.severity.value.upper()}] {f.resource}: {f.message}")

    lines.append("\n## Findings by Category")
    for result in check_results:
        if not result.findings:
            continue
        lines.append(f"\n### {result.category.value}")
        for f in sorted(result.findings, key=lambda x: x.severity.sort_order):
            lines.append(f"- [{f.severity.value.upper()}] {f.resource}: {f.message}")
            if f.remediation:
                lines.append(f"    Remediation: {f.remediation}")

    return "\n".join(lines)


# =====================================================================
# Ansible Module Entry Point
# =====================================================================

def run_module():
    from ansible.module_utils.basic import AnsibleModule

    module = AnsibleModule(
        argument_spec=dict(
            kubeconfig=dict(type="path", default="~/.kube/config"),
            context=dict(type="str", default=None),
            namespace=dict(type="str", default=None),
            severity_threshold=dict(type="str", default="info", choices=["info", "warning", "critical"]),
            checks=dict(
                type="list", elements="str",
                default=["pods", "nodes", "resources", "deployments", "events", "networking", "storage", "rbac"],
            ),
        ),
        supports_check_mode=True,
    )

    # Verify kubernetes package is available
    try:
        from kubernetes import client, config
        from kubernetes.config.config_exception import ConfigException
    except ImportError:
        module.fail_json(msg="The 'kubernetes' Python package is required. Install with: pip install kubernetes")
        return

    kubeconfig = module.params["kubeconfig"]
    context = module.params["context"]
    namespace = module.params["namespace"]
    severity_threshold = module.params["severity_threshold"]
    enabled_checks = set(module.params["checks"])

    threshold_map = {"info": Severity.INFO, "warning": Severity.WARNING, "critical": Severity.CRITICAL}
    threshold = threshold_map[severity_threshold]

    # Connect to cluster
    try:
        try:
            config.load_kube_config(config_file=kubeconfig, context=context)
        except ConfigException:
            config.load_incluster_config()
        api_client = client.ApiClient()
    except Exception as e:
        module.fail_json(msg=f"Failed to connect to Kubernetes cluster: {e}")
        return

    # Get cluster/context name
    try:
        _, active_ctx = config.list_kube_config_contexts(config_file=kubeconfig)
        cluster_name = active_ctx.get("context", {}).get("cluster", "unknown")
        context_name = active_ctx.get("name", "unknown")
    except Exception:
        cluster_name = "in-cluster"
        context_name = context or "in-cluster"

    # Collect snapshot
    try:
        snap = collect_snapshot(api_client, namespace=namespace)
    except Exception as e:
        module.fail_json(msg=f"Failed to collect cluster snapshot: {e}")
        return

    # Run health checks
    check_map = {
        "pods": check_pods,
        "nodes": check_nodes,
        "resources": check_resources,
        "deployments": check_deployments,
        "events": check_events,
        "networking": check_networking,
        "storage": check_storage,
        "rbac": check_rbac,
    }

    check_results: list[CheckResult] = []
    for name, func in check_map.items():
        if name not in enabled_checks:
            continue
        try:
            result = func(snap)
            check_results.append(result)
        except Exception as e:
            check_results.append(CheckResult(
                category=CheckCategory(check_map[name].__doc__ or name),
                error=str(e),
            ))

    # Build dependency graph and correlate
    graph = build_dependency_graph(snap)
    timeline = build_timeline(snap)
    correlation_groups, uncorrelated = correlate_findings(check_results, graph, timeline)

    # Apply severity threshold filter
    def _above_threshold(f: Finding) -> bool:
        return f.severity.sort_order <= threshold.sort_order

    filtered_results = []
    for cr in check_results:
        filtered = CheckResult(category=cr.category, error=cr.error, duration_ms=cr.duration_ms)
        filtered.findings = [f for f in cr.findings if _above_threshold(f)]
        filtered_results.append(filtered)

    filtered_groups = [
        g for g in correlation_groups
        if g.severity.sort_order <= threshold.sort_order
    ]
    filtered_uncorrelated = [f for f in uncorrelated if _above_threshold(f)]

    # Build summary
    all_findings = []
    for cr in filtered_results:
        all_findings.extend(cr.findings)

    crits = sum(1 for f in all_findings if f.severity == Severity.CRITICAL)
    warns = sum(1 for f in all_findings if f.severity == Severity.WARNING)
    infos = sum(1 for f in all_findings if f.severity == Severity.INFO)

    overall = Severity.OK
    if crits > 0:
        overall = Severity.CRITICAL
    elif warns > 0:
        overall = Severity.WARNING
    elif infos > 0:
        overall = Severity.INFO

    summary = {
        "cluster_name": cluster_name,
        "context": context_name,
        "overall_health": overall.value,
        "total_findings": len(all_findings),
        "critical_count": crits,
        "warning_count": warns,
        "info_count": infos,
        "node_count": len(snap.nodes),
        "pod_count": len(snap.pods),
        "namespace_count": len(snap.namespaces),
        "correlation_groups_count": len(filtered_groups),
    }

    # Generate text report
    report_text = generate_report_text(
        cluster_name, context_name, snap,
        filtered_results, filtered_groups, filtered_uncorrelated,
    )

    module.exit_json(
        changed=False,
        summary=summary,
        findings=[f.to_dict() for f in all_findings],
        check_results=[cr.to_dict() for cr in filtered_results],
        correlation_groups=[g.to_dict() for g in filtered_groups],
        uncorrelated_findings=[f.to_dict() for f in filtered_uncorrelated],
        report_text=report_text,
    )


def main():
    run_module()


if __name__ == "__main__":
    main()
