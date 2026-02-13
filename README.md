# kub-health-ansible

Ansible playbook for Kubernetes cluster health investigation. Runs comprehensive health checks entirely from the Ansible control node — **nothing gets installed on any target server**.

All Kubernetes API calls are **read-only** (list/get operations). Zero writes to the cluster.

> For the standalone Python CLI tool, see [kub-health](https://github.com/Ben-Nachmanson/kub-health).

## What It Checks

| Module | What It Looks For |
|---|---|
| **pods** | CrashLoopBackOff, OOMKilled, image pull failures, pending pods, excessive restarts, readiness failures |
| **nodes** | NotReady nodes, MemoryPressure, DiskPressure, PIDPressure, cordoned nodes, NoExecute taints |
| **resources** | Missing requests/limits, ResourceQuota exhaustion, request/limit ratio anomalies, actual vs requested usage |
| **deployments** | Zero-ready replicas, degraded deployments, stuck rollouts, StatefulSet/DaemonSet issues, stale ReplicaSets |
| **events** | High-frequency warning events, critical event reasons (FailedScheduling, FailedMount, Unhealthy, etc.) |
| **networking** | Selector mismatches, headless service issues, endpoint gaps, overly broad NetworkPolicies |
| **storage** | Unbound PVCs, Released PVs, storage class mismatches, capacity issues |
| **rbac** | Wildcard permissions, cluster-admin bindings, missing referenced roles, default SA token automount |

Findings are correlated into **root-cause groups** using a dependency graph and 5 strategies: node cascade, deployment grouping, storage cascade, service-endpoint correlation, and missing config detection.

## Requirements

- **Ansible** >= 2.12 on the control node
- **Python** >= 3.10 on the control node
- **kubernetes** Python package (`pip install kubernetes`)
- A valid kubeconfig with read access to the target cluster

That's it. No packages, agents, or files are installed on any remote host.

## Quick Start

```bash
# Clone the repo
git clone https://github.com/Ben-Nachmanson/kub-health-ansible.git
cd kub-health-ansible

# Install the Python dependency
pip install -r requirements.txt

# Run against your current kubeconfig context
ansible-playbook site.yml
```

## Usage Examples

```bash
# Check a specific cluster context
ansible-playbook site.yml -e kub_health_context=prod-cluster

# Check a single namespace
ansible-playbook site.yml -e kub_health_namespace=my-app

# Only show warnings and critical issues
ansible-playbook site.yml -e kub_health_severity_threshold=warning

# Fail the playbook if critical issues are found (useful in CI/CD)
ansible-playbook site.yml -e kub_health_fail_on_critical=true

# Save the full report to a file
ansible-playbook site.yml -e kub_health_report_file=/tmp/cluster-health.txt

# Use a custom kubeconfig
ansible-playbook site.yml -e kub_health_kubeconfig=/etc/kubernetes/admin.conf

# Run only specific checks
ansible-playbook site.yml -e '{"kub_health_checks": ["pods", "nodes"]}'

# Check multiple clusters using inventory
ansible-playbook -i inventory.yml site.yml
ansible-playbook -i inventory.yml site.yml --limit prod
```

## Role Variables

| Variable | Default | Description |
|---|---|---|
| `kub_health_kubeconfig` | `~/.kube/config` | Path to kubeconfig file |
| `kub_health_context` | *(current context)* | Kubeconfig context to use |
| `kub_health_namespace` | *(all namespaces)* | Limit checks to a single namespace |
| `kub_health_severity_threshold` | `info` | Minimum severity: `info`, `warning`, `critical` |
| `kub_health_checks` | All 8 modules | List of check modules to run |
| `kub_health_fail_on_critical` | `false` | Fail the play if critical issues are found |
| `kub_health_report_file` | *(empty)* | Save full text report to this path |

## Repo Structure

```
kub-health-ansible/
├── site.yml                          # Main playbook
├── inventory.yml                     # Multi-cluster inventory template
├── requirements.txt                  # Python dependencies (just kubernetes)
└── roles/
    └── kub_health/
        ├── defaults/main.yml         # Default variables
        ├── tasks/main.yml            # Role tasks
        └── library/
            └── kub_health_check.py   # Self-contained custom module (~2000 lines)
```

The custom module (`kub_health_check.py`) is entirely self-contained. It embeds all analysis logic — 8 health check modules, a resource dependency graph builder, timeline correlation, and a 5-strategy root-cause correlation engine — in a single file. No external Python dependencies beyond `kubernetes`.

## Multi-Cluster Setup

Edit `inventory.yml` to define your clusters:

```yaml
all:
  children:
    clusters:
      hosts:
        dev:
          ansible_connection: local
          kub_health_context: dev-cluster
        staging:
          ansible_connection: local
          kub_health_context: staging-cluster
        prod:
          ansible_connection: local
          kub_health_context: prod-cluster
          kub_health_fail_on_critical: true
```

Then run:

```bash
# Check all clusters
ansible-playbook -i inventory.yml site.yml

# Check only production
ansible-playbook -i inventory.yml site.yml --limit prod
```

## CI/CD Integration

Use `kub_health_fail_on_critical: true` to gate deployments:

```yaml
# In your CI pipeline
- name: Pre-deploy health check
  ansible-playbook site.yml -e kub_health_fail_on_critical=true -e kub_health_context=prod
```

The playbook exits non-zero if any critical issues are found.

## How It Works

1. The playbook runs on `localhost` with `connection: local`
2. The custom Ansible module connects to the K8s API via kubeconfig
3. A single-pass snapshot collects 30+ resource types (pods, nodes, deployments, services, RBAC, etc.)
4. 8 health check modules analyze the snapshot
5. A dependency graph maps relationships between resources (12 mapping functions)
6. 5 correlation strategies group findings into root-cause clusters
7. Results are displayed as Ansible debug output with severity-coded messages

## License

MIT
