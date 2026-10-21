"""Operational listeners must not load on the protected local Windows host."""

from cyberapp.host_safety import enforce_host_safety

enforce_host_safety()
