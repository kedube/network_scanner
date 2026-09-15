"""Pure nmap scanning logic, isolated from Home Assistant internals.

This module must not import anything from homeassistant, and must not touch
the event loop. All calls into it run inside the executor via the coordinator.
"""
from __future__ import annotations

import logging
import re
import socket
from concurrent.futures import ThreadPoolExecutor
from typing import Any

import nmap

_LOGGER = logging.getLogger(__name__)

# nmap args:
#   -sn                : ping scan only, no port scan
#   -n                 : skip DNS (we do our own reverse-DNS, in parallel, only
#                        for hosts that actually answered)
#   -T4                : aggressive timing template
#   --min-parallelism  : probe many hosts at once
#   --min-rate         : floor on probes/sec, so a quiet subnet finishes fast
#   --max-retries 1    : don't linger on unresponsive hosts
#
# Note: --host-timeout is deliberately absent. With -sn there is no port scan,
# so an unreachable host is decided in milliseconds and the ceiling almost never
# binds; when it does bind it drops slow-but-live hosts, which combined with
# --max-retries 1 made the device count flap between scans.
NMAP_ARGS = "-sn -n -T4 --min-parallelism 128 --min-rate 500 --max-retries 1"

# Reverse-DNS is done concurrently across discovered hosts. Serially, a 0.3s
# timeout per host meant ~12s of pure DNS wait on a /24 with 40 nameless devices.
RDNS_TIMEOUT = 0.3
RDNS_MAX_WORKERS = 32


class NetworkScannerClient:
    """Blocking nmap client. One instance per config entry."""

    def __init__(self, ip_range: str, mac_mapping: str) -> None:
        self.ip_range = ip_range
        self.mac_mapping = self._parse_mac_mapping(mac_mapping)
        self.nm = nmap.PortScanner()
        _LOGGER.info("Network Scanner client initialized for %s", ip_range)

    # ---------------------- helpers ----------------------
    @staticmethod
    def _parse_mac_mapping(mapping_string: str) -> dict[str, tuple[str, str]]:
        mapping: dict[str, tuple[str, str]] = {}
        for line in mapping_string.split("\n"):
            parts = line.split(";")
            if len(parts) >= 3:
                mapping[parts[0].lower()] = (parts[1], parts[2])
        return mapping

    @staticmethod
    def _short_label(name: str) -> str | None:
        """Return lowercase host label before first dot, cleaned, or None."""
        if not name:
            return None
        short = name.strip().rstrip(".").split(".", 1)[0].lower()
        short = re.sub(r"[^a-z0-9_-]", "", short)
        return short or None

    @staticmethod
    def _fast_rdns(ip: str) -> str | None:
        """Reverse-DNS for one IP; returns a cleaned short label or None.

        Called from several worker threads at once, so it must not touch
        socket.setdefaulttimeout() - that is process-global state and racing
        workers would restore each other's values. The timeout is applied by
        the caller instead, once, before the pool starts.
        """
        try:
            host, _, _ = socket.gethostbyaddr(ip)
            return NetworkScannerClient._short_label(host)
        except Exception:
            return None

    @staticmethod
    def _resolve_hostnames(ips: list[str]) -> dict[str, str | None]:
        """Reverse-DNS a batch of IPs concurrently. Never raises."""
        if not ips:
            return {}

        old_to = socket.getdefaulttimeout()
        socket.setdefaulttimeout(RDNS_TIMEOUT)
        try:
            workers = min(RDNS_MAX_WORKERS, len(ips))
            with ThreadPoolExecutor(max_workers=workers) as pool:
                return dict(zip(ips, pool.map(NetworkScannerClient._fast_rdns, ips)))
        except Exception as err:
            _LOGGER.debug("Reverse-DNS batch failed: %s", err)
            return {}
        finally:
            socket.setdefaulttimeout(old_to)

    def _get_device_info_from_mac(self, mac_address: str) -> tuple[str, str]:
        return self.mac_mapping.get(
            mac_address.lower(), ("Unknown Device", "Unknown Device")
        )

    # ---------------------- main entry point ----------------------
    def scan(self) -> list[dict[str, Any]]:
        """Run an nmap ping scan and return the list of discovered devices.

        Blocking. Must be called from the executor, never from the event loop.
        """
        try:
            self.nm.scan(hosts=self.ip_range, arguments=NMAP_ARGS)
        except Exception as err:
            _LOGGER.error("nmap scan failed with args '%s': %s", NMAP_ARGS, err)
            raise

        devices: list[dict[str, Any]] = []

        for host in self.nm.all_hosts():
            try:
                addrs = self.nm[host].get("addresses", {})
                if "mac" not in addrs or "ipv4" not in addrs:
                    continue

                ip = addrs["ipv4"]
                mac = addrs["mac"]

                # Vendor from nmap's OUI db, if known
                vendor = "Unknown"
                vendor_map = self.nm[host].get("vendor", {})
                if mac in vendor_map:
                    vendor = vendor_map[mac]

                # Hostname: try nmap result first (usually empty because -n)
                raw_hostname = self.nm[host].hostname() or ""
                if not raw_hostname:
                    for h in self.nm[host].get("hostnames", []):
                        n = h.get("name")
                        if n:
                            raw_hostname = n
                            break

                device_name, device_type = self._get_device_info_from_mac(mac)
                devices.append(
                    {
                        "ip": ip,
                        "mac": mac,
                        "name": device_name,
                        "type": device_type,
                        "vendor": vendor,
                        "hostname": self._short_label(raw_hostname),
                    }
                )
            except Exception as err:
                _LOGGER.debug("Error parsing host %s: %s", host, err)
                continue

        # Fill in the hostnames nmap could not supply (-n suppresses its own
        # lookups) with one concurrent reverse-DNS pass over just those hosts.
        unresolved = [d["ip"] for d in devices if not d["hostname"]]
        if unresolved:
            resolved = self._resolve_hostnames(unresolved)
            for device in devices:
                if not device["hostname"]:
                    device["hostname"] = resolved.get(device["ip"])

        try:
            devices.sort(key=lambda x: [int(num) for num in x["ip"].split(".")])
        except Exception:
            pass

        return devices
