"""Network Scanner integration."""
from __future__ import annotations

import logging
from datetime import timedelta

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .const import DOMAIN
from .scanner import NetworkScannerClient

_LOGGER = logging.getLogger(__name__)

PLATFORMS = ["sensor"]
SCAN_INTERVAL = timedelta(minutes=15)


async def async_setup(hass: HomeAssistant, config: dict) -> bool:
    """Set up the Network Scanner component.

    hass.data[DOMAIN] also holds per-entry coordinators (keyed by entry_id,
    set in async_setup_entry below), so the YAML block is namespaced under
    its own "_yaml_config" key instead of occupying the top level - it must
    not collide with those entry_id keys.
    """
    domain_data = hass.data.setdefault(DOMAIN, {})
    domain_data["_yaml_config"] = config.get(DOMAIN, {})
    return True


async def async_setup_entry(hass: HomeAssistant, config_entry: ConfigEntry) -> bool:
    """Set up Network Scanner from a config entry."""
    ip_range = config_entry.data.get("ip_range")

    # Collect every mac_mapping_N key that is actually present, ordered by slot
    # number. This deliberately does NOT walk the slots contiguously: the old
    # loop stopped at the first missing key, so clearing a single entry in the
    # middle (say mac_mapping_40) silently dropped every mapping numbered above
    # it even though their values were still stored on the config entry.
    def _slot_number(key: str) -> int:
        suffix = key[len("mac_mapping_") :]
        return int(suffix) if suffix.isdigit() else 0

    mac_mappings = "\n".join(
        value
        for _, value in sorted(
            (
                (key, value)
                for key, value in config_entry.data.items()
                if key.startswith("mac_mapping_") and value
            ),
            key=lambda item: _slot_number(item[0]),
        )
    )

    # Build the blocking scanner client in the executor — its constructor
    # calls `nmap --version` synchronously, which must not run on the event loop.
    client = await hass.async_add_executor_job(
        NetworkScannerClient, ip_range, mac_mappings
    )

    async def _async_update_data():
        """Run the blocking nmap scan off the event loop."""
        try:
            return await hass.async_add_executor_job(client.scan)
        except Exception as err:
            raise UpdateFailed(f"Network scan failed: {err}") from err

    # config_entry is mandatory: omitting it stopped working in HA 2025.11, and
    # the ContextVar fallback that used to cover for it is removed in 2026.8.
    coordinator: DataUpdateCoordinator = DataUpdateCoordinator(
        hass,
        _LOGGER,
        config_entry=config_entry,
        name=f"{DOMAIN}_{ip_range}",
        update_interval=SCAN_INTERVAL,
        update_method=_async_update_data,
    )

    # Do NOT await the first refresh here - a cold nmap sweep takes far longer
    # than the 10s platform-setup budget, so awaiting it stalls startup.
    # config_entry.async_create_background_task is the right home for it:
    # background tasks are excluded from the startup wait (so setup still
    # returns immediately), and unlike hass.async_create_background_task the
    # task is tied to the entry's lifecycle and gets cancelled on unload
    # instead of leaking a running scan.
    hass.data[DOMAIN][config_entry.entry_id] = coordinator

    await hass.config_entries.async_forward_entry_setups(config_entry, PLATFORMS)

    config_entry.async_create_background_task(
        hass,
        coordinator.async_refresh(),
        name=f"{DOMAIN}_initial_refresh",
    )

    return True


async def async_unload_entry(hass: HomeAssistant, config_entry: ConfigEntry) -> bool:
    """Unload a config entry."""
    unload_ok = await hass.config_entries.async_unload_platforms(config_entry, PLATFORMS)
    if unload_ok:
        hass.data[DOMAIN].pop(config_entry.entry_id, None)
    return unload_ok
