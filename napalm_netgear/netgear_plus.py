# -*- coding: utf-8 -*-
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""NAPALM driver for Netgear Plus Smart Managed switches (HTTP-based).

Tested against: GS308EP and compatible Plus Smart Managed series.
Transport: HTTP web interface via py-netgear-plus library.

These switches use password-only web authentication (no username).
The ``username`` parameter is accepted but ignored.
"""

import threading
import time
from typing import Any, Dict, List, Optional, Tuple

from napalm_device_types import SwitchDriver
from napalm.base.exceptions import ConnectionException

# ---------------------------------------------------------------------------
# Firmware update check — module-level constants and cache
# ---------------------------------------------------------------------------

# Netgear CDN base URL for firmware zip files.
# Pattern: {_FW_CDN_BASE}/{MODEL}/{MODEL}_{VERSION}.zip
_FW_CDN_BASE = "https://www.downloads.netgear.com/files/GDC"

# Known-latest firmware versions per CDN model ID.
# Verified via HEAD requests against downloads.netgear.com on 2026-05-24.
# Update this table when Netgear releases new firmware.
_FW_KNOWN_LATEST: Dict[str, str] = {
    "GS305EP":  "V2.0.0.10",
    "GS305EPP": "V2.0.0.10",
    "GS308EP":  "V2.0.0.11",
    "GS308EPP": "V2.0.0.11",
}

# In-memory cache: model_id -> (latest_version, unix_timestamp_of_check)
_fw_cache: Dict[str, Tuple[str, float]] = {}
_fw_cache_lock = threading.Lock()

# How long (seconds) to reuse a cached firmware-version result (24 hours).
_FW_CACHE_TTL = 86400


def _fw_version_tuple(version: str) -> Tuple[int, ...]:
    """Parse 'V1.0.1.4' or '1.0.1.4' into (1, 0, 1, 4). Raises ValueError on bad input."""
    v = version.strip().lstrip("Vv")
    return tuple(int(x) for x in v.split("."))


def _fw_cdn_exists(model: str, version: str) -> bool:
    """Return True if a firmware zip exists on the Netgear CDN (HEAD request)."""
    import urllib.request
    import ssl

    url = f"{_FW_CDN_BASE}/{model}/{model}_{version}.zip"
    ctx = ssl.create_default_context()
    req = urllib.request.Request(url, method="HEAD",
                                  headers={"User-Agent": "Mozilla/5.0"})
    try:
        with urllib.request.urlopen(req, timeout=3, context=ctx):
            return True
    except Exception:
        return False


def _fw_probe_newer(model: str, baseline: str) -> str:
    """Probe the Netgear CDN for firmware newer than *baseline*.

    Checks up to ~22 candidate versions (patch increments, next micro, next
    major).  Returns the highest confirmed version string, which may equal
    *baseline* if nothing newer is found.
    """
    try:
        base_t = _fw_version_tuple(baseline)
    except ValueError:
        return baseline

    if len(base_t) != 4:
        return baseline

    major, minor, micro, patch = base_t
    best_t = base_t
    best_v = baseline

    def _try(candidate: Tuple[int, ...]) -> None:
        nonlocal best_t, best_v
        v_str = "V" + ".".join(str(x) for x in candidate)
        if _fw_cdn_exists(model, v_str) and candidate > best_t:
            best_t = candidate
            best_v = v_str

    # Probe the next 20 patch versions
    for p in range(patch + 1, patch + 21):
        _try((major, minor, micro, p))

    # Probe next micro version (reset patch to 0)
    _try((major, minor, micro + 1, 0))

    # Probe next major version (e.g. V2.0.0.0 when current is V1.x.x.x)
    _try((major + 1, 0, 0, 0))

    return best_v


def _fw_get_latest(model: str) -> Optional[str]:
    """Return the latest known firmware version for *model*, using a 24-hour
    in-memory cache.  Returns ``None`` when the model is not in the known table.
    """
    model_upper = model.upper()
    baseline = _FW_KNOWN_LATEST.get(model_upper)
    if baseline is None:
        return None

    now = time.monotonic()

    with _fw_cache_lock:
        cached = _fw_cache.get(model_upper)
        if cached is not None:
            version, ts = cached
            if now - ts < _FW_CACHE_TTL:
                return version

    # Cache miss or expired — probe CDN (outside the lock to avoid blocking
    # other threads during potentially slow HTTP requests).
    latest = _fw_probe_newer(model_upper, baseline)

    with _fw_cache_lock:
        _fw_cache[model_upper] = (latest, now)

    return latest


class NetgearPlusDriver(SwitchDriver):
    """HTTP-based NAPALM driver for Netgear Plus Smart Managed switches."""

    VENDOR = "Netgear"

    def __init__(
        self,
        hostname: str,
        username: str,
        password: str,
        timeout: int = 60,
        optional_args: Optional[Dict] = None,
    ) -> None:
        # username is accepted but ignored — these switches have no username
        self.hostname = hostname
        self.password = password
        self.timeout = timeout
        self._connector = None
        self._switch_infos_cache: Optional[Dict[str, Any]] = None

        if optional_args is None:
            optional_args = {}

    # ------------------------------------------------------------------
    # Connection management
    # ------------------------------------------------------------------

    def open(self) -> None:
        """Authenticate to the switch via HTTP."""
        try:
            from py_netgear_plus import NetgearSwitchConnector
        except ImportError as exc:
            raise ConnectionException(
                "py-netgear-plus is not installed. "
                "Add 'py-netgear-plus' to your dependencies."
            ) from exc

        try:
            connector = NetgearSwitchConnector(self.hostname, self.password)
            connector.autodetect_model()
            if not connector.get_login_cookie():
                raise ConnectionException(
                    f"Login failed for {self.hostname}: bad password or unreachable."
                )
            self._connector = connector
            self._switch_infos_cache = None
        except Exception as exc:
            if isinstance(exc, ConnectionException):
                raise
            raise ConnectionException(
                f"Cannot connect to {self.hostname}: {exc}"
            ) from exc

    def close(self) -> None:
        """Log out from the switch."""
        if self._connector is not None:
            try:
                self._connector.delete_login_cookie()
            except Exception:
                pass
            self._connector = None
        self._switch_infos_cache = None

    def is_alive(self) -> Dict[str, bool]:
        return {"is_alive": self._connector is not None}

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_switch_infos(self) -> Dict[str, Any]:
        """Fetch and cache switch infos for this poll cycle."""
        if self._switch_infos_cache is None:
            self._switch_infos_cache = self._connector.get_switch_infos()
        return self._switch_infos_cache

    def _get_port_names(self) -> Dict[int, str]:
        """Fetch port names/descriptions from dashboard.cgi.

        The GS30x series embeds ``<input class="portName" value="...">``
        hidden inputs in the dashboard HTML.  py-netgear-plus does not
        parse them, so we do it here.  Returns a mapping of
        {port_number: name_string} (1-indexed, empty string if not set).
        """
        import re

        try:
            url = f"http://{self.hostname}/dashboard.cgi"
            resp = self._connector.fetch_page("get", url, {})
        except Exception:
            return {}
        if not resp or resp.status_code != 200 or not resp.text:
            return {}
        portname_re = re.compile(
            r'<input[^>]+class="portName"[^>]+value="([^"]*)"',
            re.IGNORECASE,
        )
        names = portname_re.findall(resp.text)
        return {i + 1: name for i, name in enumerate(names)}

    def _port_name(self, port_number: int) -> str:
        return f"port{port_number}"

    def _interface_to_port_number(self, interface: str) -> int:
        """Convert an interface name like 'port3' to the integer port number 3."""
        name = interface.strip().lower()
        if name.startswith("port"):
            try:
                return int(name[4:])
            except ValueError:
                pass
        raise ValueError(
            f"Cannot resolve interface {interface!r} to a port number. "
            "Expected 'portN' (e.g. 'port1')."
        )

    # ------------------------------------------------------------------
    # NAPALM getters
    # ------------------------------------------------------------------

    def get_facts(self) -> Dict[str, Any]:
        """Return a dictionary of general device facts."""
        infos = self._get_switch_infos()
        model = getattr(self._connector.switch_model, "MODEL_NAME", "")
        hostname = infos.get("switch_name", self.hostname)
        os_version = infos.get("switch_firmware", "")
        serial_number = infos.get("switch_serial_number", "")
        interface_list = [
            self._port_name(i) for i in range(1, self._connector.ports + 1)
        ]
        return {
            "vendor": self.VENDOR,
            "model": str(model),
            "hostname": hostname,
            "fqdn": hostname,
            "os_version": os_version,
            "serial_number": serial_number,
            "uptime": 0.0,
            "interface_list": interface_list,
        }

    def get_interfaces(self) -> Dict[str, Dict]:
        """Return a dictionary of interface details.

        Each interface entry contains:
        ``is_up``, ``is_enabled``, ``description``, ``last_flapped``,
        ``speed``, ``mtu``, ``mac_address``.
        """
        infos = self._get_switch_infos()
        port_names = self._get_port_names()
        interfaces: Dict[str, Dict] = {}
        for port in range(1, self._connector.ports + 1):
            name = self._port_name(port)
            status = infos.get(f"port_{port}_status", "off") == "on"
            speed = float(infos.get(f"port_{port}_connection_speed", 0) or 0)
            description = port_names.get(port, "") or infos.get(f"port_{port}_description", "") or ""
            interfaces[name] = {
                "is_up": status,
                "is_enabled": True,
                "description": description,
                "last_flapped": -1.0,
                "speed": speed,
                "mtu": 1518,
                "mac_address": "",
            }
        return interfaces

    def get_interfaces_ip(self) -> Dict[str, Dict]:
        """Return IP addresses per interface.

        Netgear Plus switches are L2 only — no routed interfaces.
        Always returns an empty dict.
        """
        return {}

    def get_interfaces_counters(self) -> Dict[str, Dict]:
        """Return interface traffic counters.

        Uses cumulative RX/TX totals (``sum_rx_mbytes`` / ``sum_tx_mbytes``)
        from ``get_switch_infos()`` converted to octets, plus CRC errors.
        """
        infos = self._get_switch_infos()
        counters: Dict[str, Dict] = {}
        for port in range(1, self._connector.ports + 1):
            name = self._port_name(port)
            # sum_*_mbytes are lifetime totals in megabytes; convert to bytes
            rx_mb = float(infos.get(f"port_{port}_sum_rx_mbytes", 0) or 0)
            tx_mb = float(infos.get(f"port_{port}_sum_tx_mbytes", 0) or 0)
            crc = int(infos.get(f"port_{port}_crc_errors", 0) or 0)
            counters[name] = {
                "tx_errors": 0,
                "rx_errors": crc,
                "tx_discards": 0,
                "rx_discards": 0,
                "tx_octets": int(tx_mb * 1_000_000),
                "rx_octets": int(rx_mb * 1_000_000),
                "tx_unicast_packets": 0,
                "rx_unicast_packets": 0,
                "tx_multicast_packets": 0,
                "rx_multicast_packets": 0,
                "tx_broadcast_packets": 0,
                "rx_broadcast_packets": 0,
            }
        return counters

    def get_environment(self) -> Dict[str, Any]:
        """Return environment data.

        Reports PoE power status per PoE port.  Temperature, fans, CPU and
        memory are not available on these switches and are returned as empty
        dicts.
        """
        infos = self._get_switch_infos()
        power: Dict[str, Any] = {}
        poe_max_single = getattr(
            self._connector.switch_model, "POE_MAX_POWER_SINGLE_PORT", None
        )
        for port in self._connector.poe_ports:
            poe_active = infos.get(f"port_{port}_poe_power_active")
            poe_status = bool(poe_active) if poe_active is not None else False
            power[self._port_name(port)] = {
                "status": poe_status,
                "capacity": float(poe_max_single) if poe_max_single else 0.0,
                "used": 0.0,
            }
        return {
            "fans": {},
            "temperature": {},
            "power": power,
            "cpu": {},
            "memory": {},
        }

    def get_mac_address_table(self) -> List[Dict]:
        """Return the MAC address table.

        Not available via the HTTP web interface of Plus switches.
        Returns an empty list.
        """
        return []

    def get_arp_table(self, vrf: str = "") -> List[Dict]:
        """Return the ARP table.

        Netgear Plus switches are L2 only and have no ARP table.
        Returns an empty list.
        """
        return []

    def get_lldp_neighbors(self) -> Dict[str, Any]:
        """Return LLDP neighbors.

        Not supported on Netgear Plus switches.
        Returns an empty dict.
        """
        return {}

    def get_lldp_neighbors_detail(self, interface: str = "") -> Dict[str, Any]:
        """Return detailed LLDP neighbor info.

        Not supported on Netgear Plus switches.
        Returns an empty dict.
        """
        return {}

    def get_vlans_detail(self) -> Dict[str, Any]:
        """Return VLAN configuration by scraping the switch's /vlan.cgi page.

        Returns a dict keyed by VLAN ID string:
          {"1": {"name": "Default", "tagged": ["port1"], "untagged": ["port2"]}}

        Parses 802.1Q Advanced VLAN data from the switch web interface.
        Each port's PVID (native VLAN) is listed with a trailing "*" in the
        per-port VLAN membership spans.
        """
        import re

        url = f"http://{self.hostname}/vlan.cgi"
        try:
            resp = self._connector.fetch_page("get", url, {})
        except Exception:
            return {}

        if not resp or resp.status_code != 200 or not resp.text:
            return {}

        text = resp.text

        # Parse VLAN IDs and names from vid-4 / vnm-4 span pairs.
        # Example: <span vid-4>...<i ...></i>24</span><span vnm-4 ...>Guest</span>
        vlan_names: Dict[str, str] = {}
        vlan_entry_re = re.compile(
            r'<span\s+vid-4[^>]*>.*?(\d+)\s*</span>\s*'
            r'<span\s+vnm-4[^>]*>([^<]*)</span>',
            re.DOTALL,
        )
        for m in vlan_entry_re.finditer(text):
            vid = m.group(1).strip()
            name = m.group(2).strip()
            vlan_names[vid] = name

        if not vlan_names:
            return {}

        vlans: Dict[str, Any] = {
            vid: {"name": name, "tagged": [], "untagged": []}
            for vid, name in vlan_names.items()
        }

        # Parse per-port PVID membership.
        # Each <span pvid-str ...>1*, 24, 25,</span> corresponds to one port
        # in order (port 1, port 2, ...). A VID followed by "*" is the native
        # (untagged) VLAN for that port; all others are tagged.
        pvid_span_re = re.compile(r'<span\s[^>]*pvid-str[^>]*>([^<]+)</span>')
        for port_idx, pvid_str in enumerate(pvid_span_re.finditer(text)):
            port_num = port_idx + 1
            if port_num > self._connector.ports:
                break
            port_name = self._port_name(port_num)
            for token in pvid_str.group(1).split(","):
                token = token.strip()
                if not token:
                    continue
                if token.endswith("*"):
                    vid = token[:-1]
                    role = "untagged"
                else:
                    vid = token
                    role = "tagged"
                if vid in vlans:
                    vlans[vid][role].append(port_name)

        return vlans

    def get_vlans(self) -> Dict[str, Any]:
        """Return VLAN information (standard NAPALM format).

        Delegates to get_vlans_detail() and merges tagged and untagged ports
        into a single ``interfaces`` list.
        """
        detail = self.get_vlans_detail()
        return {
            vid: {
                "name": info["name"],
                "interfaces": info["tagged"] + info["untagged"],
            }
            for vid, info in detail.items()
        }

    def set_vlan(self, vlan_id: int, config: Dict) -> None:
        """Create or update a VLAN.

        Not supported via HTTP API.
        """
        raise NotImplementedError(
            "VLAN management is not supported for Netgear Plus switches via HTTP."
        )

    def delete_vlan(self, vlan_id: int) -> None:
        """Delete a VLAN.

        Not supported via HTTP API.
        """
        raise NotImplementedError(
            "VLAN management is not supported for Netgear Plus switches via HTTP."
        )

    def get_config(
        self,
        retrieve: str = "all",
        full: bool = False,
        sanitized: bool = False,
        format: str = "text",
    ) -> Dict[str, str]:
        """Return device configuration.

        Netgear Plus switches do not expose running/startup config via HTTP.
        Returns empty strings for all config slots.
        """
        return {"running": "", "startup": "", "candidate": ""}

    def load_merge_candidate(self, filename: Optional[str] = None, config: Optional[str] = None) -> None:
        raise NotImplementedError(
            "Config management is not supported for Netgear Plus switches."
        )

    def load_replace_candidate(self, filename: Optional[str] = None, config: Optional[str] = None) -> None:
        raise NotImplementedError(
            "Config management is not supported for Netgear Plus switches."
        )

    def compare_config(self) -> str:
        raise NotImplementedError(
            "Config management is not supported for Netgear Plus switches."
        )

    def commit_config(self, message: str = "") -> None:
        raise NotImplementedError(
            "Config management is not supported for Netgear Plus switches."
        )

    def discard_config(self) -> None:
        raise NotImplementedError(
            "Config management is not supported for Netgear Plus switches."
        )

    def rollback(self) -> None:
        raise NotImplementedError(
            "Config management is not supported for Netgear Plus switches."
        )

    def has_pending_commit(self) -> bool:
        return False

    def ping(
        self,
        destination: str,
        source: str = "",
        ttl: int = 255,
        timeout: int = 2,
        size: int = 100,
        count: int = 5,
        vrf: str = "",
        source_interface: str = "",
    ) -> Dict[str, Any]:
        """Execute ping.

        Not supported on Netgear Plus switches via HTTP.
        """
        raise NotImplementedError(
            "ping() is not supported for Netgear Plus switches."
        )

    def traceroute(
        self,
        destination: str,
        source: str = "",
        ttl: int = 255,
        timeout: int = 2,
        vrf: str = "",
    ) -> Dict[str, Any]:
        """Execute traceroute.

        Not supported on Netgear Plus switches via HTTP.
        """
        raise NotImplementedError(
            "traceroute() is not supported for Netgear Plus switches."
        )

    def cli(self, commands: List[str], encoding: str = "text") -> Dict[str, Any]:
        """Send CLI commands.

        Netgear Plus switches have no SSH CLI — only HTTP.
        """
        raise NotImplementedError(
            "cli() is not supported for Netgear Plus switches (HTTP-only device)."
        )

    def get_users(self) -> Dict[str, Any]:
        """Return user accounts.

        Not available via HTTP API.  Returns an empty dict.
        """
        return {}

    def get_snmp_information(self) -> Dict[str, Any]:
        """Return SNMP configuration.

        Not available via HTTP API.  Returns an empty dict.
        """
        return {}

    def get_ntp_servers(self) -> Dict[str, Any]:
        """Return configured NTP servers.

        Not available via HTTP API.  Returns an empty dict.
        """
        return {}

    def get_ntp_peers(self) -> Dict[str, Any]:
        """Return NTP peers.

        Not available via HTTP API.  Returns an empty dict.
        """
        return {}

    def get_ntp_stats(self) -> List[Dict]:
        """Return NTP stats.

        Not available via HTTP API.  Returns an empty list.
        """
        return []

    # ------------------------------------------------------------------
    # SwitchDriver abstract methods (not applicable for this device)
    # ------------------------------------------------------------------

    def get_spanning_tree(self) -> Dict[str, Any]:
        """Return spanning tree status.

        Not available via HTTP API.  Returns an empty dict.
        """
        return {}

    def get_port_channels(self) -> Dict[str, Any]:
        """Return port-channel information.

        Not available via HTTP API.  Returns an empty dict.
        """
        return {}

    def get_dot1x_config(self) -> Dict[str, Any]:
        """Return 802.1X port configuration.

        Not available via HTTP API.  Returns an empty dict.
        """
        return {}

    def get_mac_acl(self) -> Dict[str, Any]:
        """Return MAC ACL information.

        Not available via HTTP API.  Returns an empty dict.
        """
        return {}

    def get_poe_status(self) -> Dict[str, Any]:
        """Return PoE status.

        Reports PoE power status from switch infos.
        """
        infos = self._get_switch_infos()
        poe_max_all = getattr(
            self._connector.switch_model, "POE_MAX_POWER_ALL_PORTS", None
        )
        poe_max_single = getattr(
            self._connector.switch_model, "POE_MAX_POWER_SINGLE_PORT", None
        )
        ports: Dict[str, Any] = {}
        for p in self._connector.poe_ports:
            poe_active = infos.get(f"port_{p}_poe_power_active")
            is_delivering = bool(poe_active) if poe_active is not None else False
            ports[self._port_name(p)] = {
                "enabled": True,
                "status": "delivering" if is_delivering else "searching",
                "poe_class": "unknown",
                "power_draw": 0.0,
                "power_budget": float(poe_max_single) if poe_max_single else 0.0,
                "voltage": 0.0,
                "current": 0.0,
            }
        return {
            "total_power_budget": float(poe_max_all) if poe_max_all else 0.0,
            "total_power_draw": 0.0,
            "ports": ports,
        }

    def set_poe_enabled(self, interface: str, enabled: bool) -> None:
        """Enable or disable PoE on a port.

        Uses py-netgear-plus to switch the PoE port state.
        """
        port_number = self._interface_to_port_number(interface)
        if port_number not in self._connector.poe_ports:
            raise ValueError(f"{interface} is not a PoE port on this switch.")
        if enabled:
            self._connector.turn_on_poe_port(port_number)
        else:
            self._connector.turn_off_poe_port(port_number)

    def power_cycle_port(self, interface: str, delay: int = 5) -> None:
        """Power-cycle a PoE port.

        Uses py-netgear-plus power cycle functionality.
        """
        port_number = self._interface_to_port_number(interface)
        if port_number not in self._connector.poe_ports:
            raise ValueError(f"{interface} is not a PoE port on this switch.")
        self._connector.power_cycle_poe_port(port_number)

    def set_interface(self, interface: str, config: Dict) -> None:
        """Configure an interface.

        Not supported via HTTP API.
        """
        raise NotImplementedError(
            "set_interface() is not supported for Netgear Plus switches."
        )

    def get_device_warnings(self) -> list:
        """Check for available firmware updates and return a warning if the
        device is not running the latest known firmware.

        The latest version is looked up once per 24 hours (per model, per
        worker process) via lightweight HEAD requests against Netgear's
        download CDN.  Returns an empty list when the model is unknown or
        when the check fails.
        """
        warnings: list = []
        try:
            model_name: str = getattr(
                self._connector.switch_model, "MODEL_NAME", ""
            ) or self._connector.switch_model.__class__.__name__
            current_fw: str = self._get_switch_infos().get("switch_firmware", "")

            if not model_name or not current_fw:
                return warnings

            latest_fw = _fw_get_latest(model_name)
            if latest_fw is None:
                return warnings

            try:
                current_t = _fw_version_tuple(current_fw)
                latest_t = _fw_version_tuple(latest_fw)
            except ValueError:
                return warnings

            if latest_t > current_t:
                warnings.append(
                    {
                        "code": "firmware_update_available",
                        "severity": "warning",
                        "title": "Firmware update available",
                        "message": (
                            f"Version {latest_fw} is available for {model_name} "
                            f"(installed: {current_fw})."
                        ),
                        "action": None,
                        "action_label": None,
                        "meta": {
                            "download_url": (
                                f"{_FW_CDN_BASE}/{model_name}"
                                f"/{model_name}_{latest_fw}.zip"
                            ),
                            "latest_version": latest_fw,
                            "current_version": current_fw,
                        },
                    }
                )
        except Exception:
            pass

        return warnings
