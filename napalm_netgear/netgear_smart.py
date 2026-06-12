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

"""NAPALM driver for Netgear Smart Managed switches.

Tested against: GS108EPP, GS110TP, GS316EPP and compatible Smart Managed Pro series.
Netmiko device_type: ``netgear_prosafe``

CLI notes
---------
* Prompt format: ``(hostname) >`` (user) / ``(hostname) #`` (privileged) /
  ``(hostname) (Config)#`` (config mode).
* Key-value output uses either ``Key: value`` or ``Key..... value`` notation
  depending on firmware generation.
* Interface names are ``0/1``, ``0/2``, … (slot/port) on all Smart Managed Pro
  models.  Link-Aggregation channels appear as ``ch1``, ``ch2``, etc.
* Config is saved with ``write memory``.
"""

import difflib
import re
import socket
import time
from typing import Any, Dict, List, Optional, Union

import netaddr
from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException

from napalm_device_types import SwitchDriver
from napalm.base import helpers as napalm_helpers
from napalm.base.exceptions import (
    CommandErrorException,
    ConnectionClosedException,
    ConnectionException,
    MergeConfigException,
    ReplaceConfigException,
)
from napalm.base.netmiko_helpers import netmiko_args
import napalm.base.constants as C


class NetgearSmartDriver(SwitchDriver):
    """NAPALM driver for Netgear Smart Managed switches (GS-series)."""

    VENDOR = "Netgear"
    # Netmiko device type – handles prompt ``(hostname) >`` / ``(hostname) #``
    NETMIKO_DEVICE_TYPE = "netgear_prosafe"

    # PoE priority mapping between the CLI's "low/high/critical" and the
    # generic priority strings used across drivers.
    _POE_PRIORITY_MAP = {"low": "PPP_LOW", "high": "PPP_HIGH", "critical": "PPP_CRITICAL"}
    _POE_PRIORITY_MAP_REV = {v: k for k, v in _POE_PRIORITY_MAP.items()}

    def __init__(
        self,
        hostname: str,
        username: str,
        password: str,
        timeout: int = 60,
        optional_args: Optional[Dict] = None,
    ) -> None:
        self.hostname = hostname
        self.username = username
        self.password = password
        self.timeout = timeout
        self.device: Optional[ConnectHandler] = None

        if optional_args is None:
            optional_args = {}

        self.force_no_enable = optional_args.get("force_no_enable", False)
        self.port = optional_args.get("port", 22)
        self.use_canonical_interface = optional_args.get("canonical_int_fmt", False)

        # Netgear Smart switches run older SSH stacks that advertise ssh-rsa but
        # reject connections from clients that negotiate rsa-sha2-256/512 first
        # (the Paramiko 3+ default).  Force legacy pubkey algorithms unless the
        # caller has already supplied their own disabled_algorithms override.
        if "disabled_algorithms" not in optional_args:
            optional_args.setdefault(
                "disabled_algorithms",
                {"pubkeys": ["rsa-sha2-256", "rsa-sha2-512"]},
            )

        # Use a generous conn_timeout for slow-to-respond embedded SSH daemons.
        optional_args.setdefault("conn_timeout", 20)
        optional_args.setdefault("banner_timeout", 20)

        self.netmiko_optional_args = netmiko_args(optional_args)

        # Config management state
        self._candidate_config: Optional[str] = None
        self._candidate_mode: Optional[str] = None   # 'merge' or 'replace'
        self._backup_config: Optional[str] = None

        # CLI style detection cache: True = "v7" (Cisco-like, GigabitEthernet/lag
        # interfaces, "show info"/"show interfaces ... status"), False = legacy
        # FASTPATH-style (0/1, ch1, "show sysinfo"/"show port all"/"show vlan").
        self._cli_v7: Optional[bool] = None
        self._port_count_v7: Optional[int] = None
        self._version_cache: Optional[str] = None

    # ------------------------------------------------------------------
    # Connection management
    # ------------------------------------------------------------------

    def open(self) -> None:
        """Open an SSH connection to the device."""
        try:
            self.device = ConnectHandler(
                device_type=self.NETMIKO_DEVICE_TYPE,
                host=self.hostname,
                username=self.username,
                password=self.password,
                timeout=self.timeout,
                **self.netmiko_optional_args,
            )
            if not self.force_no_enable:
                self.device.enable()
        except NetmikoTimeoutException as exc:
            raise ConnectionException(
                f"Cannot connect to {self.hostname}: {exc}"
            ) from exc
        except NetmikoAuthenticationException as exc:
            raise ConnectionException(
                f"Authentication failed for {self.hostname}: {exc}"
            ) from exc
        except Exception as exc:
            raise ConnectionException(
                f"Verbindungsaufbau fehlgeschlagen (ConnectionException): "
                f"Cannot connect to {self.hostname}:\n{exc}"
            ) from exc

    def close(self) -> None:
        """Close the SSH connection."""
        if self.device:
            self.device.disconnect()
            self.device = None

    def is_alive(self) -> Dict[str, bool]:
        """Return connection liveness without writing to the channel."""
        if self.device is None:
            return {"is_alive": False}
        try:
            return {"is_alive": self.device.remote_conn.transport.is_active()}
        except (socket.error, EOFError, AttributeError):
            return {"is_alive": False}

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _send_command(self, command: Union[str, List[str]]) -> str:
        """Send a command (or ordered list of fallback commands) to the device.

        Uses an explicit ``expect_string`` so that Netmiko never confuses a
        data line inside the output with the device prompt.
        """
        prompt_pattern = rf"{re.escape(self.device.base_prompt)}[>#]"

        def _do_send(cmd: str) -> str:
            return self.device.send_command(
                cmd,
                expect_string=prompt_pattern,
                read_timeout=self.timeout,
            ).strip()

        try:
            if isinstance(command, list):
                output = ""
                for cmd in command:
                    output = _do_send(cmd)
                    if "Invalid" not in output and "Error" not in output:
                        return output
                return output
            return _do_send(command)
        except (socket.error, EOFError) as exc:
            raise ConnectionClosedException(str(exc)) from exc

    # ------------------------------------------------------------------
    # Configuration-mode helpers
    # ------------------------------------------------------------------

    def _exec_prompt(self) -> str:
        return rf"{re.escape(self.device.base_prompt)}[>#]"

    def _conf_prompt(self) -> str:
        """Matches the config-mode prompt.

        Legacy FASTPATH firmware uses ``(hostname) (Config)#``; the "v7"
        Cisco-like CLI uses ``hostname(config)#`` (lowercase, no space).
        Match both case-insensitively.
        """
        return rf"(?i){re.escape(self.device.base_prompt)}\s*\(config\)[>#]"

    def _any_prompt(self) -> str:
        """Matches exec prompt and any config sub-mode prompt."""
        return rf"{re.escape(self.device.base_prompt)}(?:\s*\([^)]*\))?[>#]"

    def _enter_config_mode(self) -> None:
        self.device.send_command(
            "configure",
            expect_string=self._conf_prompt(),
            read_timeout=self.timeout,
        )

    def _exit_config_mode(self) -> None:
        self.device.send_command(
            "exit",
            expect_string=self._exec_prompt(),
            read_timeout=self.timeout,
        )

    def _save_config(self) -> None:
        self.device.send_command(
            "write memory",
            expect_string=self._exec_prompt(),
            read_timeout=self.timeout,
        )

    def _apply_config_lines(self, config_text: str) -> List[str]:
        """Send config lines while in config mode; return list of rejected lines."""
        ep_any = self._any_prompt()
        errors: List[str] = []
        for line in config_text.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith(("!", "#")):
                continue
            out = self.device.send_command(
                stripped,
                expect_string=ep_any,
                read_timeout=self.timeout,
            ).strip()
            if out and ("Error" in out or "Invalid" in out or "Unknown" in out):
                errors.append(f"  {stripped!r}: {out}")
        return errors

    @staticmethod
    def _parse_key_value(output: str, key: str) -> str:
        """Extract a value from Netgear ``key.... value`` or ``key: value`` output.

        Both dot-separator (``show version``) and colon-separator
        (``show sysinfo``) forms are handled automatically.
        """
        for line in output.splitlines():
            if key.lower() in line.lower():
                # dots form: "Software Version............................. 6.6.3"
                m = re.match(r"[^.\n]+\.{2,}\s*(.*)", line.strip())
                if m:
                    return m.group(1).strip()
                # colon form: "System Name:                         myswitch"
                m = re.match(r"[^:\n]+:\s*(.*)", line.strip())
                if m:
                    return m.group(1).strip()
        return ""

    @staticmethod
    def _parse_uptime_seconds(uptime_str: str) -> float:
        """Convert Netgear uptime string to seconds.

        Expected format: ``0 days 2 hrs 43 mins 18 secs``
        Also handles ``day(s) hour(s) min(s) sec(s)`` variants.
        """
        days = hours = minutes = seconds = 0
        m = re.search(r"(\d+)\s+day", uptime_str, re.I)
        if m:
            days = int(m.group(1))
        m = re.search(r"(\d+)\s+h(?:ou)?r", uptime_str, re.I)
        if m:
            hours = int(m.group(1))
        m = re.search(r"(\d+)\s+min", uptime_str, re.I)
        if m:
            minutes = int(m.group(1))
        m = re.search(r"(\d+)\s+sec", uptime_str, re.I)
        if m:
            seconds = int(m.group(1))
        return float(days * 86400 + hours * 3600 + minutes * 60 + seconds)

    def _detect_cli_v7(self) -> bool:
        """Detect whether this switch uses the newer "v7" Cisco-like CLI.

        Newer firmware (e.g. GS110TPv3 7.x) exposes ``GigabitEthernet``/``lag``
        interfaces and a ``show version`` with a "Firmware Version" field,
        instead of the legacy FASTPATH-style ``0/1``/``ch1`` interfaces and
        "Software Version" field.
        """
        if self._cli_v7 is None:
            self._cli_v7 = "firmware version" in self._get_version().lower()
        return self._cli_v7

    def _get_version(self) -> str:
        """Return (and cache) the output of ``show version``."""
        if self._version_cache is None:
            self._version_cache = self._send_command("show version")
        return self._version_cache

    def _send_paged_command(
        self, command: str, max_pages: int = 80, initial_delay: float = 1.0, page_delay: float = 0.3
    ) -> str:
        """Send a command and keep pressing space while the device paginates output.

        Newer firmware has no "terminal length 0" / "no pager" equivalent, so
        ``--More--`` prompts must be drained manually. Uses raw
        ``write_channel``/``read_channel`` (rather than ``send_command_timing``,
        whose per-call settle delay makes multi-page output prohibitively slow).
        """
        self.device.write_channel(command + "\n")
        time.sleep(initial_delay)
        chunk = self.device.read_channel()
        full = chunk
        pages = 0
        while "--More--" in chunk and pages < max_pages:
            self.device.write_channel(" ")
            time.sleep(page_delay)
            chunk = self.device.read_channel()
            full += chunk
            pages += 1
        # Strip ANSI/VT100 escape sequences and pager prompts.
        full = re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", full)
        full = full.replace("--More--", "")
        return full

    @staticmethod
    def _expand_port_list_v7(raw: str) -> List[str]:
        """Expand a "v7" interface-list token into individual interface names.

        Input examples::
            "g1-8"            → ["g1", "g2", ..., "g8"]
            "g9-10,lag1-8"    → ["g9", "g10", "lag1", ..., "lag8"]
            "---"             → []
        """
        raw = raw.strip()
        if not raw or raw == "---":
            return []
        ports: List[str] = []
        for token in raw.split(","):
            token = token.strip()
            if not token:
                continue
            m = re.match(r"^([a-zA-Z]+)(\d+)-(\d+)$", token)
            if m:
                prefix, start, end = m.group(1), int(m.group(2)), int(m.group(3))
                ports.extend(f"{prefix}{i}" for i in range(start, end + 1))
            else:
                ports.append(token)
        return ports

    @staticmethod
    def _parse_speed_v7(speed: str) -> float:
        """Parse a "v7" speed column (e.g. "1000M", "1G", "a-1000M") to Mbps."""
        m = re.search(r"(\d+)\s*([MG])", speed, re.I)
        if not m:
            return 0.0
        val = float(m.group(1))
        if m.group(2).upper() == "G":
            val *= 1000.0
        return val

    # ------------------------------------------------------------------
    # NAPALM getters
    # ------------------------------------------------------------------

    def get_facts(self) -> Dict:
        """Return general device facts.

        Combines ``show sysinfo`` and ``show version``.

        Example ``show sysinfo`` output::

            System Description:                  GS110TP Gigabit Smart Managed Pro Switch
            Machine Model:                       GS110TP
            Machine Type:                        Ethernet Switch
            Burned In MAC Address:               C4:AD:34:AB:12:34
            System OID String:                   1.3.6.1.4.1.4526.100.5.4
            System Uptime:                       0 days 2 hrs 43 mins 18 secs
            System Location:                     Server Room
            System Contact:                      admin@example.com
            System Name:                         myswitch

        Example ``show version`` output::

            Software Version............................. 6.6.3
            Loader Version............................... 1.0.0.15
            Boot ROM Version............................. B1.0.0.15
            Hardware Version............................. V1
            Serial Number................................ 1FE2345678
        """
        if self._detect_cli_v7():
            return self._get_facts_v7()

        sysinfo = self._send_command("show sysinfo")
        version = self._get_version()

        hostname = self._parse_key_value(sysinfo, "System Name")

        # "Machine Model" is the most reliable field for the switch SKU
        model = self._parse_key_value(sysinfo, "Machine Model")
        if not model:
            desc = self._parse_key_value(sysinfo, "System Description")
            model = desc.split()[0] if desc else ""

        os_version = (
            self._parse_key_value(version, "Software Version")
            or self._parse_key_value(sysinfo, "Software Version")
        )

        uptime_str = self._parse_key_value(sysinfo, "System Uptime")
        uptime = self._parse_uptime_seconds(uptime_str)

        serial_number = (
            self._parse_key_value(version, "Serial Number")
            or self._parse_key_value(sysinfo, "Serial Number")
            or ""
        )

        interface_list = self._get_interface_list()

        return {
            "vendor": self.VENDOR,
            "model": model,
            "hostname": hostname,
            "fqdn": hostname,
            "os_version": os_version,
            "serial_number": serial_number,
            "uptime": uptime,
            "interface_list": interface_list,
        }

    def _get_facts_v7(self) -> Dict:
        """``get_facts()`` implementation for the "v7" Cisco-like CLI.

        Example ``show info`` output::

            System Name      : (Switch)
            System Location  :
            System Contact   :
            MAC Address      : 28:94:01:6D:26:7D
            Firmware Version : 7.1.1.17
            System Up Time   : 0 days, 0 hours, 8 mins, 55 secs

        Example ``show version`` output (relevant lines)::

            SW version    7.1.1.17
            ...
            SN            7LE4535SA0117
        """
        info = self._send_command("show info")
        version = self._get_version()

        hostname = self._parse_key_value(info, "System Name")
        os_version = (self._parse_key_value(info, "Firmware Version") or "").split()[0:1]
        os_version = os_version[0] if os_version else ""

        serial_number = self._parse_key_value(version, "SN")

        uptime_str = self._parse_key_value(info, "System Up Time")
        uptime = self._parse_uptime_seconds(uptime_str)

        # No reliable "model" field is exposed once a custom hostname is set;
        # the CLI prompt defaults to the model name (e.g. "GS110TPv3") on
        # switches that have never had their System Name configured.
        model = self.device.base_prompt or ""

        interface_list = self._get_interface_list_v7()

        return {
            "vendor": self.VENDOR,
            "model": model,
            "hostname": hostname,
            "fqdn": hostname,
            "os_version": os_version,
            "serial_number": serial_number,
            "uptime": uptime,
            "interface_list": interface_list,
        }

    def _get_port_count_v7(self) -> int:
        """Return the number of GigabitEthernet ports via "show interfaces
        GigabitEthernet ?", e.g. "<1-10>  GigabitEthernet interface number"."""
        if self._port_count_v7 is None:
            output = self.device.send_command_timing(
                "show interfaces GigabitEthernet ?", strip_prompt=False, strip_command=False
            )
            m = re.search(r"<1-(\d+)>", output)
            self._port_count_v7 = int(m.group(1)) if m else 0
        return self._port_count_v7

    def _get_interface_list_v7(self) -> List[str]:
        n = self._get_port_count_v7()
        interfaces = [f"g{i}" for i in range(1, n + 1)]
        try:
            lag_out = self._send_command("show lag")
        except Exception:
            lag_out = ""
        for line in lag_out.splitlines():
            line_s = line.strip()
            m = re.match(r"^(\d+)\s*\|\s*([^|]+)\|", line_s)
            if m and m.group(2).strip() != "------":
                interfaces.append(f"lag{m.group(1)}")
        return interfaces

    def _get_interface_list(self) -> List[str]:
        """Return sorted list of slot/port interface names from ``show port all``."""
        output = self._send_command("show port all")
        interfaces: List[str] = []
        for line in output.splitlines():
            # Physical ports: "0/1 ..." and LAG channels: "ch1 ..."
            m = re.match(r"^\s*(\d+/\d+|ch\d+)\s+", line)
            if m:
                interfaces.append(m.group(1))
        return sorted(
            set(interfaces),
            key=lambda s: [int(x) if x.isdigit() else x for x in re.split(r"(\d+)", s)],
        )

    def get_interfaces(self) -> Dict[str, Dict]:
        """Return per-interface details.

        Combines ``show port all`` (link status, speed) with
        ``show interface all`` (description, MTU).

        Example ``show port all`` columns::

            Intf    Type  Admin   Physical    Physical    Link
                          Mode    Mode        Status      Status
            ------  ----  ------  ----------  ----------  ------
            0/1           Enable  Auto        100M/Full   Up
            0/2           Enable  Auto        -           Down

        Example ``show interface all`` (block per port)::

            Interface................................ 0/1
            Description.............................. uplink
            MTU...................................... 1518
        """
        if self._detect_cli_v7():
            return self._get_interfaces_v7()

        port_out = self._send_command("show port all")
        intf_out = self._send_command("show interface all")
        interfaces = self._parse_interfaces(port_out, intf_out)
        self._add_lag_info(interfaces)
        return interfaces

    def _add_lag_info(self, interfaces: Dict[str, Dict]) -> None:
        """Enrich ``interfaces`` with LAG/trunk membership from ``show port-channel all``.

        FASTPATH-based switches (NETGEAR M4xxx / GSxxxTxx Smart Managed Pro)
        expose configured link-aggregation groups via ``show port-channel
        all``, one row per group (``ch1``, ``ch2``, ...) listing its member
        ports and a Type column ("Static" or "Dynamic" for LACP). Column
        layout varies by firmware, so this parses tolerantly: the first
        token of a matching row is the LAG name, member ports are any
        ``slot/port`` tokens on the line, and the mode is derived from the
        presence of "static"/"dynamic" anywhere in the row.
        """
        try:
            output = self._send_command("show port-channel all")
        except Exception:
            return

        for line in output.splitlines():
            parts = line.split()
            if not parts or not re.match(r"^ch\d+$", parts[0], re.I):
                continue
            lag = parts[0]
            members = re.findall(r"\d+/\d+", line)
            if not members:
                continue
            lag_mode = "lacp"
            if re.search(r"\bstatic\b", line, re.I):
                lag_mode = "trunk"
            for member in members:
                if member in interfaces:
                    interfaces[member]["trunk_group"] = lag
            if lag in interfaces:
                interfaces[lag]["lag_members"] = members
                interfaces[lag]["lag_mode"] = lag_mode

    def _get_interfaces_v7(self) -> Dict[str, Dict]:
        """``get_interfaces()`` implementation for the "v7" Cisco-like CLI.

        Example ``show interfaces GigabitEthernet 1-10 status`` output::

            Port    Name      Status      Vlan    Duplex   Speed   Type
            ------  --------  ----------  ------  -------  ------  -----
            g1      uplink    Connected   1       Full     1000M   Copper
            g2                Notconnct   1       --       --      Copper
        """
        n = self._get_port_count_v7()
        interfaces: Dict[str, Dict] = {}
        if n:
            status_out = self._send_command(
                f"show interfaces GigabitEthernet 1-{n} status"
            )
            interfaces.update(self._parse_interface_status_v7(status_out))

        self._add_lag_info_v7(interfaces)
        return interfaces

    @staticmethod
    def _parse_interface_status_v7(output: str) -> Dict[str, Dict]:
        interfaces: Dict[str, Dict] = {}
        for line in output.splitlines():
            line_s = line.rstrip()
            if not line_s:
                continue
            stripped = line_s.strip()
            if stripped.lower().startswith("port") or re.match(r"^-+", stripped):
                continue
            fields = re.split(r"\s{2,}", stripped)
            if len(fields) == 7:
                port, name, status, _vlan, _duplex, speed, _type = fields
            elif len(fields) == 6:
                port, status, _vlan, _duplex, speed, _type = fields
                name = ""
            else:
                continue
            if not re.match(r"^(g\d+|lag\d+)$", port, re.I):
                continue
            status_l = status.lower()
            interfaces[port] = {
                "is_up": status_l == "connected",
                "is_enabled": status_l != "disabled",
                "description": name,
                "last_flapped": -1.0,
                "speed": NetgearSmartDriver._parse_speed_v7(speed),
                "mtu": 1500,
                "mac_address": "",
            }
        return interfaces

    def _add_lag_info_v7(self, interfaces: Dict[str, Dict]) -> None:
        """Enrich ``interfaces`` with LAG membership from "show lag".

        Example output::

             | Group   |
            Index | Type   | Ports
            ------+--------+-----------------
            1     | LACP   | g9, g10
            2     | ------ |
        """
        try:
            output = self._send_command("show lag")
        except Exception:
            return

        for line in output.splitlines():
            line_s = line.strip()
            m = re.match(r"^(\d+)\s*\|\s*([^|]+)\|\s*(.*)$", line_s)
            if not m:
                continue
            group_id, type_s, ports_s = m.group(1), m.group(2).strip(), m.group(3).strip()
            if type_s == "------" or not ports_s:
                continue
            lag_name = f"lag{group_id}"
            members = self._expand_port_list_v7(ports_s)
            member_ifaces = [interfaces[m] for m in members if m in interfaces]
            for member in members:
                if member in interfaces:
                    interfaces[member]["trunk_group"] = lag_name
            interfaces[lag_name] = {
                "is_up": any(i["is_up"] for i in member_ifaces),
                "is_enabled": True,
                "description": "",
                "last_flapped": -1.0,
                "speed": sum(i["speed"] for i in member_ifaces),
                "mtu": 1500,
                "mac_address": "",
                "lag_members": members,
                "lag_mode": "lacp" if "lacp" in type_s.lower() else "trunk",
            }

    def _parse_interfaces(
        self, port_output: str, intf_output: str = ""
    ) -> Dict[str, Dict]:
        """Parse ``show port all`` and ``show interface all`` into NAPALM format."""
        interfaces: Dict[str, Dict] = {}

        # --- parse 'show port all' ---
        # Skip header lines until we hit a separator row, then parse data rows.
        # Data row: "0/1  <type>  Enable  Auto  100M/Full  Up  ..."
        # The "Type" column is often empty; splitting by whitespace is more
        # robust than relying on fixed-width column positions.
        in_table = False
        for line in port_output.splitlines():
            line_s = line.strip()
            if re.match(r"^-{4,}", line_s):
                in_table = True
                continue
            if not in_table:
                continue
            parts = line_s.split()
            # Must start with a port name (slot/port or channel)
            if not parts or not re.match(r"^(\d+/\d+|ch\d+)$", parts[0]):
                continue
            # With an empty Type column the fields map to:
            #   parts[0]=port  parts[1]=admin  parts[2]=phys_mode
            #   parts[3]=phys_status  parts[4]=link_status
            # When Type is present (non-empty token) the indices shift by +1;
            # detect this by checking whether parts[1] looks like a type token
            # (not Enable/Disable).
            offset = 0
            if len(parts) > 1 and parts[1].lower() not in ("enable", "disable"):
                offset = 1
            if len(parts) < 5 + offset:
                continue
            port = parts[0]
            admin = parts[1 + offset]         # Enable / Disable
            phys_status = parts[3 + offset]   # e.g. "100M/Full", "1G/Full", or "-"
            link_status = parts[4 + offset]   # Up / Down

            speed_val = 0.0
            speed_m = re.search(r"(\d+)([MG])", phys_status)
            if speed_m:
                speed_val = float(speed_m.group(1))
                if speed_m.group(2) == "G":
                    speed_val *= 1000.0

            interfaces[port] = {
                "is_up": link_status.lower() == "up",
                "is_enabled": admin.lower() == "enable",
                "description": "",
                "last_flapped": -1.0,
                "speed": speed_val,
                "mtu": 1518,
                "mac_address": "",
            }

        # --- parse 'show interface all' (block format) ---
        current_port: Optional[str] = None
        for line in intf_output.splitlines():
            # Block header: "Interface................................ 0/1"
            m = re.match(r"^\s*Interface[.:\s]+(\d+/\d+|ch\d+)", line, re.I)
            if m:
                current_port = m.group(1)
                continue
            if current_port is None:
                continue
            # Description
            dm = re.match(r"^\s*(?:Description|Port Description)[.:\s]+(.*)", line, re.I)
            if dm:
                desc = dm.group(1).strip()
                if current_port in interfaces and desc:
                    interfaces[current_port]["description"] = desc
                continue
            # MTU
            mm = re.match(r"^\s*MTU[.:\s]+(\d+)", line, re.I)
            if mm:
                if current_port in interfaces:
                    interfaces[current_port]["mtu"] = int(mm.group(1))

        return interfaces

    def get_interfaces_ip(self) -> Dict[str, Dict]:
        """Return all configured IP addresses grouped by interface.

        Parses ``show ip interface`` output.  On Smart Managed switches
        only the management VLAN typically has an IP address.

        Example output block::

            IP Address....................................... 192.168.0.239
            Subnet Mask...................................... 255.255.255.0
            Default Gateway.................................. 192.168.0.1
        """
        output = self._send_command("show ip interface")
        interfaces_ip: Dict[str, Dict] = {}

        # Smart Managed switches expose a single management IP block;
        # some firmwares add an "Interface" header for the routing VLAN.
        current_iface = "vlan1"
        ip_addr = ""

        for line in output.splitlines():
            line_s = line.strip()

            # Optional interface header
            m = re.match(
                r"(?:Interface|Routing Interface)[.:\s]+(vlan\d+|\d+/\d+)",
                line_s,
                re.I,
            )
            if m:
                current_iface = m.group(1).lower()
                ip_addr = ""
                continue

            m = re.match(r"IP Address[.:\s]+([\d.]+)", line_s, re.I)
            if m:
                ip_addr = m.group(1)
                continue

            m = re.match(r"Subnet Mask[.:\s]+([\d.]+)", line_s, re.I)
            if m and ip_addr:
                try:
                    net = netaddr.IPNetwork(f"{ip_addr}/{m.group(1)}")
                    if current_iface not in interfaces_ip:
                        interfaces_ip[current_iface] = {}
                    interfaces_ip[current_iface].setdefault("ipv4", {})[ip_addr] = {
                        "prefix_length": net.prefixlen
                    }
                except (netaddr.AddrFormatError, ValueError):
                    pass
                ip_addr = ""

        return interfaces_ip

    def get_config(
        self,
        retrieve: str = "all",
        full: bool = False,
        sanitized: bool = False,
        format: str = "text",
    ) -> Dict[str, str]:
        """Return running and/or startup configuration.

        Netgear Smart Managed does not support a candidate config;
        that slot is always returned as an empty string.
        """
        configs = {"running": "", "startup": "", "candidate": ""}

        if retrieve in ("all", "running"):
            configs["running"] = self._send_command("show running-config")

        if retrieve in ("all", "startup"):
            configs["startup"] = self._send_command("show startup-config")

        if sanitized:
            configs = napalm_helpers.sanitize_configs(configs, C.CISCO_SANITIZE_FILTERS)

        return configs

    def get_arp_table(self, vrf: str = "") -> List[Dict]:
        """Return the ARP table.

        Example ``show arp`` output::

            IP Address         MAC Address         Interface  Age (min)  Type
            ---------          ----------------  ---------  ---------  -------
            192.168.0.1        00:11:22:33:44:55   0/0        -          Local
            192.168.0.100      00:aa:bb:cc:dd:ee   0/0        5          Dynamic
        """
        output = self._send_command("show arp")
        arp_table = []
        in_table = False

        for line in output.splitlines():
            line_s = line.strip()
            if not line_s:
                continue
            if re.match(r"^-{3,}", line_s):
                in_table = True
                continue
            if not in_table:
                continue

            parts = line_s.split()
            if len(parts) < 3:
                continue

            ip_addr = parts[0]
            mac_raw = parts[1]
            interface = parts[2]

            try:
                netaddr.IPAddress(ip_addr)
            except (netaddr.AddrFormatError, ValueError):
                continue

            try:
                mac_addr = napalm_helpers.mac(mac_raw)
            except Exception:
                mac_addr = mac_raw

            arp_table.append(
                {
                    "interface": interface,
                    "mac": mac_addr,
                    "ip": ip_addr,
                    "age": 0.0,
                }
            )

        return arp_table

    def get_mac_address_table(self) -> List[Dict]:
        """Return the MAC address table.

        Example ``show mac-addr-table`` output::

            VLAN ID  MAC Address         Type        Port
            -------  ------------------  ----------  ------
            1        00:11:22:33:44:55   Dynamic     0/1
            1        ff:ff:ff:ff:ff:ff   Management  CPU
        """
        if self._detect_cli_v7():
            return self._get_mac_address_table_v7()

        output = self._send_command("show mac-addr-table")
        mac_table = []
        in_table = False

        for line in output.splitlines():
            line_s = line.strip()
            if not line_s:
                continue
            if re.match(r"^-{3,}", line_s):
                in_table = True
                continue
            if not in_table:
                continue

            parts = line_s.split()
            if len(parts) < 4:
                continue

            try:
                vlan = int(parts[0])
            except ValueError:
                continue

            mac_raw = parts[1]
            entry_type = parts[2].lower()
            interface = parts[3]

            try:
                mac_addr = napalm_helpers.mac(mac_raw)
            except Exception:
                mac_addr = mac_raw

            mac_table.append(
                {
                    "mac": mac_addr,
                    "interface": interface,
                    "vlan": vlan,
                    "static": entry_type in ("static", "management"),
                    "active": True,
                    "moves": None,
                    "last_move": None,
                }
            )

        return mac_table

    def _get_mac_address_table_v7(self) -> List[Dict]:
        """``get_mac_address_table()`` implementation for the "v7" Cisco-like CLI.

        Example ``show mac address-table`` output::

             VID  | MAC Address       | Type       | Ports
            ------+-------------------+------------+-------
               1  | 28:94:01:6D:26:7D | Management | CPU
               1  | 00:1A:8C:87:4E:C6 | Dynamic     | g1
        """
        output = self._send_paged_command("show mac address-table")
        mac_table = []

        for line in output.splitlines():
            line_s = line.strip()
            if not line_s or "|" not in line_s:
                continue
            if re.match(r"^-+\+", line_s):
                continue

            parts = [p.strip() for p in line_s.split("|")]
            if len(parts) < 4:
                continue

            vid_s, mac_raw, entry_type, interface = parts[0], parts[1], parts[2], parts[3]
            if not vid_s.isdigit():
                continue

            try:
                mac_addr = napalm_helpers.mac(mac_raw)
            except Exception:
                mac_addr = mac_raw

            mac_table.append(
                {
                    "mac": mac_addr,
                    "interface": interface,
                    "vlan": int(vid_s),
                    "static": entry_type.lower() in ("static", "management"),
                    "active": True,
                    "moves": None,
                    "last_move": None,
                }
            )

        return mac_table

    def get_lldp_neighbors(self) -> Dict[str, List[Dict]]:
        """Return a dict of LLDP neighbors keyed by local port.

        Example ``show lldp remote-device all`` output::

            Local     RemID  Chassis ID            Port ID          System Name
            Interface
            --------- -----  --------------------  ---------------  ---------------
            0/1       1      00:1a:2b:3c:4d:5e     0/1              router-1
        """
        neighbors: Dict[str, List[Dict]] = {}
        for row in self._get_lldp_table():
            neighbors.setdefault(row["local_port"], []).append(
                {"hostname": row["system_name"], "port": row["port_id"]}
            )
        return neighbors

    def _get_lldp_table(self) -> List[Dict]:
        """Parse ``show lldp remote-device all`` into a list of row dicts."""
        output = self._send_command("show lldp remote-device all")
        rows: List[Dict] = []
        in_table = False

        for line in output.splitlines():
            line_s = line.strip()
            if not line_s:
                continue
            if re.match(r"^-{4,}", line_s):
                in_table = True
                continue
            if not in_table:
                continue

            parts = line_s.split()
            # Columns: Local Interface, RemID, Chassis ID, Port ID, System Name
            if len(parts) < 3:
                continue
            if not re.match(r"^\d+/\d+$", parts[0]):
                continue

            rows.append(
                {
                    "local_port": parts[0],
                    "remote_id": parts[1] if len(parts) > 1 else "",
                    "remote_chassis_id": parts[2] if len(parts) > 2 else "",
                    "port_id": parts[3] if len(parts) > 3 else "",
                    "system_name": " ".join(parts[4:]) if len(parts) > 4 else "",
                }
            )

        return rows

    def get_lldp_neighbors_detail(self, interface: str = "") -> Dict[str, List[Dict]]:
        """Return detailed LLDP neighbor information.

        Fetches per-port detail via ``show lldp remote-device detail <port>``
        and falls back to the summary table values for missing fields.
        """
        details: Dict[str, List[Dict]] = {}

        for row in self._get_lldp_table():
            if interface and row["local_port"] != interface:
                continue

            detail_out = self._send_command(
                f"show lldp remote-device detail {row['local_port']}"
            )
            parsed = self._parse_lldp_detail(detail_out)

            # Fill in from summary table if the detail command returned nothing
            if not parsed["remote_chassis_id"]:
                parsed["remote_chassis_id"] = row["remote_chassis_id"]
            if not parsed["remote_port"]:
                parsed["remote_port"] = row["port_id"]
            if not parsed["remote_system_name"]:
                parsed["remote_system_name"] = row["system_name"]

            details.setdefault(row["local_port"], []).append(parsed)

        return details

    @staticmethod
    def _parse_lldp_detail(output: str) -> Dict:
        """Parse ``show lldp remote-device detail`` block output."""
        result: Dict = {
            "parent_interface": "",
            "remote_port": "",
            "remote_port_description": "",
            "remote_chassis_id": "",
            "remote_system_name": "",
            "remote_system_description": "",
            "remote_system_capab": [],
            "remote_system_enable_capab": [],
        }

        for line in output.splitlines():
            line_s = line.strip()
            # Handle both dot-separator and colon-separator
            m = re.match(r"([^.\n]+)\.{2,}\s*(.*)", line_s)
            if not m:
                m = re.match(r"([^:\n]+):\s*(.*)", line_s)
            if not m:
                continue

            key = m.group(1).strip().lower()
            val = m.group(2).strip()

            if "chassis id" in key:
                result["remote_chassis_id"] = val
            elif "port id" in key and "desc" not in key:
                result["remote_port"] = val
            elif "port desc" in key or "port description" in key:
                result["remote_port_description"] = val
            elif "system name" in key:
                result["remote_system_name"] = val
            elif "system desc" in key or "system description" in key:
                result["remote_system_description"] = val
            elif "system cap" in key and "enabl" not in key:
                result["remote_system_capab"] = [
                    c.strip().lower() for c in val.split(",") if c.strip()
                ]
            elif "enabled cap" in key or ("system cap" in key and "enabl" in key):
                result["remote_system_enable_capab"] = [
                    c.strip().lower() for c in val.split(",") if c.strip()
                ]

        return result

    def get_vlans(self) -> Dict[str, Dict]:
        """Return VLAN information.

        Example ``show vlan`` output::

            VLAN ID  VLAN Name       VLAN Type   Interface(s)
            -------  --------------- ----------  -----------------------------------
            1        Default         Default     0/1-0/8
            10       Management      Static      0/1, 0/3
        """
        if self._detect_cli_v7():
            return self._get_vlans_v7()

        output = self._send_command("show vlan")
        vlans: Dict[str, Dict] = {}
        current_id: Optional[str] = None
        in_table = False

        for line in output.splitlines():
            line_s = line.strip()
            if not line_s:
                continue
            if re.match(r"^-{3,}", line_s):
                in_table = True
                continue
            if not in_table:
                continue

            m = re.match(r"^(\d+)\s+(\S+)\s+\S+\s*(.*)", line_s)
            if m:
                current_id = str(int(m.group(1)))
                vlans[current_id] = {
                    "name": m.group(2),
                    "interfaces": self._parse_vlan_ports(m.group(3).strip()),
                }
            elif current_id is not None and line_s:
                # Continuation line with additional ports
                vlans[current_id]["interfaces"].extend(self._parse_vlan_ports(line_s))

        return vlans

    @staticmethod
    def _parse_vlan_ports(ports_raw: str) -> List[str]:
        """Parse Netgear VLAN port string and expand ranges.

        Input examples::
            "0/1-0/8"         → ["0/1", "0/2", …, "0/8"]
            "0/1, 0/3, 0/5"  → ["0/1", "0/3", "0/5"]
            "0/1-4"           → ["0/1", "0/2", "0/3", "0/4"]
        """
        interfaces: List[str] = []
        for token in ports_raw.split(","):
            token = token.strip()
            if not token:
                continue
            # Range: "0/1-0/8" (fully qualified) or "0/1-8" (short form)
            range_m = re.match(r"^(\d+)/(\d+)-(?:(\d+)/)?(\d+)$", token)
            if range_m:
                slot = range_m.group(1)
                start = int(range_m.group(2))
                end = int(range_m.group(4))
                interfaces.extend(f"{slot}/{i}" for i in range(start, end + 1))
            elif re.match(r"^\d+/\d+$", token):
                interfaces.append(token)
        return interfaces

    def _get_vlans_v7(self) -> Dict[str, Dict]:
        """``get_vlans()`` implementation for the "v7" Cisco-like CLI.

        Example ``show vlan 1-4094`` output::

            VLAN  Name           Type     Untagged Ports     Tagged Ports
            ----  -------------- -------- ------------------ ------------------
            1     default        Default  g1-8,lag1-8        ---
            10    MGMT           Static   ---                g1-8
        """
        output = self._send_paged_command("show vlan 1-4094")
        vlans: Dict[str, Dict] = {}
        for line in output.splitlines():
            line_s = line.strip()
            if not line_s or "|" not in line_s:
                continue
            if line_s.upper().startswith("VID") or line_s.upper().startswith("VLAN"):
                continue
            if re.match(r"^-+\+", line_s):
                continue
            parts = [p.strip() for p in line_s.split("|")]
            if len(parts) < 4:
                continue
            vid_s, name, untagged, tagged = parts[0], parts[1], parts[2], parts[3]
            if not vid_s.isdigit():
                continue
            vlans[vid_s] = {
                "name": name,
                "untagged": self._expand_port_list_v7(untagged),
                "tagged": self._expand_port_list_v7(tagged),
            }
        return vlans

    # ------------------------------------------------------------------
    # NAPALM configuration management
    # ------------------------------------------------------------------

    def load_merge_candidate(
        self, filename: Optional[str] = None, config: Optional[str] = None
    ) -> None:
        """Stage CLI commands to be merged into the running configuration.

        *config* is a plain-text string of CLI commands as typed in config
        mode (one command per line).  Sub-mode entry/exit lines are supported.
        Blank lines and lines starting with ``!`` or ``#`` are ignored.

        The configuration is **not** applied until :meth:`commit_config`.

        :raises MergeConfigException: on invalid input.
        """
        if filename is not None:
            try:
                with open(filename) as fh:
                    config = fh.read()
            except OSError as exc:
                raise MergeConfigException(str(exc)) from exc
        if config is None:
            raise MergeConfigException("Either 'filename' or 'config' must be provided.")
        self._candidate_config = config
        self._candidate_mode = "merge"

    def load_replace_candidate(
        self, filename: Optional[str] = None, config: Optional[str] = None
    ) -> None:
        """Stage a full running-config replacement candidate.

        Netgear Smart Managed does not support atomic config replace;
        commit applies the candidate lines additively (same as merge).
        :meth:`compare_config` still shows a full unified diff.

        :raises ReplaceConfigException: on invalid input.
        """
        if filename is not None:
            try:
                with open(filename) as fh:
                    config = fh.read()
            except OSError as exc:
                raise ReplaceConfigException(str(exc)) from exc
        if config is None:
            raise ReplaceConfigException("Either 'filename' or 'config' must be provided.")
        self._candidate_config = config
        self._candidate_mode = "replace"

    def compare_config(self) -> str:
        """Return a human-readable diff of the pending candidate vs running config.

        Merge candidate → lines prefixed with ``+``.
        Replace candidate → unified diff against current running config.
        Returns an empty string when no candidate is staged.
        """
        if self._candidate_config is None:
            return ""

        if self._candidate_mode == "merge":
            lines = []
            for line in self._candidate_config.splitlines():
                if line.strip() and not line.strip().startswith(("!", "#")):
                    lines.append(f"+{line}")
            return "\n".join(lines)

        running = self._send_command("show running-config")
        diff = difflib.unified_diff(
            running.splitlines(),
            self._candidate_config.splitlines(),
            fromfile="running-config",
            tofile="candidate-config",
            lineterm="",
        )
        return "\n".join(diff)

    def commit_config(self, message: str = "", revert_in: Optional[int] = None) -> None:
        """Apply the staged candidate configuration to the device and persist it.

        1. Saves current running config as rollback backup.
        2. Enters config mode and pushes the candidate lines.
        3. Returns to exec mode.
        4. Persists with ``write memory``.

        :raises MergeConfigException / ReplaceConfigException: if no candidate
            is staged or if lines are rejected by the device.
        """
        if self._candidate_config is None:
            raise MergeConfigException("No candidate configuration is staged.")

        ex_cls = (
            ReplaceConfigException
            if self._candidate_mode == "replace"
            else MergeConfigException
        )

        self._backup_config = self._send_command("show running-config")

        errors: List[str] = []
        try:
            self._enter_config_mode()
            errors = self._apply_config_lines(self._candidate_config)
        finally:
            self._exit_config_mode()

        if errors:
            raise ex_cls("The following commands were rejected:\n" + "\n".join(errors))

        self._save_config()
        self._candidate_config = None
        self._candidate_mode = None

    def discard_config(self) -> None:
        """Discard the staged candidate configuration without applying it."""
        self._candidate_config = None
        self._candidate_mode = None

    def rollback(self) -> None:
        """Revert the running config to the state before the last commit.

        :raises CommandErrorException: if :meth:`commit_config` has not been
            called in this session.
        """
        if self._backup_config is None:
            raise CommandErrorException(
                "No backup configuration available – "
                "commit_config has not been called in this session."
            )

        current = self._send_command("show running-config")
        rollback_cmds = NetgearSmartDriver._diff_to_commands(self._backup_config, current)

        if rollback_cmds:
            try:
                self._enter_config_mode()
                self._apply_config_lines("\n".join(rollback_cmds))
            finally:
                self._exit_config_mode()
            self._save_config()

        self._backup_config = None

    @staticmethod
    def _parse_config_blocks(config_text: str) -> Dict[str, List[str]]:
        """Parse a running-config into ``context → [command lines]`` mapping.

        The special key ``"__global__"`` holds top-level commands.
        Sub-mode blocks (``interface …``, ``vlan …``) are stored under the
        opening line that introduces them.
        """
        blocks: Dict[str, List[str]] = {"__global__": []}
        ctx = "__global__"

        for line in config_text.splitlines():
            stripped = line.strip()

            if not stripped or stripped == "!":
                ctx = "__global__"
                continue

            if stripped.startswith("!"):
                continue

            if re.match(r"^(interface|vlan)\s+\S+", stripped, re.I):
                ctx = stripped
                if ctx not in blocks:
                    blocks[ctx] = []
                continue

            if stripped.lower() == "exit":
                ctx = "__global__"
                continue

            blocks.setdefault(ctx, []).append(stripped)

        return blocks

    @staticmethod
    def _negate_command(cmd: str) -> Optional[str]:
        """Return the ``no`` form of *cmd*, or ``None`` if not known."""
        for kw in (
            "description",
            "name",
            "spanning-tree",
            "lldp",
            "ip address",
        ):
            if re.match(rf"^{re.escape(kw)}\b", cmd, re.I):
                return f"no {kw}"
        return None

    @staticmethod
    def _diff_to_commands(backup: str, current: str) -> List[str]:
        """Generate the minimal set of config commands to revert *current* to *backup*."""
        backup_blocks = NetgearSmartDriver._parse_config_blocks(backup)
        current_blocks = NetgearSmartDriver._parse_config_blocks(current)

        cmds: List[str] = []
        all_ctxs = set(backup_blocks.keys()) | set(current_blocks.keys())

        for ctx in sorted(all_ctxs):
            backup_lines = set(backup_blocks.get(ctx, []))
            current_lines = set(current_blocks.get(ctx, []))

            if backup_lines == current_lines:
                continue

            in_block = ctx != "__global__"
            if in_block:
                cmds.append(ctx)

            # Lines added since backup → negate them
            for line in current_lines - backup_lines:
                neg = NetgearSmartDriver._negate_command(line)
                if neg:
                    cmds.append(f"  {neg}" if in_block else neg)

            # Lines removed since backup → restore them
            for line in backup_lines - current_lines:
                cmds.append(f"  {line}" if in_block else line)

            if in_block:
                cmds.append("exit")

        return cmds

    # ------------------------------------------------------------------
    # Additional NAPALM getters
    # ------------------------------------------------------------------

    def has_pending_commit(self) -> bool:
        """Return True when a candidate configuration is staged."""
        return self._candidate_config is not None

    def get_environment(self) -> Dict:
        """Return device environment data (CPU, memory).

        Netgear Smart Managed switches do not expose fan, temperature, or
        power rail data through the CLI; those fields are returned as assumed
        healthy (``status: True``) with ``-1.0`` for numeric values.

        Tries ``show process cpu`` and ``show memory`` for utilisation data.
        """
        cpu_out = self._send_command(["show process cpu", "show cpu"])
        mem_out = self._send_command(["show memory", "show memory cpu"])

        cpu_pct = 0.0
        m = re.search(r"(?:CPU Utilization|utilization)[.:\s]+(\d+)%?", cpu_out, re.I)
        if m:
            cpu_pct = float(m.group(1))
        else:
            # Some firmwares: "5 percent"
            m = re.search(r"(\d+)\s+percent", cpu_out, re.I)
            if m:
                cpu_pct = float(m.group(1))

        mem_pct = 0.0
        m = re.search(r"(?:Memory Utilization|utilization)[.:\s]+(\d+)%?", mem_out, re.I)
        if m:
            mem_pct = float(m.group(1))

        return {
            "fans": {},
            "temperature": {},
            "power": {},
            "cpu": {0: {"%usage": cpu_pct}},
            "memory": {
                "available_ram": int((1 - mem_pct / 100) * 100),
                "used_ram": int(mem_pct),
            },
        }

    def get_interfaces_counters(self) -> Dict[str, Dict]:
        """Return per-interface packet and byte counters.

        Parses ``show interface counters`` (or ``show interface ethernet 0/1``).
        Each block starts with ``Interface................................ 0/1``.
        """
        output = self._send_command(
            ["show interface counters", "show interface ethernet all"]
        )

        def _int(s: str) -> int:
            return int(s.replace(",", "")) if s.strip().replace(",", "").isdigit() else 0

        counters: Dict[str, Dict] = {}
        current_port: Optional[str] = None
        current: Optional[Dict] = None

        _zero: Dict = {
            "tx_errors": 0, "rx_errors": 0,
            "tx_discards": 0, "rx_discards": 0,
            "tx_octets": 0, "rx_octets": 0,
            "tx_unicast_packets": 0, "rx_unicast_packets": 0,
            "tx_multicast_packets": 0, "rx_multicast_packets": 0,
            "tx_broadcast_packets": 0, "rx_broadcast_packets": 0,
        }

        _mapping = {
            "tx error": "tx_errors",
            "rx error": "rx_errors",
            "tx discard": "tx_discards",
            "rx discard": "rx_discards",
            "tx byte": "tx_octets",
            "rx byte": "rx_octets",
            "tx unicast": "tx_unicast_packets",
            "rx unicast": "rx_unicast_packets",
            "tx multicast": "tx_multicast_packets",
            "rx multicast": "rx_multicast_packets",
            "tx broadcast": "tx_broadcast_packets",
            "rx broadcast": "rx_broadcast_packets",
        }

        for line in output.splitlines():
            m = re.match(r"^\s*Interface[.:\s]+(\d+/\d+|ch\d+)", line, re.I)
            if m:
                if current_port and current:
                    counters[current_port] = current
                current_port = m.group(1)
                current = dict(_zero)
                continue

            if current is None:
                continue

            # Parse "Key.... value" or "Key: value"
            kv = re.match(r"([^.\n]+)[.:\.]{2,}\s*(.*)", line.strip())
            if not kv:
                kv = re.match(r"([^:\n]+):\s*(.*)", line.strip())
            if not kv:
                continue
            key = kv.group(1).strip().lower()
            val = kv.group(2).strip()

            for pat, field in _mapping.items():
                if pat in key:
                    current[field] = _int(val)
                    break

        if current_port and current:
            counters[current_port] = current

        return counters

    def get_users(self) -> Dict[str, Dict]:
        """Return local user accounts.

        Example ``show users`` output::

            User      Access Level   Session Timeout  Password Strength
            --------  ------------   ---------------  -----------------
            admin     Read/Write     5                Enabled
        """
        output = self._send_command("show users")
        users: Dict[str, Dict] = {}
        in_table = False

        for line in output.splitlines():
            line_s = line.strip()
            if not line_s:
                continue
            if re.match(r"^-{4,}", line_s):
                in_table = True
                continue
            if not in_table:
                continue

            parts = line_s.split()
            if len(parts) < 2:
                continue

            username = parts[0]
            role = parts[1].lower()
            level = 15 if "write" in role or "admin" in role else 1
            users[username] = {"level": level, "password": "", "sshkeys": []}

        return users

    def get_snmp_information(self) -> Dict:
        """Return SNMP configuration.

        Parses ``show sysinfo`` for contact/location/chassis-ID and
        ``show snmp`` for community strings.
        """
        sysinfo = self._send_command("show sysinfo")
        contact = self._parse_key_value(sysinfo, "System Contact")
        location = self._parse_key_value(sysinfo, "System Location")
        mac = self._parse_key_value(sysinfo, "Burned In MAC Address").replace("-", ":").upper()

        snmp_out = self._send_command("show snmp")
        communities: Dict[str, Dict] = {}

        in_comm = False
        for line in snmp_out.splitlines():
            line_s = line.strip()
            if "Community" in line_s and ("Name" in line_s or "String" in line_s):
                in_comm = True
                continue
            if not in_comm or not line_s:
                continue
            if re.match(r"^-{3,}", line_s):
                continue
            parts = line_s.split()
            if len(parts) >= 2:
                comm_name = parts[0]
                # Access mode may be "Read Only" (2 tokens) or "Read Write" (2 tokens)
                access = " ".join(parts[1:3]).lower()
                mode = "rw" if "write" in access or "rw" in access else "ro"
                communities[comm_name] = {"acl": "", "mode": mode}

        return {
            "contact": contact,
            "location": location,
            "community": communities,
            "chassis_id": mac,
        }

    def get_ntp_servers(self) -> Dict[str, Dict]:
        """Return configured NTP/SNTP servers from ``show sntp server``."""
        output = self._send_command(["show sntp server", "show ntp server"])
        servers: Dict[str, Dict] = {}

        for line in output.splitlines():
            line_s = line.strip()
            # Key/value line: "SNTP Server Address..... 192.168.0.1"
            # Use re.search so "SNTP Server Address" is also matched.
            m = re.search(
                r"Server\s+(?:Address|IP|Host)?[.:\s]+((?:\d{1,3}\.){3}\d{1,3}|[\w][\w.-]+\.\w+)",
                line_s,
                re.I,
            )
            if m:
                servers[m.group(1)] = {}
                continue
            # Plain IP in a table row (first column)
            m = re.match(r"^((?:\d{1,3}\.){3}\d{1,3})", line_s)
            if m:
                servers[m.group(1)] = {}

        return servers

    def get_ntp_peers(self) -> Dict[str, Dict]:
        """Return NTP peers (same as servers on Netgear Smart Managed)."""
        return self.get_ntp_servers()

    def get_ntp_stats(self) -> List[Dict]:
        """Netgear Smart Managed CLI does not expose per-peer NTP statistics."""
        return []

    def get_optics(self) -> Dict:
        """SFP DDM/DOM data is not accessible via the Smart Managed CLI."""
        return {}

    def get_ipv6_neighbors_table(self) -> List[Dict]:
        """IPv6 ND table is not exposed via the Smart Managed CLI."""
        return []

    def get_route_to(
        self,
        destination: str = "",
        protocol: str = "",
        longer: bool = False,
    ) -> Dict[str, List[Dict]]:
        """Return routing table entries.

        Smart Managed Pro switches support only a default gateway;
        ``show ip route`` is parsed where available.
        """
        output = self._send_command("show ip route")
        routes: Dict[str, List[Dict]] = {}
        proto_map = {"c": "connected", "s": "static"}

        for line in output.splitlines():
            line_s = line.strip()
            if not line_s or re.match(r"^[Cc]ode", line_s):
                continue

            m = re.match(
                r"^([A-Za-z])\*?\s+([\d./]+)"
                r"(?:\s+\[(\d+)/(\d+)\])?"
                r"(?:\s+via\s+([\d.]+))?",
                line_s,
            )
            if not m:
                continue

            code = m.group(1).lower()
            prefix = m.group(2)
            preference = int(m.group(3)) if m.group(3) else 0
            next_hop = m.group(5) or ""
            prot = proto_map.get(code, code)
            connected = code == "c"

            if destination and prefix != destination:
                continue
            if protocol and prot != protocol.lower():
                continue

            entry = {
                "protocol": prot,
                "current_active": True,
                "last_active": False,
                "age": -1,
                "next_hop": next_hop if not connected else "",
                "outgoing_interface": "",
                "selected_next_hop": True,
                "preference": preference,
                "inactive_reason": "",
                "routing_table": "global",
                "protocol_attributes": {},
            }
            routes.setdefault(prefix, []).append(entry)

        return routes

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
    ) -> Dict:
        """Ping *destination* from the device.

        Uses ``ping <dst> count <N>``.  Source IP and packet size selection
        are not supported by the Smart Managed CLI.

        :returns: NAPALM-standard ping result dict.
        """
        cmd = f"ping {destination} count {count}"
        output = self._send_command(cmd)

        if "Error" in output or "Invalid" in output:
            return {"error": output.strip()}

        sent = received = 0
        m = re.search(
            r"(\d+)\s+packets?\s+transmitted.*?(\d+)\s+(?:packets?\s+)?received",
            output,
            re.I | re.S,
        )
        if m:
            sent = int(m.group(1))
            received = int(m.group(2))

        rtt_min = rtt_max = rtt_avg = 0.0
        m = re.search(
            r"min/avg/max\s*=\s*([\d.]+)/([\d.]+)/([\d.]+)",
            output,
            re.I,
        )
        if m:
            rtt_min = float(m.group(1))
            rtt_avg = float(m.group(2))
            rtt_max = float(m.group(3))

        return {
            "success": {
                "probes_sent": sent,
                "packet_loss": sent - received,
                "rtt_min": rtt_min,
                "rtt_max": rtt_max,
                "rtt_avg": rtt_avg,
                "rtt_stddev": 0.0,
                "results": [],
            }
        }

    def cli(
        self,
        commands: List[str],
        encoding: str = "text",
    ) -> Dict[str, Union[str, Dict[str, Any]]]:
        """Execute a list of CLI commands and return their raw output."""
        if encoding != "text":
            raise NotImplementedError(
                f"Encoding '{encoding}' is not supported by this driver."
            )
        result: Dict[str, Union[str, Dict[str, Any]]] = {}
        for cmd in commands:
            result[cmd] = self._send_command(cmd)
        return result

    # ── SNMP / Health ──────────────────────────────────────────────────────────

    def get_device_warnings(self) -> list:
        """Return device warnings. SNMP detection handled by poll task."""
        return []

    def get_snmp_config(self):
        """Return SNMP config if a community is configured on the switch."""
        try:
            from napalm_device_types.models import SNMPConfigDict
        except ImportError:
            return None

        try:
            out = self._send_command("show snmp")
        except Exception:
            return None

        if not out:
            return None

        community = None
        in_comm = False
        for line in out.splitlines():
            line_s = line.strip()
            if "Community" in line_s and ("Name" in line_s or "String" in line_s):
                in_comm = True
                continue
            if not in_comm or not line_s or re.match(r"^-{3,}", line_s):
                continue
            parts = line_s.split()
            if parts:
                access = " ".join(parts[1:3]).lower() if len(parts) >= 2 else ""
                if "write" not in access:  # prefer read-only
                    community = parts[0]
                    break
                elif community is None:
                    community = parts[0]

        if not community:
            return None

        return SNMPConfigDict(running=True, community=community, port=161, version="2c")

    def run_device_action(self, action: str) -> Dict:
        """Execute a named action on the switch."""
        if action == "fix_snmp":
            return self._action_fix_snmp()
        raise NotImplementedError(f"Unknown action: {action!r}")

    def _action_fix_snmp(self) -> Dict:
        """Enable SNMP with community 'public' (read-only) on the Netgear Smart switch."""
        if self._detect_cli_v7():
            # The "v7" Cisco-like CLI (e.g. GS110TPv3 7.x) has no
            # "snmp-server"/"show snmp" commands at all — SNMP can only be
            # enabled via the web UI on this firmware generation.
            return {
                "success": False,
                "output": (
                    "SNMP cannot be configured via CLI on this switch's firmware "
                    "(no 'snmp-server' commands available). Enable SNMP manually "
                    "via the switch's web UI, or ignore this warning."
                ),
            }

        lines: list = []

        self._enter_config_mode()
        # Netgear Smart CLI: snmp-server community <name> ro
        self._send_command("snmp-server community public ro")
        lines.append("[config] SNMP community 'public' (read-only) configured.")
        self._exit_config_mode()
        self._save_config()
        lines.append("[config] Configuration saved.")

        # Verify
        try:
            out = self._send_command("show snmp")
            success = "public" in out
        except Exception:
            success = False
            out = ""
        if success:
            lines.append("[ok] SNMP active with community 'public'.")
        else:
            lines.append(f"[warn] Verification failed: {out[:100]}")

        return {"success": success, "output": "\n".join(lines)}

    # ------------------------------------------------------------------
    # PoE
    # ------------------------------------------------------------------

    def get_poe_status(self) -> Dict[str, Dict]:
        """Return PoE configuration per port from ``show power inline``.

        Example output::

            Power management mode: Port limit mode
            ...
            Port State Status     Priority Class   Power Up    Max.Power (Admin)
                                                               (mW)
            ---- ----- ---------- -------- ------- ----------- -----------------
            g1   Auto  on         low      class4  802.3at     4700  (30000)
            g7   Never off        low      N/A     802.3at     0     (30000)
        """
        output = self._send_command("show power inline")

        allocation_method = "PPAM_USAGE"
        mode_m = re.search(r"Power management mode:\s*(.+)", output, re.I)
        if mode_m:
            mode = mode_m.group(1).strip().lower()
            if "port limit" in mode:
                allocation_method = "PPAM_VALUE"
            elif "class" in mode:
                allocation_method = "PPAM_CLASS"

        result: Dict[str, Dict] = {}
        in_table = False
        for line in output.splitlines():
            line_s = line.strip()
            if re.match(r"^-{4,}", line_s):
                in_table = True
                continue
            if not in_table or not line_s:
                continue
            parts = line_s.split()
            if len(parts) < 4 or not re.match(r"^(g\d+|\d+/\d+|ch\d+)$", parts[0], re.I):
                continue
            port, state, _status, priority = parts[0], parts[1], parts[2], parts[3]

            max_power_mw = 0.0
            m = re.search(r"\((\d+)\)\s*$", line_s)
            if m:
                max_power_mw = float(m.group(1))

            result[port] = {
                "port_id": port,
                "is_poe_enabled": state.lower() == "auto",
                "poe_priority": self._POE_PRIORITY_MAP.get(priority.lower(), "PPP_LOW"),
                "poe_allocation_method": allocation_method,
                "allocated_power_in_watts": max_power_mw / 1000.0,
                "pre_standard_detect_enabled": False,
            }

        return result

    def set_poe(self, interface: str, config: Dict) -> None:
        """Update PoE configuration for a single port.

        Uses the ``power inline`` interface sub-commands (ProSafe CLI).
        """
        lines = [f"interface {interface}"]
        if "is_poe_enabled" in config:
            lines.append("power inline auto" if config["is_poe_enabled"] else "power inline never")
        if "poe_priority" in config:
            priority = self._POE_PRIORITY_MAP_REV.get(config["poe_priority"], "low")
            lines.append(f"power inline priority {priority}")
        if "allocated_power_in_watts" in config and config.get("poe_allocation_method") == "PPAM_VALUE":
            limit_mw = int(round(float(config["allocated_power_in_watts"]) * 1000))
            lines.append(f"power inline limit {limit_mw}")
        lines.append("exit")

        if len(lines) <= 2:
            return

        self._enter_config_mode()
        try:
            errors = self._apply_config_lines("\n".join(lines))
            if errors:
                raise CommandErrorException(f"set_poe({interface}) errors: {errors}")
        finally:
            self._exit_config_mode()
        self._save_config()

    # ------------------------------------------------------------------
    # LAG / trunk membership
    # ------------------------------------------------------------------

    def set_lag_members(self, lag_name: str, members: List[str]) -> None:
        """Set the full member-port list of a LAG/trunk group (e.g. ``"ch1"``).

        Diffs ``members`` against the LAG's current members (as reported by
        ``get_interfaces()``) and issues ``addport``/``deleteport`` interface
        sub-commands for the difference. FASTPATH-based switches (NETGEAR
        M4xxx / GSxxxTxx Smart Managed Pro) configure LAG membership
        per-port via ``interface <port>`` / ``addport <lag>`` / ``deleteport
        <lag>``.
        """
        current = self.get_interfaces().get(lag_name, {})
        current_members = set(current.get("lag_members") or [])
        desired = set(members)
        sort_key = lambda s: [int(x) if x.isdigit() else x for x in re.split(r"(\d+)", s)]  # noqa: E731
        to_remove = sorted(current_members - desired, key=sort_key)
        to_add = sorted(desired - current_members, key=sort_key)

        if not to_remove and not to_add:
            return

        lines: List[str] = []
        for port in to_remove:
            lines.append(f"interface {port}")
            lines.append(f"deleteport {lag_name}")
            lines.append("exit")
        for port in to_add:
            lines.append(f"interface {port}")
            lines.append(f"addport {lag_name}")
            lines.append("exit")

        self._enter_config_mode()
        try:
            errors = self._apply_config_lines("\n".join(lines))
            if errors:
                raise CommandErrorException(f"set_lag_members({lag_name}) errors: {errors}")
        finally:
            self._exit_config_mode()
        self._save_config()

    # ------------------------------------------------------------------
    # Health metrics (SNMP)
    # ------------------------------------------------------------------

    @classmethod
    async def get_health_metrics(cls, snmp_get, snmp_walk) -> dict:
        import asyncio
        import re
        from napalm_device_types._ucd_metrics import build_if_metrics, ticks_to_seconds

        _OID_SNMP_UPTIME   = "1.3.6.1.2.1.1.3.0"
        _NETGEAR_MEM_FREE  = "1.3.6.1.4.1.4526.100.1.1.4.1.0"
        _NETGEAR_MEM_TOTAL = "1.3.6.1.4.1.4526.100.1.1.4.2.0"
        _NETGEAR_CPU_STR   = "1.3.6.1.4.1.4526.100.1.1.4.9.0"
        _OID_IF_DESCR      = "1.3.6.1.2.1.2.2.1.2"
        _OID_IF_SPEED      = "1.3.6.1.2.1.2.2.1.5"
        _OID_IF_IN_OCT     = "1.3.6.1.2.1.2.2.1.10"
        _OID_IF_OUT_OCT    = "1.3.6.1.2.1.2.2.1.16"
        _OID_IF_IN_ERR     = "1.3.6.1.2.1.2.2.1.14"
        _OID_IF_OUT_ERR    = "1.3.6.1.2.1.2.2.1.20"

        (uptime_raw, free_s, total_s, cpu_s,
         descr, speed, in_oct, out_oct, in_err, out_err) = await asyncio.gather(
            snmp_get(_OID_SNMP_UPTIME),
            snmp_get(_NETGEAR_MEM_FREE),
            snmp_get(_NETGEAR_MEM_TOTAL),
            snmp_get(_NETGEAR_CPU_STR),
            snmp_walk(_OID_IF_DESCR),
            snmp_walk(_OID_IF_SPEED),
            snmp_walk(_OID_IF_IN_OCT),
            snmp_walk(_OID_IF_OUT_OCT),
            snmp_walk(_OID_IF_IN_ERR),
            snmp_walk(_OID_IF_OUT_ERR),
        )

        metrics: dict = {}

        secs = ticks_to_seconds(uptime_raw)
        if secs is not None:
            metrics["uptime_seconds"] = secs

        if free_s and total_s:
            try:
                free_kb  = int(free_s)
                total_kb = int(total_s)
                used_kb  = max(0, total_kb - free_kb)
                metrics["memory_total_bytes"] = total_kb * 1024
                metrics["memory_used_bytes"]  = used_kb  * 1024
                metrics["memory_percent"]     = round(used_kb / total_kb * 100, 1) if total_kb else 0.0
            except ValueError:
                pass

        if cpu_s:
            m = re.search(r'5\s+Secs\s*\(\s*([\d.]+)\s*%\)', cpu_s)
            if m:
                try:
                    metrics["cpu_percent"] = float(m.group(1))
                except ValueError:
                    pass

        build_if_metrics(metrics, descr, speed, in_oct, out_oct, in_err, out_err)
        return metrics

        return {"success": success, "output": "\n".join(lines)}
