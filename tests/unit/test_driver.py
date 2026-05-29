"""Unit tests for NetgearSmartDriver — no real device required."""

import pytest
from unittest.mock import MagicMock, patch

from napalm_netgear_plus.netgear_smart import NetgearSmartDriver


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def driver():
    """Return a driver instance with a mocked Netmiko connection."""
    with patch("napalm_netgear_plus.netgear_smart.ConnectHandler"):
        drv = NetgearSmartDriver(
            hostname="192.168.0.239",
            username="admin",
            password="password",
        )
        drv.device = MagicMock()
        drv.device.base_prompt = "(GS110TP) "
        yield drv


# ---------------------------------------------------------------------------
# Sample CLI output fixtures
# ---------------------------------------------------------------------------

SHOW_SYSINFO = """\
System Description:                  GS110TP Gigabit Smart Managed Pro Switch
Machine Model:                       GS110TP
Machine Type:                        Ethernet Switch
Burned In MAC Address:               C4:AD:34:AB:12:34
System OID String:                   1.3.6.1.4.1.4526.100.5.4
System Uptime:                       2 days 3 hrs 15 mins 42 secs
System Location:                     Server Room
System Contact:                      admin@example.com
System Name:                         myswitch
"""

SHOW_VERSION = """\
Software Version............................. 6.6.3
Loader Version............................... 1.0.0.15
Boot ROM Version............................. B1.0.0.15
Hardware Version............................. V1
Serial Number................................ 1FE2A0B1C2
"""

SHOW_PORT_ALL = """\
Intf       Type    Admin    Physical    Physical    Link    Link   LACP    Actor   Partner Admin
                   Mode     Mode        Status      Status  Trap   Mode    Port    Port    LACP
                                                                   Priority Priority        Timeout
---------  ------  -------  ----------  ----------  ------  -----  -----  ------  ------  -------
0/1               Enable   Auto        1G/Full     Up      Enable  Disable 128   0   Long
0/2               Enable   Auto        -           Down    Enable  Disable 128   0   Long
0/3               Disable  Auto        -           Down    Enable  Disable 128   0   Long
"""

SHOW_INTERFACE_ALL = """\
Interface................................ 0/1
Description.............................. uplink-to-router
MTU...................................... 1518

Interface................................ 0/2
Description.............................. server-1
MTU...................................... 1518

Interface................................ 0/3
MTU...................................... 1518
"""

SHOW_IP_INTERFACE = """\
IP Address....................................... 192.168.0.239
Subnet Mask...................................... 255.255.255.0
Default Gateway.................................. 192.168.0.1
"""

SHOW_ARP = """\
IP Address         MAC Address         Interface  Age (min)  Type
---------          ------------------  ---------  ---------  -------
192.168.0.1        00:11:22:33:44:55   0/0        -          Local
192.168.0.100      aa:bb:cc:dd:ee:ff   0/0        5          Dynamic
"""

SHOW_MAC = """\
VLAN ID  MAC Address         Type        Port
-------  ------------------  ----------  ------
1        00:11:22:33:44:55   Dynamic     0/1
1        aa:bb:cc:dd:ee:ff   Static      0/2
1        ff:ff:ff:ff:ff:ff   Management  CPU
"""

SHOW_VLAN = """\
VLAN ID  VLAN Name       VLAN Type   Interface(s)
-------  --------------- ----------  -----------------------------------
1        Default         Default     0/1, 0/2, 0/3
10       Management      Static      0/1
20       Servers         Static      0/2, 0/3
"""

SHOW_LLDP_ALL = """\
Local     RemID  Chassis ID            Port ID          System Name
Interface
--------- -----  --------------------  ---------------  ---------------
0/1       1      00:1a:2b:3c:4d:5e     Gi0/1            core-router
"""

SHOW_LLDP_DETAIL = """\
Chassis ID Subtype............................. MAC Address
Chassis ID................................... 00:1a:2b:3c:4d:5e
Port ID Subtype.............................. Interface Name
Port ID...................................... Gi0/1
Port Description............................. WAN uplink
System Name.................................. core-router
System Description........................... Cisco IOS XE
System Capabilities.......................... Bridge, Router
Enabled Capabilities......................... Router
"""

SHOW_SNMP = """\
SNMP Community

Community Name  Access Mode  Status
--------------  -----------  ------
public          Read Only    Enable
private         Read Write   Enable
"""

SHOW_USERS = """\
User      Access Level   Session Timeout  Password Strength
--------  ------------   ---------------  -----------------
admin     Read/Write     5                Enabled
guest     Read Only      5                Enabled
"""

SHOW_SNTP = """\
SNTP Server
SNTP Server Address....................... 192.168.0.1
SNTP Server Port......................... 123
"""


# ---------------------------------------------------------------------------
# Tests: get_facts
# ---------------------------------------------------------------------------


class TestGetFacts:
    def test_returns_required_keys(self, driver):
        driver._send_command = lambda cmd: SHOW_SYSINFO
        driver._get_interface_list = lambda: []
        facts = driver.get_facts()
        for key in ("vendor", "model", "hostname", "os_version", "serial_number",
                    "uptime", "interface_list", "fqdn"):
            assert key in facts

    def test_vendor(self, driver):
        driver._send_command = lambda cmd: (
            SHOW_SYSINFO if "sysinfo" in cmd else SHOW_VERSION
        )
        driver._get_interface_list = lambda: []
        facts = driver.get_facts()
        assert facts["vendor"] == "Netgear"

    def test_model(self, driver):
        driver._send_command = lambda cmd: (
            SHOW_SYSINFO if "sysinfo" in cmd else SHOW_VERSION
        )
        driver._get_interface_list = lambda: []
        facts = driver.get_facts()
        assert facts["model"] == "GS110TP"

    def test_hostname(self, driver):
        driver._send_command = lambda cmd: (
            SHOW_SYSINFO if "sysinfo" in cmd else SHOW_VERSION
        )
        driver._get_interface_list = lambda: []
        facts = driver.get_facts()
        assert facts["hostname"] == "myswitch"

    def test_os_version(self, driver):
        driver._send_command = lambda cmd: (
            SHOW_SYSINFO if "sysinfo" in cmd else SHOW_VERSION
        )
        driver._get_interface_list = lambda: []
        facts = driver.get_facts()
        assert facts["os_version"] == "6.6.3"

    def test_serial_number(self, driver):
        driver._send_command = lambda cmd: (
            SHOW_SYSINFO if "sysinfo" in cmd else SHOW_VERSION
        )
        driver._get_interface_list = lambda: []
        facts = driver.get_facts()
        assert facts["serial_number"] == "1FE2A0B1C2"

    def test_uptime_parsing(self, driver):
        driver._send_command = lambda cmd: (
            SHOW_SYSINFO if "sysinfo" in cmd else SHOW_VERSION
        )
        driver._get_interface_list = lambda: []
        facts = driver.get_facts()
        expected = 2 * 86400 + 3 * 3600 + 15 * 60 + 42
        assert facts["uptime"] == float(expected)


# ---------------------------------------------------------------------------
# Tests: _parse_uptime_seconds
# ---------------------------------------------------------------------------


class TestParseUptimeSeconds:
    def test_full(self):
        assert NetgearSmartDriver._parse_uptime_seconds(
            "2 days 3 hrs 15 mins 42 secs"
        ) == float(2 * 86400 + 3 * 3600 + 15 * 60 + 42)

    def test_zero(self):
        assert NetgearSmartDriver._parse_uptime_seconds(
            "0 days 0 hrs 0 mins 0 secs"
        ) == 0.0

    def test_hours_only(self):
        assert NetgearSmartDriver._parse_uptime_seconds("1 hrs 0 mins 0 secs") == 3600.0


# ---------------------------------------------------------------------------
# Tests: _parse_key_value
# ---------------------------------------------------------------------------


class TestParseKeyValue:
    def test_colon_separator(self):
        output = "System Name:                         myswitch"
        assert NetgearSmartDriver._parse_key_value(output, "System Name") == "myswitch"

    def test_dot_separator(self):
        output = "Software Version............................. 6.6.3"
        assert NetgearSmartDriver._parse_key_value(output, "Software Version") == "6.6.3"

    def test_missing_key_returns_empty(self):
        assert NetgearSmartDriver._parse_key_value("some output", "Nonexistent Key") == ""


# ---------------------------------------------------------------------------
# Tests: get_interfaces
# ---------------------------------------------------------------------------


class TestGetInterfaces:
    def _mock(self, driver):
        def _send(cmd):
            if "port" in cmd:
                return SHOW_PORT_ALL
            return SHOW_INTERFACE_ALL
        driver._send_command = _send

    def test_all_ports_present(self, driver):
        self._mock(driver)
        ifaces = driver.get_interfaces()
        assert "0/1" in ifaces
        assert "0/2" in ifaces
        assert "0/3" in ifaces

    def test_link_up(self, driver):
        self._mock(driver)
        assert driver.get_interfaces()["0/1"]["is_up"] is True

    def test_link_down(self, driver):
        self._mock(driver)
        assert driver.get_interfaces()["0/2"]["is_up"] is False

    def test_admin_disabled(self, driver):
        self._mock(driver)
        assert driver.get_interfaces()["0/3"]["is_enabled"] is False

    def test_speed_1g(self, driver):
        self._mock(driver)
        assert driver.get_interfaces()["0/1"]["speed"] == 1000.0

    def test_description_from_interface_all(self, driver):
        self._mock(driver)
        assert driver.get_interfaces()["0/1"]["description"] == "uplink-to-router"


# ---------------------------------------------------------------------------
# Tests: get_interfaces_ip
# ---------------------------------------------------------------------------


class TestGetInterfacesIp:
    def test_management_ip(self, driver):
        driver._send_command = lambda cmd: SHOW_IP_INTERFACE
        result = driver.get_interfaces_ip()
        assert "vlan1" in result
        assert "192.168.0.239" in result["vlan1"]["ipv4"]

    def test_prefix_length(self, driver):
        driver._send_command = lambda cmd: SHOW_IP_INTERFACE
        result = driver.get_interfaces_ip()
        assert result["vlan1"]["ipv4"]["192.168.0.239"]["prefix_length"] == 24


# ---------------------------------------------------------------------------
# Tests: get_arp_table
# ---------------------------------------------------------------------------


class TestGetArpTable:
    def test_entry_count(self, driver):
        driver._send_command = lambda cmd: SHOW_ARP
        arp = driver.get_arp_table()
        assert len(arp) == 2

    def test_entry_keys(self, driver):
        driver._send_command = lambda cmd: SHOW_ARP
        entry = driver.get_arp_table()[0]
        for k in ("interface", "mac", "ip", "age"):
            assert k in entry

    def test_mac_normalised(self, driver):
        driver._send_command = lambda cmd: SHOW_ARP
        macs = {e["mac"] for e in driver.get_arp_table()}
        # napalm_helpers.mac normalises to "AA:BB:CC:DD:EE:FF" format
        assert any(":" in mac for mac in macs)


# ---------------------------------------------------------------------------
# Tests: get_mac_address_table
# ---------------------------------------------------------------------------


class TestGetMacAddressTable:
    def test_entry_count(self, driver):
        driver._send_command = lambda cmd: SHOW_MAC
        mac_table = driver.get_mac_address_table()
        assert len(mac_table) == 3

    def test_static_flag(self, driver):
        driver._send_command = lambda cmd: SHOW_MAC
        statics = [e for e in driver.get_mac_address_table() if e["static"]]
        # "Static" and "Management" rows are static
        assert len(statics) == 2

    def test_dynamic_flag(self, driver):
        driver._send_command = lambda cmd: SHOW_MAC
        dynamics = [e for e in driver.get_mac_address_table() if not e["static"]]
        assert len(dynamics) == 1


# ---------------------------------------------------------------------------
# Tests: get_vlans
# ---------------------------------------------------------------------------


class TestGetVlans:
    def test_vlan_ids(self, driver):
        driver._send_command = lambda cmd: SHOW_VLAN
        vlans = driver.get_vlans()
        assert set(vlans.keys()) == {"1", "10", "20"}

    def test_vlan_name(self, driver):
        driver._send_command = lambda cmd: SHOW_VLAN
        assert driver.get_vlans()["10"]["name"] == "Management"

    def test_vlan_interfaces(self, driver):
        driver._send_command = lambda cmd: SHOW_VLAN
        assert "0/1" in driver.get_vlans()["1"]["interfaces"]


# ---------------------------------------------------------------------------
# Tests: _parse_vlan_ports
# ---------------------------------------------------------------------------


class TestParseVlanPorts:
    def test_single_port(self):
        assert NetgearSmartDriver._parse_vlan_ports("0/1") == ["0/1"]

    def test_range(self):
        assert NetgearSmartDriver._parse_vlan_ports("0/1-0/4") == [
            "0/1", "0/2", "0/3", "0/4"
        ]

    def test_short_range(self):
        assert NetgearSmartDriver._parse_vlan_ports("0/1-4") == [
            "0/1", "0/2", "0/3", "0/4"
        ]

    def test_comma_separated(self):
        result = NetgearSmartDriver._parse_vlan_ports("0/1, 0/3, 0/5")
        assert result == ["0/1", "0/3", "0/5"]


# ---------------------------------------------------------------------------
# Tests: get_lldp_neighbors
# ---------------------------------------------------------------------------


class TestGetLldpNeighbors:
    def test_neighbor_present(self, driver):
        driver._send_command = lambda cmd: SHOW_LLDP_ALL
        neighbors = driver.get_lldp_neighbors()
        assert "0/1" in neighbors

    def test_neighbor_hostname(self, driver):
        driver._send_command = lambda cmd: SHOW_LLDP_ALL
        neighbors = driver.get_lldp_neighbors()
        assert neighbors["0/1"][0]["hostname"] == "core-router"


# ---------------------------------------------------------------------------
# Tests: _parse_lldp_detail
# ---------------------------------------------------------------------------


class TestParseLldpDetail:
    def test_chassis_id(self):
        r = NetgearSmartDriver._parse_lldp_detail(SHOW_LLDP_DETAIL)
        assert r["remote_chassis_id"] == "00:1a:2b:3c:4d:5e"

    def test_port_id(self):
        r = NetgearSmartDriver._parse_lldp_detail(SHOW_LLDP_DETAIL)
        assert r["remote_port"] == "Gi0/1"

    def test_system_name(self):
        r = NetgearSmartDriver._parse_lldp_detail(SHOW_LLDP_DETAIL)
        assert r["remote_system_name"] == "core-router"

    def test_capabilities(self):
        r = NetgearSmartDriver._parse_lldp_detail(SHOW_LLDP_DETAIL)
        assert "bridge" in r["remote_system_capab"]
        assert "router" in r["remote_system_capab"]


# ---------------------------------------------------------------------------
# Tests: get_snmp_information
# ---------------------------------------------------------------------------


class TestGetSnmpInformation:
    def test_communities(self, driver):
        def _send(cmd):
            if "sysinfo" in cmd:
                return SHOW_SYSINFO
            return SHOW_SNMP
        driver._send_command = _send
        snmp = driver.get_snmp_information()
        assert "public" in snmp["community"]
        assert snmp["community"]["public"]["mode"] == "ro"
        assert snmp["community"]["private"]["mode"] == "rw"

    def test_location(self, driver):
        def _send(cmd):
            if "sysinfo" in cmd:
                return SHOW_SYSINFO
            return SHOW_SNMP
        driver._send_command = _send
        snmp = driver.get_snmp_information()
        assert snmp["location"] == "Server Room"


# ---------------------------------------------------------------------------
# Tests: get_users
# ---------------------------------------------------------------------------


class TestGetUsers:
    def test_users_present(self, driver):
        driver._send_command = lambda cmd: SHOW_USERS
        users = driver.get_users()
        assert "admin" in users
        assert "guest" in users

    def test_admin_level(self, driver):
        driver._send_command = lambda cmd: SHOW_USERS
        assert driver.get_users()["admin"]["level"] == 15

    def test_guest_level(self, driver):
        driver._send_command = lambda cmd: SHOW_USERS
        assert driver.get_users()["guest"]["level"] == 1


# ---------------------------------------------------------------------------
# Tests: get_ntp_servers
# ---------------------------------------------------------------------------


class TestGetNtpServers:
    def test_server_found(self, driver):
        driver._send_command = lambda cmd: SHOW_SNTP
        servers = driver.get_ntp_servers()
        assert "192.168.0.1" in servers


# ---------------------------------------------------------------------------
# Tests: config management
# ---------------------------------------------------------------------------


class TestConfigManagement:
    def test_load_merge_from_string(self, driver):
        driver.load_merge_candidate(config="interface 0/1\n  description test\nexit")
        assert driver._candidate_config is not None
        assert driver._candidate_mode == "merge"

    def test_load_replace_from_string(self, driver):
        driver.load_replace_candidate(config="! running config\nvlan 10\n  name test\nexit")
        assert driver._candidate_mode == "replace"

    def test_discard_clears_candidate(self, driver):
        driver.load_merge_candidate(config="vlan 99\n  name test\nexit")
        driver.discard_config()
        assert driver._candidate_config is None
        assert driver._candidate_mode is None

    def test_has_pending_commit_false(self, driver):
        assert driver.has_pending_commit() is False

    def test_has_pending_commit_true(self, driver):
        driver.load_merge_candidate(config="vlan 99\n  name test\nexit")
        assert driver.has_pending_commit() is True

    def test_compare_config_merge(self, driver):
        driver.load_merge_candidate(config="vlan 99\n  name test\nexit")
        diff = driver.compare_config()
        assert diff.startswith("+")

    def test_compare_config_empty_when_no_candidate(self, driver):
        assert driver.compare_config() == ""

    def test_load_merge_from_file(self, driver, tmp_path):
        cfg_file = tmp_path / "candidate.txt"
        cfg_file.write_text("vlan 99\n  name test\nexit\n")
        driver.load_merge_candidate(filename=str(cfg_file))
        assert "vlan 99" in driver._candidate_config

    def test_load_merge_raises_without_input(self, driver):
        from napalm.base.exceptions import MergeConfigException
        with pytest.raises(MergeConfigException):
            driver.load_merge_candidate()

    def test_load_replace_raises_without_input(self, driver):
        from napalm.base.exceptions import ReplaceConfigException
        with pytest.raises(ReplaceConfigException):
            driver.load_replace_candidate()

    def test_rollback_raises_without_backup(self, driver):
        from napalm.base.exceptions import CommandErrorException
        with pytest.raises(CommandErrorException):
            driver.rollback()


# ---------------------------------------------------------------------------
# Tests: _parse_config_blocks / _diff_to_commands
# ---------------------------------------------------------------------------


class TestConfigDiff:
    BACKUP = """\
vlan database
vlan 10
  name Management
exit
interface 0/1
  description uplink
exit
"""
    CURRENT = """\
vlan database
vlan 10
  name Management
exit
interface 0/1
  description changed
exit
"""

    def test_diff_detects_change(self):
        cmds = NetgearSmartDriver._diff_to_commands(
            TestConfigDiff.BACKUP, TestConfigDiff.CURRENT
        )
        # Should contain a "no description" and "description uplink" line
        joined = " ".join(cmds)
        assert "description" in joined


# ---------------------------------------------------------------------------
# Tests: get_config
# ---------------------------------------------------------------------------


class TestGetConfig:
    def test_running_retrieved(self, driver):
        driver._send_command = lambda cmd: "! running config"
        cfg = driver.get_config(retrieve="running")
        assert cfg["running"] == "! running config"
        assert cfg["startup"] == ""

    def test_startup_retrieved(self, driver):
        driver._send_command = lambda cmd: "! startup config"
        cfg = driver.get_config(retrieve="startup")
        assert cfg["startup"] == "! startup config"
        assert cfg["running"] == ""

    def test_candidate_always_empty(self, driver):
        driver._send_command = lambda cmd: ""
        cfg = driver.get_config()
        assert cfg["candidate"] == ""


# ---------------------------------------------------------------------------
# Tests: is_alive
# ---------------------------------------------------------------------------


class TestIsAlive:
    def test_alive_when_connected(self, driver):
        driver.device.remote_conn.transport.is_active.return_value = True
        assert driver.is_alive() == {"is_alive": True}

    def test_dead_when_no_device(self, driver):
        driver.device = None
        assert driver.is_alive() == {"is_alive": False}


# ---------------------------------------------------------------------------
# Tests: cli
# ---------------------------------------------------------------------------


class TestCli:
    def test_returns_output_per_command(self, driver):
        driver._send_command = lambda cmd: f"output of {cmd}"
        result = driver.cli(["show sysinfo", "show version"])
        assert result["show sysinfo"] == "output of show sysinfo"
        assert result["show version"] == "output of show version"

    def test_raises_on_non_text_encoding(self, driver):
        with pytest.raises(NotImplementedError):
            driver.cli(["show sysinfo"], encoding="json")
