# napalm-netgear

NAPALM community driver for **Netgear Smart Managed** and **Netgear Plus Managed** switches
(GS108EPP, GS110TP, GS316EPP and compatible Smart Managed Pro series).

## Tested devices

| Model | Series | Tested |
|---|---|---|
| GS110TP | Smart Managed Pro | ✅ |
| GS108EPP | Smart Managed Pro | ✅ |
| GS316EPP | Smart Managed Pro | ✅ |

> Other models from the Netgear Smart Managed Pro series should work as well —
> contributions welcome.

## Requirements

| Dependency | Minimum version |
|---|---|
| Python | 3.8 |
| NAPALM | 4.0 |
| Netmiko | 4.0 |

## Installation

```bash
pip install napalm-netgear
```

Or from source:

```bash
git clone https://github.com/napalm-automation-community/napalm-netgear
cd napalm-netgear
pip install -e .
```

## Quick start

```python
from napalm import get_network_driver

driver = get_network_driver("netgear_smart")
with driver("192.168.0.239", "admin", "password") as device:
    facts = device.get_facts()
    print(facts)
```

## Implemented getters

| Getter | Status | Notes |
|---|---|---|
| `get_facts` | ✅ | model, hostname, os_version, serial, uptime |
| `get_interfaces` | ✅ | status, speed, description, MTU |
| `get_interfaces_ip` | ✅ | management VLAN IP/mask |
| `get_config` | ✅ | running + startup |
| `get_arp_table` | ✅ | |
| `get_mac_address_table` | ✅ | |
| `get_lldp_neighbors` | ✅ | |
| `get_lldp_neighbors_detail` | ✅ | |
| `get_vlans` | ✅ | |
| `get_environment` | ✅ | CPU + memory only |
| `get_interfaces_counters` | ✅ | |
| `get_users` | ✅ | |
| `get_snmp_information` | ✅ | |
| `get_ntp_servers` | ✅ | |
| `get_ntp_peers` | ✅ | same as servers |
| `get_route_to` | ✅ | static/connected only |
| `ping` | ✅ | |
| `cli` | ✅ | |
| `is_alive` | ✅ | |
| `load_merge_candidate` | ✅ | |
| `load_replace_candidate` | ✅ | additive — no atomic replace |
| `compare_config` | ✅ | |
| `commit_config` | ✅ | |
| `discard_config` | ✅ | |
| `rollback` | ✅ | session-scoped backup |
| `get_bgp_neighbors` | ❌ | not applicable |
| `get_optics` | ❌ | DDM not exposed via CLI |
| `get_ipv6_neighbors_table` | ❌ | not exposed via CLI |
| `get_ntp_stats` | ❌ | not exposed via CLI |

## Optional arguments

| Argument | Default | Description |
|---|---|---|
| `port` | `22` | SSH port |
| `force_no_enable` | `False` | Skip `enable` after login |
| `canonical_int_fmt` | `False` | Use canonical interface names |

Any additional keyword arguments are forwarded to Netmiko.

## CLI notes

* Netmiko device type: `netgear_prosafe`
* Prompt pattern: `(hostname) >` / `(hostname) #` / `(hostname) (Config)#`
* Interface naming: `0/1`, `0/2`, … (slot/port); LAG channels: `ch1`, `ch2`, …
* Config is persisted with `write memory`
* Key-value output uses `Key: value` **or** `Key..... value` notation
  depending on firmware generation — both are handled automatically

## Development

```bash
pip install -e ".[dev]"
pytest tests/
```

## License

Apache 2.0 — see [LICENSE](LICENSE).
