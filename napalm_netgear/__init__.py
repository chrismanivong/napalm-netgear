"""NAPALM driver for Netgear Smart Managed switches."""

from napalm_netgear_plus.netgear_smart import NetgearSmartDriver
from napalm_netgear_plus.netgear_plus import NetgearPlusDriver

__all__ = ["NetgearSmartDriver", "NetgearPlusDriver"]
