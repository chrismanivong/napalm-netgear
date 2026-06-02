"""NAPALM driver for Netgear Smart Managed switches."""

from napalm_netgear.netgear_smart import NetgearSmartDriver
from napalm_netgear.netgear_plus import NetgearPlusDriver

__all__ = ["NetgearSmartDriver", "NetgearPlusDriver"]
