# Copyright (C) 2022 Mandiant, Inc. All Rights Reserved.

import binascii

import speakeasy.winenv.defs.windows.iphlpapi as iphlpapi_types
import speakeasy.winenv.defs.windows.windows as windefs

from .. import api


class Iphlpapi(api.ApiHandler):
    """
    Implements exported functions from iphlpapi.dll
    """

    name = "iphlpapi"
    apihook = api.ApiHandler.apihook
    impdata = api.ApiHandler.impdata

    def __init__(self, emu):
        super().__init__(emu)

        self.iphlpapi_types = iphlpapi_types

    @staticmethod
    def _adapter_value(adapter, name, default=None):
        if isinstance(adapter, dict):
            return adapter.get(name, default)
        return getattr(adapter, name, default)

    @apihook("GetAdaptersInfo", argc=2)
    def GetAdaptersInfo(self, emu, argv, ctx: api.ApiContext = None):
        ptr_adapter_info, size_ptr = argv
        rv = 0

        adapters = emu.config.network.adapters
        adapter_count = len(adapters)

        if not ptr_adapter_info:
            adapter_info = self.iphlpapi_types.IP_ADAPTER_INFO(emu.get_ptr_size())
            size = adapter_info.sizeof()
            self.mem_write(size_ptr, size.to_bytes(4, "little"))
            return windefs.ERROR_BUFFER_OVERFLOW

        for index, adapter in enumerate(adapters):
            adapter_info = self.iphlpapi_types.IP_ADAPTER_INFO(emu.get_ptr_size())

            name = self._adapter_value(adapter, "name") or ""
            description = self._adapter_value(adapter, "description") or ""
            mac_address = self._adapter_value(adapter, "mac_address") or ""
            adapter_type = self._adapter_value(adapter, "type") or ""
            ip_address = self._adapter_value(adapter, "ip_address") or ""
            subnet_mask = self._adapter_value(adapter, "subnet_mask") or ""

            adapter_info.AdapterName = name.encode("utf-8")
            adapter_info.Description = description.encode("utf-8")
            adapter_info.AddressLength = 6
            try:
                adapter_info.Address = binascii.unhexlify(mac_address.replace("-", "").replace(":", ""))
            except (binascii.Error, ValueError):
                adapter_info.Address = b"\x00" * 6
            adapter_info.Type = iphlpapi_types.get_adapter_type(adapter_type)
            adapter_info.IpAddressList.IpAddress = ip_address.encode("utf-8")
            adapter_info.IpAddressList.IpMask = subnet_mask.encode("utf-8")
            adapter_info.DhcpEnabled = bool(self._adapter_value(adapter, "dhcp_enabled", False))

            if index < adapter_count - 1:
                ptr_next = self.mem_alloc(adapter_info.sizeof(), tag="api.struct.IP_ADAPTER_INFO")
            else:
                ptr_next = 0

            adapter_info.Next = ptr_next
            self.mem_write(ptr_adapter_info, self.get_bytes(adapter_info))
            ptr_adapter_info = ptr_next

        return rv
