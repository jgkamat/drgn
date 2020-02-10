# SPDX-License-Identifier: GPL-3.0+

"""
Kconfig
------


The ``drgn.helpers.linux.kconfig`` module provides helpers for reading kernel
configuration from memory. This is only supported if CONFIG_IKCONFIG is set.
"""


import sys
import gzip
import types

from drgn import NULL, cast, container_of

__all__ = (
    "kconfig",
)

def kconfig(prog):
    try:
        return prog.cache["kconfig_options_map"]
    except KeyError:
        pass

    try:
        start = prog.symbol("kernel_config_data").address
        size = prog.symbol("kernel_config_data_end").address - start
        raw_data = prog.read(start, size)
    except LookupError:
        try:
            # Try reading data in format present before kernel 5.0.
            start = prog['kernel_config_data'].address_
            size = len(prog['kernel_config_data'])
            raw_data = prog.read(start, size)
            trim_left = raw_data.find(b'IKCFG_ST') + len(b'IKCFG_ST')
            trim_right = raw_data.rfind(b'IKCFG_ED')
            if trim_left == -1 or trim_right == -1:
                raise LookupError("IKCFG not Found")
            raw_data = raw_data[trim_left:trim_right]
        except LookupError:
            raise LookupError("kernel configuration data not found; kernel must be compiled with CONFIG_IKCONFIG")

    raw_options = gzip.decompress(raw_data).decode().split('\n')

    result = {}

    for line in raw_options:
        if not line or line.startswith('#'):
            continue
        split_option = line.split('=')

        if len(split_option) == 2:
            result[split_option[0]] = split_option[1]
        # Else, we have a malformed entry, ignore.

    # Make result mapping 'immutable', so changes cannot propagate to the cache
    result = types.MappingProxyType(result)
    prog.cache["kconfig_options_map"] = result
    return result
