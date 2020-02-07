import os
import typing

from drgn.helpers.linux import kernel_config

from tests.helpers.linux import LinuxHelperTestCase


class TestKConfig(LinuxHelperTestCase):
    def test_kernel_config(self):
        if not os.path.isfile('/proc/config.gz'):
            self.skipTest("CONFIG_IKCONFIG_PROC not set.")
        m = kernel_config.kconfig(self.prog)
        self.assertIsInstance(m, typing.Mapping)
        self.assertIn(m['CONFIG_IKCONFIG'], {'y', 'm'})
