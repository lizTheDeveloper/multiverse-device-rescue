from rescue.models import Platform, RiskLevel
from rescue.module_base import ModuleBase


class ConfigurableModule(ModuleBase):
    name = "configurable_mod"
    category = "test"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE

    def __init__(self):
        self.sensitivity = "normal"

    def check(self, profile):
        pass

    def fix(self, findings, mode):
        pass

    def configure(self, config):
        self.sensitivity = config.get("sensitivity", self.sensitivity)


class PlainModule(ModuleBase):
    name = "plain_mod"
    category = "test"
    platforms = [Platform.DARWIN]

    def check(self, profile):
        pass

    def fix(self, findings, mode):
        pass


def test_configure_default_is_noop():
    mod = PlainModule()
    mod.configure({"anything": "goes"})  # must not raise


def test_configure_overridden_updates_state():
    mod = ConfigurableModule()
    assert mod.sensitivity == "normal"

    mod.configure({"sensitivity": "elevated"})

    assert mod.sensitivity == "elevated"
