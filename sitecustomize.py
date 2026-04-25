"""Runtime compatibility shims for packaged Zurvan environments."""

import sys
import types


def _install_pyqt6_uic_stub():
    try:
        import PyQt6
    except Exception:
        return

    if "PyQt6.uic" in sys.modules or hasattr(PyQt6, "uic"):
        return

    uic = types.ModuleType("PyQt6.uic")

    def _unavailable(*args, **kwargs):
        raise RuntimeError(
            "PyQt6.uic is not available in this runtime. "
            "Install a PyQt6 build that ships uic support to load .ui files."
        )

    uic.loadUi = _unavailable
    uic.loadUiType = _unavailable
    sys.modules["PyQt6.uic"] = uic
    setattr(PyQt6, "uic", uic)


_install_pyqt6_uic_stub()
