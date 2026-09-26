#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""MCLanP2P client entry point.

    python main.py

Requires Python 3.7+ and nothing else: tkinter ships with CPython on
Windows/macOS, and the network stack is pure standard library.

The explicit imports below look redundant (ui imports net already) but
they are what lets PyInstaller's static analysis see every module —
without them the built exe crashes with "No module named 'udptunnel'".
"""
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

# explicit, so the bundler can find them.
# net.py is now a facade over four mixins, and PyInstaller's static
# analysis does not follow the import inside a mixin module back to the
# package -- every one of them has to be named here or the built exe
# dies with "No module named 'net_transport'".
import wsproto          # noqa: F401
import udptunnel        # noqa: F401
import protocol         # noqa: F401
import common           # noqa: F401
import channel          # noqa: F401
import net_sig          # noqa: F401
import net_room         # noqa: F401
import net_transport    # noqa: F401
import net_proxy        # noqa: F401
import net              # noqa: F401
import ui               # noqa: F401


def main():
    try:
        import tkinter  # noqa: F401
    except ImportError:
        print("缺少 tkinter，无法启动图形界面。")
        print("  Debian/Ubuntu:  sudo apt install python3-tk")
        print("  Fedora/RHEL:    sudo dnf install python3-tkinter")
        print("  Windows/macOS:  重新安装 Python 并勾选 tcl/tk and IDLE")
        return 1
    ui.main()
    return 0


if __name__ == "__main__":
    sys.exit(main())
