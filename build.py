#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Build the MCLanP2P client into a single Windows exe.

    python build.py            -> dist/MCLanP2P.exe
    (or just double-click build_client.bat)

The server is NOT built: it stays a plain Python script on the server.
That's deliberate — the server only needs python3 (present on every Linux
distro), and deploying source keeps `deploy-server.sh` a simple file copy
with no toolchain, no glibc compatibility concerns, and no upload step.

The exe must be built on Windows: tkinter is platform-specific and
PyInstaller cannot cross-compile.
"""
import os
import platform
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
DIST = os.path.join(HERE, "dist")
NAME = "MCLanP2P"

GREEN = YELLOW = CYAN = RED = NC = ""
if sys.stdout.isatty() and os.name == "nt":
    try:
        os.system("")  # enable VT100 escapes on Windows 10+
        GREEN, YELLOW, CYAN, RED, NC = "\033[32m", "\033[33m", "\033[36m", "\033[31m", "\033[0m"
    except Exception:
        pass


def info(m):
    print(f"{CYAN}[INFO]{NC} {m}")


def ok(m):
    print(f"{GREEN}[ OK ]{NC} {m}")


def warn(m):
    print(f"{YELLOW}[WARN]{NC} {m}")


def die(m, code=1):
    print(f"{RED}[FAIL]{NC} {m}", file=sys.stderr)
    sys.exit(code)


def run(cmd, **kw):
    print("       $ " + " ".join(str(c) for c in cmd))
    return subprocess.run(cmd, **kw)


def main():
    print("")
    print("=" * 60)
    print("   build client -> %s.exe" % NAME)
    print("=" * 60)
    print("")

    if platform.system() != "Windows":
        warn("this exe must be built on Windows (tkinter is platform-specific)")
        warn("on this machine, run the client directly instead:  cd client && python main.py")
        if platform.system() == "Linux":
            warn("(if tkinter is missing:  sudo apt install python3-tk)")
        sys.exit(1)

    try:
        import PyInstaller  # noqa: F401
        info("PyInstaller present")
    except ImportError:
        info("installing PyInstaller...")
        r = run([sys.executable, "-m", "pip", "install", "pyinstaller"])
        if r.returncode != 0:
            die("cannot install PyInstaller. Install it manually:\n"
                "       pip install pyinstaller")
        import PyInstaller  # noqa: F401

    ok("PyInstaller %s" % PyInstaller.__version__)

    # sanity: every module the client needs must be importable here
    info("checking client modules...")
    sys.path.insert(0, os.path.join(HERE, "client"))
    for mod in ("wsproto", "udptunnel", "protocol", "common",
                "channel", "net_sig", "net_room", "net_transport",
                "net_proxy", "net", "ui", "natpunch", "tcppunch",
                "upnp"):
        try:
            __import__(mod)
        except Exception as e:
            die("module '%s' is broken: %s: %s" % (mod, type(e).__name__, e))
    ok("all client modules import cleanly")

    entry = os.path.join(HERE, "client", "main.py")
    if not os.path.isfile(entry):
        die("missing %s" % entry)

    sep = os.pathsep
    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--noconfirm", "--onefile", "--clean", "--windowed",
        "--name", NAME,
        "--distpath", DIST,
        "--workpath", os.path.join(HERE, "build"),
        "--specpath", os.path.join(HERE, "build"),
        "--add-data", os.path.join(HERE, "client") + sep + ".",
        "--hidden-import", "wsproto",
        "--hidden-import", "udptunnel",
        "--hidden-import", "protocol",
        "--hidden-import", "common",
        "--hidden-import", "channel",
        "--hidden-import", "net_sig",
        "--hidden-import", "net_room",
        "--hidden-import", "net_transport",
        "--hidden-import", "net_proxy",
        "--hidden-import", "net",
        "--hidden-import", "ui",
        "--hidden-import", "natpunch",
        "--hidden-import", "tcppunch",
        "--hidden-import", "upnp",
        entry,
    ]
    r = run(cmd, cwd=HERE)
    if r.returncode != 0:
        die("build failed")

    exe = os.path.join(DIST, NAME + ".exe")
    if not os.path.isfile(exe):
        die("expected %s but it is missing" % exe)

    mb = os.path.getsize(exe) / 1024 / 1024
    ok("built: %s (%.1f MB)" % (exe, mb))

    print("")
    print("=" * 60)
    print("   done")
    print("=" * 60)
    print("")
    print("     %s" % exe)
    print("")
    print("   把 settings.json 放在 exe 旁边可以预填服务器/昵称等；")
    print("   不放也没关系，界面会记住你上次填的内容。")
    print("")


if __name__ == "__main__":
    main()
