# -*- coding: utf-8 -*-
"""MCLanP2P desktop GUI (tkinter).

The GUI is a shell: it collects settings, hands them to NetworkManager,
and renders what comes back. It never implements networking.

Layout follows the reference client (MC-Link): dark cards, Chinese labels,
a live status panel and a log panel with copy/save/clear. Everything lives
in a scrollable canvas so nothing gets cut off on a small window.
"""
import contextlib
import os
import queue
import socket
import subprocess
import sys
import threading
import time
import tkinter as tk
import webbrowser
from tkinter import filedialog, messagebox, ttk

from net import (NetworkManager, load_settings, save_settings, test_server,
                 settings_path, app_dir, human_bytes, human_rate,
                 MODE_AUTO, MODE_DIRECT, MODE_RELAY)
from protocol import (STATE_TEXT, MAX_PLAYERS, MIN_PLAYERS,
                      MAX_PLAYERS_LIMIT, nat_label)

# ============================================================
# Theme
# ============================================================

BG = "#11151c"
CARD = "#1b2230"
CARD_ALT = "#232c3d"
BORDER = "#2f3a4f"

FG = "#e8edf7"
FG_DIM = "#9aa7bd"
FG_MUTED = "#6d7a94"

ACCENT = "#4c8dff"
ACCENT_DARK = "#3a6fd8"
OK = "#3ddc84"
WARN = "#ffb020"
BAD = "#ff5f56"

LOG_BG = "#0c1016"
LOG_FG = "#c7d3e8"

FONT = ("Microsoft YaHei UI", 10)
FONT_BOLD = ("Microsoft YaHei UI", 10, "bold")
FONT_SMALL = ("Microsoft YaHei UI", 9)
FONT_TITLE = ("Microsoft YaHei UI", 17, "bold")
FONT_MONO = ("Consolas", 9)

TICK_MS = 150
UI_REFRESH_MS = 1000
MAX_LOG_LINES = 500

DEFAULT_SERVER = "ws://127.0.0.1:5000/ws"

MODE_LABELS = {
    MODE_AUTO: "自动（先直连，失败转中转）",
    MODE_DIRECT: "直连（UDP 打洞，一直重试）",
    MODE_RELAY: "中转（经服务器，最稳）",
}
MODE_ORDER = [MODE_AUTO, MODE_DIRECT, MODE_RELAY]

MODE_HINTS = {
    MODE_AUTO: "先尝试 UDP 打洞直连；失败两次后自动改用服务器中转。推荐日常使用。",
    MODE_DIRECT: "只走 UDP 打洞，每 3 秒重试直到连上，永不走中转。适合确认能打洞的网络。",
    MODE_RELAY: "游戏数据经信令服务器转发。只要能连上服务器就一定可用，延迟略高。",
}

STATE_COLORS = {
    "ONLINE": OK,
    "CONNECTING": WARN,
    "WAITING": WARN,
    "ERROR": BAD,
    "IDLE": FG_MUTED,
}


def lan_addresses():
    """This machine's LAN IPv4s — shown as a hint for same-LAN friends."""
    out = []
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None,
                                       socket.AF_INET):
            ip = info[4][0]
            if ip not in out and not ip.startswith("127."):
                out.append(ip)
    except Exception:
        pass
    if not out:
        # hostname resolution is unreliable behind some NAT setups
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            out.append(s.getsockname()[0])
            s.close()
        except Exception:
            pass
    return out


# ============================================================
# Widgets
# ============================================================

class ScrollFrame:
    """A vertical scroll container for the whole window.

    The window has a fixed-ish size but the content does not: without this,
    a laptop at 1366x768 lost the bottom of the log panel entirely.

    Why bind_all and not per-widget bindings
    ---------------------------------------
    Tk dispatches the wheel event to the widget under the cursor (and on
    Windows, to the focused widget), and it does NOT bubble. Binding each
    child individually is the obvious fix, but it misses anything created
    later and still dies on widgets that swallow the event.

    `bind_all` registers on the "all" bind tag, which runs LAST -- after the
    widget, its class and the toplevel. That means:

      * every widget in the app is covered, including ones built later;
      * widgets with their own wheel behaviour (Text, Treeview, Listbox)
        run first and get the event before us.

    For those own-scrolling widgets we then chain: if the widget can still
    scroll in the requested direction, leave it alone; otherwise let the
    page scroll. So the wheel never feels "stuck" over the log panel or a
    short list.
    """

    # widgets that scroll their own content and must be given first refusal
    OWN_SCROLL = (tk.Text, tk.Listbox, ttk.Treeview)

    def __init__(self, parent, bg=BG):
        self.canvas = tk.Canvas(parent, bg=bg, highlightthickness=0, bd=0)
        self.canvas.pack(side="left", fill="both", expand=True)

        bar = ttk.Scrollbar(parent, orient="vertical",
                            command=self.canvas.yview)
        bar.pack(side="right", fill="y")
        self.canvas.configure(yscrollcommand=bar.set)

        self.inner = tk.Frame(self.canvas, bg=bg)
        self._win = self.canvas.create_window((0, 0), window=self.inner,
                                              anchor="nw")

        self.inner.bind("<Configure>", self._on_inner)
        self.canvas.bind("<Configure>", self._on_canvas)

    def finalize(self):
        """Call once, after the whole layout exists.

        Forces a geometry pass so the scroll region reflects the real
        content height, then installs the global wheel handler.
        """
        with contextlib.suppress(Exception):
            self.inner.update_idletasks()
        self._refresh_region()

        self.canvas.bind_all("<MouseWheel>", self._wheel)      # Win / macOS
        self.canvas.bind_all("<Button-4>", self._wheel_linux)  # X11 up
        self.canvas.bind_all("<Button-5>", self._wheel_linux)  # X11 down

    def _refresh_region(self):
        with contextlib.suppress(Exception):
            self.canvas.configure(scrollregion=self.canvas.bbox("all"))

    def _on_inner(self, _e):
        self._refresh_region()

    def _on_canvas(self, e):
        # keep the inner frame as wide as the canvas
        self.canvas.itemconfig(self._win, width=e.width)
        self._refresh_region()

    @staticmethod
    def _descendants(widget):
        out = []
        try:
            kids = widget.winfo_children()
        except Exception:
            return out
        for kid in kids:
            out.append(kid)
            out.extend(ScrollFrame._descendants(kid))
        return out

    # ------------------------------------------------------------ wheel

    def _own_can_scroll(self, widget, direction):
        """True if `widget` should keep the event (it can still move)."""
        try:
            if not isinstance(widget, self.OWN_SCROLL):
                return False
            first, last = widget.yview()
            if direction < 0:      # scrolling up
                return first > 0.0
            return last < 1.0      # scrolling down
        except Exception:
            return False

    def _scroll(self, direction):
        self.canvas.yview_scroll(direction, "units")
        return "break"

    def _wheel(self, e):
        direction = -1 if getattr(e, "delta", 0) > 0 else 1
        if self._own_can_scroll(getattr(e, "widget", None), direction):
            return
        return self._scroll(int(direction * self._steps(e)))

    def _wheel_linux(self, e):
        direction = -1 if getattr(e, "num", 5) == 4 else 1
        if self._own_can_scroll(getattr(e, "widget", None), direction):
            return
        return self._scroll(direction)

    @staticmethod
    def _steps(e):
        """Windows reports delta in multiples of 120; macOS can be finer."""
        try:
            delta = abs(float(getattr(e, "delta", 120)))
        except Exception:
            return 1
        if delta <= 0:
            return 1
        return max(1, int(round(delta / 120.0)))


class Card(tk.Frame):
    """A bordered panel with an optional title."""

    def __init__(self, master, title=None, **kwargs):
        super().__init__(master, bg=CARD, highlightbackground=BORDER,
                         highlightthickness=1, **kwargs)
        self.body = tk.Frame(self, bg=CARD)
        self.body.pack(fill="both", expand=True, padx=14, pady=12)
        if title:
            tk.Label(self.body, text=title, bg=CARD, fg=FG_DIM,
                     font=FONT_BOLD, anchor="w").pack(fill="x", pady=(0, 8))


class Row(tk.Frame):
    """label + value line used by the status panel."""

    def __init__(self, master, label, width=8, color=None):
        super().__init__(master, bg=CARD)
        tk.Label(self, text=label, bg=CARD, fg=FG_DIM, font=FONT_SMALL,
                 anchor="w", width=width).pack(side="left")
        self.var = tk.StringVar(value="—")
        tk.Label(self, textvariable=self.var, bg=CARD,
                 fg=color or FG, font=FONT_BOLD,
                 anchor="w").pack(side="left", fill="x", expand=True)


class ScrolledList(ttk.Treeview):
    """A single-column selectable list.

    Rows are (key, text) pairs. The key is stored as the Treeview item id,
    so it survives even when it is NOT shown -- which is exactly the case
    for room codes now that the list only displays world name, host and
    headcount.
    """

    _seq = 0

    def __init__(self, master, height=4, **kw):
        super().__init__(master, show="headings", columns=("v",),
                         height=height, **kw)
        self.heading("v", text="")
        self.column("v", width=10, anchor="w")

    def set_items(self, pairs):
        """pairs: iterable of (key, display_text)."""
        self.delete(*self.get_children())
        for key, text in pairs:
            # An empty iid is illegal in Tk, and an all-digit one is not
            # valid either, so every key is prefixed with a letter.
            ScrolledList._seq += 1
            iid = "k%s" % key if key else "auto%d" % ScrolledList._seq
            self.insert("", "end", iid=iid, values=(text,))

    def selected_key(self):
        """The key of the selected row (the iid with its prefix removed)."""
        sel = self.selection()
        if not sel:
            return ""
        iid = sel[0]
        return iid[1:] if iid.startswith("k") else ""

    def selected_text(self):
        sel = self.selection()
        return self.item(sel[0], "values")[0] if sel else ""


# ============================================================
# Application
# ============================================================

class App:
    def __init__(self, root):
        self.root = root
        self.net = None
        self.connected = False
        self.events = queue.Queue()

        s = load_settings()
        # no settings file yet -> this is the first launch on this machine
        self._first_run = not os.path.exists(settings_path())
        self.var_url = tk.StringVar(value=s.get("ServerUrl") or DEFAULT_SERVER)
        self.var_name = tk.StringVar(value=s.get("Nickname") or "")
        self.var_ip = tk.StringVar(value=s.get("ManualIP") or "")
        self.var_mcport = tk.StringVar(value=str(s.get("McPort") or 25565))
        self.var_udpport = tk.StringVar(value=str(s.get("UdpPort") or 30000))
        # Empty means "derive it from the UDP port", which is the right
        # default: the only rule that matters is that the two differ.
        self.var_tcpport = tk.StringVar(value=str(s.get("TcpPort") or ""))
        self.var_proxyport = tk.StringVar(value=str(s.get("ProxyPort") or 25566))
        self.var_room = tk.StringVar(value=s.get("RoomName") or "我的世界")
        self.var_maxplayers = tk.StringVar(
            value=str(s.get("MaxPlayers") or MAX_PLAYERS))

        mode = s.get("ConnMode") or MODE_AUTO
        if mode not in MODE_LABELS:
            mode = MODE_AUTO
        self.var_mode = tk.StringVar(value=mode)

        for v in (self.var_url, self.var_name, self.var_ip, self.var_mode,
                  self.var_mcport, self.var_udpport, self.var_proxyport,
                  self.var_tcpport,
                  self.var_room, self.var_maxplayers):
            v.trace_add("write", lambda *_: self._autosave())
        self.var_mode.trace_add("write", lambda *_: self._on_mode_change())

        self._build_window()
        self._build_styles()
        self._build_layout()

        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        self.root.after(TICK_MS, self._tick)
        self.root.after(UI_REFRESH_MS, self._refresh_status)

        self._log("MCLanP2P 已启动", "info")
        self._log("配置目录：%s" % app_dir(), "dim")
        self._log("提示：先用「中转」模式验证能联机，再换「自动」试直连。", "dim")
        if self._first_run:
            self._show_first_run()

    # -------------------------------------------------------- 首次启动引导

    FIRST_RUN = (
        "三步开始联机：\n\n"
        "1. 填服务器地址 → 点「测试连接」，右上角变绿再继续\n"
        "      （自己部署：ws://你的公网IP:5000/ws）\n\n"
        "2. 填昵称 → 点「连接」\n\n"
        "3. 开世界的那个人点「创建房间」，其他人「刷新」后选中加入\n"
        "      房客进 Minecraft 连 127.0.0.1:本地代理端口（默认 25566）\n\n"
        "联机模式建议先用「中转」验证，能玩了再换「自动」试直连。"
    )

    def _show_first_run(self):
        """Explain the three steps on the very first launch.

        Only once: the settings file is written as soon as anything is
        typed, so the second start never shows this again.
        """
        for line in self.FIRST_RUN.split("\n"):
            if line.strip():
                self._log(line, "info")
        try:
            messagebox.showinfo("MCLanP2P — 首次使用", self.FIRST_RUN)
        except Exception:
            pass

    # -------------------------------------------------------- window

    def _build_window(self):
        self.root.title("MCLanP2P — Minecraft 联机")
        self.root.geometry("980x820")
        # a small min size: below this the scroll container takes over
        # instead of clipping the bottom cards
        self.root.minsize(760, 520)
        self.root.configure(bg=BG)
        try:
            self.root.call("tk", "scaling", 1.25)
        except Exception:
            pass

    def _build_styles(self):
        style = ttk.Style(self.root)
        try:
            style.theme_use("clam")
        except Exception:
            pass

        style.configure(".", background=BG, foreground=FG, font=FONT,
                        bordercolor=BORDER, focuscolor=ACCENT)
        style.configure("TEntry", fieldbackground=CARD_ALT, background=CARD_ALT,
                        foreground=FG, insertcolor=FG, bordercolor=BORDER,
                        lightcolor=BORDER, darkcolor=BORDER, padding=6)
        style.map("TEntry", fieldbackground=[("disabled", CARD)],
                  foreground=[("disabled", FG_MUTED)])
        style.configure("Mode.TRadiobutton", background=CARD, foreground=FG,
                        font=FONT, indicatorcolor=CARD_ALT)
        style.map("Mode.TRadiobutton", background=[("active", CARD)],
                  foreground=[("active", FG)])
        style.configure("Vertical.TScrollbar", background=CARD_ALT,
                        troughcolor=BG, bordercolor=BG, arrowcolor=FG_DIM)
        style.configure("Treeview", background=CARD_ALT, fieldbackground=CARD_ALT,
                        foreground=FG, bordercolor=BORDER)
        style.map("Treeview", background=[("selected", ACCENT_DARK)],
                  foreground=[("selected", "#ffffff")])

    def _build_layout(self):
        wrap = tk.Frame(self.root, bg=BG)
        wrap.pack(fill="both", expand=True)

        scroller = ScrollFrame(wrap)
        outer = tk.Frame(scroller.inner, bg=BG)
        outer.pack(fill="both", expand=True, padx=18, pady=16)

        self._build_header(outer)

        mid = tk.Frame(outer, bg=BG)
        mid.pack(fill="x", pady=(14, 0))

        left = tk.Frame(mid, bg=BG)
        left.pack(side="left", fill="both", expand=True, padx=(0, 10))
        right = tk.Frame(mid, bg=BG)
        right.pack(side="left", fill="both", expand=True, padx=(10, 0))

        self._build_server_card(left)
        self._build_mode_card(left)
        self._build_identity_card(left)

        self._build_room_card(right)
        self._build_action_card(right)
        self._build_status_card(right)

        self._build_log_card(outer)

        # now the whole layout exists: measure it and arm the wheel
        scroller.finalize()
        self._scroller = scroller   # so the build test can inspect it

    def _build_header(self, parent):
        header = tk.Frame(parent, bg=BG)
        header.pack(fill="x")

        left = tk.Frame(header, bg=BG)
        left.pack(side="left")
        tk.Label(left, text="MCLanP2P", bg=BG, fg=FG,
                 font=FONT_TITLE).pack(side="left")
        tk.Label(left, text="  Minecraft 联机", bg=BG, fg=FG_MUTED,
                 font=FONT_SMALL).pack(side="left", pady=(8, 0))

        self.lbl_server = tk.Label(header, text="● 未测试服务器", bg=BG,
                                   fg=WARN, font=FONT_BOLD)
        self.lbl_server.pack(side="right", pady=(6, 0))

    # -------------------------------------------------------- left

    def _build_server_card(self, parent):
        card = Card(parent, title="服务器")
        card.pack(fill="x", pady=(0, 10))

        tk.Label(card.body, text="信令服务器地址", bg=CARD, fg=FG_DIM,
                 font=FONT_SMALL, anchor="w").pack(fill="x")
        ttk.Entry(card.body, textvariable=self.var_url).pack(
            fill="x", pady=(4, 0))

        tk.Label(card.body, text="自己部署时填 ws://你的公网IP:5000/ws",
                 bg=CARD, fg=FG_MUTED, font=FONT_SMALL,
                 anchor="w").pack(fill="x", pady=(4, 0))

        bar = tk.Frame(card.body, bg=CARD)
        bar.pack(fill="x", pady=(10, 0))
        self.btn_test = self._button(bar, "测试连接", self.on_test_server,
                                     width=10, secondary=True)
        self.btn_test.pack(side="left")
        self._button(bar, "恢复默认", self.on_reset_server, width=10,
                     secondary=True).pack(side="left", padx=(8, 0))

    def _build_mode_card(self, parent):
        card = Card(parent, title="连接模式")
        card.pack(fill="x", pady=(0, 10))

        for mode in MODE_ORDER:
            ttk.Radiobutton(card.body, text=MODE_LABELS[mode], value=mode,
                            variable=self.var_mode, style="Mode.TRadiobutton",
                            command=self._on_mode_change).pack(fill="x",
                                                               anchor="w")

        self.lbl_mode_hint = tk.Label(card.body, text="", bg=CARD, fg=FG_MUTED,
                                      font=FONT_SMALL, anchor="w",
                                      wraplength=340, justify="left")
        self.lbl_mode_hint.pack(fill="x", pady=(8, 0))

    def _build_identity_card(self, parent):
        card = Card(parent, title="身份与本地端口")
        card.pack(fill="x")

        tk.Label(card.body, text="昵称（房间成员列表里显示）", bg=CARD,
                 fg=FG_DIM, font=FONT_SMALL, anchor="w").pack(fill="x")
        ttk.Entry(card.body, textvariable=self.var_name).pack(fill="x",
                                                              pady=(4, 10))

        tk.Label(card.body, text="手动公网 IP（选填，STUN 失败时用）",
                 bg=CARD, fg=FG_DIM, font=FONT_SMALL, anchor="w").pack(fill="x")
        ttk.Entry(card.body, textvariable=self.var_ip).pack(fill="x",
                                                            pady=(4, 10))

        ports = tk.Frame(card.body, bg=CARD)
        ports.pack(fill="x")
        for label, var in (("MC 端口", self.var_mcport),
                           ("UDP 打洞", self.var_udpport),
                           ("TCP 打洞", self.var_tcpport),
                           ("本地代理", self.var_proxyport)):
            col = tk.Frame(ports, bg=CARD)
            col.pack(side="left", fill="x", expand=True, padx=(0, 6))
            tk.Label(col, text=label, bg=CARD, fg=FG_DIM, font=FONT_SMALL,
                     anchor="w").pack(fill="x")
            ttk.Entry(col, textvariable=var).pack(fill="x", pady=(4, 0))

        tk.Label(card.body,
                 text="MC 端口=房主世界端口；UDP=本客户端打洞端口；"
                      "本地代理=作为房客时 Minecraft 要连的端口。占用会自动顺延。",
                 bg=CARD, fg=FG_MUTED, font=FONT_SMALL, anchor="w",
                 wraplength=340, justify="left").pack(fill="x", pady=(8, 0))

    # -------------------------------------------------------- right

    def _build_room_card(self, parent):
        card = Card(parent, title="房间")
        card.pack(fill="x", pady=(0, 10))

        names = tk.Frame(card.body, bg=CARD)
        names.pack(fill="x")

        name_col = tk.Frame(names, bg=CARD)
        name_col.pack(side="left", fill="x", expand=True, padx=(0, 6))
        tk.Label(name_col, text="世界名（建房用）", bg=CARD, fg=FG_DIM,
                 font=FONT_SMALL, anchor="w").pack(fill="x")
        ttk.Entry(name_col, textvariable=self.var_room).pack(fill="x",
                                                             pady=(4, 0))

        cap_col = tk.Frame(names, bg=CARD)
        cap_col.pack(side="left", padx=(6, 0))
        tk.Label(cap_col, text="人数上限", bg=CARD, fg=FG_DIM,
                 font=FONT_SMALL, anchor="w").pack(fill="x")
        ttk.Entry(cap_col, textvariable=self.var_maxplayers,
                  width=6).pack(fill="x", pady=(4, 0))

        tk.Label(card.body,
                 text="人数上限 %d-%d，房主建房时生效；房间满了其他人会看到"
                      "「房间已满」。"
                 % (MIN_PLAYERS, MAX_PLAYERS_LIMIT),
                 bg=CARD, fg=FG_MUTED, font=FONT_SMALL, anchor="w",
                 wraplength=340, justify="left").pack(fill="x", pady=(6, 8))

        row = tk.Frame(card.body, bg=CARD)
        row.pack(fill="x")
        self.btn_create = self._button(row, "创建房间", self.on_create, width=10)
        self.btn_create.pack(side="left")
        self._button(row, "刷新", self.on_refresh, width=6,
                     secondary=True).pack(side="left", padx=(6, 0))
        self._button(row, "加入", self.on_join, width=6,
                     secondary=True).pack(side="left", padx=(6, 0))
        self._button(row, "删除", self.on_delete, width=6,
                     secondary=True).pack(side="left", padx=(6, 0))

        self.lst_rooms = ScrolledList(card.body, height=4)
        self.lst_rooms.pack(fill="x", pady=(8, 0))

        tk.Label(card.body, text="成员", bg=CARD, fg=FG_DIM, font=FONT_SMALL,
                 anchor="w").pack(fill="x", pady=(10, 0))
        # Taller than before: each row is now two lines (name/latency, then
        # NAT). Three showed one and a half members, which is worse than
        # useless when you are trying to compare two people's networks.
        self.lst_members = ScrolledList(card.body, height=6)
        self.lst_members.pack(fill="x", pady=(4, 0))

    def _build_action_card(self, parent):
        card = Card(parent, title="操作")
        card.pack(fill="x", pady=(0, 10))

        row = tk.Frame(card.body, bg=CARD)
        row.pack(fill="x")
        self.btn_connect = self._button(row, "连接", self.on_connect,
                                        width=12, primary=True)
        self.btn_connect.pack(side="left")
        self._button(row, "离开房间", self.on_leave, width=10,
                     secondary=True).pack(side="left", padx=(8, 0))

        # the address guests must type into Minecraft
        addr = tk.Frame(card.body, bg=CARD)
        addr.pack(fill="x", pady=(10, 0))
        tk.Label(addr, text="Minecraft 连接地址", bg=CARD, fg=FG_DIM,
                 font=FONT_SMALL, anchor="w").pack(fill="x")
        line = tk.Frame(addr, bg=CARD)
        line.pack(fill="x", pady=(4, 0))
        self.lbl_addr = tk.Label(line, text="—", bg=CARD_ALT, fg=ACCENT,
                                 font=FONT_MONO, anchor="w", padx=8, pady=5)
        self.lbl_addr.pack(side="left", fill="x", expand=True)
        self._button(line, "复制", self.on_copy_addr, width=6,
                     secondary=True).pack(side="left", padx=(6, 0))

        self.lbl_hint = tk.Label(card.body, text="填好服务器和昵称后点「连接」。",
                                 bg=CARD, fg=FG_MUTED, font=FONT_SMALL,
                                 anchor="w", wraplength=360, justify="left")
        self.lbl_hint.pack(fill="x", pady=(10, 0))

    def _build_status_card(self, parent):
        card = Card(parent, title="运行状态")
        card.pack(fill="x")

        self.rows = {}
        for key, label in (("state", "状态"), ("mode", "模式"),
                           ("room", "房间"), ("members", "成员"),
                           ("channels", "通道"), ("local", "本地端口"),
                           ("latency", "延迟"), ("speed", "速度"),
                           ("traffic", "流量")):
            r = Row(card.body, label)
            r.pack(fill="x", pady=1)
            self.rows[key] = r

    # -------------------------------------------------------- log

    def _build_log_card(self, parent):
        card = Card(parent, title="日志")
        card.pack(fill="both", expand=True, pady=(14, 0))

        bar = tk.Frame(card.body, bg=CARD)
        bar.pack(fill="x", pady=(0, 8))
        self._button(bar, "复制", self.on_copy_log, width=6,
                     secondary=True).pack(side="left")
        self._button(bar, "保存", self.on_save_log, width=6,
                     secondary=True).pack(side="left", padx=(6, 0))
        self._button(bar, "清空", self.on_clear_log, width=6,
                     secondary=True).pack(side="left", padx=(6, 0))
        self._button(bar, "打开日志目录", self.on_open_log_dir, width=12,
                     secondary=True).pack(side="left", padx=(6, 0))
        self._button(bar, "打开配置目录", self.on_open_config_dir, width=12,
                     secondary=True).pack(side="right")

        frame = tk.Frame(card.body, bg=LOG_BG)
        frame.pack(fill="both", expand=True)

        self.log_text = tk.Text(frame, bg=LOG_BG, fg=LOG_FG, font=FONT_MONO,
                                relief="flat", wrap="word", height=12,
                                insertbackground=FG, padx=10, pady=8,
                                state="disabled")
        self.log_text.pack(side="left", fill="both", expand=True)

        scroll = ttk.Scrollbar(frame, orient="vertical",
                               command=self.log_text.yview)
        scroll.pack(side="right", fill="y")
        self.log_text.configure(yscrollcommand=scroll.set)

        # the log scrolls itself; "break" stops the outer canvas from
        # stealing the wheel event
        self.log_text.bind("<MouseWheel>",
                           lambda e: (self.log_text.yview_scroll(
                               int(-1 * (e.delta / 120)), "units"),
                               "break")[1])
        self.log_text.bind("<Button-4>",
                           lambda e: (self.log_text.yview_scroll(-1, "units"),
                                      "break")[1])
        self.log_text.bind("<Button-5>",
                           lambda e: (self.log_text.yview_scroll(1, "units"),
                                      "break")[1])

        for tag, color in (("normal", LOG_FG), ("info", ACCENT), ("ok", OK),
                           ("warn", WARN), ("error", BAD), ("dim", FG_MUTED),
                           ("in", "#8ab4f8"), ("out", "#c7d3e8")):
            self.log_text.tag_configure(tag, foreground=color)

    # -------------------------------------------------------- helpers

    def _button(self, parent, text, command, width=10, primary=False,
                secondary=False):
        bg = ACCENT if primary else CARD_ALT
        fg = "#ffffff" if primary else FG
        btn = tk.Button(parent, text=text, command=command, width=width,
                        bg=bg, fg=fg,
                        activebackground=ACCENT_DARK if primary else BORDER,
                        activeforeground="#ffffff",
                        disabledforeground=FG_MUTED,
                        font=FONT_BOLD if primary else FONT,
                        relief="flat", bd=0, padx=10, pady=7,
                        cursor="hand2", highlightthickness=0)
        btn._primary = primary
        return btn

    def _set_enabled(self, btn, enabled):
        if enabled:
            btn.configure(state="normal",
                          bg=ACCENT if getattr(btn, "_primary", False) else CARD_ALT)
        else:
            btn.configure(state="disabled", bg=CARD)

    def _int(self, var, default):
        try:
            v = int(str(var.get()).strip() or default)
        except (ValueError, AttributeError, TypeError):
            return default
        return v if 1 <= v <= 65535 else default

    def _mc_port(self):
        return self._int(self.var_mcport, 25565)

    def _udp_port(self):
        return self._int(self.var_udpport, 30000)

    def _tcp_port(self):
        """0 = derive from the UDP port. Never raises on a blank field."""
        raw = (self.var_tcpport.get() or "").strip()
        if not raw:
            return 0
        try:
            return max(0, min(65535, int(raw)))
        except ValueError:
            return 0

    def _proxy_port(self):
        return self._int(self.var_proxyport, 25566)

    def _max_players(self):
        """Room capacity, clamped. Never raises: a half-typed field must
        not break autosave."""
        try:
            n = int(str(self.var_maxplayers.get()).strip())
        except (ValueError, AttributeError):
            return MAX_PLAYERS
        return max(MIN_PLAYERS, min(MAX_PLAYERS_LIMIT, n))

    def _autosave(self):
        save_settings(ServerUrl=self.var_url.get(), Nickname=self.var_name.get(),
                      ManualIP=self.var_ip.get(), ConnMode=self.var_mode.get(),
                      McPort=self._mc_port(), UdpPort=self._udp_port(),
                      ProxyPort=self._proxy_port(),
                      TcpPort=self._tcp_port(),
                      RoomName=self.var_room.get(),
                      MaxPlayers=self._max_players())

    def _on_mode_change(self):
        mode = self.var_mode.get()
        if mode not in MODE_LABELS:
            mode = MODE_AUTO
        self.lbl_mode_hint.configure(text=MODE_HINTS.get(mode, ""))
        # Apply it to a session that is already running, not just to the
        # next one. Telling someone "you can switch to relay" and then
        # having the switch do nothing is worse than not mentioning it.
        #
        # Off the Tk thread: set_mode tears down channels and tunnels and
        # spawns punch loops. It happens to be fast today, but doing
        # network-object lifecycle work on the UI thread is the kind of
        # thing that starts timing out the moment anyone adds a join.
        net = getattr(self, "net", None)
        if net is not None and getattr(self, "connected", False):
            threading.Thread(target=self._apply_mode, args=(net, mode),
                             daemon=True).start()

    def _apply_mode(self, net, mode):
        """Runs OFF the Tk thread.

        Tk is not thread-safe. Every other background path in this file
        reports through the event queue for exactly that reason, and this
        one must too: writing straight to the log widget from here can
        corrupt the widget or crash the interpreter, and it only ever
        happens in the error path -- i.e. precisely when the user is
        already confused and least able to tell us what happened.
        """
        try:
            net.set_mode(mode)
        except Exception as e:
            self.events.put(("log", "切换模式失败：%s" % e))

    # -------------------------------------------------------- events

    def _log(self, line, kind="normal"):
        try:
            self.log_text.configure(state="normal")
            self.log_text.insert("end", "[%s] " % time.strftime("%H:%M:%S"),
                                 "dim")
            self.log_text.insert("end", line + "\n", kind)
            count = int(self.log_text.index("end-1c").split(".")[0])
            if count > MAX_LOG_LINES:
                self.log_text.delete("1.0", "%d.0" % (count - MAX_LOG_LINES))
            self.log_text.see("end")
        finally:
            self.log_text.configure(state="disabled")

    def _tick(self):
        try:
            while True:
                kind, payload = self.events.get_nowait()
                if kind == "log":
                    self._log(payload, self._classify(payload))
                elif kind == "status":
                    self.rows["state"].var.set(payload)
                    # The connect button is disabled for the duration of the
                    # (blocking) connect so it cannot be double-clicked. It
                    # was only ever re-enabled on FAILURE -- so after a
                    # successful connect the button stayed dead and the user
                    # could not disconnect at all. Re-enable it the moment
                    # the session is live.
                    if self.connected and payload not in ("连接中",):
                        try:
                            self.btn_connect.configure(state="normal")
                        except Exception:
                            pass
                elif kind == "rooms":
                    self._render_rooms(payload)
                elif kind == "members":
                    self._render_members(payload)
                elif kind == "connect_failed":
                    self._on_connect_failed(payload)
        except queue.Empty:
            pass
        self.root.after(TICK_MS, self._tick)

    @staticmethod
    def _classify(line):
        low = line.lower()
        if "fail" in low or "error" in low or "失败" in line or "错误" in line:
            return "error"
        if "warn" in low or "重试" in line or "等待" in line or "重连" in line:
            return "warn"
        if "->" in line:
            return "out"
        if "<-" in line:
            return "in"
        if "ready" in low or "connected" in low or "成功" in line or "就绪" in line:
            return "ok"
        return "normal"

    def _refresh_status(self):
        if self.net is not None:
            s = self.net.snapshot()
            self.rows["mode"].var.set(MODE_LABELS.get(s["mode"], s["mode"]))
            self.rows["room"].var.set(s["room"] or "—")
            self.rows["members"].var.set(
                "%d / %d" % (s["members"], s.get("max_players") or MAX_PLAYERS))
            self.rows["channels"].var.set("%d 条 / %d 流" %
                                          (s["channels"], s["streams"]))

            if s["is_host"]:
                self.rows["local"].var.set("MC %d" % s["mc_port"])
            else:
                self.rows["local"].var.set("代理 %s" % (s["proxy_port"] or "—"))

            ms = s.get("latency_ms") or 0
            if ms > 0:
                self.rows["latency"].var.set("%.0f ms" % ms)
                self.rows["latency"].winfo_children()[-1].configure(
                    fg=OK if ms < 80 else (WARN if ms < 200 else BAD))
            else:
                self.rows["latency"].var.set("—")

            up = s.get("rate_up") or 0.0
            down = s.get("rate_down") or 0.0
            self.rows["speed"].var.set("↑%s ↓%s" % (human_rate(up),
                                                     human_rate(down)))
            self.rows["traffic"].var.set("↑%s ↓%s" %
                                         (human_bytes(s["bytes_up"]),
                                          human_bytes(s["bytes_down"])))

            addr = "—"
            if s["is_host"]:
                lan = lan_addresses()
                addr = "本机世界 %d" % s["mc_port"]
                if lan:
                    addr += "（局域网可用 %s）" % lan[0]
            elif s["proxy_port"]:
                addr = "127.0.0.1:%d" % s["proxy_port"]
            self.lbl_addr.configure(text=addr)

            col = STATE_COLORS.get(s.get("state"), FG)
            self.rows["state"].winfo_children()[-1].configure(fg=col)
        self.root.after(UI_REFRESH_MS, self._refresh_status)

    def _render_rooms(self, rooms):
        """Show rooms WITHOUT the code -- it still travels with the row as
        its key, so 加入/删除 keep working."""
        pairs = []
        for r in rooms or []:
            cap = r.get("maxPlayers") or MAX_PLAYERS
            pairs.append((
                r.get("roomCode", ""),
                "%s（房主 %s，%d/%d 人）"
                % (r.get("roomName", ""), r.get("ownerName", "?"),
                   r.get("memberCount", 0), cap),
            ))
        self.lst_rooms.set_items(pairs)

    def _render_members(self, members):
        """Name + latency + NAT grade for everyone in the room.

        The NAT line is the point of showing this at all. "Cannot connect"
        reports almost always turn out to be one specific member's network,
        and previously the only way to find out was to ask that person to
        dig through their own log. Now the host can see it directly -- and
        so can everyone else, which also tells you whether the problem is
        yours or theirs.
        """
        pairs = []
        for m in members or []:
            tag = " [房主]" if m.get("isHost") else ""
            lat = m.get("latency", 0)
            lat_text = "%d ms" % lat if lat else "测量中"
            nat = nat_label(m.get("natType") or "unknown",
                            m.get("natSubtype"),
                            m.get("natFilter"))
            # One line, not two. A Treeview row cannot wrap -- a "\n"
            # here is silently rendered as a space -- so the two-line
            # version just produced a truncated, unreadable string.
            pairs.append((m.get("id", ""),
                          "%s%s  %s  ·  %s"
                          % (m.get("name", "?"), tag, lat_text, nat)))
        self.lst_members.set_items(pairs)

    # -------------------------------------------------------- actions

    def on_test_server(self):
        url = self.var_url.get().strip()
        if not url:
            messagebox.showerror("参数错误", "请填写服务器地址")
            return
        self.lbl_server.configure(text="● 测试中 ...", fg=WARN)
        self._set_enabled(self.btn_test, False)

        def worker():
            ok, msg, rtt = test_server(url)
            self.root.after(0, lambda: self._on_test_result(ok, msg, rtt))

        threading.Thread(target=worker, daemon=True).start()

    def _on_test_result(self, ok, msg, rtt):
        self._set_enabled(self.btn_test, True)
        if ok:
            self.lbl_server.configure(
                text="● 服务器正常 %.0f ms" % rtt if rtt else "● 服务器正常",
                fg=OK)
            self._log(msg, "ok")
        else:
            self.lbl_server.configure(text="● 服务器不可用", fg=BAD)
            self._log(msg, "error")

    def on_reset_server(self):
        self.var_url.set(DEFAULT_SERVER)
        self._log("服务器地址已恢复默认", "dim")

    def on_copy_addr(self):
        text = self.lbl_addr.cget("text")
        if not text or text == "—":
            messagebox.showinfo("提示", "连接后才会显示地址")
            return
        if "127.0.0.1:" not in text:
            messagebox.showinfo("提示", "只有房客才有 Minecraft 连接地址")
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        self._log("已复制 Minecraft 地址：%s" % text, "ok")

    def on_connect(self):
        if self.net is not None:
            self.on_disconnect()
            return

        name = self.var_name.get().strip()
        if not name:
            messagebox.showwarning("MCLanP2P", "请填写昵称")
            return

        self._autosave()
        self.net = NetworkManager(
            log_cb=lambda m: self.events.put(("log", m)),
            status_cb=lambda m: self.events.put(("status", m)),
            rooms_cb=lambda r: self.events.put(("rooms", r)),
            members_cb=lambda m: self.events.put(("members", m)),
            mc_port=self._mc_port(),
            proxy_port=self._proxy_port(),
        )
        self.net.punch_port = self._udp_port()
        self.net.tcp_punch_port_cfg = self._tcp_port()
        self.net.mode = self.var_mode.get()

        # connect() blocks: DNS + up to 6s of STUN + the WS handshake.
        # Running it on the Tk thread froze the whole window for that long,
        # with no way to cancel.
        self.connected = True
        self.btn_connect.configure(text="断开")
        self.btn_connect.configure(state="disabled")
        self._log("正在连接...")
        self.rows["state"].var.set("连接中")

        net = self.net
        url = self.var_url.get().strip()
        manual = self.var_ip.get().strip()
        mode = self.var_mode.get()

        def worker():
            try:
                net.connect(url, name, manual, mode)
            except Exception as e:
                self.events.put(("connect_failed", "%s: %s"
                                 % (type(e).__name__, e)))

        threading.Thread(target=worker, daemon=True).start()

    def _on_connect_failed(self, detail):
        """Re-enable the button and report the failure.

        Runs on the Tk thread (via the event queue) because the failure
        happened on the worker thread and Tk is not thread-safe.
        """
        self._log("连接失败：%s" % detail, "error")
        try:
            self.btn_connect.configure(state="normal")
        except Exception:
            pass
        self.connected = False
        self.btn_connect.configure(text="连接")
        self.rows["state"].var.set("连接失败")
        try:
            if self.net is not None:
                self.net.disconnect()
        except Exception:
            pass
        self.net = None
        messagebox.showerror("连接失败", detail)

    def on_disconnect(self):
        if self.net is None:
            return
        try:
            self.net.disconnect()
        except Exception:
            pass
        self.net = None
        self.connected = False
        self.btn_connect.configure(text="连接")
        self.rows["state"].var.set("未连接")
        self.lbl_hint.configure(text="已断开。")
        self._log("已断开", "info")

    def on_create(self):
        if not self._require_net():
            return
        name = self.var_room.get().strip() or "我的世界"
        cap = self._max_players()
        self.net.create_room(name, cap)
        self._log("创建房间：%s" % name, "info")

    def on_refresh(self):
        if not self._require_net():
            return
        self.net.refresh_rooms()

    def on_join(self):
        if not self._require_net():
            return
        code = self.lst_rooms.selected_key()
        if not code:
            messagebox.showinfo("提示", "请先在列表里选中一个房间")
            return
        self.net.join_room(code)
        self._log("加入房间：%s" % code, "info")

    def on_delete(self):
        if not self._require_net():
            return
        code = self.lst_rooms.selected_key()
        if not code:
            messagebox.showinfo("提示", "请先在列表里选中一个房间")
            return
        self.net.delete_room(code)

    def on_leave(self):
        if self.net is None:
            return
        self.net.leave_room()
        self._log("已离开房间", "info")

    def _require_net(self):
        if self.net is None:
            messagebox.showinfo("提示", "请先点「连接」")
            return False
        return True

    # -------------------------------------------------------- log actions

    def on_copy_log(self):
        self.root.clipboard_clear()
        self.root.clipboard_append(self.log_text.get("1.0", "end").strip())
        self._log("日志已复制到剪贴板", "dim")

    def on_save_log(self):
        path = filedialog.asksaveasfilename(
            title="保存日志", defaultextension=".txt",
            initialfile=time.strftime("mclanp2p-%Y%m%d-%H%M%S.txt"),
            filetypes=[("文本文件", "*.txt"), ("所有文件", "*.*")])
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(self.log_text.get("1.0", "end"))
            self._log("日志已保存：%s" % path, "ok")
        except Exception as e:
            messagebox.showerror("保存失败", str(e))

    def on_clear_log(self):
        self.log_text.configure(state="normal")
        self.log_text.delete("1.0", "end")
        self.log_text.configure(state="disabled")

    def _open_dir(self, path):
        try:
            os.makedirs(path, exist_ok=True)
        except Exception:
            pass
        try:
            if os.name == "nt":
                os.startfile(path)
            elif sys.platform == "darwin":
                subprocess.run(["open", path], check=False)
            else:
                webbrowser.open("file://" + path)
        except Exception as e:
            messagebox.showinfo("目录", "%s\n\n(%s)" % (path, e))

    def on_open_config_dir(self):
        from common import app_dir
        self._open_dir(app_dir())

    def on_open_log_dir(self):
        from common import log_dir
        self._open_dir(log_dir())

    # -------------------------------------------------------- close

    def on_close(self):
        try:
            if self.net is not None:
                self.net.disconnect()
        except Exception:
            pass
        self.root.destroy()


def main():
    root = tk.Tk()
    App(root)
    root.mainloop()


if __name__ == "__main__":
    main()
