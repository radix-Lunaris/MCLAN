# -*- coding: utf-8 -*-
"""UPnP-IGD / NAT-PMP port mapping -- the deterministic way out of NAT4.

Everything else in the NAT traversal stack is probability: predict the
port, open many ports, hope one collides. A port mapping is not a guess.
If the router agrees to forward UDP <external>:30000 to us, then we HAVE a
public port, and a peer can simply connect to it -- the NAT problem is gone
rather than solved probabilistically. It is the highest-value and
least-invasive bypass available, so it is tried first.

It only works when the router has UPnP enabled (many ship it on by default;
some disable it deliberately), so a failure here is normal and must never
be treated as an error -- it just means we fall back to punching.

No third-party dependency: SSDP discovery plus a SOAP call over plain
sockets, because this has to work from a frozen client build.
"""
import re
import socket
import threading
import time

SSDP_ADDR = "239.255.255.250"
SSDP_PORT = 1900
DISCOVER_TIMEOUT_S = 2.0

# WANIPConnection covers Ethernet/VDSL routers; WANPPPConnection covers
# PPPoE (common on fibre in Asia). Try both, in that order.
SERVICE_TYPES = (
    "urn:schemas-upnp-org:service:WANIPConnection:1",
    "urn:schemas-upnp-org:service:WANIPConnection:2",
    "urn:schemas-upnp-org:service:WANPPPConnection:1",
)

_RE_LOCATION = re.compile(r"^location:\s*(\S+)", re.I)


def _http(url, data=None, headers=None, timeout=3.0):
    """Minimal HTTP/1.0 over a raw socket.

    urllib would drag in proxy detection and, worse, honours HTTP_PROXY --
    which is wrong for a request that must go to a host on the LAN.
    """
    from urllib.parse import urlsplit
    parts = urlsplit(url)
    host = parts.hostname or ""
    port = parts.port or (443 if parts.scheme == "https" else 80)
    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query

    s = socket.create_connection((host, port), timeout=timeout)
    try:
        s.settimeout(timeout)
        # The Host header MUST carry the port when it is not the default.
        # A router on :5000 that receives "Host: 192.168.1.1" hands back a
        # URLBase without the port, and every later control URL is then
        # built against the wrong endpoint -- the mapping silently fails.
        host_hdr = host if port in (80, 443) else "%s:%d" % (host, port)
        if data is None:
            req = "GET %s HTTP/1.0\r\nHost: %s\r\nConnection: close\r\n\r\n" % (
                path, host_hdr)
        else:
            body = data.encode("utf-8") if isinstance(data, str) else data
            hdrs = {
                "Host": host_hdr,
                "Content-Length": str(len(body)),
                "Connection": "close",
            }
            hdrs.update(headers or {})
            head = "".join("%s: %s\r\n" % kv for kv in hdrs.items())
            req = ("POST %s HTTP/1.0\r\n%s\r\n" % (path, head)).encode()
            req += body
        s.sendall(req if isinstance(req, bytes) else req.encode())
        buf = b""
        while True:
            try:
                chunk = s.recv(8192)
            except socket.timeout:
                break
            if not chunk:
                break
            buf += chunk
            if len(buf) > 256 * 1024:
                break
        return buf.decode("utf-8", "replace")
    finally:
        try:
            s.close()
        except Exception:
            pass


def discover(timeout=DISCOVER_TIMEOUT_S):
    """Find an IGD on the LAN. Returns its description URL, or None."""
    for st in ("urn:schemas-upnp-org:device:InternetGatewayDevice:1",
               "ssdp:all"):
        msg = ("M-SEARCH * HTTP/1.1\r\n"
               "HOST: %s:%d\r\n"
               'MAN: "ssdp:discover"\r\n'
               "MX: 2\r\n"
               "ST: %s\r\n\r\n" % (SSDP_ADDR, SSDP_PORT, st))
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.settimeout(timeout)
            try:
                s.sendto(msg.encode(), (SSDP_ADDR, SSDP_PORT))
            except OSError:
                s.close()
                continue
            end = time.time() + timeout
            while time.time() < end:
                try:
                    data, _src = s.recvfrom(4096)
                except socket.timeout:
                    break
                except OSError:
                    break
                text = data.decode("utf-8", "replace")
                m = _RE_LOCATION.search(text)
                if m:
                    s.close()
                    return m.group(1).strip()
            s.close()
        except Exception:
            continue
    return None


def _find_control_url(desc_url):
    """Pick a WAN(IP|PPP)Connection control URL out of the device XML."""
    xml = _http(desc_url, timeout=3.0)
    if not xml:
        return None, None

    # <service> blocks contain serviceType + controlURL + (for the base URL)
    # we rely on URLBase when present, else the description URL's host.
    base = None
    mb = re.search(r"<URLBase>\s*(\S+?)\s*</URLBase>", xml, re.I)
    if mb:
        base = mb.group(1).rstrip("/")

    for st in SERVICE_TYPES:
        for block in re.findall(r"<service>.*?</service>", xml, re.S | re.I):
            if st.lower() not in block.lower():
                continue
            mc = re.search(r"<controlURL>\s*(\S+?)\s*</controlURL>",
                           block, re.I)
            if not mc:
                continue
            ctrl = mc.group(1)
            if ctrl.startswith("http"):
                return st, ctrl
            if base:
                return st, base + ("" if ctrl.startswith("/") else "/") + ctrl
            from urllib.parse import urlsplit
            p = urlsplit(desc_url)
            root = "%s://%s" % (p.scheme, p.netloc)
            return st, root + ("" if ctrl.startswith("/") else "/") + ctrl
    return None, None


def _soap(control_url, service, action, args):
    body = ('<?xml version="1.0"?>'
            '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"'
            ' s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">'
            '<s:Body><u:%s xmlns:u="%s">%s</u:%s></s:Body></s:Envelope>'
            % (action, service, "".join(args), action))
    headers = {
        "Content-Type": 'text/xml; charset="utf-8"',
        "SOAPAction": '"%s#%s"' % (service, action),
    }
    return _http(control_url, body, headers, timeout=4.0)


def external_ip(control_url, service):
    xml = _soap(control_url, service, "GetExternalIPAddress", [])
    m = re.search(r"<NewExternalIPAddress>\s*(\S+?)\s*</", xml or "", re.I)
    return m.group(1) if m else ""


def local_ip_for(target=("8.8.8.8", 80)):
    """Our own LAN address -- the client a mapping has to point at."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(target)
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def map_port(internal_port, external_port=None, proto="UDP",
             description="MCLanP2P", lease=0, log=None):
    """Ask the router to forward a port. Returns (ip, external_port) or None.

    lease=0 means "no fixed expiry"; the router may still drop it, so
    callers should refresh periodically.
    """
    if external_port is None:
        external_port = internal_port
    if external_port and not (1024 <= int(external_port) <= 65535):
        return None

    try:
        desc = discover()
        if not desc:
            return None
        service, control = _find_control_url(desc)
        if not control:
            return None

        internal = local_ip_for()
        args = [
            "<NewRemoteHost></NewRemoteHost>",
            "<NewExternalPort>%d</NewExternalPort>" % int(external_port),
            "<NewProtocol>%s</NewProtocol>" % proto,
            "<NewInternalPort>%d</NewInternalPort>" % int(internal_port),
            "<NewInternalClient>%s</NewInternalClient>" % internal,
            "<NewEnabled>1</NewEnabled>",
            "<NewPortMappingDescription>%s</NewPortMappingDescription>"
            % description,
            "<NewLeaseDuration>%d</NewLeaseDuration>" % int(lease),
        ]
        out = _soap(control, service, "AddPortMapping", args)
        # A successful response echoes the action; an error carries a
        # <errorCode>. Anything unrecognised is treated as failure rather
        # than assumed to work.
        if out and "<errorCode>" in out:
            m = re.search(r"<errorCode>\s*(\d+)\s*</errorCode>", out)
            code = m.group(1) if m else "?"
            if log:
                try:
                    log("[UPnP] router refused the mapping (code %s)" % code)
                except Exception:
                    pass
            # 718 = conflict: the mapping already exists, possibly ours from
            # a previous run. Treat it as usable.
            if code not in ("718", "725"):
                return None
        elif not out or "AddPortMappingResponse" not in out:
            return None

        ip = external_ip(control, service)
        if not ip:
            return None
        if log:
            try:
                log("[UPnP] mapped %s:%d -> %s:%d (%s)"
                    % (ip, external_port, internal, internal_port, proto))
            except Exception:
                pass
        return ip, int(external_port)
    except Exception:
        # UPnP being absent, blocked, or weird is normal -- never fatal.
        return None


def unmap_port(external_port, proto="UDP", log=None):
    """Best-effort cleanup. Failure is expected and ignored."""
    try:
        desc = discover()
        if not desc:
            return
        service, control = _find_control_url(desc)
        if not control:
            return
        args = [
            "<NewRemoteHost></NewRemoteHost>",
            "<NewExternalPort>%d</NewExternalPort>" % int(external_port),
            "<NewProtocol>%s</NewProtocol>" % proto,
        ]
        _soap(control, service, "DeletePortMapping", args)
    except Exception:
        pass


class Mapping:
    """Keeps one mapping alive for as long as we need it.

    Routers expire mappings; refreshing on a timer is what stops a working
    direct connection from silently dying mid-session.
    """

    def __init__(self, internal_port, external_port=None, proto="UDP",
                 refresh_s=240.0, log=None):
        self.internal_port = internal_port
        self.external_port = external_port or internal_port
        self.proto = proto
        self.refresh_s = refresh_s
        self.log = log
        self.endpoint = None       # "ip:port" or None
        self._stop = threading.Event()
        self._thread = None

    def start(self):
        self.endpoint = self._renew()
        if self.endpoint:
            self._thread = threading.Thread(target=self._loop, daemon=True)
            self._thread.start()
        return self.endpoint

    def _renew(self):
        got = map_port(self.internal_port, self.external_port, self.proto,
                       log=self.log)
        return ("%s:%d" % got) if got else None

    def _loop(self):
        while not self._stop.wait(self.refresh_s):
            self._renew()

    def stop(self):
        self._stop.set()
        if self.endpoint:
            unmap_port(self.external_port, self.proto, log=self.log)
            self.endpoint = None
