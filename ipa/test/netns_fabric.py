#!/usr/bin/env python3
"""netns_fabric.py -- a veth network to test the datapath on: one ingress
interface and one veth pair per logical port. Needs root.

Usage:
    sudo python3 ipa/test/netns_fabric.py --n-ports 5 --hold
"""
import argparse
import os
import subprocess
import sys
import time

DEFAULT_PREFIX = "ipa"
ETH_P_ALL = 0x0003
DEFAULT_ETHERTYPE = 0x88B5


class FabricError(RuntimeError):
    """The fabric could not be built, or the box cannot support one."""


def _run(args, check=True):
    p = subprocess.run(args, capture_output=True, text=True)
    if check and p.returncode != 0:
        raise FabricError(f"{' '.join(args)} failed: {p.stderr.strip()}")
    return p


def _have_root():
    return hasattr(os, "geteuid") and os.geteuid() == 0


def existing_links(prefix=DEFAULT_PREFIX):
    """Every link whose name starts with `prefix`, as the kernel lists them."""
    out = _run(["ip", "-o", "link", "show"], check=False).stdout
    names = []
    for line in out.splitlines():
        parts = line.split(":", 2)
        if len(parts) < 2:
            continue
        name = parts[1].strip().split("@")[0]
        if name.startswith(prefix):
            names.append(name)
    return names


def cleanup(prefix=DEFAULT_PREFIX, verbose=True):
    """Remove every link left behind by a fabric with this prefix."""
    removed = []
    for name in existing_links(prefix):
        if _run(["ip", "link", "del", name], check=False).returncode == 0:
            removed.append(name)
    if verbose:
        print(f"[fabric] cleanup: removed {len(removed)} link(s)"
              + (f": {', '.join(removed)}" if removed else ""))
    return removed


# --- The XDP_PASS program that makes veth's ndo_xdp_xmit available on the peers. ---
_PASS_SRC = """
int xdp_pass_stub(struct xdp_md *ctx) {
    return XDP_PASS;
}
"""


class NetnsFabric:
    """`n_ports` veth pairs, one per logical port, with XDP-capable peers."""

    def __init__(self, n_ports: int = 5, prefix: str = DEFAULT_PREFIX,
                 enable_redirect: bool = True, verbose: bool = True,
                 port_queues: int = 1):
        if n_ports < 1:
            raise ValueError("n_ports must be >= 1")
        if port_queues < 1:
            raise ValueError("port_queues must be >= 1")
        self.n_ports = n_ports
        self.port_queues = port_queues
        self.prefix = prefix
        self.enable_redirect = enable_redirect
        self.verbose = verbose

        self.port_to_iface = {}
        self.peer_of = {}
        self.ifindex_of = {}
        self.pass_attached = []
        self.ingress = None
        self.ingress_peer = None
        self.ingress_ifindex = None
        self._bpf = None
        self._socks = {}
        self._built = False

    def _name(self, port):
        return f"{self.prefix}{port}"

    def _peer(self, port):
        return f"{self.prefix}{port}p"

    def _ingress_names(self):
        return f"{self.prefix}in", f"{self.prefix}inp"

    def build(self):
        if sys.platform != "linux":
            raise FabricError(f"needs Linux, not {sys.platform}")
        if not _have_root():
            raise FabricError("needs root (veth creation and XDP attach)")
        if _run(["ip", "-V"], check=False).returncode != 0:
            raise FabricError("`ip` not available (install iproute2)")

        stale = existing_links(self.prefix)
        if stale:
            if self.verbose:
                print(f"[fabric] removing {len(stale)} stale link(s) from an "
                      f"earlier run")
            cleanup(self.prefix, verbose=False)

        import socket as _socket

        pairs = [(None, *self._ingress_names())]
        pairs += [(port, self._name(port), self._peer(port))
                  for port in range(self.n_ports)]
        for port, a, b in pairs:
            q = [] if port is None or self.port_queues == 1 else \
                ["numrxqueues", str(self.port_queues),
                 "numtxqueues", str(self.port_queues)]
            _run(["ip", "link", "add", a, *q, "type", "veth", "peer",
                  "name", b, *q])
            for end in (a, b):
                _run(["sysctl", "-qw",
                      f"net.ipv6.conf.{end}.disable_ipv6=1"], check=False)
            _run(["ip", "link", "set", a, "up"])
            _run(["ip", "link", "set", b, "up"])
            if port is None:
                self.ingress, self.ingress_peer = a, b
                self.ingress_ifindex = _socket.if_nametoindex(a)
            else:
                self.port_to_iface[port] = a
                self.peer_of[port] = b
                self.ifindex_of[port] = _socket.if_nametoindex(a)

        self._built = True
        if self.verbose:
            print(f"[fabric] {self.n_ports} port pair(s) + a dedicated ingress "
                  f"{self.ingress} (ifindex={self.ingress_ifindex})")

        if self.enable_redirect:
            self._attach_pass_stubs()
        return self

    def _attach_pass_stubs(self):
        """XDP_PASS on every egress peer, so bpf_redirect into it can work."""
        try:
            from bcc import BPF
        except Exception as e:
            raise FabricError(
                f"BCC unavailable ({e}); it is needed to attach the XDP_PASS "
                f"stub that makes redirect into a veth work. Build the fabric "
                f"with enable_redirect=False to skip it -- but then any "
                f"bpf_redirect will silently lose the packet.")
        self._bpf = BPF(text=_PASS_SRC)
        fn = self._bpf.load_func("xdp_pass_stub", BPF.XDP)
        for port in range(self.n_ports):
            peer = self.peer_of[port]
            try:
                self._bpf.attach_xdp(peer, fn, flags=4)
                self.pass_attached.append(port)
            except Exception as e:
                if self.verbose:
                    print(f"[fabric] WARNING: XDP_PASS stub failed on {peer} "
                          f"({e}); redirect to port {port} will be lost")
        if self.verbose:
            print(f"[fabric] XDP_PASS stub on {len(self.pass_attached)} peer(s)"
                  f" -- enables bpf_redirect into veth")

    def destroy(self):
        for s in self._socks.values():
            try:
                s.close()
            except Exception:
                pass
        self._socks.clear()
        if self._bpf is not None:
            for port in self.pass_attached:
                try:
                    self._bpf.remove_xdp(self.peer_of[port], flags=4)
                except Exception:
                    pass
            self._bpf = None
        if self._built:
            cleanup(self.prefix, verbose=self.verbose)
            self._built = False

    def __enter__(self):
        return self.build()

    def __exit__(self, *exc):
        self.destroy()
        return False

    def _sock(self, iface, rx=True):
        import socket as _socket
        key = (iface, rx)
        if key not in self._socks:
            s = _socket.socket(_socket.AF_PACKET, _socket.SOCK_RAW,
                               _socket.htons(ETH_P_ALL))
            s.bind((iface, 0))
            s.setblocking(False)
            self._socks[key] = s
        return self._socks[key]

    def open_captures(self, ports=None):
        """Start listening on the given ports' peers before sending."""
        ports = range(self.n_ports) if ports is None else ports
        for p in ports:
            s = self._sock(self.peer_of[p])
            try:
                while True:
                    s.recv(65535)
            except BlockingIOError:
                pass
            except OSError:
                pass
        return self

    def send(self, frame: bytes, port: int = None):
        """Inject `frame` so it arrives on the ingress interface."""
        iface = self.ingress_peer if port is None else self.peer_of[port]
        self._sock(iface).send(frame)

    def capture(self, timeout: float = 0.5, ports=None, match=None):
        """Read one frame from whichever peer produces one first."""
        import select
        ports = list(range(self.n_ports)) if ports is None else list(ports)
        watch = {}
        for p in ports:
            watch[self._sock(self.peer_of[p]).fileno()] = p

        deadline = time.time() + timeout
        while time.time() < deadline:
            r, _, _ = select.select(list(watch), [], [],
                                    max(0.0, deadline - time.time()))
            if not r:
                break
            for fd in r:
                port = watch[fd]
                try:
                    data = self._sock(self.peer_of[port]).recv(65535)
                except BlockingIOError:
                    continue
                except OSError:
                    continue
                if match is not None and not match(data):
                    continue
                return port, data
        return None, None

    def send_and_capture(self, frame: bytes, timeout: float = 0.5, match=None):
        """Inject, then report which port the packet left by (None = dropped)."""
        self.open_captures()
        self.send(frame)
        return self.capture(timeout=timeout, match=match)


def main():
    p = argparse.ArgumentParser(
        description=__doc__.split("Usage")[0].strip(),
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--cleanup", action="store_true",
                   help="remove every link with the prefix and exit "
                        "(for state left by a killed run)")
    p.add_argument("--prefix", default=DEFAULT_PREFIX,
                   help=f"interface name prefix (default {DEFAULT_PREFIX})")
    p.add_argument("--n-ports", type=int, default=5,
                   help="how many veth pairs to build (default 5)")
    p.add_argument("--hold", action="store_true",
                   help="build the fabric and stay up until Ctrl-C, so another "
                        "process can deploy a pipeline onto it")
    a = p.parse_args()

    if a.cleanup:
        if not _have_root():
            sys.exit("--cleanup needs root")
        cleanup(a.prefix)
        return 0

    try:
        with NetnsFabric(n_ports=a.n_ports, prefix=a.prefix) as fab:
            print(f"[fabric] ingress    : {fab.ingress} "
                  f"(ifindex {fab.ingress_ifindex}), peer {fab.ingress_peer}")
            print(f"[fabric] ports      : {fab.port_to_iface}")
            print(f"[fabric] peers      : {fab.peer_of}")
            print(f"[fabric] ifindexes  : {fab.ifindex_of}")
            print(f"[fabric] redirect-ready ports: {fab.pass_attached}")
            print()
            print("Deploy a pipeline onto it with:")
            print(f"  sudo IPA_XDP_MODE=native "
                  f"IPA_IFACE_PATTERN='{a.prefix}{{i}}' \\")
            print(f"    python3 ipa/execute_pipeline.py --method template "
                  f"--iface {fab.ingress}")
            if a.hold:
                print("\n[fabric] holding. Ctrl-C to tear down.")
                while True:
                    time.sleep(3600)
    except FabricError as e:
        sys.exit(f"[fabric] {e}")
    except KeyboardInterrupt:
        print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
