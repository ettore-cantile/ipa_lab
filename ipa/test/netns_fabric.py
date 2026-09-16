#!/usr/bin/env python3
"""
netns_fabric.py -- a real kernel datapath to test against, built from veth.

Why this exists
---------------
Every performance and correctness number in this repository comes from
BPF_PROG_TEST_RUN. That syscall runs the program with a buffer and hands back
the return code: no interface, no driver, no redirect. It can prove that three
pipelines compute the same class. It cannot prove that a packet ever LEAVES,
let alone that it leaves on the port the model chose.

This module builds the missing half on a plain Linux box:

    ipa0  <--veth-->  ipa0p        port 0, the ingress (XDP attaches here)
    ipa1  <--veth-->  ipa1p        port 1
    ...                            one pair per logical port

Inject a frame on ipa0p, and it arrives at ipa0 as ingress traffic. The XDP
program runs for real, in native mode, and bpf_redirect() moves the frame to
ipaK, which delivers it out ipaKp -- where a raw socket is waiting. What comes
back is the answer to the question TEST_RUN cannot ask: did the packet come out
of the right port?

This is not an emulator. It is the same kernel code path a physical NIC takes,
minus the driver and the DMA. `veth` supports native XDP, so the attach mode is
the deployment mode, not a stand-in for it.

The veth redirect constraint
----------------------------
Redirecting INTO a veth goes through veth_xdp_xmit(), and the kernel only
allocates the XDP receive queues that path needs when the RECEIVING side has an
XDP program attached. So every egress peer gets a trivial XDP_PASS program --
not to do anything, but to make ndo_xdp_xmit available. Without it the redirect
silently fails and every packet is lost with no error, which looks exactly like
a model that decided to drop everything. `pass_attached` records which peers
got one.

Usage
-----
    from netns_fabric import NetnsFabric

    with NetnsFabric(n_ports=5) as fab:
        cfg = NodeConfig.resolve(sem.logical_ports,
                                 port_to_iface=fab.port_to_iface)
        ...  deploy a pipeline on fab.ingress ...
        port = fab.send_and_capture(frame)      # which port did it leave by?

Everything is named with the prefix and removed on exit, including after an
exception. Stale state from a killed run:

    sudo python3 ipa/test/netns_fabric.py --cleanup

Needs Linux + root.
"""
import argparse
import os
import subprocess
import sys
import time

DEFAULT_PREFIX = "ipa"
ETH_P_ALL = 0x0003

# The frame a port is expected to carry when nothing else is specified: an
# ARP-shaped broadcast is ignored by the stack on the peer side, so a capture
# there sees the pipeline's output and not the kernel's own chatter.
DEFAULT_ETHERTYPE = 0x88B5      # IEEE 802 local experimental Ethertype 1


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
    """Remove every link left behind by a fabric with this prefix.

    Deleting one end of a veth pair removes both, so peers that vanish
    mid-loop are expected, not an error.
    """
    removed = []
    for name in existing_links(prefix):
        if _run(["ip", "link", "del", name], check=False).returncode == 0:
            removed.append(name)
    if verbose:
        print(f"[fabric] cleanup: removed {len(removed)} link(s)"
              + (f": {', '.join(removed)}" if removed else ""))
    return removed


# --------------------------------------------------------------------------
# The XDP_PASS program that makes veth's ndo_xdp_xmit available on the peers.
# Kept as source rather than a checked-in .o so this module needs nothing
# prebuilt; BCC is already a dependency of every kernel test here.
# --------------------------------------------------------------------------
_PASS_SRC = """
int xdp_pass_stub(struct xdp_md *ctx) {
    return XDP_PASS;
}
"""


class NetnsFabric:
    """`n_ports` veth pairs, one per logical port, with XDP-capable peers.

    Attributes after __enter__:
      port_to_iface   {logical_port: iface}    -> NodeConfig.resolve(...)
      peer_of         {logical_port: iface}    the far side of each pair
      ingress         the interface a pipeline attaches XDP to (port 0)
      ifindex_of      {logical_port: ifindex}
      pass_attached   ports whose peer carries the XDP_PASS stub
    """

    def __init__(self, n_ports: int = 5, prefix: str = DEFAULT_PREFIX,
                 ingress_port: int = 0, enable_redirect: bool = True,
                 verbose: bool = True):
        if n_ports < 1:
            raise ValueError("n_ports must be >= 1")
        if not 0 <= ingress_port < n_ports:
            raise ValueError(f"ingress_port {ingress_port} outside [0, {n_ports})")
        self.n_ports = n_ports
        self.prefix = prefix
        self.ingress_port = ingress_port
        self.enable_redirect = enable_redirect
        self.verbose = verbose

        self.port_to_iface = {}
        self.peer_of = {}
        self.ifindex_of = {}
        self.pass_attached = []
        self._bpf = None
        self._socks = {}
        self._built = False

    # -- names -------------------------------------------------------------
    def _name(self, port):
        return f"{self.prefix}{port}"

    def _peer(self, port):
        return f"{self.prefix}{port}p"

    @property
    def ingress(self):
        return self.port_to_iface[self.ingress_port]

    # -- lifecycle ---------------------------------------------------------
    def build(self):
        if sys.platform != "linux":
            raise FabricError(f"needs Linux, not {sys.platform}")
        if not _have_root():
            raise FabricError("needs root (veth creation and XDP attach)")
        if _run(["ip", "-V"], check=False).returncode != 0:
            raise FabricError("`ip` not available (install iproute2)")

        # A previous run killed before its cleanup would leave links with these
        # exact names, and `ip link add` would fail on the first one.
        stale = existing_links(self.prefix)
        if stale:
            if self.verbose:
                print(f"[fabric] removing {len(stale)} stale link(s) from an "
                      f"earlier run")
            cleanup(self.prefix, verbose=False)

        import socket as _socket
        for port in range(self.n_ports):
            a, b = self._name(port), self._peer(port)
            _run(["ip", "link", "add", a, "type", "veth", "peer", "name", b])
            # No IPv6 on a fabric interface: the kernel would send MLD and
            # router solicitations on every fresh veth, and that traffic lands
            # in the same captures the test reads its answer from.
            for end in (a, b):
                _run(["sysctl", "-qw",
                      f"net.ipv6.conf.{end}.disable_ipv6=1"], check=False)
            _run(["ip", "link", "set", a, "up"])
            _run(["ip", "link", "set", b, "up"])
            self.port_to_iface[port] = a
            self.peer_of[port] = b
            self.ifindex_of[port] = _socket.if_nametoindex(a)

        self._built = True
        if self.verbose:
            print(f"[fabric] {self.n_ports} veth pair(s), ingress={self.ingress}"
                  f" (ifindex={self.ifindex_of[self.ingress_port]})")

        if self.enable_redirect:
            self._attach_pass_stubs()
        return self

    def _attach_pass_stubs(self):
        """XDP_PASS on every egress peer, so bpf_redirect into it can work.

        Not decoration: without an XDP program on the receiving side, veth does
        not allocate the queues ndo_xdp_xmit needs, the redirect fails, and the
        packet disappears with no error anywhere.
        """
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
                self._bpf.attach_xdp(peer, fn, flags=4)      # DRV_MODE
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

    # -- traffic -----------------------------------------------------------
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
        """Start listening on the given ports' peers before sending.

        A socket opened after the frame is sent has already missed it, so this
        is separate from capture(): open, then send, then read.
        """
        ports = range(self.n_ports) if ports is None else ports
        for p in ports:
            s = self._sock(self.peer_of[p])
            try:                            # drain anything already queued
                while True:
                    s.recv(65535)
            except BlockingIOError:
                pass
            except OSError:
                pass
        return self

    def send(self, frame: bytes, port: int = None):
        """Inject `frame` on a port's PEER, so it arrives as ingress traffic."""
        port = self.ingress_port if port is None else port
        s = self._sock(self.peer_of[port])
        s.send(frame)

    def capture(self, timeout: float = 0.5, ports=None, match=None):
        """Read one frame from whichever peer produces one first.

        `match` is a predicate on the raw bytes. Frames it rejects are skipped
        and the wait continues, which matters because a freshly created veth
        carries the kernel's own traffic -- IPv6 MLD and router solicitations,
        dst_mac 33:33:... -- and the first frame to arrive is not necessarily
        the one that was injected. Without a filter that noise is reported as
        the pipeline's answer.

        Returns (port, frame), or (None, None) if nothing matching arrived
        before the timeout -- which is what a DROP looks like from out here,
        and is a result, not an error.
        """
        import select
        ports = list(range(self.n_ports)) if ports is None else list(ports)
        watch = {}
        for p in ports:
            if p == self.ingress_port:
                continue            # the frame we injected is not a result
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
                    continue            # kernel chatter, keep waiting
                return port, data
        return None, None

    def send_and_capture(self, frame: bytes, timeout: float = 0.5, match=None):
        """Inject, then report which port the packet left by (None = dropped)."""
        self.open_captures()
        self.send(frame)
        return self.capture(timeout=timeout, match=match)


def build_probe_frame(payload: bytes = b"", ethertype: int = DEFAULT_ETHERTYPE,
                      dst=b"\xff\xff\xff\xff\xff\xff",
                      src=b"\x02\x00\x00\x00\x00\x99") -> bytes:
    """A minimal L2 frame, padded to the 60-byte Ethernet minimum."""
    f = dst + src + ethertype.to_bytes(2, "big") + payload
    return f + b"\x00" * max(0, 60 - len(f))


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
