"""
node_config.py -- L3: the node's own view. Logical port -> ifindex, MAC, state.

Three things were conflated before this file existed:

    model output class  ==  logical port  ==  kernel ifindex

None of those equalities holds. `install_mac_per_class` keyed mac_table by
CLASS and assumed class k lived on `eth{k}`; the Pipeline 1 codegen assumed
kernel ifindexes ran 2..7; P2/P3 used the raw ifindex clamped into the one-hot
range. On a real Kathara node the ifindexes are 201/209/217..., so all three
assumptions were wrong in different ways.

Here the chain is explicit and each arrow is a separate lookup:

    class ──(model: class_semantics)──> logical_port
    logical_port ──(node: this file)──> ifindex, src_mac, dst_mac
    ifindex ──(datapath)──────────────> bpf_redirect

The model states which logical port it wants. The node states which interface
realises that port. Neither guesses the other's half.
"""

import json
import os
import socket
from dataclasses import dataclass, field
from typing import Dict, List, Optional


DEFAULT_TOPOLOGY_PATH = "/etc/ipa/topology.json"


class NodeConfigError(ValueError):
    """Raised when the node cannot realise what the model asks for."""


@dataclass
class PortBinding:
    """One logical port, as realised on this node."""
    logical_port: int
    iface: str
    ifindex: Optional[int] = None
    src_mac: Optional[List[int]] = None
    dst_mac: Optional[List[int]] = None
    present: bool = False
    carrier: bool = False

    def describe(self) -> str:
        if not self.present:
            return f"port {self.logical_port} -> {self.iface} (ABSENT on this node)"
        state = "up" if self.carrier else "down"
        return (f"port {self.logical_port} -> {self.iface} "
                f"(ifindex={self.ifindex}, link {state})")


def port_map_from_env():
    """Logical port -> interface name, taken from the environment.

    Two knobs, explicit first:

      IPA_PORT_MAP="0=ipav0,1=ipav1,4=enp0s3"   exact, per port
      IPA_IFACE_PATTERN="ipav{i}"               a naming convention

    Returns (port_to_iface_or_None, pattern). The default pattern stays
    "eth{i}", which is a convention of one lab and not a property of the
    datapath: a node whose interfaces are named anything else had no way to
    say so, and every FORWARD class came out unforwardable with five "no such
    interface" notes and no hint of what to set.
    """
    raw = os.environ.get("IPA_PORT_MAP", "").strip()
    pattern = os.environ.get("IPA_IFACE_PATTERN", "eth{i}")
    if not raw:
        return None, pattern
    mapping = {}
    for item in raw.split(","):
        item = item.strip()
        if not item:
            continue
        if "=" not in item:
            raise NodeConfigError(
                f"IPA_PORT_MAP: expected comma-separated PORT=IFACE pairs "
                f"(e.g. '0=ipav0,1=ipav1'), got {item!r}")
        port, iface = item.split("=", 1)
        try:
            mapping[int(port.strip())] = iface.strip()
        except ValueError:
            raise NodeConfigError(
                f"IPA_PORT_MAP: {port.strip()!r} is not a logical port number")
    return mapping, pattern


@dataclass
class NodeConfig:
    """Resolved per-node state: which logical ports this node can actually use.

    `port_to_iface` is the node's mapping. It defaults to the `eth{port}`
    convention, which is what this lab uses -- but it is a DEFAULT of the node
    configuration, not an assumption baked into the datapath, and any node can
    override it.
    """

    hostname: str
    node_index: Optional[int] = None          # index in the topology's node one-hot
    port_to_iface: Dict[int, str] = field(default_factory=dict)
    bindings: Dict[int, PortBinding] = field(default_factory=dict)

    # -- construction ------------------------------------------------------
    @staticmethod
    def resolve(logical_ports: List[int],
                port_to_iface: Optional[Dict[int, str]] = None,
                hostname: Optional[str] = None,
                node_index: Optional[int] = None,
                iface_pattern: str = "eth{i}") -> "NodeConfig":
        """Resolve every logical port the model may select against this node.

        `logical_ports` comes from the MODEL (ClassSemantics.logical_ports), so
        only the ports the model can actually ask for are resolved -- a node
        does not need to provide interfaces for ports no class selects.
        """
        host = hostname or socket.gethostname()
        if port_to_iface:
            p2i = dict(port_to_iface)
        else:
            env_map, env_pattern = port_map_from_env()
            # An explicit argument beats the environment; the environment beats
            # the built-in convention. iface_pattern is only overridden when the
            # caller left it at the default, so an explicit argument still wins.
            if iface_pattern == "eth{i}":
                iface_pattern = env_pattern
            p2i = {p: iface_pattern.format(i=p) for p in logical_ports}
            if env_map:
                p2i.update({p: n for p, n in env_map.items() if p in logical_ports})
        cfg = NodeConfig(hostname=host, node_index=node_index, port_to_iface=p2i)
        for p in sorted(logical_ports):
            name = p2i.get(p)
            if name is None:
                raise NodeConfigError(
                    f"{host}: the model selects logical port {p} but the node "
                    f"configuration has no interface for it. Add the mapping "
                    f"(IPA_PORT_MAP='{p}=<iface>', or IPA_IFACE_PATTERN) or "
                    f"use a model that does not select that port.")
            cfg.bindings[p] = _bind(p, name)
        return cfg

    # -- queries -----------------------------------------------------------
    def ifindex_of(self, logical_port: int) -> Optional[int]:
        b = self.bindings.get(logical_port)
        return b.ifindex if b and b.present else None

    @property
    def usable_ports(self) -> List[int]:
        return sorted(p for p, b in self.bindings.items() if b.present)

    @property
    def absent_ports(self) -> List[int]:
        return sorted(p for p, b in self.bindings.items() if not b.present)

    def ifindex_table(self) -> Dict[int, int]:
        """kernel ifindex -> logical port, the direction the datapath needs to
        turn ctx->ingress_ifindex into a one-hot column."""
        return {b.ifindex: p for p, b in self.bindings.items()
                if b.present and b.ifindex is not None}

    # -- validation --------------------------------------------------------
    def validate(self, logical_ports: List[int], strict: bool = False) -> List[str]:
        """Check this node can realise the model's ports.

        Returns the list of problems. With strict=True a missing port is a
        hard failure instead: preferable before a measurement run, where a
        silently unforwardable class would corrupt the result. In normal
        operation an absent port is expected -- a node of below-maximum degree
        genuinely has no interface for some of the model's ports -- and the
        datapath must treat that class as unforwardable rather than redirect
        somewhere arbitrary.
        """
        problems = []
        for p in logical_ports:
            b = self.bindings.get(p)
            if b is None:
                problems.append(f"logical port {p} not resolved at all")
            elif not b.present:
                problems.append(f"logical port {p} -> {b.iface}: no such interface")
            elif b.ifindex is None:
                problems.append(f"logical port {p} -> {b.iface}: no ifindex")
        if strict and problems:
            raise NodeConfigError(
                f"{self.hostname}: cannot realise the model's logical ports:\n  "
                + "\n  ".join(problems))
        return problems

    def summary(self) -> str:
        lines = [f"  node {self.hostname}"
                 + (f" (node_index={self.node_index})" if self.node_index is not None else "")]
        for p in sorted(self.bindings):
            lines.append(f"    {self.bindings[p].describe()}")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
def _bind(port: int, iface: str) -> PortBinding:
    b = PortBinding(logical_port=port, iface=iface)
    b.present = os.path.isdir(f"/sys/class/net/{iface}")
    if not b.present:
        return b
    try:
        b.ifindex = socket.if_nametoindex(iface)
    except OSError:
        b.present = False
        return b
    try:
        with open(f"/sys/class/net/{iface}/address") as f:
            b.src_mac = [int(x, 16) for x in f.read().strip().split(":")]
    except OSError:
        b.src_mac = None
    b.dst_mac = _neighbor_mac(iface)
    b.carrier = _carrier(iface)
    return b


def _carrier(iface: str) -> bool:
    for fn, want in (("carrier", "1"), ("operstate", "up")):
        try:
            with open(f"/sys/class/net/{iface}/{fn}") as f:
                return f.read().strip() == want
        except OSError:
            continue
    return False


def _neighbor_mac(iface: str) -> Optional[List[int]]:
    """Next-hop MAC from the kernel's ARP table; None if not resolved yet."""
    try:
        with open("/proc/net/arp") as f:
            rows = f.readlines()[1:]
    except OSError:
        return None
    for line in rows:
        c = line.split()
        if len(c) < 6 or c[5] != iface:
            continue
        if c[3] in ("00:00:00:00:00:00", "<incomplete>"):
            continue
        return [int(x, 16) for x in c[3].split(":")]
    return None


# ---------------------------------------------------------------------------
def load_topology(path: str = DEFAULT_TOPOLOGY_PATH) -> dict:
    """Per-deployment topology. Describes nodes, interfaces and node indices.

    It deliberately says NOTHING about which class is DROP: class semantics
    belong to the model (class_semantics.py), and a topology that could
    override them would let the same model mean different things on different
    networks.
    """
    if not os.path.exists(path):
        return {}
    with open(path) as f:
        topo = json.load(f)
    for forbidden in ("drop_class", "class_semantics", "n_out"):
        if forbidden in topo:
            raise NodeConfigError(
                f"{path} contains {forbidden!r}. Class semantics are a property "
                f"of the MODEL, not of the topology -- declare it in the model "
                f"descriptor instead.")
    return topo


def node_index_of(hostname: str, topology: dict) -> Optional[int]:
    """This node's index in the topology's node one-hot.

    Must come from the topology, because the index has to match the ordering
    the model was trained on. The datapath currently derives the node one-hot
    from ipa->model_id instead, which is a separate known defect -- this
    function is what a fix for it would consume.
    """
    idx = topology.get("node_index")
    if not idx:
        return None
    return idx.get(hostname)
