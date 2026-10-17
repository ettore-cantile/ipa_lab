"""node_config.py -- the node's view: logical port -> ifindex, MAC, state.

class --(model)--> logical port --(node)--> ifindex, MACs --(datapath)--> redirect
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
    """Logical port -> interface name, taken from the environment."""
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
    """Resolved per-node state."""

    hostname: str
    node_index: Optional[int] = None
    port_to_iface: Dict[int, str] = field(default_factory=dict)
    bindings: Dict[int, PortBinding] = field(default_factory=dict)

    @staticmethod
    def resolve(logical_ports: List[int],
                port_to_iface: Optional[Dict[int, str]] = None,
                hostname: Optional[str] = None,
                node_index: Optional[int] = None,
                iface_pattern: str = "eth{i}") -> "NodeConfig":
        """Resolve every logical port the model may select against this node."""
        host = hostname or socket.gethostname()
        if port_to_iface:
            p2i = dict(port_to_iface)
        else:
            env_map, env_pattern = port_map_from_env()
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

    def ifindex_of(self, logical_port: int) -> Optional[int]:
        b = self.bindings.get(logical_port)
        return b.ifindex if b and b.present else None

    @property
    def usable_ports(self) -> List[int]:
        return sorted(p for p, b in self.bindings.items() if b.present)

    @property
    def absent_ports(self) -> List[int]:
        return sorted(p for p, b in self.bindings.items() if not b.present)


    def validate(self, logical_ports: List[int], strict: bool = False) -> List[str]:
        """Check this node can realise the model's ports."""
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
    """Next-hop MAC from the kernel's ARP table;"""
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


def load_topology(path: str = DEFAULT_TOPOLOGY_PATH) -> dict:
    """Per-deployment topology."""
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
    """This node's index in the topology's node one-hot."""
    idx = topology.get("node_index")
    if not idx:
        return None
    return idx.get(hostname)
