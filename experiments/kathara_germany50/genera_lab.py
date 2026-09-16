"""genera_lab.py -- emit the Kathara lab (lab.conf + one <node>.startup per
node) from the SNDlib Germany50 topology.

Run it from anywhere:  python3 genera_lab.py [--xml PATH] [--out DIR]
Then:                  python3 make_lab.py      (populates <out>/shared)
                       cd <out> && kathara lstart

This script and everything beside it are the EXPERIMENT. The engine lives in
<repo>/ipa/ and imports nothing from here; make_lab.py copies the core into the
lab's shared/ mount, so the dependency only ever points experiment -> core.

It rewrites lab.conf and every <node>.startup in the output directory, so it
is guarded behind __main__ and an explicit CLI: importing this module used to
execute the whole generation as a side effect, and the hardcoded relative
'germany50.xml' meant it only worked when the cwd happened to be the repo root.

TOPOLOGY SCOPE -- why the two end hosts are generated here.

The trained checkpoint expects n_interfaces=6 and n_nodes=52
(N_IN = 6 + 6 + 1 + 52 = 65, n_out = 6 + 1 = 7). Those numbers come from the
topology the model was trained on, which importSNDLib.load_sndlib_topology()
builds as the 50 SNDlib backbone routers PLUS two end hosts:

    load_sndlib_topology('germany50.xml',
                         attach_h_src_to='Karlsruhe',
                         attach_h_dst_to='Flensburg')
    -> 52 nodes, max degree 6

Karlsruhe has degree 5 in bare Germany50; attaching h_src makes it the unique
degree-6 node, which is where n_interfaces=6 comes from, and 50 + 2 = 52 is
where n_nodes=52 comes from.

This generator used to emit only the 50 routers. The lab therefore had 50 nodes
and max degree 5, which made the model's 6/52 look like padding invented for no
reason -- a contradiction between the model and the environment that does not
actually exist. Generating the two hosts removes it: the emulated lab now has
exactly the shape the checkpoint was trained for.

The hosts are end hosts, not routers: they run no FRR/OSPF, just an address on
their access link and a default route through the router they attach to.
"""
import argparse
import os
import xml.etree.ElementTree as ET

NS = {'snd': 'http://sndlib.zib.de/network'}

# Where the two end hosts attach. Must match the attach_h_src_to /
# attach_h_dst_to used to build the training topology (see module docstring):
# change these and the model's n_interfaces/n_nodes stop describing the lab.
DEFAULT_HOSTS = {"h_src": "karlsruhe", "h_dst": "flensburg"}


def generate(xml_path: str, out_dir: str, hosts: dict = None) -> None:
    tree = ET.parse(xml_path)
    root = tree.getroot()

    hosts = DEFAULT_HOSTS if hosts is None else hosts

    routers = [n.get('id').lower() for n in root.findall('.//snd:node', NS)]
    links = []

    for link in root.findall('.//snd:link', NS):
        src = link.find('snd:source', NS).text.lower()
        tgt = link.find('snd:target', NS).text.lower()
        links.append((src, tgt))

    for host, attach in hosts.items():
        if attach not in routers:
            raise ValueError(
                f"host {host!r} attaches to {attach!r}, which is not a node of "
                f"{os.path.basename(xml_path)}. Known nodes: {sorted(routers)}")

    # Access links go LAST, after all backbone links. That keeps every backbone
    # /30 and every router's eth0..ethN assignment byte-identical to a run
    # without hosts -- only the attachment routers gain one extra interface.
    host_names = list(hosts)
    links += [(host, hosts[host]) for host in host_names]

    nodes = routers + host_names
    ifaces = {node: 0 for node in nodes}

    lab_conf = ""
    # Apply our custom Docker image containing both FRR and eBPF. The hosts use
    # the same image: they need python3 and the /shared mount to run
    # send_ipa.py / recv_ipa.py, they just never start the routing daemons.
    for node in nodes:
        lab_conf += f"{node}[image]=\"kathara/frr_ebpf\"\n"


    # Prepare basic startup commands (Removed apt-get for instant boot)
    startup_files = {node: [
        "bash /shared/fix_bpf.sh", # <-- Added startup script to fix BCC at boot
        "sysctl -w net.ipv4.ip_forward=1",
        "sysctl -w net.ipv6.conf.all.disable_ipv6=1",
        "mount -t debugfs debugfs /sys/kernel/debug", # <-- Added debugfs mount
    
        # Wake up the routing daemons
        "sed -i 's/zebra=no/zebra=yes/g' /etc/frr/daemons",
        "sed -i 's/ospfd=no/ospfd=yes/g' /etc/frr/daemons",
    
        # Write OSPF base configuration
        "cat << 'EOF' > /etc/frr/frr.conf",
        "frr defaults traditional",
        "router ospf",
        " network 10.0.0.0/8 area 0",
        "EOF",
        "chown frr:frr /etc/frr/frr.conf"
    ] for node in routers}

    # End hosts: same base setup, but no routing daemon and no ip_forward --
    # they originate and terminate traffic, they do not forward it.
    for host in host_names:
        startup_files[host] = [
            "bash /shared/fix_bpf.sh",
            "sysctl -w net.ipv6.conf.all.disable_ipv6=1",
            "mount -t debugfs debugfs /sys/kernel/debug",
        ]

    # Configure loopback interfaces
    loopbacks = {}
    for idx, node in enumerate(nodes):
        lo_ip = f"10.255.255.{idx+1}"
        loopbacks[node] = lo_ip
        startup_files[node].append(f"ip addr add {lo_ip}/32 dev lo")
        startup_files[node].append("ip link set lo up")

    # Populate the /etc/hosts file
    for node in nodes:
        for n, ip in loopbacks.items():
            startup_files[node].append(f"echo '{ip} {n}' >> /etc/hosts")

    subnet_counter = 0
    host_gw = {}   # host -> IP of its attachment router on the access link

    # Create collision domains and configure IPv4 addresses
    for src, tgt in links:
        cd_name = f"l{subnet_counter+1}"
        lab_conf += f"{src}[{ifaces[src]}]=\"{cd_name}\"\n"
        lab_conf += f"{tgt}[{ifaces[tgt]}]=\"{cd_name}\"\n"

        third_octet = subnet_counter // 64
        fourth_octet = (subnet_counter % 64) * 4
    
        ip_src = f"10.0.{third_octet}.{fourth_octet + 1}/30"
        ip_tgt = f"10.0.{third_octet}.{fourth_octet + 2}/30"

        startup_files[src].append(f"ip addr add {ip_src} dev eth{ifaces[src]}")
        startup_files[src].append(f"ip link set eth{ifaces[src]} up")
    
        startup_files[tgt].append(f"ip addr add {ip_tgt} dev eth{ifaces[tgt]}")
        startup_files[tgt].append(f"ip link set eth{ifaces[tgt]} up")

        if src in host_names:
            host_gw[src] = f"10.0.{third_octet}.{fourth_octet + 2}"

        ifaces[src] += 1
        ifaces[tgt] += 1
        subnet_counter += 1

    # Restart FRR after IPs are assigned (routers only -- the hosts run none)
    for node in routers:
        startup_files[node].append("service frr restart")

    # Hosts reach the rest of the network through their attachment router: the
    # access link is a /30 whose .1 is the host and .2 the router (the host is
    # listed first in the link tuple above, so it takes ip_src).
    for host in host_names:
        startup_files[host].append(f"ip route add default via {host_gw[host]}")

    # lab/ is generated output and is not tracked: it may not exist yet.
    os.makedirs(out_dir, exist_ok=True)

    # Save lab.conf
    with open(os.path.join(out_dir, "lab.conf"), "w") as f:
        f.write(lab_conf)

    # Save the individual .startup files
    for node, cmds in startup_files.items():
        with open(os.path.join(out_dir, f"{node}.startup"), "w") as f:
            f.write("# Startup configuration generated automatically\n")
            f.write("\n".join(cmds) + "\n")

    max_deg = max(ifaces.values())
    top = max(routers, key=lambda n: ifaces[n])
    print(f"Generation complete: {len(nodes)} nodes "
          f"({len(routers)} routers + {len(host_names)} hosts), "
          f"{len(links)} links -> {out_dir}")
    print("Nodes will boot immediately with eBPF and debugfs enabled.")
    print(f"Max node degree: {max_deg} ({top}, interfaces eth0..eth{max_deg - 1})")
    for host in host_names:
        print(f"  {host} -> {hosts[host]} (default via {host_gw[host]})")
    # The checkpoint's input width is derived from exactly these two numbers, so
    # say out loud whether the generated lab still matches it.
    print(f"Model compatibility: n_nodes={len(nodes)}, n_interfaces={max_deg} "
          f"-> N_IN = {max_deg} + {max_deg} + 1 + {len(nodes)} = "
          f"{max_deg + max_deg + 1 + len(nodes)}, n_out = {max_deg + 1}")


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    p = argparse.ArgumentParser(
        description="Generate the Kathara lab from an SNDlib topology XML")
    p.add_argument("--xml", default=os.path.join(here, "germany50.xml"),
                   help="SNDlib topology XML (default: germany50.xml next to this script)")
    p.add_argument("--out", default=os.path.join(here, "lab"),
                   help="directory to write lab.conf and <node>.startup into "
                        "(default: ./lab next to this script). That directory is "
                        "the Kathara lab root; run make_lab.py afterwards to "
                        "populate its shared/ mount from the core.")
    p.add_argument("--host", action="append", metavar="NAME=ROUTER", default=None,
                   help="end host to attach, e.g. --host h_src=karlsruhe. Repeatable. "
                        f"Default: {', '.join(f'{h}={r}' for h, r in DEFAULT_HOSTS.items())} "
                        "(the attachment points the model was trained on).")
    p.add_argument("--no-hosts", action="store_true",
                   help="generate the bare 50-router backbone with no end hosts. "
                        "The result does NOT match the checked-in checkpoint "
                        "(50 nodes / max degree 5 instead of 52 / 6).")
    args = p.parse_args()

    if args.no_hosts:
        hosts = {}
    elif args.host:
        hosts = {}
        for spec in args.host:
            if "=" not in spec:
                p.error(f"--host expects NAME=ROUTER, got {spec!r}")
            name, router = spec.split("=", 1)
            hosts[name.strip().lower()] = router.strip().lower()
    else:
        hosts = None   # generate() falls back to DEFAULT_HOSTS

    generate(args.xml, args.out, hosts=hosts)


if __name__ == "__main__":
    main()
