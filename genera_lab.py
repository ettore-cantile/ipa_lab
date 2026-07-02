import xml.etree.ElementTree as ET

# Parse the XML file
tree = ET.parse('germany50.xml')
root = tree.getroot()
ns = {'snd': 'http://sndlib.zib.de/network'}

nodes = [n.get('id').lower() for n in root.findall('.//snd:node', ns)]
links = []

for link in root.findall('.//snd:link', ns):
    src = link.find('snd:source', ns).text.lower()
    tgt = link.find('snd:target', ns).text.lower()
    links.append((src, tgt))

ifaces = {node: 0 for node in nodes}

lab_conf = ""
# Apply our custom Docker image containing both FRR and eBPF
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
] for node in nodes}

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

    ifaces[src] += 1
    ifaces[tgt] += 1
    subnet_counter += 1

# Restart FRR after IPs are assigned
for node in nodes:
    startup_files[node].append("service frr restart")

# Save lab.conf
with open("lab.conf", "w") as f:
    f.write(lab_conf)

# Save the individual .startup files
for node, cmds in startup_files.items():
    with open(f"{node}.startup", "w") as f:
        f.write("# Startup configuration generated automatically\n")
        f.write("\n".join(cmds) + "\n")

print("Generation complete! Nodes will boot immediately with eBPF and debugfs enabled.")