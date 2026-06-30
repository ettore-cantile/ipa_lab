import networkx as nx
import matplotlib.pyplot as plt
from lxml import etree

def load_sndlib_topology(xml_file, attach_h_src_to=None, attach_h_dst_to=None, output_xml_file=None, directed=False):
    ns = {"snd": "http://sndlib.zib.de/network"}
    tree = etree.parse(xml_file)
    root = tree.getroot()

    # Estrai nodi originali
    node_elems = root.xpath("//snd:node", namespaces=ns)
    node_names = [n.get("id") for n in node_elems]

    # Aggiungi nodi h_src e h_dst se richiesto
    new_nodes = []
    if attach_h_src_to is not None:
        new_nodes.append("h_src")
    if attach_h_dst_to is not None:
        new_nodes.append("h_dst")

    # Estendi la mappatura nome → indice numerico
    all_names = sorted(node_names + new_nodes)
    name_to_idx = {name: idx for idx, name in enumerate(all_names)}

    G = nx.DiGraph() if directed else nx.Graph()
    for name, idx in name_to_idx.items():
        G.add_node(idx)

    # Aggiungi archi esistenti
    for link in root.xpath("//snd:link", namespaces=ns):
        src = link.find("snd:source", namespaces=ns).text
        tgt = link.find("snd:target", namespaces=ns).text
        G.add_edge(name_to_idx[src], name_to_idx[tgt])

    # Modifica XML se richiesto
    if attach_h_src_to:
        _add_node_and_link_to_xml(root, "h_src", attach_h_src_to, ns)
        G.add_edge(name_to_idx["h_src"], name_to_idx[attach_h_src_to])
        G.add_edge(name_to_idx[attach_h_src_to], name_to_idx["h_src"])
    if attach_h_dst_to:
        _add_node_and_link_to_xml(root, "h_dst", attach_h_dst_to, ns)
        G.add_edge(name_to_idx["h_dst"], name_to_idx[attach_h_dst_to])
        G.add_edge(name_to_idx[attach_h_dst_to], name_to_idx["h_dst"])

    if output_xml_file:
        tree.write(output_xml_file, pretty_print=True, xml_declaration=True, encoding="UTF-8")
        print(f"📄 File XML modificato salvato in: {output_xml_file}")

    # Statistiche
    num_nodes = G.number_of_nodes()
    max_degree = max(dict(G.degree()).values())
    print(f"✅ Topologia importata: {num_nodes} nodi, grado massimo = {max_degree}")

    return G, name_to_idx, num_nodes, max_degree

def _add_node_and_link_to_xml(root, new_node_id, attach_to_id, ns):
    # Crea nuovo nodo
    new_node_elem = etree.Element(f"{{{ns['snd']}}}node", id=new_node_id)
    root.find(".//snd:nodes", namespaces=ns).append(new_node_elem)

    # Crea nuovo link andata
    link1 = etree.Element(f"{{{ns['snd']}}}link", id=f"{new_node_id}-{attach_to_id}")
    etree.SubElement(link1, f"{{{ns['snd']}}}source").text = new_node_id
    etree.SubElement(link1, f"{{{ns['snd']}}}target").text = attach_to_id
    root.find(".//snd:links", namespaces=ns).append(link1)

    # Crea nuovo link ritorno
    link2 = etree.Element(f"{{{ns['snd']}}}link", id=f"{attach_to_id}-{new_node_id}")
    etree.SubElement(link2, f"{{{ns['snd']}}}source").text = attach_to_id
    etree.SubElement(link2, f"{{{ns['snd']}}}target").text = new_node_id
    root.find(".//snd:links", namespaces=ns).append(link2)

def plot_topology(G, title="Topologia NetworkX"):
    plt.figure(figsize=(8, 6))
    pos = nx.spring_layout(G, seed=42)
    nx.draw(G, pos, with_labels=True, node_size=300, font_size=8)
    plt.title(title)
    plt.show()
