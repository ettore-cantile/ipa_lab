IPA Lab — Intelligent PAckets with eBPF
This repository contains the lab implementation of Intelligent PAckets (IPA) with an eBPF-accelerated data plane, developed on top of the Katharà network emulator. The goal is to embed compact machine learning models directly inside packet headers and execute per-hop inference to achieve adaptive, mission-driven forwarding decisions — without any control-plane signaling.

The work extends the original proof-of-concept by Polverini, Cianfrani, and Listanti (Sapienza University of Rome / University of Molise) with a kernel-space eBPF/XDP forwarding engine that performs MLP inference at line rate.

Background: Intelligent PAckets (IPA)
IPA is a packet-centric networking paradigm in which a lightweight ML model is serialized, quantized to 8-bit integers, and embedded directly in the packet header. At each hop, the receiving node:

Parses the IPA header and extracts the model weights.

Builds an input vector from local state: interface availability, ingress interface (one-hot), normalized TTL, and current node identifier (one-hot).

Runs inference to select the egress interface or issue a DROP action.

Forwards the packet without any interaction with a centralized controller.

This approach allows the network to react to changing conditions purely in the data plane. Different missions (e.g., failure recovery, deadline-constrained delivery, congestion management) can be associated with different models embedded in the packet header, enabling per-packet adaptive behavior without requiring operators to reconfigure forwarding rules or tunnels.

Topology: Germany50
The experimental setup uses the Germany50 topology from the SNDlib repository, a real-world backbone network with:

Property	Value
Nodes	50 (+ 2 virtual hosts)
Max node degree	6
Total nodes in emulation	52
Source host	h_src attached to Karlsruhe
Destination host	h_dst attached to Flensburg
Max simultaneous failures	10
The topology is imported from germany50.xml via importSNDLib.py, which also generates the Katharà-compatible germany_kathara.xml lab configuration. Each router runs the eBPF/XDP switch (switch_core.py) compiled against the topology's interface mapping.

Training Pipeline
Run the full pipeline from your local machine (requires Python 3.10+, PyTorch, pandas, networkx, scikit-learn):

bash
# Method 1 — standard float training (default)
python esegui_pipeline.py

# Method 2 — Quantization-Aware Training
python esegui_pipeline.py --method qat

# To regenerate the dataset from scratch, uncomment the generate_dataset()
# call in esegui_pipeline.py (~line 63) before running.
The pipeline produces:

frr_germany50_5_model_4x2.pt (Method 1) or frr_qat_model.pt (Method 2)

weights.json — int8 quantized weights ready for the eBPF switch

Console accuracy plots for train/validation loss and accuracy

Copy weights.json into the shared/ folder before starting the Katharà lab.

Quantization Methods
Three methods are being explored to minimize the accuracy loss introduced by int8 quantization, which is required to embed the model in the IPA packet header and to fit within the eBPF integer arithmetic constraints.

Method 1 — Post-Training Quantization (PTQ)
The model is trained in standard float32. After training, extract_weights.py applies:

text
w_int8 = clamp(round(w_float * 128), -128, 127)
This is the baseline approach. The main risk is weight overflow: float weights outside [-1, 1] get clamped and lose information. Weight decay (1e-4) and gradient clipping (max_norm=1.0) are used to keep weights small.

Method 2 — Quantization-Aware Training (QAT)
The model uses QATFastRerouteMLP, which applies fake-quantization during the forward pass via the Straight-Through Estimator (STE):

text
w_q = clamp(round(w * 128), -128, 127) / 128
Gradients flow through the rounding and clamping operations as if they were the identity, allowing the optimizer to learn weights that are already robust to int8 quantization. The float weights are saved normally; extract_weights.py is unchanged.

Method 3 — eBPF Integer-Native Inference (in progress)
The eBPF kernel program itself performs MLP inference using only integer arithmetic with SCALE_FACTOR=128. Weights are stored in BPF maps as int8 arrays. The forward pass computes:

c
// Hidden layer 1
for (int j = 0; j < HIDDEN_DIM; j++) {
    int32_t acc = 0;
    for (int i = 0; i < INPUT_DIM; i++)
        acc += (int32_t)w1[j][i] * (int32_t)input[i];
    h1[j] = acc > 0 ? acc : 0;  // ReLU
}
The final output class (egress interface index) is looked up in fwd_table and the packet is redirected with bpf_redirect(). This method moves inference entirely into kernel space with zero syscall overhead.

How the eBPF Switch Works
switch_core.py implements the IPA forwarding logic as an XDP program attached to every interface of each Katharà router:

At startup, it loads weights.json, computes MYSTERY_NUMBER = MLP(input_vector) for the local node, and populates the fwd_table BPF hash map with {MYSTERY_NUMBER → egress_ifindex} entries.

On packet arrival, the XDP hook reads the IPA header from the packet, extracts the pre-computed forwarding key, and performs an O(1) BPF map lookup.

The packet is either redirected to the correct egress interface (XDP_REDIRECT) or dropped (XDP_DROP).

The MYSTERY_NUMBER key is derived from the int8 dot-product of the weight matrix and the local input vector, ensuring the BPF map lookup is deterministic and reproducible from both the kernel and the Python controller.

References
M. Polverini, A. Cianfrani, M. Listanti, "Intelligent Packets: Embedding Machine Learning Models into Network Packets", submitted to IEEE INFOCOM Workshops ICCN 2026.

M. Polverini, "IPA Prototype", github.com/marcopolverini/ipa-prototype, 2026.

S. Miano, F. Risso, "Extended Berkeley Packet Filter", CNIT Technical Report 06 — Network Programmability, 2020.

S. Orlowski et al., "SNDlib 1.0 — Survivable Network Design Library", Networks, vol. 55, no. 3, 2010.
