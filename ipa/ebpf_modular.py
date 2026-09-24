"""
ebpf_modular.py  —  Pipeline 3: Modular Neural Pipeline.

Design space position:
  - Neural inference is decomposed into a tail-call chain of TWO generic
    layer programs (not one per layer, not one per model):
      layer_first  : always hop 0. Input is the protocol-fixed 65-feature
                      IPA vector, read SPARSELY straight from scratch_meta +
                      link_state (same trick as Pipeline 2's arch_generic_2layer
                      -- only ~9 of 65 inputs are ever non-zero per packet).
                      Output width n_out is dynamic, up to ML1_MAX_H1.
      layer_hidden  : hop 1..n_layers-1. Dense n_in -> n_out (both dynamic,
                      up to MLH_MAX_H), reading/writing scratch_acts.
  - Whichever hop is the model's LAST layer (decided at runtime, not by
    which program is wired at that slot -- see below) argmaxes and forwards
    instead of chaining further
  - Maximum flexibility: changing model architecture (depth AND width) =
    change the registered (n_in, n_out) list + weights for that model_id;
    no eBPF recompilation, for any depth/width combination within the
    compiled ceilings below

Why two programs, not one "fully generic" block:
  An earlier version of this file used ONE block generic over n_in up to 80
  (to also cover the 65-wide first layer) with a DENSE map-lookup loop over
  every input position. That blew the kernel's BPF_COMPLEXITY_LIMIT_INSNS
  (4096 instructions on this lab's kernel -- the historic pre-5.2 hard cap,
  not the newer 1M-instruction limit): looping densely over 65 mostly-zero
  inputs for every hidden neuron is enormously wasteful, since real IPA
  packets only ever have ~9 non-zero features (link_state bits, one ingress-
  iface bit, ttl, one node bit). Splitting the first hop into its own
  program that reads those ~9 positions directly (mirroring Pipeline 2's
  sparse fc1) cuts its cost by roughly 7x and keeps hidden-to-hidden hops
  small (dense, but bounded to a small MLH_MAX_H, not the 65-wide input).
  Two small compiled programs fit the 4096-instruction cap; one large one
  did not.

Compile-time ceilings (verifier needs a compile-time trip count; wider/
deeper models need these raised and the program reloaded once -- raising
them grows layer_first/layer_hidden's own instruction count, watch the
4096-instruction cap on kernels that still enforce it):
  n_in         from the feature descriptor (was a fixed 65;
                       not a ceiling, the exact, protocol-mandated width)
  ML1_MAX_H1   = 8   (first layer's output width ceiling)
  MLH_MAX_H    = 8   (every later layer's input AND output width ceiling,
                       including the model's last layer, e.g. the
                       protocol-fixed 7-class output)
  layer_chain size = 16 (max depth; Linux tail-call limit is ~33 anyway)
A layer whose shape exceeds these is rejected at load time by
load_modular_weights() with a clear error, not silently corrupted.

Why the two programs never conflict across concurrently-registered models
of different depths:
  layer_chain[0] is ALWAYS layer_first.fd and layer_chain[i>=1] is ALWAYS
  layer_hidden.fd, for every model, regardless of that model's own depth --
  because layer 0 is always "the first layer" and layer i>=1 is always "a
  later layer", true for any model. Whether a given hop is ALSO "the last
  layer" (argmax+redirect instead of ReLU+continue) is decided INSIDE the
  program from data (layer_idx+1 == n_layers, both read from per-model
  registries), never by which program sits at that tail-call slot. So
  model A (3 layers) and model B (2 layers) can share layer_chain[1]
  perfectly fine: for A it continues to layer_chain[2], for B it argmaxes,
  and both facts are resolved from A/B's own registry entry, not from the
  slot itself.

Maps:
  scratch_acts     : BPF_PERCPU_ARRAY  0 -> struct act_vec {long long v[N]}
                      (hidden activations, the WHOLE vector in one entry so a
                      layer reads it with a single lookup and writes it back
                      through the same pointer; NOT used for the first layer --
                      that reads scratch_meta + link_state directly)
  scratch_meta      : BPF_PERCPU_ARRAY  0 -> {model_id, scale, layer_idx, ingress_if, ttl}
  layer_weights     : BPF_ARRAY  0 -> struct lw_blk {__u8 w[N]}  (the WHOLE weight
                      block in ONE struct-valued entry, so all the weights cost a
                      SINGLE bpf_map_lookup_elem instead of one helper call per
                      byte; eBPF C code casts each byte to __s8 via LW_W();
                      Python side stores int8 as v & 0xFF two's complement)
  layer_chain       : BPF_PROG_ARRAY  0 -> layer_first.fd, 1..15 -> layer_hidden.fd
  layer_registry    : model_id -> {scale_factor, n_layers, sem_bank}
  layer_shapes      : {model_id, layer_idx} -> {n_in, n_out, weight_offset}
  class_action_t3   : (model_id, sem_bank, class) -> {action, logical port}
  mac_table_t3      : u32 LOGICAL PORT -> fwd_action {ifindex, src/dst MAC}
  cls_stats_t3      : per-class redirect counter
  pkt_stats_t3      : [0]=HIT [1]=MISS [2]=DROP

Action: the last layer runs argmax -> class, then
class_action_t3[(model_id, sem_bank, class)] gives this model's action +
logical port, and a single mac_table_t3[port]
lookup resolves the L2 next-hop and bpf_redirect()s (cls 6 = DROP). No output
key, no per-TTL validation -- the NN decides, the table only maps class->port.

Feature encoding (protocol-fixed, independent of hidden depth/width):
  link_state[0..5] + ingress-iface one-hot [6..11] + ttl [12] + node one-hot
  [13..64] -- always the first layer's n_in=65 input; the last layer's
  n_out comes from the model descriptor (7 for the checked-in checkpoint, of
  which 5 forward, class 5 drops and class 6 is unused), matching the argmax
  action above. layer_first reads these straight from scratch_meta/link_state
  (no dense 65-slot scratch_acts array is ever built for it).

Weight storage:
  layer_weights uses an unsigned-byte leaf (__u8). The libbcc build in the
  container image cannot resolve a signed-byte leaf type, so signedness is
  handled explicitly: the eBPF C code casts each byte to __s8 via LW_W()
  before arithmetic, and load_modular_weights() stores each int8 as
  v & 0xFF (identical two's-complement bits) inside the struct-valued block.
"""
import os

# Scratch map layout constants
SCRATCH_ACT_SIZE   = 128   # max activations at any layer boundary
SCRATCH_META_SLOTS = 16    # metadata slots

# Metadata indices in scratch_meta
META_MODEL_ID     = 0
META_SCALE        = 1
META_LAYER_IDX    = 2
META_NODE_CTX     = 3   # (node_index << 16) | ingress_port
META_TTL          = 4

# Compile-time layer-shape ceilings (see module docstring)
# Was `PROTO_N_IN = 65   # protocol-fixed IPA feature vector width`. It is not
# protocol-fixed: 65 = 6 link_state + 6 ingress_iface + 1 ttl + 52 node, the
# Germany50 lab summed up. Resolved from the descriptor instead; the compiled
# ceiling is ML1_MAX_N_IN below.
def reference_n_in():
    """Input width of the model this repo is configured for."""
    import model_meta as _mm
    return _mm.derive_shape(
        _mm.load_model_meta(os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "weights.json")),
        topology_config=_mm.load_topology_config())["n_in"]
ML1_MAX_H1   = 8    # first layer's output width ceiling
P3_MAX_QUEUES = 8   # must match IPA_MAX_QUEUES in the eBPF source above
MLH_MAX_H    = 8    # later layers' input/output width ceiling
LAYER_CHAIN_SIZE = 16

# Size of the single shared layer_weights block, in int8 slots. MUST stay
# equal to the MAX_LAYER_WEIGHT_ENTRIES #define in the eBPF source below (and
# a power of two: the datapath masks its weight index with
# MAX_LAYER_WEIGHT_ENTRIES-1 to keep a runtime-variable index verifier-safe).
# Every concurrently registered model_id carves a non-overlapping slice out of
# this one block, so this constant is also the hard cap on concurrent models.
# Exported so callers check the cap against the real value instead of
# re-hardcoding 2048.
MAX_LAYER_WEIGHT_ENTRIES = 2048

EBPF_MODULAR_COMMON_HEADER = r"""
#include <uapi/linux/if_ether.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/udp.h>
#include <uapi/linux/in.h>

/* Same fallback ebpf_program.py carries: some minimal-header setups do
 * not get IPPROTO_UDP from the includes above. RFC 791 value. */
#ifndef IPPROTO_UDP
#define IPPROTO_UDP 17
#endif

struct ipa_hdr {
    __u8   model_id;
    __u8   model_type;
    __u8   param_size;
    __be16 scale_factor;
    __u8   input_size;
    __u8   output_size;
    __u8   hidden_layers;
    __u8   neurons_per_layer;
    __u8   n_feature_types;
    __u8   feat0_code;  __u8 feat0_count;
    __u8   feat1_code;  __u8 feat1_count;
    __u8   feat2_code;  __u8 feat2_count;
    __u8   feat3_code;  __u8 feat3_count;
    __u8   n_output_types;
    __u8   out0_code;   __u8 out0_count;
} __attribute__((packed));

struct fwd_action {
    __u32 ifindex;
    __u8  src_mac[6];
    __u8  dst_mac[6];
} __attribute__((packed));

/* ---- class semantics: class -> action -> logical port --------------------
 * Same contract as P2 (see ebpf_template_arch.py). The datapath never infers
 * an action from a class index. */
#define ACT_INVALID 0
#define ACT_FORWARD 1
#define ACT_DROP    2
#define ACT_UNUSED  3
#define MAX_N_OUT   32
struct class_act { __u8 action; __u8 port; __u8 _p0; __u8 _p1; };

/* ---- TTL handling for a forwarding hop -----------------------------------
 * A node that redirects a packet IS a router hop and must decrement the TTL,
 * or a forwarding loop never dies. Until this existed the datapath read
 * ip->ttl as a model feature and never wrote it: a redirected packet kept its
 * TTL forever, which on this topology produced a permanent loop between two
 * adjacent nodes instead of the packet eventually expiring.
 *
 * Incremental checksum fix per RFC 1624, in the canonical form used by the
 * kernel's own samples/bpf/xdp_fwd_kern.c. TTL is the high byte of the
 * {ttl,protocol} 16-bit word, so decrementing it subtracts 0x0100 from that
 * word; the one's-complement checksum is corrected by adding htons(0x0100)
 * and folding the carry back in.
 *
 * Called ONLY on the forwarding path, AFTER inference: the model must see the
 * TTL as received, which is what the Python reference replicates. */
static inline __attribute__((always_inline))
void ipa_ttl_dec(struct iphdr *iph) {
    __u32 _c = (__u32)iph->check;
    _c += (__u32)bpf_htons(0x0100);
    iph->check = (__u16)(_c + (_c >= 0xFFFF));
    iph->ttl--;
}

/* Scratch maps: PERCPU to avoid contention.
 *
 * scratch_acts holds the WHOLE activation vector in ONE struct-valued per-CPU
 * entry (key 0) instead of one entry per slot. layer_hidden used to call
 * scratch_acts.lookup() once per (output neuron, input) PAIR -- the same few
 * activations re-read for every output neuron -- and every layer re-wrote them
 * with one .update() per slot. With a struct the whole vector is one lookup per
 * hop, and the writes go straight through the returned pointer (a per-CPU
 * lookup returns THIS cpu's writable copy), so the .update() helper calls
 * disappear too. Same "N lookups -> 1" transformation already applied to the
 * dense feature vectors (see common.py). */
#define SCRATCH_ACT_SIZE   128
#define SCRATCH_META_SLOTS  16
struct act_vec { long long v[SCRATCH_ACT_SIZE]; };
/* Make the compiler forget what it knows about a variable's range.
 *
 * Needed because clang and the verifier reason differently. After
 *     if (n > CEILING) return XDP_PASS;
 * clang knows n <= CEILING and deletes any mask as redundant, while the
 * verifier keeps carrying the register's original range -- measured at
 * [0, 0xffff] for n_out, which made it walk the loops below for 65 536 values
 * instead of 8 and blow past its complexity budget (over 100 000 scalar ids
 * for a 9 000-instruction program).
 *
 * The barrier makes the mask survive compilation, and the verifier reads the
 * real bound off it. */
#define barrier_var(x) asm volatile("" : "=r"(x) : "0"(x))

BPF_PERCPU_ARRAY(scratch_acts, struct act_vec, 1);
BPF_PERCPU_ARRAY(scratch_meta, long long, SCRATCH_META_SLOTS);

/* Weight map: the WHOLE weight block in ONE struct-valued entry (key 0), so a
 * layer reads every weight it needs after a SINGLE bpf_map_lookup_elem instead
 * of one helper call per weight byte. Measured before this change: the large
 * majority of P3's 160 map lookups per packet were single-byte weight reads.
 *
 * __u8 storage (not __s8): BCC's str2ctype on an older libbcc such as the one in a stripped
 * container has no 'signed char', only 'unsigned char'. Sign semantics are
 * preserved -- the eBPF code re-casts each byte to (__s8) via LW_W(). */
#define MAX_LAYER_WEIGHT_ENTRIES 2048
struct lw_blk { __u8 w[MAX_LAYER_WEIGHT_ENTRIES]; };
BPF_ARRAY(layer_weights, struct lw_blk, 1);

/* Read weight `i` out of an already-looked-up block. The AND is what makes the
 * variable index verifier-safe: MAX_LAYER_WEIGHT_ENTRIES is a power of two, so
 * the masked index is provably inside the map value and needs no per-access
 * bound check. It never actually wraps -- load_modular_weights() rejects any
 * model whose block would not fit. */
#define LW_W(blk, i) ((long long)(__s8)((blk)->w[(__u32)(i) & (MAX_LAYER_WEIGHT_ENTRIES - 1)]))

/* link_state: 6 egress up/down slots (feature [0..5]), held in ONE struct-valued
 * entry (key 0) so layer_first reads the whole vector with a SINGLE lookup
 * instead of 6. Written by the userspace carrier monitor. 1=up, 0=down. */
/* COMPILED CEILINGS for the dense per-slot features, not deployment values.
 *
 * These were the literals 6 and 4 -- the Germany50 lab's interface count and
 * its queue count -- written into the struct sizes AND into every loop bound,
 * so the compiled datapath only fit that one network. The consumption loops
 * are already gated by the descriptor's per-feature `sz`, so widening the
 * compiled bound costs a few unrolled iterations and changes no result: slots
 * past the model's real size are skipped, never summed.
 *
 * A deployment whose n_interfaces / n_queues exceeds these must raise the
 * ceiling and recompile -- the control plane checks and says so, instead of
 * silently reading past the vector. See model_meta.MAX_N_IFACES/MAX_N_QUEUES. */
#define IPA_MAX_IFACES  8
/* Back to 8, matching Pipeline 2 -- but the round trip is the interesting
 * part, so it is recorded here rather than thrown away.
 *
 * This was 8, then 1, now 8 again. It went to 1 because layer_first sat at the
 * verifier's complexity limit: reading the node index from a map -- so the
 * node one-hot means which NODE this is, rather than which MODEL the packet
 * carries -- adds one independent scalar to the unrolled loop, and the state
 * space is the PRODUCT of the tracked scalars, not their sum. Twelve
 * configurations were tried and every one was refused; the only one that
 * loaded was the one where the node was not independent at all. Cutting this
 * ceiling to 1 was what freed the room, because the checked-in descriptor
 * declares NO queue feature -- its codes are 1, 2, 3, 4 and queue_occupancy is
 * 5 -- so eight slots were kept alive across the whole loop for nothing.
 *
 * What made 8 affordable again is the INVERTED LOOP NEST in layer_first (see
 * the comment there). It cost +433 instructions and removed 28 evaluations of
 * the five-way descriptor dispatch and 56 dense gates per packet. Those are
 * different currencies: the verifier charges for PATHS, not for size, and the
 * program got bigger while getting very much cheaper to verify.
 *
 * Measured with `diag_p3_bisect.py --ceilings` on that rewrite:
 *
 *     queues 1 -> layer_first  6 850 instructions, loads
 *     queues 2 ->              7 320, loads
 *     queues 4 ->              8 365, loads
 *     queues 8 ->             10 207, loads
 *
 * Before the rewrite, at queues 8, nothing loaded at all.
 *
 * The cost of sitting at 8 with a descriptor that declares no queue feature is
 * STATIC SIZE ONLY: the FEAT_QUEUE_OCC arm is never taken at runtime, so the
 * executed path does not change. What does run is zeroing qs[], eight stores
 * instead of one.
 *
 * These limits are cliffs, not slopes -- cutting IPA_MAX_IFACES from 8 to 6
 * *as well* once made it fail again. Change this number and re-measure with
 * --ceilings; do not reason about it. And a model needing more slots than this
 * is REFUSED by load_modular_weights, never truncated. */
#define IPA_MAX_QUEUES  8
struct ls_vec { __u32 v[IPA_MAX_IFACES]; };
BPF_ARRAY(link_state, struct ls_vec, 1);

/* queue_occupancy feature: n_queues occupancy slots in one struct-valued entry
 * (key 0), seeded by queue_state_monitor.py. Present so a descriptor can use the
 * queue_occupancy feature type; unused if the model's descriptor omits it. */
struct qs_vec { __u32 v[IPA_MAX_QUEUES]; };
BPF_ARRAY(queue_state, struct qs_vec, 1);

/* Per-model feature descriptor (model_desc registry): which feature types the
 * first-hop input uses, their size and starting column in the layer-0 input
 * row. Populated by the control plane from model_meta.resolve_descriptor(); read
 * at runtime by layer_first to build the IV generically instead of the old
 * hardcoded 65-feature layout. */
#define ML_MAX_FEAT 4
/* Trip-count ceiling for the bias-multiplier loop below. MUST equal
 * LAYER_CHAIN_SIZE (the BPF_PROG_ARRAY size): a model cannot have more layers
 * than the chain has slots, so the loop always covers every reachable depth. */
#define ML_MAX_DEPTH 16
/* `scale` era `_pad`. E' la normalizzazione con cui il modello e' stato
 * addestrato (ttl/30, ttl/16, ...): una proprieta' del MODELLO, quindi va
 * nel descrittore a runtime e non in un #define. Con 0 si ricade sul
 * default compilato, cosi' i descrittori scritti prima restano validi. */
struct feat_ent { __u8 code; __u8 size; __u8 col_off; __u8 scale; };
struct model_desc { __u8 n_feat; __u8 n_in; __u8 _p0; __u8 _p1; struct feat_ent feats[ML_MAX_FEAT]; };

/* Divisione con TRONCAMENTO VERSO LO ZERO e divisore a runtime.
 *
 * BPF non ha la divisione con segno: clang si ferma con "unsupported signed
 * division, please convert to unsigned div/mod". Finche' il divisore era un
 * #define il compilatore lo trasformava in uno shift e il problema non
 * esisteva; da quando la scala viene dal descrittore il divisore e' una
 * variabile, e la divisione va fatta a mano.
 *
 * Il numeratore E' con segno -- i pesi possono essere negativi -- mentre il
 * divisore e' sempre positivo. Si divide quindi il valore assoluto senza
 * segno e si rimette il segno. Il troncamento verso lo zero non e' un
 * dettaglio: e' esattamente cio' che fa `trunc_div` nel riferimento Python, e
 * le due implementazioni coincidono sui negativi solo se arrotondano allo
 * stesso modo. */
static __always_inline long long ipa_div_trunc(long long num, __u64 den)
{
    if (den == 0) den = 1;
    if (num < 0)
        return -(long long)(((__u64)(-num)) / den);
    return (long long)(((__u64)num) / den);
}

BPF_HASH(model_desc, __u8, struct model_desc, 256);

/* Layer chain tail-call map: slot 0 = layer_first.fd, slots 1..15 =
 * layer_hidden.fd -- see module docstring for why this never conflicts
 * across concurrently-registered models of different depths. */
BPF_PROG_ARRAY(layer_chain, 16);

/* mac_table_t3: LOGICAL PORT (from class_action_t3) -> {ifindex, src/dst MAC}.
 * The NN decides the port; this only resolves the L2 next-hop. */
/* mac_table_t3 is keyed by LOGICAL PORT, not by class. */
BPF_ARRAY(mac_table_t3, struct fwd_action, MAX_N_OUT);
/* Kernel ingress ifindex -> LOGICAL PORT (1-based; absent means "not one of
 * this node's ports", which contributes nothing).
 *
 * The ingress_iface one-hot used to be indexed by ctx->ingress_ifindex
 * DIRECTLY, i.e. by a kernel ifindex. Kernel ifindexes are allocated by the
 * kernel and are arbitrary -- 2 and 3 on a container, 207 and 209 on a box
 * that has created a few veths -- so on real hardware the guard
 * (_raw_iface >= 1 && _raw_iface <= n_interfaces) is false and the trained
 * feature contributes NOTHING. Pipeline 1 had a table for this but baked it at
 * compile time as [2, 3, 4, ...], which is the same assumption spelled
 * differently.
 *
 * Which interface realises which logical port is a NODE fact, discovered at
 * runtime, exactly like mac_table. This is that map, on the ingress side.
 */
BPF_HASH(ingress_port_t3, __u32, __u32, 64);

/* This node's index in the node one-hot, written by the control plane.
 *
 * A HASH and not an ARRAY, deliberately: a BPF_ARRAY is pre-allocated and
 * zero-filled, so a lookup always succeeds and "nothing installed" reads back
 * as node 0 -- indistinguishable from a real node 0, which is the very defect
 * this map exists to remove. With a hash, absent means absent.
 *
 * Read ONLY by the dispatcher. layer_first must not grow another map lookup:
 * see META_NODE_CTX. */
BPF_HASH(node_id_t3, __u32, __u32, 1);

/* class_action_t3: (model_id, class) -> {action, logical port}, keyed by the
 * composite (model_id, bank, class) flattened into an ARRAY index. Same
 * layout and same reasons as class_action_t2 (see ebpf_template_arch.py): it
 * used to be keyed by class alone, one table shared by every model_id. The
 * lookup stays a single inlined array lookup, O(1) in the number of models;
 * the bank makes re-registering a model_id switch n_layers and semantics in
 * one layer_registry update. */
#define CLASS_ACT_BANKS   2
#define CLASS_ACT_MODELS  256   /* model_id is a __u8 */
#define CLASS_ACT_KEY(mid, bank, cls) \
    (((((__u32)(mid) & 0xffU) * CLASS_ACT_BANKS + ((__u32)(bank) & 1U)) \
      * MAX_N_OUT) + (__u32)(cls))
BPF_ARRAY(class_action_t3, struct class_act,
          CLASS_ACT_MODELS * CLASS_ACT_BANKS * MAX_N_OUT);
BPF_ARRAY(pkt_stats_t3, __u64, 3);   /* [0]=HIT [1]=MISS [2]=DROP */
BPF_ARRAY(cls_stats_t3, __u64, MAX_N_OUT);   /* per-class redirect counter */

/* CTR_INC(): real per-packet map-lookup counter, active only when
 * IPA_COUNT_LOOKUPS is #defined before this source (measurement builds --
 * see common.py instrument_map_lookups()). No-op otherwise. */
#ifdef IPA_COUNT_LOOKUPS
BPF_PERCPU_ARRAY(lookup_ctr, __u64, 1);
/* BCC's rewriter refuses table.lookup() calls that appear textually inside
 * a macro expansion -- must be a real function (static inline, like
 * ml_argmax_forward below), not a #define body. */
static inline __attribute__((always_inline)) void ctr_inc(void) {
    int _lci = 0;
    __u64 *_lcv = lookup_ctr.lookup(&_lci);
    if (_lcv) *_lcv += 1;   /* per-CPU: no atomic needed */
}
#define CTR_INC() ctr_inc()
#else
#define CTR_INC() do {} while (0)
#endif

/* Explicit signed cast so arithmetic is correct after __u8 storage */
#define WEIGHT(p) ((__s8)(*p))
#define RELU(x)  ((x) > 0 ? (x) : 0)

/* Metadata slot indices */
#define META_MODEL_ID    0
#define META_SCALE       1
#define META_LAYER_IDX   2
/* The node's view of this packet, packed into one slot:
 *
 *      bits 23..16 : this NODE's index   (0xff = unknown, so 0..254)
 *      bits 15..0  : the LOGICAL PORT the packet arrived on (0 = none)
 *
 * Packed rather than given a slot each, and this is the whole reason:
 * layer_first is at the verifier's complexity limit. Every extra
 * bpf_map_lookup_elem() in it is a helper call, and a helper call costs far
 * more verifier state than the arithmetic around it. Measured -- layer_first
 * loads at 9 994 instructions with one lookup here, and was REFUSED at 9 402,
 * 9 205 and 9 176 with a second one, in four different shapes. Every refused
 * version was SMALLER than the one that loads.
 *
 * Both halves are the same kind of fact -- where this packet is, as the node
 * sees it -- so one slot is honest, not a hack. */
#define META_NODE_CTX    3
#define META_TTL         4

/* Per-model metadata: model_id -> {scale_factor, n_layers, sem_bank}.
 * n_layers tells each hop when it has reached the last layer
 * (layer_idx+1==n_layers). sem_bank selects which of this model's two
 * class_action_t3 banks is live -- see CLASS_ACT_KEY; it is committed in this
 * entry, which the control plane writes LAST. */
struct layer_model_entry {
    __u16 scale_factor;
    __u8  n_layers;
    __u8  sem_bank;
} __attribute__((packed));
BPF_HASH(layer_registry, __u8, struct layer_model_entry, 256);

/* Per-(model_id, layer_idx) shape: which n_in/n_out this hop computes and
 * where its weights start in the flat layer_weights array. This is what
 * makes the layer chain architecture-agnostic -- it never assumes a fixed
 * width or depth, it just looks up what THIS model's THIS layer needs.
 * (layer 0's n_in is fixed by the feature descriptor, so only its n_out is
 * actually consulted -- see layer_first.) */
struct layer_shape_key {
    __u8 model_id;
    __u8 layer_idx;
} __attribute__((packed));
struct layer_shape_entry {
    __u16 n_in;
    __u16 n_out;
    __u32 weight_offset;
} __attribute__((packed));
BPF_HASH(layer_shapes, struct layer_shape_key, struct layer_shape_entry, 512);

/* Shared argmax + mac_table + redirect epilogue, used by both layer_first
 * (1-layer models) and layer_hidden whenever they are the model's last
 * layer. A plain C helper, not a macro, so both callers get one copy of
 * the logic without the macro-argument foot-guns of the previous 3-block
 * design (see git history: struct padding bugs from more implicit magic). */
static inline __attribute__((always_inline))
int ml_argmax_forward(struct xdp_md *ctx, void *data, void *data_end,
                      int best_cls, __u32 n_out, __u32 sem_key0) {
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;

    /* (model_id, class) -> action -> logical port, from THIS model's live
     * bank of the descriptor-filled map. The previous `best_cls >= 6`
     * hardcoded both the DROP class and the class==port assumption; neither
     * holds for this model (trained DROP is class 5) nor for any other output
     * width. sem_key0 is the first row of that bank, CLASS_ACT_KEY(model_id,
     * sem_bank, 0), computed by the caller without adding a value that stays
     * live across the layer loop: layer_first sits at the 512-byte BPF stack
     * limit in its instrumented builds (IPA_COUNT_LOOKUPS, and the T1/T2
     * latency build of bench_throughput) -- measured, clang 18. See last_key
     * in layer_first. */
    if (best_cls < 0 || (__u32)best_cls >= n_out) {
        int mi = 1; __u64 *mv = pkt_stats_t3.lookup(&mi);
        if (mv) __sync_fetch_and_add(mv, 1);
        return XDP_PASS;
    }
    __u32 _ci = (__u32)best_cls;
    __u32 _sk = sem_key0 + _ci;
    struct class_act *ca = class_action_t3.lookup(&_sk);
    if (!ca || ca->action == ACT_INVALID) {
        int mi = 1; __u64 *mv = pkt_stats_t3.lookup(&mi);
        if (mv) __sync_fetch_and_add(mv, 1);
        return XDP_PASS;
    }
    if (ca->action == ACT_DROP) {
        int di = 2; __u64 *dv = pkt_stats_t3.lookup(&di);
        if (dv) __sync_fetch_and_add(dv, 1);
        /* Same reason as Pipeline 2: the decision happened, so it is recorded
         * whatever is then done with the packet. */
        __u64 *dcv = cls_stats_t3.lookup(&_ci);
        if (dcv) __sync_fetch_and_add(dcv, 1);
        return XDP_DROP;
    }
    if (ca->action != ACT_FORWARD) {           /* ACT_UNUSED */
        __u64 *ucv = cls_stats_t3.lookup(&_ci);
        if (ucv) __sync_fetch_and_add(ucv, 1);
        int mi = 1; __u64 *mv = pkt_stats_t3.lookup(&mi);
        if (mv) __sync_fetch_and_add(mv, 1);
        return XDP_PASS;
    }

    /* Re-parse the IP header: this epilogue is reached through the tail-call
     * chain, so it does not inherit the dispatcher's pointers. Needed only for
     * the TTL decrement below -- the packet was already validated by the
     * dispatcher, but the verifier requires the bounds check again anyway. */
    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return XDP_PASS;

    /* mac_table_t3 is keyed by LOGICAL PORT, cls_stats_t3 by CLASS. Keeping
     * them in one variable named `cls` (holding the port) wrote the per-class
     * counter at a port index; it agreed only because the reference model
     * numbers its ports the same as its forwarding classes. */
    __u32 port = (__u32)ca->port;
    struct fwd_action *action = mac_table_t3.lookup(&port);
    if (action != NULL && action->ifindex != 0) {
        /* A hop must not forward a packet whose TTL would reach 0. See the
         * ipa_ttl_dec() comment: counted as MISS and passed to the kernel. */
        if (ip->ttl <= 1) {
            int ti = 1; __u64 *tv = pkt_stats_t3.lookup(&ti);
            if (tv) __sync_fetch_and_add(tv, 1);
            return XDP_PASS;
        }
        ipa_ttl_dec(ip);
        int si = 0; __u64 *v = pkt_stats_t3.lookup(&si);
        if (v) __sync_fetch_and_add(v, 1);
        __u64 *cv = cls_stats_t3.lookup(&_ci);   /* keyed by CLASS */
        if (cv) __sync_fetch_and_add(cv, 1);
        __builtin_memcpy(eth->h_source, action->src_mac, 6);
        __builtin_memcpy(eth->h_dest,   action->dst_mac, 6);
        return bpf_redirect(action->ifindex, 0);
    }
    /* no mac_table entry for that LOGICAL PORT (link down / not provisioned) */
    int si = 1; __u64 *v = pkt_stats_t3.lookup(&si);
    if (v) __sync_fetch_and_add(v, 1);
    return XDP_PASS;
}
"""

# -----------------------------------------------------------------
# Dispatcher: parse packet, stash metadata, tail call layer_chain[0].
# No scratch_acts writes here -- layer_first reads scratch_meta/link_state
# directly (sparse), it never needs a dense 65-slot feature array.
# -----------------------------------------------------------------
EBPF_MODULAR_DISPATCHER = EBPF_MODULAR_COMMON_HEADER + r"""

int modular_dispatcher(struct xdp_md *ctx) {
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;
    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end)  return XDP_PASS;
    /* Read protocol via absolute RFC 791 byte offset (byte 9), not ip->protocol,
     * to avoid bitfield packing ambiguity -- see ebpf_program.py FIX(#4). */
    __u8 ip_proto = *((__u8 *)ip + 9);
    if (ip_proto != IPPROTO_UDP)   return XDP_PASS;
    /* ...and derive the UDP header from the real ihl*4, not sizeof(struct
     * iphdr): the second half of the same FIX(#4), which was applied to the
     * protocol read here but not to this offset. Wrong whenever ihl > 5. */
    __u32 _ip_hlen = (((__u8 *)ip)[0] & 0x0fU) << 2U;
    if (_ip_hlen < 20U) return XDP_PASS;
    struct udphdr *udp = (struct udphdr *)((void *)ip + _ip_hlen);
    if ((void *)(udp + 1) > data_end)  return XDP_PASS;
    if (udp->dest != bpf_htons(9999))  return XDP_PASS;
    struct ipa_hdr *ipa = (struct ipa_hdr *)(udp + 1);
    if ((void *)(ipa + 1) > data_end)  return XDP_PASS;

    __u8 model_id = ipa->model_id;
    struct layer_model_entry *lentry = layer_registry.lookup(&model_id);
    if (!lentry) return XDP_PASS;

    int idx;
    idx = META_MODEL_ID;   { long long v = model_id;               scratch_meta.update(&idx, &v); }
    idx = META_SCALE;      { long long v = lentry->scale_factor;   scratch_meta.update(&idx, &v); }
    idx = META_LAYER_IDX;  { long long v = 0LL;                    scratch_meta.update(&idx, &v); }
    /* Both halves of the node context, resolved HERE and packed into one
     * slot, so the layers pay one lookup instead of two. The dispatcher is
     * small and can afford the two map reads; layer_first cannot afford even
     * one more. See the META_NODE_CTX comment. */
    idx = META_NODE_CTX;
    { __u32 _kif = ctx->ingress_ifindex;
      __u32 *_lp = ingress_port_t3.lookup(&_kif);
      __u32 _port = _lp ? (*_lp & 0xffffU) : 0U;
      __u32 _nz = 0;
      __u32 *_nid = node_id_t3.lookup(&_nz);
      /* 0xff = unknown, so a node index is 0..254. */
      __u32 _nd = (_nid && *_nid < 0xffU) ? *_nid : 0xffU;
      long long v = (long long)((_nd << 16) | _port);
      scratch_meta.update(&idx, &v); }
    idx = META_TTL;        { long long v = ip->ttl;                scratch_meta.update(&idx, &v); }

    /* Tail call to layer_chain[0] = layer_first. It reads model_id/scale/
     * ttl/ingress_if straight back out of scratch_meta and link_state --
     * the protocol-fixed 65-feature vector is never materialized densely. */
    layer_chain.call(ctx, 0);
    return XDP_PASS;
}
"""

# -----------------------------------------------------------------
# layer_first: always hop 0. Sparse read of the protocol-fixed 65-feature
# IPA vector (mirrors Pipeline 2's arch_generic_2layer fc1 loop) -> n_out
# up to ML1_MAX_H1. Argmax+forward directly if this is also the last layer
# (a 1-layer model), otherwise ReLU + write scratch_acts + chain to hop 1.
# -----------------------------------------------------------------
EBPF_LAYER_FIRST = EBPF_MODULAR_COMMON_HEADER + r"""
/* PROTO_N_IN is gone: it was 65, the Germany50 feature sum, and layer_first
 * reads its input sparsely through model_desc, never through that width. */

#define ML1_MAX_H1   8
/* Compiled CEILING on the queue_occupancy feature, not the deployment's queue
 * count. Was `ML_N_QUEUES 4` -- the lab's value, read as if it were a law.
 * The ceiling now lives in IPA_MAX_QUEUES, shared with Pipeline 2. */

/* Must match model_meta.DEFAULT_TTL_SCALE (the checkpoint's initial_ttl). */
#define ML_TTL_SCALE 30
#define ML_MAX_N_IN  128
#define FEAT_LINK_STATE  0x01
#define FEAT_INGRESS_IF  0x02
#define FEAT_TTL         0x03
#define FEAT_NODE_ID     0x04
#define FEAT_QUEUE_OCC   0x05

int layer_first(struct xdp_md *ctx) {
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    int mi_model = META_MODEL_ID;
    long long *mp = scratch_meta.lookup(&mi_model);
    if (!mp) return XDP_PASS;
    __u8 model_id = (__u8)(*mp);

    int ms = META_SCALE;
    long long *sp = scratch_meta.lookup(&ms);
    if (!sp || *sp == 0) return XDP_PASS;

    struct layer_model_entry *lentry = layer_registry.lookup(&model_id);
    if (!lentry) return XDP_PASS;
    __u8 n_layers = lentry->n_layers;
    if (n_layers == 0) return XDP_PASS;
    /* "Is this also the last layer" and, if so, the first class_action_t3 row
     * of this model's live bank, in ONE value: bit 31 is the flag, the low
     * bits are CLASS_ACT_KEY(model_id, sem_bank, 0). It replaces the __u8
     * is_last that was already live across the whole loop below. Carrying the
     * key separately -- model_id and lentry kept alive until the epilogue --
     * pushed the latency-instrumented build (bench_throughput, T1/T2) past
     * the 512-byte BPF stack; packed here it adds no live value at all. */
    __u32 last_key = (n_layers == 1)
        ? (0x80000000U | CLASS_ACT_KEY(model_id, lentry->sem_bank, 0)) : 0U;

    struct layer_shape_key key = {};
    key.model_id  = model_id;
    key.layer_idx = 0;
    struct layer_shape_entry *shape = layer_shapes.lookup(&key);
    if (!shape) return XDP_PASS;

    __u32 n_out = shape->n_out;
    __u32 woff  = shape->weight_offset;
    if (n_out == 0 || n_out > ML1_MAX_H1) return XDP_PASS;
    /* Barrier then mask: see barrier_var. The mask is a no-op for every value
     * the guard lets through, and exists only so the verifier can prune. */
    barrier_var(n_out);
    n_out &= 0xfU;               /* ML1_MAX_H1 = 8, so 4 bits suffice */

    /* Per-model feature descriptor: n_in (= sum of feature sizes) + feature
     * layout, read at runtime -> the first-hop IV is built GENERICALLY instead
     * of the old hardcoded 65-feature layout. Populated by the CP via
     * model_meta.resolve_descriptor(). */
    struct model_desc *desc = model_desc.lookup(&model_id);
    if (!desc) return XDP_PASS;
    __u32 n_in = desc->n_in;
    if (n_in == 0 || n_in > ML_MAX_N_IN) return XDP_PASS;
    barrier_var(n_in);
    n_in &= 0xffU;               /* ML_MAX_N_IN = 128 */
    __u32 bias_off = n_in * n_out;

    int mtl = META_TTL;
    long long *ttlp = scratch_meta.lookup(&mtl);
    __u32 _ttl = ttlp ? (__u32)(*ttlp) & 0xff : 0;

    /* One lookup, one ternary -- exactly the shape that loads. The node
     * index rides in the upper half of the same word; unpacking it is two ALU
     * ops on an already-bounded value, which costs the verifier nothing like a
     * second helper call would. 0xff0000 is "no port, unknown node". */
    int mctx = META_NODE_CTX;
    long long *cxp = scratch_meta.lookup(&mctx);
    __u32 _ctx = cxp ? (__u32)(*cxp) : 0xff0000U;
    __u32 _raw_iface = _ctx & 0xffffU;
    /* EXACTLY one byte, [0, 255] -- the range the verifier had when this
     * came from `(__u32)model_id`, a __u8. Holding a 256 "unknown" sentinel
     * needed 9 bits, and that was the last difference from the version that
     * loads. 0xff is the sentinel instead, so node indices run 0..254. */
    __u32 _node      = (_ctx >> 16) & 0xffU;

    /* The NODE's own index, not the packet's model_id. Resolved by the
     * dispatcher and passed through scratch_meta, like the ingress port above:
     * one read, one bound, no extra branch inside the unrolled loop. The value
     * is already clamped to [0, 256], 256 meaning unknown. */

    /* dense feature vectors, each read once (single lookup), reused per neuron.
     * Sized to the topology; the descriptor's per-feature size gates the slots. */
    long long ls[IPA_MAX_IFACES];
    { int lsz = 0; struct ls_vec *lsp = link_state.lookup(&lsz);
      #pragma unroll
      for (int i = 0; i < IPA_MAX_IFACES; i++)
          ls[i] = lsp ? (long long)(lsp->v[i]) : 0LL; }
    /* queue_state is only read if this model's descriptor declares the
     * queue_occupancy feature -- the default descriptor does not. */
    long long qs[IPA_MAX_QUEUES];
    #pragma unroll
    for (int i = 0; i < IPA_MAX_QUEUES; i++) qs[i] = 0LL;
    __u8 _need_qs = 0;
    #pragma unroll
    for (int f = 0; f < ML_MAX_FEAT; f++)
        if (f < desc->n_feat && desc->feats[f].code == FEAT_QUEUE_OCC) _need_qs = 1;
    if (_need_qs) {
      int qsz = 0; struct qs_vec *qsp = queue_state.lookup(&qsz);
      if (qsp) {
        #pragma unroll
        for (int i = 0; i < IPA_MAX_QUEUES; i++) qs[i] = (long long)(qsp->v[i]);
      }
    }

    /* Whole weight block in ONE lookup -- every LW_W() below is a pointer read. */
    int _lwz = 0;
    struct lw_blk *LW = layer_weights.lookup(&_lwz);
    if (!LW) return XDP_PASS;

    /* layer_first is always layer 0, where bias and products both carry
     * scale**1: no bias multiplier is needed here. layer_hidden computes one
     * because its products carry scale**(layer_idx+1). See ebpf_program.py's
     * _gen_dense_layer for the derivation. */
    long long out[ML1_MAX_H1];

    /* The loop nest here is INVERTED with respect to the obvious form: the
     * feature loop is OUTSIDE and the neuron loop INSIDE. It reads oddly, so
     * the reason is worth stating.
     *
     * A descriptor entry's fields -- code, size, col_off -- do not depend on
     * which neuron is being computed. With the neuron loop outside, as it was,
     * the five-way dispatch on `code` was re-evaluated
     * ML1_MAX_H1 * ML_MAX_FEAT = 32 times per packet, and the `i < size` gate
     * on a dense vector 8 * 8 = 64 times, all to re-derive the same answer.
     * Inverted, the dispatch runs ML_MAX_FEAT = 4 times and each dense gate
     * once per slot; the inner neuron loops are then straight-line
     * multiply-accumulate with no branch in them at all.
     *
     * THE ARITHMETIC IS UNCHANGED, term for term. Only the order in which the
     * terms are summed differs, and two's-complement int64 addition is
     * associative and commutative -- including on overflow, which wraps
     * identically either way -- so every accumulator ends bit-identical to the
     * previous form. Each term is still computed exactly as before: in
     * particular the TTL term still divides the PRODUCT, once, at full width.
     *
     * out[] is the accumulator now, in place of the per-neuron `acc`. That is
     * deliberate: out[] was ALREADY live across the whole loop, so this moves
     * state the verifier was tracking anyway rather than adding any. */
    #pragma unroll
    for (int j = 0; j < ML1_MAX_H1; j++)
        out[j] = LW_W(LW, woff + bias_off + j);

    /* No `j < n_out` gate inside the accumulation: neurons past n_out are
     * computed and thrown away. Their weight rows fall outside this model's
     * block, but LW_W masks every index to the compiled array, so the read is
     * in bounds -- just meaningless. Nothing ever sees it: the argmax below
     * skips those neurons, and layer_hidden gates its input loop on n_in
     * rather than trusting zeros. Gating here instead would cost 8 branches in
     * the TTL arm and 64 in the link_state arm, which is the cost this whole
     * rewrite exists to remove. Pipeline 2 already relies on the same
     * property for h1/h2. */
    #pragma unroll
    for (int f = 0; f < ML_MAX_FEAT; f++) {
        if (f >= desc->n_feat) continue;
        __u8  code = desc->feats[f].code;
        __u32 sz   = desc->feats[f].size;
        __u32 coff = desc->feats[f].col_off;
        if (code == FEAT_TTL) {
            /* Diviso per la scala di ADDESTRAMENTO, che viene dal descrittore
             * (feat_ent.scale); con 0 si ricade sul default compilato. La
             * divisione passa da ipa_div_trunc perche' BPF non ha la
             * divisione con segno e il numeratore qui ce l'ha. */
            __u64 _sc = desc->feats[f].scale ? desc->feats[f].scale
                                             : ML_TTL_SCALE;
            #pragma unroll
            for (int j = 0; j < ML1_MAX_H1; j++)
                out[j] += ipa_div_trunc((long long)_ttl
                           * LW_W(LW, woff + j * n_in + coff), _sc);
        } else if (code == FEAT_LINK_STATE) {
            #pragma unroll
            for (int i = 0; i < IPA_MAX_IFACES; i++) {
                if ((__u32)i >= sz) continue;
                long long x = ls[i];
                #pragma unroll
                for (int j = 0; j < ML1_MAX_H1; j++)
                    out[j] += x * LW_W(LW, woff + j * n_in + coff + i);
            }
        } else if (code == FEAT_QUEUE_OCC) {
            #pragma unroll
            for (int i = 0; i < IPA_MAX_QUEUES; i++) {
                if ((__u32)i >= sz) continue;
                long long x = qs[i];
                #pragma unroll
                for (int j = 0; j < ML1_MAX_H1; j++)
                    out[j] += x * LW_W(LW, woff + j * n_in + coff + i);
            }
        } else if (code == FEAT_INGRESS_IF) {
            /* One-hot: a single column, the same column for every neuron, so
             * the bound check happens once instead of once per neuron. */
            if (_raw_iface >= 1 && _raw_iface <= sz) {
                __u32 c = coff + (_raw_iface - 1);
                #pragma unroll
                for (int j = 0; j < ML1_MAX_H1; j++)
                    out[j] += LW_W(LW, woff + j * n_in + c);
            }
        } else if (code == FEAT_NODE_ID) {
            if (_node < sz) {
                __u32 c = coff + _node;
                #pragma unroll
                for (int j = 0; j < ML1_MAX_H1; j++)
                    out[j] += LW_W(LW, woff + j * n_in + c);
            }
        }
    }

    /* LLONG_MIN, not -1e7: the logits of a 1-layer model are unbounded int64
     * accumulations (ttl up to 255 x int8 weights), so an all-negative output
     * row below the old -9999999 sentinel would leave best_cls at its initial
     * 0 instead of the real argmax. Same fix as ebpf_template_arch.py. */
    long long best_val = -9223372036854775807LL - 1LL;
    int best_cls = 0;

    /* Finalise: ReLU (or argmax) over the real neurons, zero over the rest.
     * The argmax still walks j in ascending order with a strict `>`, so a tie
     * still resolves to the lowest class, exactly as when it was interleaved
     * with the accumulation. The zeroing keeps the activation vector this hop
     * publishes byte-for-byte what it was before this rewrite. */
    #pragma unroll
    for (int j = 0; j < ML1_MAX_H1; j++) {
        if (j >= n_out) { out[j] = 0LL; continue; }
        if (last_key) {
            if (out[j] > best_val) { best_val = out[j]; best_cls = j; }
        } else {
            out[j] = RELU(out[j]);
        }
    }

    if (!last_key) {
        /* ONE lookup of this CPU's activation vector, then plain stores through
         * the returned pointer -- replaces ML1_MAX_H1 separate .update() calls. */
        int _az = 0;
        struct act_vec *ACT = scratch_acts.lookup(&_az);
        if (!ACT) return XDP_PASS;
        #pragma unroll
        for (int j = 0; j < ML1_MAX_H1; j++) ACT->v[j] = out[j];
        int li = META_LAYER_IDX;
        long long nv = 1LL;
        scratch_meta.update(&li, &nv);
        layer_chain.call(ctx, 1);
        return XDP_PASS;
    }

    return ml_argmax_forward(ctx, data, data_end, best_cls, n_out,
                             last_key & 0x7fffffffU);
}
"""

# -----------------------------------------------------------------
# layer_hidden: hop 1..n_layers-1. Dense n_in -> n_out (+ ReLU, unless this
# is the model's last layer, in which case argmax+forward instead).
# -----------------------------------------------------------------
EBPF_LAYER_HIDDEN = EBPF_MODULAR_COMMON_HEADER + r"""
#define MLH_MAX_H  8

int layer_hidden(struct xdp_md *ctx) {
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    int mi_model = META_MODEL_ID;
    long long *mp = scratch_meta.lookup(&mi_model);
    if (!mp) return XDP_PASS;
    __u8 model_id = (__u8)(*mp);

    int mi_layer = META_LAYER_IDX;
    long long *lp = scratch_meta.lookup(&mi_layer);
    if (!lp) return XDP_PASS;
    __u8 layer_idx = (__u8)(*lp);

    struct layer_model_entry *lentry = layer_registry.lookup(&model_id);
    if (!lentry) return XDP_PASS;
    __u8 n_layers = lentry->n_layers;
    if (n_layers == 0 || layer_idx >= n_layers) return XDP_PASS;
    __u8 is_last = (layer_idx + 1 == n_layers) ? 1 : 0;

    struct layer_shape_key key = {};
    key.model_id  = model_id;
    key.layer_idx = layer_idx;
    struct layer_shape_entry *shape = layer_shapes.lookup(&key);
    if (!shape) return XDP_PASS;

    __u32 n_in  = shape->n_in;
    __u32 n_out = shape->n_out;
    __u32 woff  = shape->weight_offset;
    if (n_in == 0 || n_in > MLH_MAX_H || n_out == 0 || n_out > MLH_MAX_H) return XDP_PASS;
    /* Same reason as in layer_first. */
    barrier_var(n_in);
    barrier_var(n_out);
    n_in  &= 0xfU;
    n_out &= 0xfU;
    /* Bias multiplier: the weights are stored as round(w_float * scale), so
     * this layer's products carry scale**(layer_idx+1) while a bias stored the
     * same way carries only scale**1. Multiplying the bias by scale**layer_idx
     * puts the two in the same units. Without it the biases are progressively
     * under-weighted with depth and the datapath disagrees with the trained
     * model on 28% of decisions (measured: argmax agreement 72% -> 96%).
     *
     * Unrolled to ML_MAX_DEPTH because the verifier needs a constant trip
     * count; layer_idx < n_layers <= LAYER_CHAIN_SIZE, so every reachable
     * depth is covered. A model deep enough for scale**layer_idx to overflow
     * int64 would already have overflowed its accumulators. */
    long long bias_mul = 1LL;
    #pragma unroll
    for (int _bp = 0; _bp < ML_MAX_DEPTH; _bp++) {
        if (_bp < layer_idx) bias_mul *= (long long)lentry->scale_factor;
    }

    __u32 bias_off = n_in * n_out;

    /* Weight block and this CPU's activation vector, each read ONCE for the
     * whole layer. Previously the inner loop did a layer_weights lookup AND a
     * scratch_acts lookup per (output neuron, input) pair -- so the same few
     * activations were re-fetched for every output neuron. */
    int _lwz = 0;
    struct lw_blk *LW = layer_weights.lookup(&_lwz);
    if (!LW) return XDP_PASS;
    int _az = 0;
    struct act_vec *ACT = scratch_acts.lookup(&_az);
    if (!ACT) return XDP_PASS;

    long long out[MLH_MAX_H];
    /* LLONG_MIN sentinel -- see layer_first / ebpf_template_arch.py. */
    long long best_val = -9223372036854775807LL - 1LL;
    int best_cls = 0;

    #pragma unroll
    for (int j = 0; j < MLH_MAX_H; j++) {
        if (j >= n_out) { out[j] = 0LL; continue; }
        long long acc = LW_W(LW, woff + bias_off + j) * bias_mul;
        #pragma unroll
        for (int i = 0; i < MLH_MAX_H; i++) {
            if (i >= n_in) continue;
            acc += ACT->v[i] * LW_W(LW, woff + j * n_in + i);
        }
        if (is_last) {
            if (acc > best_val) { best_val = acc; best_cls = j; }
        } else {
            out[j] = RELU(acc);
        }
    }

    if (!is_last) {
        /* Stores through the pointer already looked up above -- no extra
         * helper call per slot. */
        #pragma unroll
        for (int j = 0; j < MLH_MAX_H; j++) ACT->v[j] = out[j];
        int li = META_LAYER_IDX;
        long long nv = (long long)(layer_idx + 1);
        scratch_meta.update(&li, &nv);
        layer_chain.call(ctx, layer_idx + 1);
        return XDP_PASS;
    }

    return ml_argmax_forward(ctx, data, data_end, best_cls, n_out,
                             CLASS_ACT_KEY(model_id, lentry->sem_bank, 0));
}
"""

# Full combined source for single-program compilation
EBPF_MODULAR_FULL = (
    EBPF_MODULAR_DISPATCHER
    + "\n" + EBPF_LAYER_FIRST.replace(EBPF_MODULAR_COMMON_HEADER, "")
    + "\n" + EBPF_LAYER_HIDDEN.replace(EBPF_MODULAR_COMMON_HEADER, "")
)


def load_modular_weights(
    bpf_obj,
    weights_int8: list,
    model_id: int = 0,
    scale: int = 128,
    layer_dims: list = None,
    base_offset: int = 0,
    features: list = None,
    semantics=None,
) -> int:
    """
    Populate layer_registry, layer_shapes and layer_weights for Pipeline 3.

    layer_dims: ordered list of (n_in, n_out) tuples, one per layer, e.g.
      [(65, 4), (4, 4), (4, 7)] for today's 65-4-4-7 model (the default,
      used when layer_dims is None -- backward compatible with the one
      trained model checked into the repo). Any depth/width combination
      works as long as:
        - the first layer's n_in matches the feature descriptor
          (layer_first reads the vector sparsely, not generically)
          and its n_out is <= ML1_MAX_H1
        - every later layer's n_in and n_out are both <= MLH_MAX_H
      This is what makes Pipeline 3 genuinely architecture-agnostic: no
      eBPF recompilation for a different depth or different hidden widths,
      just a different layer_dims + weights. By protocol, the last layer's
      n_out should be 7 (6 egress classes + drop) -- not enforced here, but
      a mismatch will desync the mac_table class range from what the
      network expects.

    base_offset: lets the caller stack several models' weights in the same
      layer_weights array without overlap (like Pipeline 2's weight_offset).
      Returns the total weight count this model consumed, so the caller can
      compute the next model's base_offset as a running sum -- models may
      have different total sizes (different depth/width), unlike Pipeline 2
      where every model shares the same 2-hidden-layer topology.

    Weight layout in the flat array (relative to base_offset): each layer's
    weights back-to-back, each as [n_in*n_out weights][n_out biases] --
    identical to the flat layout already used by weights.json for the
    3-layer case, so the checked-in weights.json needs no migration.

    NOTE: layer_weights map uses __u8 in C (to avoid BCC str2ctype
    KeyError: 'signed char' on older libbcc).  We store the int8 value
    as its unsigned two's-complement bit pattern (c_uint8).  The eBPF C
    code re-casts each byte to (__s8) before accumulation, so arithmetic
    is correct.
    """
    # The datapath's queue vector is IPA_MAX_QUEUES wide, and Pipeline 3's is
    # 1 (see the comment on that #define). A wider queue feature would be
    # silently truncated to the first slot by the `i < sz` gate, so it is
    # refused here instead.
    if features:
        for _f in features:
            if _f.get("type") == "queue_occupancy" and int(_f.get("size", 0)) > P3_MAX_QUEUES:
                raise ValueError(
                    f"Pipeline 3 compiles a queue_occupancy vector of "
                    f"{P3_MAX_QUEUES} slot(s); this descriptor asks for "
                    f"{_f['size']}. Raise IPA_MAX_QUEUES in the eBPF source and "
                    f"RE-MEASURE whether layer_first still loads -- it sits at "
                    f"the verifier's complexity limit, and that ceiling is what "
                    f"currently buys the room for the node index.")


    from ctypes import c_uint8, c_uint16, c_uint32, Structure

    if layer_dims is None:
        layer_dims = [(65, 4), (4, 4), (4, 7)]

    # Class semantics: required, not derived from n_out. With no argument the
    # shared resolver reads the descriptor and announces any fallback.
    if semantics is None:
        from model_meta import descriptor_semantics_or_reference
        semantics = descriptor_semantics_or_reference(layer_dims[-1][1],
                                                      "Pipeline3")
    semantics.validate()
    if semantics.n_out != layer_dims[-1][1]:
        raise ValueError(
            f"class semantics declare n_out={semantics.n_out} but the last "
            f"layer outputs {layer_dims[-1][1]}. Descriptor and model must "
            f"agree before either reaches the datapath.")

    n_layers = len(layer_dims)
    if n_layers == 0 or n_layers > LAYER_CHAIN_SIZE:
        raise ValueError(f"n_layers={n_layers} must be in [1, {LAYER_CHAIN_SIZE}] (layer_chain size)")

    for i, (n_in, n_out) in enumerate(layer_dims):
        if i == 0:
            # First-layer n_in = the descriptor's N_IN (sum of feature sizes),
            # no longer fixed to 65: layer_first now builds the IV generically
            # from model_desc. Must match the model_desc seeded for this model_id
            # (see load_model_desc) and stay within the compiled ceiling.
            if n_in <= 0 or n_in > 128:  # MAX_N_IN / ML_MAX_N_IN in the eBPF source
                raise ValueError(
                    f"first layer n_in={n_in} outside [1, 128] (ML_MAX_N_IN)")
            if n_out <= 0 or n_out > ML1_MAX_H1:
                raise ValueError(
                    f"first layer n_out={n_out} exceeds the compiled ceiling "
                    f"ML1_MAX_H1={ML1_MAX_H1} -- raise it in ebpf_modular.py and reload")
        else:
            if n_in <= 0 or n_in > MLH_MAX_H or n_out <= 0 or n_out > MLH_MAX_H:
                raise ValueError(
                    f"layer {i} shape ({n_in},{n_out}) exceeds the compiled ceiling "
                    f"MLH_MAX_H={MLH_MAX_H} -- raise it in ebpf_modular.py and reload")

    total_weights = sum(n_in * n_out + n_out for (n_in, n_out) in layer_dims)
    if base_offset + total_weights > MAX_LAYER_WEIGHT_ENTRIES:
        raise ValueError(
            f"base_offset={base_offset} + total_weights={total_weights} "
            f"exceeds MAX_LAYER_WEIGHT_ENTRIES={MAX_LAYER_WEIGHT_ENTRIES} -- too "
            f"many concurrent model_id's. Raise it here AND the matching #define "
            f"in the eBPF source (keep it a power of two).")
    if len(weights_int8) < total_weights:
        raise ValueError(
            f"layer_dims={layer_dims} needs {total_weights} weights, "
            f"got only {len(weights_int8)}")

    # Flat per-layer offsets (relative to base_offset)
    layer_offsets = []
    offset = base_offset
    for (n_in, n_out) in layer_dims:
        layer_offsets.append(offset)
        offset += n_in * n_out + n_out

    # layer_weights is ONE struct-valued entry holding the whole weight block
    # (see the lw_blk declaration in the eBPF source), so registering a model is
    # a read-modify-write of that single entry -- ONE map update instead of one
    # per weight. Read-modify matters: several model_id's share the block at
    # different base_offsets, so writing a fresh buffer would wipe the models
    # registered before this one.
    lw_tbl = bpf_obj["layer_weights"]
    blk = lw_tbl[c_uint32(0)]
    for idx, w in enumerate(weights_int8[:total_weights]):
        blk.w[base_offset + idx] = int(w) & 0xFF
    lw_tbl[c_uint32(0)] = blk

    class LayerShapeKey(Structure):
        _pack_ = 1
        _fields_ = [("model_id", c_uint8), ("layer_idx", c_uint8)]

    class LayerShapeEntry(Structure):
        _pack_ = 1
        _fields_ = [("n_in", c_uint16), ("n_out", c_uint16), ("weight_offset", c_uint32)]

    shapes_table = bpf_obj["layer_shapes"]
    for layer_idx, ((n_in, n_out), woff) in enumerate(zip(layer_dims, layer_offsets)):
        shapes_table[LayerShapeKey(model_id=model_id, layer_idx=layer_idx)] = \
            LayerShapeEntry(n_in=n_in, n_out=n_out, weight_offset=woff)

    # Semantics into this model's INACTIVE bank; the layer_registry write below
    # (still the last one) commits n_layers and sem_bank together. Other
    # model_ids' rows are never written.
    from ebpf_template_arch import load_class_action
    bank = load_class_action(bpf_obj, "class_action_t3", "layer_registry",
                             model_id, semantics)

    class LayerModelEntry(Structure):
        _pack_ = 1
        _fields_ = [("scale_factor", c_uint16), ("n_layers", c_uint8),
                    ("sem_bank", c_uint8)]

    bpf_obj["layer_registry"][c_uint8(model_id)] = \
        LayerModelEntry(scale_factor=scale, n_layers=n_layers, sem_bank=bank)

    shape_str = "-".join(str(d[0]) for d in layer_dims) + f"-{layer_dims[-1][1]}"
    print(f"[Pipeline3] model_id={model_id} registered: scale={scale}, "
          f"shape={shape_str}, n_layers={n_layers}, "
          f"base_offset={base_offset}, total_weights={total_weights}")

    # Seed the first-hop feature descriptor (default 65-feature layout unless a
    # custom one is passed) so layer_first builds its IV generically. Folded in
    # here so every existing caller (methods + test harnesses) registers
    # model_desc without a separate call. n_in must equal the first layer's n_in.
    if features is None:
        from model_meta import derive_shape, DEFAULT_META, load_topology_config
        features = derive_shape(dict(DEFAULT_META),
                                topology_config=load_topology_config())["features"]
    load_model_desc(bpf_obj, features, n_in=layer_dims[0][0], model_id=model_id)
    return total_weights


# Max features per descriptor -- must match ML_MAX_FEAT in the eBPF source.
ML_MAX_FEAT = 4


def load_model_desc(bpf_obj, features: list, n_in: int, model_id: int = 0) -> None:
    """
    Populate model_desc[model_id] so layer_first builds the first-hop input
    vector GENERICALLY from a per-model descriptor (instead of the old hardcoded
    65-feature layout). Call once per registered model_id, alongside
    load_modular_weights(); n_in must equal layer_dims[0][0].

    features: resolved descriptor (list of {"type","size"}, from
              model_meta.derive_shape) in the order the model was trained on;
              its flat (code,size,col_off) form comes from
              model_meta.resolve_descriptor(). Default [link_state,
              ingress_iface, ttl, node] / n_in=65 reproduces the historical
              layer-0 layout byte-for-byte.
    """
    from ctypes import c_uint8, Structure
    from model_meta import resolve_descriptor

    ents = resolve_descriptor(features)
    if len(ents) > ML_MAX_FEAT:
        raise ValueError(
            f"descriptor has {len(ents)} features, exceeds ML_MAX_FEAT={ML_MAX_FEAT} "
            f"(raise ML_MAX_FEAT in ebpf_modular.py and reload to support it)")
    if n_in > 128:  # ML_MAX_N_IN in the eBPF source
        raise ValueError(f"n_in={n_in} exceeds ML_MAX_N_IN=128")

    class FeatEnt(Structure):
        _pack_ = 1
        _fields_ = [("code", c_uint8), ("size", c_uint8),
                    ("col_off", c_uint8), ("scale", c_uint8)]

    class ModelDesc(Structure):
        _pack_ = 1
        _fields_ = [("n_feat", c_uint8), ("n_in", c_uint8),
                    ("_p0", c_uint8), ("_p1", c_uint8),
                    ("feats", FeatEnt * ML_MAX_FEAT)]

    # feat_ent.scale is ONE byte. It used to be written as min(255, scale):
    # a model trained on ttl/300 would have run with ttl/255, silently. 0 is
    # kept -- it means "not declared" and the datapath falls back to its
    # compiled default -- anything else outside the byte is refused.
    for e in ents:
        sc = int(e.get("scale", 0) or 0)
        if not 0 <= sc <= 255:
            raise ValueError(
                f"feature code {e['code']}: scale {sc} does not fit "
                f"feat_ent.scale (one byte, 0..255). Refused rather than "
                f"truncated: the datapath would divide by another number.")

    d = ModelDesc(n_feat=len(ents), n_in=n_in)
    for i, e in enumerate(ents):
        d.feats[i] = FeatEnt(code=e["code"], size=e["size"],
                             col_off=e["col_off"],
                             scale=int(e.get("scale", 0) or 0))
    bpf_obj["model_desc"][c_uint8(model_id)] = d
    print(f"[Pipeline3] model_desc[{model_id}] = n_feat={len(ents)} n_in={n_in} "
          f"feats={[(e['code'], e['size'], e['col_off'], e.get('scale'))
                    for e in ents]}")
