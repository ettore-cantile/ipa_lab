#!/usr/bin/env python3
"""
verify_prog_run.py  --  BPF_PROG_TEST_RUN verifier for the 3 IPA pipelines.

Usage (root, inside Kathara frankfurt container or any BCC host):

    python3 verify_prog_run.py --method hardcoded
    python3 verify_prog_run.py --method template
    python3 verify_prog_run.py --method modular
    python3 verify_prog_run.py --method modular --model-id 3

Exit 0 = all TTLs PASS.  Exit 1 = at least one mismatch.

--- Architecture per professor spec ---

Pipeline 1 - Hardcoded Model (baseline assoluta)
  Un programma eBPF per modello, pesi hardcoded come letterali C, inferenza
  completamente unrolled.  Nessuna BPF map per i pesi, nessuna fwd_table.
  Azione: switch(best_cls) { case 0: bpf_redirect(ifindex0); ... case 6: DROP }
  dispatcher -> tail call -> ipa_switch (tutto in un blocco, max velocita)

Pipeline 2 - Pre-built Architecture Template (compromesso pratico)
  Un programma per forma architetturale (es. arch_65_4_4_7), pesi in
  BPF_ARRAY.  Dispatcher consulta arch_registry[model_id] -> arch_id,
  poi tail call -> arch_65_4_4_7 che legge i pesi da arch_weights[offset+i].
  Azione: bpf_redirect(ifindex[best_cls]) diretto dopo argmax (no fwd_table).
  Aggiornamento modello = sovrascrivere arch_weights, zero recompile.

Pipeline 3 - Modular Neural Pipeline (massima flessibilita)
  La rete e spezzata in layer indipendenti.  Ogni layer e un programma XDP:
    layer_65_4  -> layer_4_4 -> layer_4_7_argmax
  Le attivazioni intermedie sono salvate in BPF_PERCPU_ARRAY scratch.
  Ogni layer fa una tail call al successivo.  Il costo misurato e quello
  di multiple tail calls + letture/scritture scratch per lo stato intermedio.
  Azione finale: bpf_redirect(ifindex[best_cls]) in layer_4_7_argmax.

Perche retval != 3 con BPF_PROG_TEST_RUN:
  bpf_redirect() in sandbox non ha una NIC reale: il kernel esegue il redirect
  logicamente ma restituisce XDP_ABORTED(0), mai XDP_REDIRECT(3).
  Criterio di PASS: retval == 0 (XDP_ABORTED = redirect fire) E
  cls_stats[ref_cls] incrementato (conferma che la classe inferita coincide).

Fixed bug (2026-07-09): _cb() used b[cap['perf']].event(data) which calls
  BCC's automatic struct deserializer.  On libbcc ~0.18 (Kathara container)
  _get_event_class() fails for any struct field typed __u8 / __u32 with:
    'Type: __u8 not recognized. Please define the data with ctypes manually.'
  then calls sys.exit(1), which propagates as SystemExit inside the ctypes
  callback and floods stderr once per packet.
  Fix: define MissEventT2 and MissEventT3 as explicit ctypes.Structure classes
  whose _fields_ match the C struct layout exactly (same field order, types,
  pack=1).  Replace .event(data) with ctypes.cast(data, ctypes.POINTER(...))
  in _cb(), bypassing BCC's type decoder entirely.
"""

import os
import sys
import json
import struct
import argparse
import ctypes as ct

from bcc import BPF

# ---------------------------------------------------------------------------
# BPF_PROG_TEST_RUN via raw syscall (libbcc legacy: no bpf_prog_test_run)
# ---------------------------------------------------------------------------

_libc = ct.CDLL("libc.so.6", use_errno=True)
BPF_PROG_TEST_RUN = 10

class _BpfAttrTest(ct.Structure):
    _fields_ = [
        ("prog_fd",       ct.c_uint32),
        ("retval",        ct.c_uint32),
        ("data_size_in",  ct.c_uint32),
        ("data_size_out", ct.c_uint32),
        ("data_in",       ct.c_uint64),
        ("data_out",      ct.c_uint64),
        ("repeat",        ct.c_uint32),
        ("duration",      ct.c_uint32),
    ]

def prog_test_run(prog_fd: int, frame: bytes, repeat: int = 1):
    out = (ct.c_uint8 * 2048)()
    a = _BpfAttrTest(
        prog_fd       = prog_fd,
        data_size_in  = len(frame),
        data_size_out = ct.sizeof(out),
        data_in       = ct.cast(ct.c_char_p(frame), ct.c_void_p).value,
        data_out      = ct.cast(out, ct.c_void_p).value,
        repeat        = repeat,
    )
    r = _libc.syscall(321, BPF_PROG_TEST_RUN, ct.byref(a), ct.sizeof(a))
    if r != 0:
        e = ct.get_errno()
        raise OSError(e, os.strerror(e))
    return a.retval, a.duration

# ---------------------------------------------------------------------------
# ctypes mirror structs for perf event deserialization.
# BCC ~0.18 cannot auto-decode __u8 / __u32 fields -> 'Type: __u8 not
# recognized'.  We bypass .event() entirely and cast the raw data pointer.
# Layout MUST match the C structs in ebpf_template_arch.py / ebpf_modular.py
# exactly (same field order, same sizes, __attribute__((packed)) -> _pack_=1).
# ---------------------------------------------------------------------------

class MissEventT2(ct.Structure):
    """Mirrors struct miss_event_t2 { __u8 model_id; __u8 ttl;
       __u32 ingress_ifindex; __u8 arch_id; __u64 key; } __packed__"""
    _pack_ = 1
    _fields_ = [
        ("model_id",        ct.c_uint8),
        ("ttl",             ct.c_uint8),
        ("ingress_ifindex", ct.c_uint32),
        ("arch_id",         ct.c_uint8),
        ("key",             ct.c_uint64),
    ]

class MissEventT3(ct.Structure):
    """Mirrors struct miss_event_t3 { __u8 model_id; __u8 ttl;
       __u32 ingress_ifindex; __u8 layer_idx; __u64 key; } __packed__"""
    _pack_ = 1
    _fields_ = [
        ("model_id",        ct.c_uint8),
        ("ttl",             ct.c_uint8),
        ("ingress_ifindex", ct.c_uint32),
        ("layer_idx",       ct.c_uint8),
        ("key",             ct.c_uint64),
    ]

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

SHARED_DIR   = os.path.dirname(os.path.abspath(__file__))
MODEL_PT     = os.path.join(SHARED_DIR, "frr_germany50_5_model_4x2.pt")
WEIGHTS_JSON = os.path.join(SHARED_DIR, "weights_float.json")

# ---------------------------------------------------------------------------
# Weights loader
# ---------------------------------------------------------------------------

def load_weights(model_path=MODEL_PT):
    from extract_weights import extract_weights_int8
    weights = extract_weights_int8(model_path)
    scale = 128
    if os.path.exists(WEIGHTS_JSON):
        with open(WEIGHTS_JSON) as f:
            scale = int(json.load(f).get("scale_factor", 128))
    return weights, scale

# ---------------------------------------------------------------------------
# Frame builder
# ---------------------------------------------------------------------------

def build_frame(model_id: int, ttl: int, scale: int) -> bytes:
    """
    Ethernet / IP / UDP / IPA frame for BPF_PROG_TEST_RUN.
    ingress_ifindex = 0 in the test sandbox (no real NIC).
    """
    eth = b'\x00'*6 + b'\x00'*6 + struct.pack('!H', 0x0800)
    # IP: ttl at byte offset 8 from start of IP header
    ip = struct.pack('!BBHHHBBH4s4s',
                     0x45, 0, 48, 0, 0,
                     ttl, 17, 0,
                     b'\x0a\x00\x00\x01', b'\x0a\x00\x00\x02')
    udp = struct.pack('!HHHH', 12345, 9999, 28, 0)
    # IPA header: model_id, model_type, param_size, scale_factor, input_size,
    # output_size, hidden_layers, neurons_per_layer, n_feature_types,
    # feat0_code, feat0_count, feat1_code, feat1_count,
    # feat2_code, feat2_count, feat3_code, feat3_count,
    # n_output_types, out0_code, out0_count
    ipa = struct.pack('!BBHBBBBBBBBBBBBBBBBb',
                      model_id, 0, scale,
                      65, 7, 2, 4,
                      3,
                      0, 65, 0, 0, 0, 0, 0, 0,
                      1, 0, 7, 0)
    return eth + ip + udp + ipa

# ---------------------------------------------------------------------------
# Python reference inference  (mirrors eBPF quantized arithmetic exactly)
# ---------------------------------------------------------------------------

def ref_infer(weights, scale: int, ttl: int, model_id: int, ifindex: int = 0):
    """
    Returns (best_cls, best_val).
    Feature encoding (must match eBPF exactly):
      x[12]         = ttl
      x[5+ifindex]  = 1   (if 1 <= ifindex <= 6)
      x[13+model_id]= 1   (if 0 <= model_id <= 51)
    In TEST_RUN sandbox: ingress_ifindex=0, so x[5+0]=x[5] is always 0
    (index 5 is in the unused [0..5] block), iface contribution is zero.
    """
    def s8(v):
        return ct.c_int8(int(v) & 0xFF).value

    N_IN, N_H1, N_H2, N_OUT = 65, 4, 4, 7
    off_fc1_b = N_IN * N_H1
    off_fc2_w = off_fc1_b + N_H1
    off_fc2_b = off_fc2_w + N_H1 * N_H2
    off_out_w = off_fc2_b + N_H2
    off_out_b = off_out_w + N_H2 * N_OUT

    x = [0] * N_IN
    x[12] = ttl
    if 1 <= ifindex <= 6:
        x[5 + ifindex] = 1
    if 0 <= model_id <= 51:
        x[13 + model_id] = 1

    h1 = []
    for j in range(N_H1):
        acc = s8(weights[off_fc1_b + j])
        for i in range(N_IN):
            acc += x[i] * s8(weights[j * N_IN + i])
        h1.append(max(0, acc))

    h2 = []
    for j in range(N_H2):
        acc = s8(weights[off_fc2_b + j])
        for i in range(N_H1):
            acc += h1[i] * s8(weights[off_fc2_w + j * N_H1 + i])
        h2.append(max(0, acc))

    best_val, best_cls = -10**9, 0
    for k in range(N_OUT):
        acc = s8(weights[off_out_b + k])
        for i in range(N_H2):
            acc += h2[i] * s8(weights[off_out_w + k * N_H2 + i])
        if acc > best_val:
            best_val, best_cls = acc, k

    return best_cls, best_val

# ---------------------------------------------------------------------------
# Pipeline 1: Hardcoded  (NO fwd_table, pesi hardcoded in C)
# ---------------------------------------------------------------------------

def setup_hardcoded(model_id: int, model_path: str):
    """
    Carica ipa_dispatcher + ipa_switch (Pipeline 1).
    - model_progs[model_id] = fd di ipa_switch  (tail call)
    - model_cache[model_id] popolato con is_valid=1
    - Nessuna fwd_table: l'azione e switch(best_cls)->bpf_redirect(ifindex)
      scritta direttamente nel C generato.
    Verifica: cls_stats[ref_cls] incrementato dopo TEST_RUN su ipa_switch.
    """
    from ebpf_program import generate_ebpf_hardcoded, N_WEIGHTS
    weights, scale = load_weights(model_path)
    src = generate_ebpf_hardcoded(weights, scale, model_id)
    b   = BPF(text=src)
    # Carica sia il dispatcher sia il programma foglia
    fn      = b.load_func("ipa_switch",  BPF.XDP)   # leaf: fa inferenza+redirect
    # Dispatcher (se presente): wire tail-call
    try:
        disp = b.load_func("ipa_dispatcher", BPF.XDP)
        b["model_progs"][ct.c_int(model_id)] = ct.c_int(fn.fd)
    except Exception:
        disp = fn  # il sorgente non ha dispatcher separato

    # Popola model_cache
    class ModelData(ct.Structure):
        _pack_ = 1
        _fields_ = [
            ("weights",      ct.c_uint8 * N_WEIGHTS),
            ("is_valid",     ct.c_uint8),
            ("scale_factor", ct.c_uint16),
        ]
    entry = ModelData(is_valid=1, scale_factor=scale)
    for i, v in enumerate(weights[:N_WEIGHTS]):
        entry.weights[i] = ct.c_uint8(int(v) & 0xFF).value
    b["model_cache"][ct.c_uint8(model_id)] = entry

    return {
        "b":         b,
        "fn":        fn,      # programma usato per TEST_RUN
        "disp":      disp,
        "weights":   weights,
        "scale":     scale,
        "cls_stats": b["cls_stats"],
        "pkt_stats": b["pkt_stats"],
        "pipeline":  1,
    }

# ---------------------------------------------------------------------------
# Pipeline 2: Template  (pesi in arch_weights BPF_ARRAY, NO fwd_table)
# ---------------------------------------------------------------------------

def setup_template(model_id: int, model_path: str):
    """
    Carica ipa_switch_template (dispatcher) + arch_65_4_4_7 (leaf).
    - arch_registry[model_id] = {arch_id=0, weight_offset=0, scale_factor}
    - arch_weights[0..318] = pesi int8 (scritti via ctypes fd-level)
    - arch_progs[0] = fd di arch_65_4_4_7
    - Nessuna fwd_table: arch_65_4_4_7 fa bpf_redirect(ifindex[best_cls]).
    Verifica: pkt_stats_t2[HIT] incrementato dopo TEST_RUN su arch_65_4_4_7.
    """
    from ebpf_template_arch import (
        EBPF_TEMPLATE_ARCH_DISPATCHER,
        EBPF_ARCH_65_4_4_7,
        load_arch_weights,
    )
    weights, scale = load_weights(model_path)
    src = "#define IPA_ARCH_COMBINED 1\n" + \
          EBPF_TEMPLATE_ARCH_DISPATCHER + "\n" + \
          EBPF_ARCH_65_4_4_7
    b       = BPF(text=src)
    disp_fn = b.load_func("ipa_switch_template", BPF.XDP)
    leaf_fn = b.load_func("arch_65_4_4_7",       BPF.XDP)
    b["arch_progs"][ct.c_int(0)] = ct.c_int(leaf_fn.fd)
    load_arch_weights(b, weights, model_id=model_id, scale=scale)
    return {
        "b":         b,
        "fn":        leaf_fn,   # TEST_RUN sul leaf (bypass tail-call sandbox)
        "disp":      disp_fn,
        "weights":   weights,
        "scale":     scale,
        "cls_stats": b["cls_stats_t2"] if "cls_stats_t2" in str(b.tables) else None,
        "pkt_stats": b["pkt_stats_t2"],
        "pipeline":  2,
        "perf_name": "miss_events_t2",
        "perf_cls":  MissEventT2,
    }

# ---------------------------------------------------------------------------
# Pipeline 3: Modular  (un XDP prog per layer, scratch map per attivazioni)
# ---------------------------------------------------------------------------

def setup_modular(model_id: int, model_path: str):
    """
    Carica modular_dispatcher + layer_65_4 + layer_4_4 + layer_4_7_argmax.
    - layer_chain[0..2] = fd dei 3 layer
    - scratch_acts (PERCPU_ARRAY) porta le attivazioni tra layer via tail call
    - Nessuna fwd_table: layer_4_7_argmax fa bpf_redirect(ifindex[best_cls]).
    TEST_RUN sul leaf layer_4_7_argmax: le attivazioni h2 vengono pre-popolate
    in scratch_acts dal test runner tramite _prime_scratch() prima di ogni run.
    Verifica: pkt_stats_t3[HIT] incrementato.
    """
    from ebpf_modular import EBPF_MODULAR_FULL, load_modular_weights
    weights, scale = load_weights(model_path)
    b       = BPF(text=EBPF_MODULAR_FULL)
    disp_fn = b.load_func("modular_dispatcher", BPF.XDP)
    lf0     = b.load_func("layer_65_4",         BPF.XDP)
    lf1     = b.load_func("layer_4_4",          BPF.XDP)
    lf2     = b.load_func("layer_4_7_argmax",   BPF.XDP)
    b["layer_chain"][ct.c_int(0)] = ct.c_int(lf0.fd)
    b["layer_chain"][ct.c_int(1)] = ct.c_int(lf1.fd)
    b["layer_chain"][ct.c_int(2)] = ct.c_int(lf2.fd)
    load_modular_weights(b, weights, model_id=model_id, scale=scale)
    return {
        "b":         b,
        "fn":        lf0,       # TEST_RUN dal primo layer (chain completa)
        "disp":      disp_fn,
        "weights":   weights,
        "scale":     scale,
        "pkt_stats": b["pkt_stats_t3"],
        "pipeline":  3,
        "perf_name": "miss_events_t3",
        "perf_cls":  MissEventT3,
    }

# ---------------------------------------------------------------------------
# Lettura contatori cls_stats / pkt_stats
# ---------------------------------------------------------------------------

def _read_u64(table, key_val):
    try:
        return int(table[ct.c_int(key_val)].value)
    except Exception:
        try:
            return int(table[ct.c_uint32(key_val)].value)
        except Exception:
            return 0

def _reset_stats(setup):
    ps = setup["pkt_stats"]
    for i in range(3):
        ps[ct.c_int(i)] = ct.c_ulonglong(0)
    cs = setup.get("cls_stats")
    if cs is not None:
        for i in range(7):
            try:
                cs[ct.c_uint32(i)] = ct.c_ulonglong(0)
            except Exception:
                pass

# ---------------------------------------------------------------------------
# Perf buffer handler
# ---------------------------------------------------------------------------

def _make_perf_cb(event_cls, label):
    """
    Returns a perf callback that deserializes the event using the provided
    ctypes Structure class instead of BCC's .event() -- which fails on
    libbcc ~0.18 for structs containing __u8 fields.
    """
    def _cb(cpu, data, size):
        if size < ct.sizeof(event_cls):
            return
        ev = ct.cast(data, ct.POINTER(event_cls)).contents
        print(f"  [{label}] miss cpu={cpu} model_id={ev.model_id} "
              f"ttl={ev.ttl} ifindex={ev.ingress_ifindex} key={ev.key:#018x}")
    return _cb

# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------

XDP_PASS    = 2
XDP_ABORTED = 0   # bpf_redirect() nel TEST_RUN sandbox restituisce questo

def run(method: str, model_id: int, model_path: str,
        ttl_min: int, ttl_max: int, repeat: int):
    print("=" * 70)
    print(f" IPA/eBPF BPF_PROG_TEST_RUN  --  method={method}  model_id={model_id}")
    print("=" * 70)
    print()
    print("NOTA: bpf_redirect() in TEST_RUN sandbox -> retval=XDP_ABORTED(0).")
    print("      PASS = retval==0 (redirect fire) + cls_stats/pkt_stats hit.")
    print()

    setup_fn = {"hardcoded": setup_hardcoded,
                "template":  setup_template,
                "modular":   setup_modular}[method]
    setup = setup_fn(model_id, model_path)

    b, fn     = setup["b"], setup["fn"]
    weights   = setup["weights"]
    scale     = setup["scale"]
    ps        = setup["pkt_stats"]
    cs        = setup.get("cls_stats")
    pipeline  = setup["pipeline"]

    # Open perf buffer with manual ctypes deserializer (avoids BCC __u8 crash)
    perf_name = setup.get("perf_name")
    perf_cls  = setup.get("perf_cls")
    if perf_name and perf_cls:
        cb = _make_perf_cb(perf_cls, f"P{pipeline}")
        b[perf_name].open_perf_buffer(cb, page_cnt=8)

    print(f"[setup] scale={scale}  weights={len(weights)}  "
          f"prog_fd={fn.fd}")

    passed = failed = 0
    for ttl in range(ttl_min, ttl_max + 1):
        _reset_stats(setup)
        frame = build_frame(model_id, ttl, scale)
        retval, dur_ns = prog_test_run(fn.fd, frame, repeat=repeat)

        # Drain perf buffer after each run (non-blocking)
        if perf_name and perf_cls:
            b.perf_buffer_poll(timeout=0)

        ref_cls, ref_val = ref_infer(weights, scale, ttl, model_id, ifindex=0)

        # ---- criterio di PASS ----
        # retval==0 significa che bpf_redirect ha sparato (non XDP_PASS=2)
        # Controlliamo anche che pkt_stats[HIT] sia >0 (confirm hit path)
        hit_count = _read_u64(ps, 0)

        # Per Pipeline 1 usiamo anche cls_stats per verificare la classe
        if pipeline == 1 and cs is not None:
            cls_count = _read_u64(cs, ref_cls)
            ok = (retval == XDP_ABORTED) and (cls_count > 0)
            detail = f"retval={retval} cls_stats[{ref_cls}]={cls_count}"
        else:
            ok = (retval == XDP_ABORTED) and (hit_count > 0)
            detail = f"retval={retval} pkt_stats[HIT]={hit_count}"

        # XDP_PASS significa che il pacchetto NON e stato inoltrato (FAIL)
        if retval == XDP_PASS:
            ok = False
            detail += "  <-- XDP_PASS: inferenza non completata o cache miss"

        lat_us = dur_ns / 1000 / repeat
        status = "PASS" if ok else "FAIL"
        if ok:
            passed += 1
        else:
            failed += 1

        print(f"  TTL={ttl:3d}  ref_cls={ref_cls}  ref_val={ref_val:8d}  "
              f"{detail}  lat={lat_us:.2f}us  [{status}]")

    miss  = _read_u64(ps, 1)
    drop  = _read_u64(ps, 2)
    print("-" * 70)
    print(f"Risultati: {passed} PASS / {failed} FAIL  "
          f"(TTL range [{ttl_min},{ttl_max}])")
    print(f"pkt_stats: HIT={_read_u64(ps,0)}  MISS={miss}  DROP={drop}")
    return failed


def main():
    p = argparse.ArgumentParser(description="IPA/eBPF pipeline verifier")
    p.add_argument("--method",   choices=["hardcoded","template","modular"],
                   default="hardcoded")
    p.add_argument("--model-id", type=int, default=0)
    p.add_argument("--model",    default=MODEL_PT)
    p.add_argument("--ttl-min",  type=int, default=1)
    p.add_argument("--ttl-max",  type=int, default=10)
    p.add_argument("--repeat",   type=int, default=1000,
                   help="BPF_PROG_TEST_RUN repeat per misura latenza")
    args = p.parse_args()
    sys.exit(run(args.method, args.model_id, args.model,
                 args.ttl_min, args.ttl_max, args.repeat))


if __name__ == "__main__":
    main()
