#!/usr/bin/env python3
"""
Throwaway diagnostic: tests whether a properly-constructed ctx_in lets
BPF_PROG_TEST_RUN honor a CHOSEN ctx->ingress_ifindex, instead of the
kernel's sandbox default (empirically 1, see TEST_RUN_DEFAULT_INGRESS_IFINDEX
in verify_prog_run.py).

Hypothesis (from a suggested fix): the prior attempt to pass ctx_in failed
(100% XDP_PASS) not because ingress_ifindex itself is unsettable, but
because data/data_end/data_meta in that ctx_in were wrong -- the kernel's
XDP TEST_RUN handler treats ctx_in->data/data_end as OFFSETS into
data_in/data_size_in (not raw pointers) and is picky about them (in
particular data_end is expected to equal the frame size). An all-zero
ctx_in would have data_end=0, making every XDP program's own
"data_end - data < header_size" bound check fail immediately -- exactly
the observed symptom.

This script builds ctx_in with data=0, data_end=len(frame), data_meta=0,
and a CHOSEN ingress_ifindex, then runs Pipeline 2 (template, raw
ingress_ifindex clamp, easiest to predict) for several candidate ifindex
values and checks whether the kernel's chosen class matches a reference
computed WITH that exact ifindex. If the kernel's answer tracks the
candidate value (not stuck on 1 or defaulting to 0), ctx_in is honored and
the fix is real -- worth adopting; if not, this documents exactly how it
fails so we know not to chase it further.

Needs Linux + BCC + root. Delete after use.
"""
import os
import sys
import ctypes as ct

_TEST_DIR = os.path.dirname(os.path.abspath(__file__))
SHARED_DIR = os.path.dirname(_TEST_DIR)
for _d in (SHARED_DIR, _TEST_DIR):
    if _d not in sys.path:
        sys.path.insert(0, _d)
os.chdir(SHARED_DIR)

from bcc import BPF
import verify_prog_run as V
from verify_multi_model import ref_infer_shape, synth_weights

_libc = ct.CDLL("libc.so.6", use_errno=True)
_SYS_bpf = 321
_BPF_PROG_TEST_RUN = 10


class _XdpMd(ct.Structure):
    _fields_ = [
        ("data",            ct.c_uint32),
        ("data_end",        ct.c_uint32),
        ("data_meta",       ct.c_uint32),
        ("ingress_ifindex", ct.c_uint32),
        ("rx_queue_index",  ct.c_uint32),
        ("egress_ifindex",  ct.c_uint32),
    ]


def prog_test_run_with_ctx(prog_fd: int, frame: bytes, ingress_ifindex: int, repeat: int = 1):
    out = (ct.c_uint8 * 2048)()
    buf = ct.create_string_buffer(frame, len(frame))
    ctx = _XdpMd(data=0, data_end=len(frame), data_meta=0,
                 ingress_ifindex=ingress_ifindex, rx_queue_index=0, egress_ifindex=0)
    a = V._BpfAttrTest(
        prog_fd=prog_fd,
        data_size_in=len(frame),
        data_size_out=ct.sizeof(out),
        data_in=ct.cast(buf, ct.c_void_p).value,
        data_out=ct.cast(out, ct.c_void_p).value,
        repeat=repeat,
        ctx_size_in=ct.sizeof(ctx),
        ctx_in=ct.cast(ct.byref(ctx), ct.c_void_p).value,
    )
    r = _libc.syscall(_SYS_bpf, _BPF_PROG_TEST_RUN, ct.byref(a), ct.sizeof(a))
    if r != 0:
        e = ct.get_errno()
        return None, os.strerror(e)
    return a.retval, None


def main():
    if not sys.platform.startswith("linux"):
        print("Needs Linux + BCC + root.")
        sys.exit(1)

    from ebpf_template_arch import EBPF_TEMPLATE_ARCH_DISPATCHER, EBPF_ARCH_GENERIC_2LAYER, load_arch_weights
    # The real trained 65-4-4-7 model is NOT sensitive to the iface feature
    # (class 0 dominates regardless -- confirmed: ref_val shifts per ifindex
    # but never flips the winner). Use the SAME synthetic weights that
    # already proved sensitive to this exact feature earlier in the session
    # (verify_multi_model.py's P2 model_id=1, seed=1234) so a real signal
    # is actually observable.
    dims = [(65, 6), (6, 5), (5, 7)]
    weights = synth_weights(dims, seed=1234)
    scale = 30
    model_id = 0
    ttl = 3

    src = "#define IPA_ARCH_COMBINED 1\n" + EBPF_TEMPLATE_ARCH_DISPATCHER + "\n" + EBPF_ARCH_GENERIC_2LAYER
    b = BPF(text=src)
    disp_fn = b.load_func("ipa_switch_template", BPF.XDP)
    leaf_fn = b.load_func("arch_generic_2layer", BPF.XDP)
    b["arch_progs"][ct.c_int(0)] = ct.c_int(leaf_fn.fd)
    load_arch_weights(b, weights, model_id=model_id, scale=scale, n_h1=6, n_h2=5)
    V._seed_link_state(b, 1)
    V._install_mac_table(b, "mac_table_t2")

    frame = V.build_frame(model_id, ttl, scale)
    cs = b["cls_stats_t2"]
    ps = b["pkt_stats_t2"]

    print("[diag] Pipeline 2 (raw ctx->ingress_ifindex clamp), synthetic 65-6-5-7 (iface-sensitive), ttl=3, model_id=0")
    print("[diag] For each candidate ifindex: kernel result (via ctx_in) vs reference (that exact ifindex)\n")

    any_varies = False
    prev_kernel_cls = None
    for cand in range(0, 7):
        ref_cls, ref_val = ref_infer_shape(weights, dims, ttl, model_id, ifindex=cand)

        for i in range(7):
            cs[ct.c_int(i)] = ct.c_ulonglong(0)
        for i in range(3):
            ps[ct.c_int(i)] = ct.c_ulonglong(0)
        retval, err = prog_test_run_with_ctx(disp_fn.fd, frame, ingress_ifindex=cand, repeat=1)

        if err is not None:
            print(f"  ifindex={cand}: SYSCALL FAILED ({err})")
            continue

        kernel_cls = None
        for i in range(6):
            if cs[ct.c_int(i)].value > 0:
                kernel_cls = i
                break
        if kernel_cls is None and ps[ct.c_int(2)].value > 0:
            kernel_cls = 6  # DROP
        match = "MATCH" if kernel_cls == ref_cls else "MISMATCH"
        print(f"  ifindex={cand}: retval={retval}  kernel_cls={kernel_cls}  ref_cls={ref_cls}  ref_val={ref_val:>8}  [{match}]")
        if prev_kernel_cls is not None and kernel_cls != prev_kernel_cls:
            any_varies = True
        prev_kernel_cls = kernel_cls

    print()
    if any_varies:
        print("[diag] kernel_cls VARIES across candidate ifindex values -> ctx_in IS honored on this kernel.")
        print("[diag] The proposed ctx_in fix works. Worth adopting for real per-topology ingress tests.")
    else:
        print("[diag] kernel_cls is IDENTICAL for every candidate ifindex -> ctx_in ingress_ifindex is")
        print("[diag] NOT actually reaching the program (still defaulting), or this model isn't sensitive")
        print("[diag] to the iface feature. Check the MISMATCH/MATCH column above for the real signal.")


if __name__ == "__main__":
    main()
