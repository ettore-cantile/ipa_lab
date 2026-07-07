#!/usr/bin/env python3
"""
load_hardcoded.py — Load and attach the hardcoded IPA/eBPF model programs.

Usage:
    sudo python3 load_hardcoded.py --iface eth0 --model 42 [--config config/hardcoded_models.json]

What it does:
    1. Raises RLIMIT_MEMLOCK to RLIM_INFINITY (required for bpf() syscall)
    2. Compiles model_dispatcher.c and model_<id>.c with clang/BPF target
    3. Loads both programs into the kernel via bpftool
    4. Registers model_<id> in the PROG_ARRAY jump table at index model_id
    5. Attaches the dispatcher to the XDP hook on the specified interface

Reuses shared/common.py for IPA header utilities.
"""

import argparse
import json
import os
import resource
import subprocess
import sys

# ---------------------------------------------------------------------------
# RLIMIT_MEMLOCK — must be raised BEFORE any bpf() syscall.
# libbpf / bpftool need to lock memory for BPF maps and programs.
# Without this the kernel returns EPERM even when running as root.
# ---------------------------------------------------------------------------
def _raise_memlock() -> None:
    try:
        resource.setrlimit(
            resource.RLIMIT_MEMLOCK,
            (resource.RLIM_INFINITY, resource.RLIM_INFINITY)
        )
    except ValueError:
        # Fallback: set a large fixed value (256 MiB) if INFINITY is rejected
        limit = 256 * 1024 * 1024
        resource.setrlimit(resource.RLIMIT_MEMLOCK, (limit, limit))
        print(f"[warn] RLIMIT_MEMLOCK set to {limit // 1024 // 1024} MiB (INFINITY not allowed)")

_raise_memlock()

# Add shared/ to path for reuse of common.py
SHARED_DIR = os.path.join(os.path.dirname(__file__), '..', '..', '..', 'shared')
sys.path.insert(0, SHARED_DIR)

try:
    import common  # noqa: F401 — shared IPA utilities
except ImportError:
    print("[warn] shared/common.py not found — IPA utilities unavailable")

EBPF_DIR = os.path.join(os.path.dirname(__file__), '..', 'ebpf')
CONFIG_DEFAULT = os.path.join(os.path.dirname(__file__), '..', 'config', 'hardcoded_models.json')


def compile_bpf(src: str, out: str) -> None:
    """Compile a BPF C source file to an ELF object."""
    cmd = [
        'clang', '-O2', '-g', '-target', 'bpf',
        '-D__TARGET_ARCH_x86',
        '-I', '/usr/include',
        '-c', src, '-o', out
    ]
    print(f'[compile] {" ".join(cmd)}')
    subprocess.run(cmd, check=True)


def load_and_attach(iface: str, model_id: int, config: dict) -> None:
    """
    Load dispatcher + model program, wire up the jump table, attach XDP.
    Uses bpftool + ip-link as portable shell commands.
    Replace the jump-table update with a proper libbpf binding for production.
    """
    dispatcher_obj = os.path.join(EBPF_DIR, 'model_dispatcher.o')
    model_src = os.path.join(EBPF_DIR, f'model_{model_id}.c')
    model_obj = os.path.join(EBPF_DIR, f'model_{model_id}.o')

    # Compile
    compile_bpf(os.path.join(EBPF_DIR, 'model_dispatcher.c'), dispatcher_obj)
    compile_bpf(model_src, model_obj)

    # Pin path for the dispatcher program
    pin_dispatcher = f'/sys/fs/bpf/dispatcher_{iface}'
    pin_model     = f'/sys/fs/bpf/model_{model_id}'

    # Remove stale pins if present
    for pin in (pin_dispatcher, pin_model):
        if os.path.exists(pin):
            os.remove(pin)

    # Load dispatcher
    print(f'[load] dispatcher → {iface} (XDP)')
    subprocess.run(
        ['bpftool', 'prog', 'load', dispatcher_obj, pin_dispatcher],
        check=True
    )
    subprocess.run(
        ['ip', 'link', 'set', 'dev', iface, 'xdp',
         'obj', dispatcher_obj, 'sec', 'xdp'],
        check=True
    )

    # Load model program
    print(f'[load] model_{model_id} → jump table index {model_id}')
    subprocess.run(
        ['bpftool', 'prog', 'load', model_obj, pin_model],
        check=True
    )

    # Wire model into the jump table
    # Get the map id of model_jmp_table from the loaded dispatcher
    result = subprocess.run(
        ['bpftool', 'prog', 'show', 'pinned', pin_dispatcher, '--json'],
        capture_output=True, text=True, check=True
    )
    import json as _json
    prog_info = _json.loads(result.stdout)
    map_ids = prog_info.get('map_ids', [])
    if map_ids:
        jmp_map_id = map_ids[0]  # model_jmp_table is the only map
        model_fd_result = subprocess.run(
            ['bpftool', 'prog', 'show', 'pinned', pin_model, '--json'],
            capture_output=True, text=True, check=True
        )
        model_info = _json.loads(model_fd_result.stdout)
        model_prog_id = model_info['id']
        subprocess.run(
            ['bpftool', 'map', 'update', 'id', str(jmp_map_id),
             'key', *[str(b) for b in model_id.to_bytes(4, 'little')],
             'value', 'id', str(model_prog_id)],
            check=True
        )
        print(f'[ok] Jump table map {jmp_map_id}: index {model_id} → prog id {model_prog_id}')
    else:
        print('[warn] Could not find model_jmp_table map — update it manually with bpftool')

    print(f'[ok] Hardcoded model {model_id} loaded and attached on {iface}')


def main():
    if os.geteuid() != 0:
        print('[error] This script must be run as root (sudo)', file=sys.stderr)
        sys.exit(1)

    parser = argparse.ArgumentParser(description='Load hardcoded IPA/eBPF model')
    parser.add_argument('--iface', required=True, help='Network interface name')
    parser.add_argument('--model', type=int, default=42, help='Model ID to load')
    parser.add_argument('--config', default=CONFIG_DEFAULT, help='Model registry JSON')
    args = parser.parse_args()

    with open(args.config) as f:
        config = json.load(f)

    load_and_attach(args.iface, args.model, config)


if __name__ == '__main__':
    main()
