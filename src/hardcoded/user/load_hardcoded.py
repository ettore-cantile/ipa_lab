#!/usr/bin/env python3
"""
load_hardcoded.py — Load and attach the hardcoded IPA/eBPF model programs.

Usage:
    sudo python3 load_hardcoded.py --iface <iface> --model 42 [--config ...]
    sudo python3 load_hardcoded.py --list-ifaces   # show available interfaces

What it does:
    1. Raises RLIMIT_MEMLOCK to RLIM_INFINITY (required for bpf() syscall)
    2. Validates that the requested interface exists
    3. Compiles model_dispatcher.c and model_<id>.c with clang/BPF target
    4. Loads both programs into the kernel via bpftool
    5. Registers model_<id> in the PROG_ARRAY jump table at index model_id
    6. Attaches the dispatcher to the XDP hook on the specified interface
"""

import argparse
import json
import os
import resource
import subprocess
import sys

# ---------------------------------------------------------------------------
# Raise RLIMIT_MEMLOCK before any bpf() syscall (required by libbpf/bpftool)
# ---------------------------------------------------------------------------
def _raise_memlock() -> None:
    try:
        resource.setrlimit(
            resource.RLIMIT_MEMLOCK,
            (resource.RLIM_INFINITY, resource.RLIM_INFINITY)
        )
    except ValueError:
        limit = 256 * 1024 * 1024
        resource.setrlimit(resource.RLIMIT_MEMLOCK, (limit, limit))
        print(f"[warn] RLIMIT_MEMLOCK set to {limit // 1024 // 1024} MiB")

_raise_memlock()

# Add shared/ to path
SHARED_DIR = os.path.join(os.path.dirname(__file__), '..', '..', '..', 'shared')
sys.path.insert(0, SHARED_DIR)
try:
    import common  # noqa: F401
except ImportError:
    print("[warn] shared/common.py not found")

EBPF_DIR    = os.path.join(os.path.dirname(__file__), '..', 'ebpf')
CONFIG_DEFAULT = os.path.join(os.path.dirname(__file__), '..', 'config', 'hardcoded_models.json')


# ---------------------------------------------------------------------------
# Interface helpers
# ---------------------------------------------------------------------------
def list_interfaces() -> list[str]:
    """Return names of all UP network interfaces (excluding loopback)."""
    ifaces = []
    net_path = '/sys/class/net'
    for name in os.listdir(net_path):
        if name == 'lo':
            continue
        operstate_path = os.path.join(net_path, name, 'operstate')
        try:
            state = open(operstate_path).read().strip()
        except OSError:
            state = 'unknown'
        ifaces.append((name, state))
    return ifaces


def validate_iface(iface: str) -> None:
    """Exit with a helpful message if the interface does not exist."""
    if not os.path.exists(f'/sys/class/net/{iface}'):
        available = list_interfaces()
        print(f'[error] Interface "{iface}" not found.', file=sys.stderr)
        print('[info]  Available interfaces:', file=sys.stderr)
        for name, state in available:
            print(f'          {name:20s}  state={state}', file=sys.stderr)
        print('[hint]  Re-run with --iface <name> using one of the above.', file=sys.stderr)
        sys.exit(1)


# ---------------------------------------------------------------------------
# BPF compilation
# ---------------------------------------------------------------------------
def compile_bpf(src: str, out: str) -> None:
    cmd = [
        'clang', '-O2', '-g', '-target', 'bpf',
        '-D__TARGET_ARCH_x86',
        '-I', '/usr/include',
        '-c', src, '-o', out
    ]
    print(f'[compile] {" ".join(cmd)}')
    subprocess.run(cmd, check=True)


# ---------------------------------------------------------------------------
# Load & attach
# ---------------------------------------------------------------------------
def load_and_attach(iface: str, model_id: int, config: dict) -> None:
    dispatcher_obj = os.path.join(EBPF_DIR, 'model_dispatcher.o')
    model_src      = os.path.join(EBPF_DIR, f'model_{model_id}.c')
    model_obj      = os.path.join(EBPF_DIR, f'model_{model_id}.o')

    compile_bpf(os.path.join(EBPF_DIR, 'model_dispatcher.c'), dispatcher_obj)
    compile_bpf(model_src, model_obj)

    pin_dispatcher = f'/sys/fs/bpf/dispatcher_{iface}'
    pin_model      = f'/sys/fs/bpf/model_{model_id}'

    for pin in (pin_dispatcher, pin_model):
        if os.path.exists(pin):
            os.remove(pin)

    # Load dispatcher into kernel + attach to XDP hook
    print(f'[load] dispatcher → {iface} (XDP)')
    subprocess.run(['bpftool', 'prog', 'load', dispatcher_obj, pin_dispatcher], check=True)
    subprocess.run(
        ['ip', 'link', 'set', 'dev', iface, 'xdp', 'obj', dispatcher_obj, 'sec', 'xdp'],
        check=True
    )

    # Load model program
    print(f'[load] model_{model_id} → jump table index {model_id}')
    subprocess.run(['bpftool', 'prog', 'load', model_obj, pin_model], check=True)

    # Wire model into PROG_ARRAY jump table
    import json as _json
    result = subprocess.run(
        ['bpftool', 'prog', 'show', 'pinned', pin_dispatcher, '--json'],
        capture_output=True, text=True, check=True
    )
    prog_info = _json.loads(result.stdout)
    map_ids = prog_info.get('map_ids', [])
    if map_ids:
        jmp_map_id = map_ids[0]
        model_info = _json.loads(
            subprocess.run(
                ['bpftool', 'prog', 'show', 'pinned', pin_model, '--json'],
                capture_output=True, text=True, check=True
            ).stdout
        )
        model_prog_id = model_info['id']
        subprocess.run(
            ['bpftool', 'map', 'update', 'id', str(jmp_map_id),
             'key', *[str(b) for b in model_id.to_bytes(4, 'little')],
             'value', 'id', str(model_prog_id)],
            check=True
        )
        print(f'[ok] Jump table map {jmp_map_id}: index {model_id} → prog id {model_prog_id}')
    else:
        print('[warn] model_jmp_table not found — update manually with bpftool')

    print(f'[ok] Hardcoded model {model_id} loaded and attached on {iface}')
    print(f'[hint] To detach: sudo ip link set dev {iface} xdp off')


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def main():
    if os.geteuid() != 0:
        print('[error] Must be run as root (sudo)', file=sys.stderr)
        sys.exit(1)

    parser = argparse.ArgumentParser(description='Load hardcoded IPA/eBPF model')
    parser.add_argument('--iface', help='Network interface name')
    parser.add_argument('--model', type=int, default=42, help='Model ID (default: 42)')
    parser.add_argument('--config', default=CONFIG_DEFAULT, help='Model registry JSON')
    parser.add_argument('--list-ifaces', action='store_true',
                        help='List available network interfaces and exit')
    args = parser.parse_args()

    if args.list_ifaces:
        print('[info] Available interfaces:')
        for name, state in list_interfaces():
            print(f'  {name:20s}  state={state}')
        sys.exit(0)

    if not args.iface:
        parser.error('--iface is required (use --list-ifaces to see options)')

    validate_iface(args.iface)

    with open(args.config) as f:
        config = json.load(f)

    load_and_attach(args.iface, args.model, config)


if __name__ == '__main__':
    main()
