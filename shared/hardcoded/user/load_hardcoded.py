#!/usr/bin/env python3
"""
load_hardcoded.py — Load and attach the hardcoded IPA/eBPF model programs.

Usage (inside a Kathara container or on the host):
    sudo python3 /shared/hardcoded/user/load_hardcoded.py --iface eth0 --model 42
    sudo python3 /shared/hardcoded/user/load_hardcoded.py --list-ifaces
"""

import argparse
import json
import os
import resource
import subprocess
import sys

# Raise RLIMIT_MEMLOCK before any bpf() syscall
def _raise_memlock() -> None:
    try:
        resource.setrlimit(resource.RLIMIT_MEMLOCK,
                           (resource.RLIM_INFINITY, resource.RLIM_INFINITY))
    except ValueError:
        limit = 256 * 1024 * 1024
        resource.setrlimit(resource.RLIMIT_MEMLOCK, (limit, limit))
        print(f"[warn] RLIMIT_MEMLOCK set to {limit // 1024 // 1024} MiB")

_raise_memlock()

# Paths — works both from /shared/ (Kathara) and from repo root (host)
SCRIPT_DIR  = os.path.dirname(os.path.abspath(__file__))
EBPF_DIR    = os.path.join(SCRIPT_DIR, '..', 'ebpf')
CONFIG_DIR  = os.path.join(SCRIPT_DIR, '..', 'config')
CONFIG_DEFAULT = os.path.join(CONFIG_DIR, 'hardcoded_models.json')

# shared/common.py
sys.path.insert(0, os.path.join(SCRIPT_DIR, '..', '..'))
try:
    import common  # noqa: F401
except ImportError:
    print("[warn] common.py not found")


def list_interfaces():
    ifaces = []
    for name in os.listdir('/sys/class/net'):
        if name == 'lo':
            continue
        try:
            state = open(f'/sys/class/net/{name}/operstate').read().strip()
        except OSError:
            state = 'unknown'
        ifaces.append((name, state))
    return ifaces


def validate_iface(iface: str) -> None:
    if not os.path.exists(f'/sys/class/net/{iface}'):
        print(f'[error] Interface "{iface}" not found.', file=sys.stderr)
        print('[info]  Available interfaces:', file=sys.stderr)
        for name, state in list_interfaces():
            print(f'          {name:20s}  state={state}', file=sys.stderr)
        print('[hint]  Use --list-ifaces to see all options.', file=sys.stderr)
        sys.exit(1)


def compile_bpf(src: str, out: str) -> None:
    cmd = ['clang', '-O2', '-g', '-target', 'bpf',
           '-D__TARGET_ARCH_x86', '-I', '/usr/include',
           '-c', src, '-o', out]
    print(f'[compile] {" ".join(cmd)}')
    subprocess.run(cmd, check=True)


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

    print(f'[load] dispatcher → {iface} (XDP)')
    subprocess.run(['bpftool', 'prog', 'load', dispatcher_obj, pin_dispatcher], check=True)
    subprocess.run(['ip', 'link', 'set', 'dev', iface, 'xdp',
                    'obj', dispatcher_obj, 'sec', 'xdp'], check=True)

    print(f'[load] model_{model_id} → jump table index {model_id}')
    subprocess.run(['bpftool', 'prog', 'load', model_obj, pin_model], check=True)

    import json as _json
    prog_info = _json.loads(
        subprocess.run(['bpftool', 'prog', 'show', 'pinned', pin_dispatcher, '--json'],
                       capture_output=True, text=True, check=True).stdout)
    map_ids = prog_info.get('map_ids', [])
    if map_ids:
        jmp_map_id = map_ids[0]
        model_prog_id = _json.loads(
            subprocess.run(['bpftool', 'prog', 'show', 'pinned', pin_model, '--json'],
                           capture_output=True, text=True, check=True).stdout)['id']
        subprocess.run(
            ['bpftool', 'map', 'update', 'id', str(jmp_map_id),
             'key', *[str(b) for b in model_id.to_bytes(4, 'little')],
             'value', 'id', str(model_prog_id)], check=True)
        print(f'[ok] Jump table map {jmp_map_id}: index {model_id} → prog id {model_prog_id}')
    else:
        print('[warn] model_jmp_table not found — update manually')

    print(f'[ok] Model {model_id} loaded on {iface}')
    print(f'[hint] To detach: ip link set dev {iface} xdp off')


def main():
    if os.geteuid() != 0:
        print('[error] Must be run as root (sudo)', file=sys.stderr)
        sys.exit(1)

    parser = argparse.ArgumentParser(description='Load hardcoded IPA/eBPF model')
    parser.add_argument('--iface', help='Network interface (e.g. eth0 inside Kathara)')
    parser.add_argument('--model', type=int, default=42)
    parser.add_argument('--config', default=CONFIG_DEFAULT)
    parser.add_argument('--list-ifaces', action='store_true')
    args = parser.parse_args()

    if args.list_ifaces:
        for name, state in list_interfaces():
            print(f'  {name:20s}  state={state}')
        sys.exit(0)

    if not args.iface:
        parser.error('--iface required (use --list-ifaces to see options)')

    validate_iface(args.iface)

    with open(args.config) as f:
        config = json.load(f)

    load_and_attach(args.iface, args.model, config)


if __name__ == '__main__':
    main()
