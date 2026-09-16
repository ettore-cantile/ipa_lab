#!/usr/bin/env python3
"""
make_lab.py -- assemble the runnable Kathara lab for this experiment.

Why this exists
---------------
Kathara mounts a directory literally named `shared/`, sitting in the lab root,
at /shared inside every machine. That convention is what used to keep the whole
engine parked at `<repo>/shared/`: the core could not move without breaking the
mount, so the emulator's layout dictated the project's layout.

The dependency now points the other way. The core lives in `<repo>/ipa/` and
knows nothing about Kathara. This script COPIES what a node needs into
`lab/shared/`, which makes the direction explicit and checkable:

    ipa/                      (core, scenario-free)
    experiments/kathara_germany50/
        traffic/  host_setup/ (this experiment's scripts)
        make_lab.py  ------>  lab/shared/   (assembled, disposable)
                              lab/lab.conf, lab/<node>.startup

Nothing under ipa/ imports anything from here, and `lab/` is generated output:
delete it and re-run.

Usage
-----
    python3 genera_lab.py                 # lab.conf + <node>.startup into lab/
    python3 make_lab.py                   # populate lab/shared/
    cd lab && kathara lstart

    python3 make_lab.py --check           # report what would be copied, copy nothing
    python3 make_lab.py --link-headers DIR  # symlink/copy a host header tree in
"""
import argparse
import os
import shutil
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
CORE = os.path.join(REPO, "ipa")
LAB = os.path.join(HERE, "lab")
MOUNT = os.path.join(LAB, "shared")

# Directories under ipa/ that a NODE needs at runtime. The benches and the
# torch-only paths are deliberately included: the kernel suite runs on a node.
CORE_INCLUDE = ["methods", "poc_aot", "synth", "test"]

# Never copied into a node: caches, and the host header tree (huge, and placed
# separately by --link-headers / host_setup/fetch_host_headers.sh).
SKIP_NAMES = {"__pycache__", "host_headers", ".pytest_cache"}


def _copy_tree(src, dst, report):
    for root, dirs, files in os.walk(src):
        dirs[:] = [d for d in dirs if d not in SKIP_NAMES]
        rel = os.path.relpath(root, src)
        target = dst if rel == "." else os.path.join(dst, rel)
        os.makedirs(target, exist_ok=True)
        for f in files:
            if f.endswith((".pyc", ".pyo")):
                continue
            shutil.copy2(os.path.join(root, f), os.path.join(target, f))
            report.append(os.path.relpath(os.path.join(target, f), MOUNT))


def assemble(check=False, headers=None):
    if not os.path.isdir(CORE):
        sys.exit(f"[make_lab] core not found at {CORE}")
    report = []

    if check:
        print(f"[make_lab] would assemble {MOUNT} from:")
        print(f"  core     : {CORE}  (top-level *.py/*.json/*.pt + {CORE_INCLUDE})")
        print(f"  traffic  : {os.path.join(HERE, 'traffic')}")
        print(f"  host_setup: {os.path.join(HERE, 'host_setup')}")
        print("  scenario : topology_config.json, scenario.json")
        if headers:
            print(f"  headers  : {headers} -> shared/host_headers")
        return 0

    if os.path.isdir(MOUNT):
        shutil.rmtree(MOUNT)
    os.makedirs(MOUNT)

    # 1. core: top-level files + the package subdirectories a node runs
    for name in sorted(os.listdir(CORE)):
        if name in SKIP_NAMES:
            continue
        src = os.path.join(CORE, name)
        if os.path.isdir(src):
            if name in CORE_INCLUDE:
                _copy_tree(src, os.path.join(MOUNT, name), report)
        elif name.endswith((".py", ".json", ".pt")):
            shutil.copy2(src, os.path.join(MOUNT, name))
            report.append(name)

    # 2. this experiment's scripts, flat at /shared so the startups and the
    #    docs' `python3 /shared/<x>.py` invocations keep working
    for sub in ("traffic", "host_setup"):
        d = os.path.join(HERE, sub)
        if os.path.isdir(d):
            for f in sorted(os.listdir(d)):
                if f in SKIP_NAMES:
                    continue
                shutil.copy2(os.path.join(d, f), os.path.join(MOUNT, f))
                report.append(f)

    # 3. the scenario config, at the path the nodes' startup scripts install
    #    from. This is the file that tells the engine 6/52/4 -- the engine has
    #    no built-in topology any more.
    for f in ("topology_config.json", "scenario.json"):
        src = os.path.join(HERE, f)
        if os.path.exists(src):
            shutil.copy2(src, os.path.join(MOUNT, f))
            report.append(f)

    # 4. optional host kernel headers for BCC
    if headers:
        dst = os.path.join(MOUNT, "host_headers")
        if not os.path.isdir(headers):
            sys.exit(f"[make_lab] --link-headers: {headers} is not a directory")
        print(f"[make_lab] copying header tree {headers} -> {dst} (this is slow)")
        shutil.copytree(headers, dst)

    print(f"[make_lab] assembled {len(report)} files into {MOUNT}")
    print(f"[make_lab] next: cd {LAB} && kathara lstart")
    if not headers:
        print("[make_lab] NOTE: shared/host_headers is absent. BCC on the nodes "
              "needs it -- run host_setup/fetch_host_headers.sh on the Linux "
              "host, then re-run with --link-headers <tree>.")
    return 0


def main():
    p = argparse.ArgumentParser(description=__doc__.split("Usage")[0].strip(),
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--check", action="store_true",
                   help="print what would be copied and exit")
    p.add_argument("--link-headers", metavar="DIR", default=None,
                   help="host kernel header tree to place at shared/host_headers")
    a = p.parse_args()
    sys.exit(assemble(check=a.check, headers=a.link_headers))


if __name__ == "__main__":
    main()
