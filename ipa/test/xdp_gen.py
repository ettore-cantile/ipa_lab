#!/usr/bin/env python3
"""Generatore XDP: frame gia' in forma di xdp_frame, senza skb e senza copia.

PERCHE'. Con pktgen ogni pacchetto e' un skb, e il veth che lo riceve con XDP
lo deve COPIARE per dargli i 256 byte di headroom che XDP pretende (pktgen ne
riserva 64). E' costo del trasporto, non della pipeline, e su una NIC vera con
XDP nativo non c'e': il driver consegna al programma il frame grezzo. Il tetto
di sola ricezione misurato con pktgen (rxonly, ~4,8 Mpps) contiene quella
copia.

COME. BPF_PROG_TEST_RUN con BPF_F_TEST_XDP_LIVE_FRAMES (kernel >= 5.18): il
kernel esegue un programma XDP su frame presi da una sua page_pool, e il
verdetto viene ESEGUITO davvero. Il programma qui fa bpf_redirect verso il lato
generatore della coppia veth; veth_xdp_xmit mette l'xdp_frame direttamente nel
ring del lato DUT, e il programma del DUT lo vede come lo vedrebbe da un
driver: niente skb, niente copia. E' lo stesso meccanismo di xdp-trafficgen
(xdp-tools), riscritto qui per due motivi: xdp-trafficgen genera i SUOI
pacchetti, e le pipeline riconoscono il modello dal primo byte del payload di
pktgen (PKTGEN_MAGIC_MODEL_ID); e serve il conteggio dei tentativi dentro la
finestra stazionaria del banco.

I FRAME SI RICICLANO. In modalita' live il kernel inizializza il contenuto di
una pagina solo quando la page_pool la crea, non quando la ricicla. Il DUT
modifica il frame (TTL, checksum, MAC) prima di rediregerlo, e la pagina torna
alla page_pool del generatore cosi' com'e': senza rimedio il TTL scenderebbe a
ogni giro fino alla scadenza -- lo stesso difetto gia' trovato nel banco a
BPF_PROG_TEST_RUN (claims E2). Il programma generatore RISCRIVE quindi a ogni
esecuzione le prime HDR_COPY byte (Ethernet, IPv4, UDP e l'inizio del payload)
da un modello in una mappa.

LIMITE. Niente cadenza: il test_run spinge al massimo. Serve per la capacita'
(fase saturazione), non per un rate offerto fissato.

USO (sonda di fattibilita', confronta i due generatori sulla stessa coppia veth
e lo stesso ricevitore, nella stessa sessione):

    sudo python3 ipa/test/xdp_gen.py --rounds 3
"""
import argparse
import ctypes as ct
import os
import socket
import struct
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))

_BPF_SYSCALL_NR = {"x86_64": 321, "aarch64": 280}
BPF_PROG_TEST_RUN = 10
BPF_F_TEST_XDP_LIVE_FRAMES = 1 << 1

# Byte riscritti a ogni esecuzione: Ethernet 14 + IPv4 20 + UDP 8 + i primi
# 6 del payload, cioe' tutto cio' che il DUT tocca (MAC, TTL, checksum IP) piu'
# il byte del modello, con margine.
HDR_COPY = 48

# Frame per chiamata. Una chiamata blocca il thread finche' non li ha mandati
# tutti; e' quindi anche la granularita' dello stop (~15-30 ms a 2-4 Mpps).
CALL_FRAMES = 1 << 16

PKTGEN_MAGIC = 0xBE9BE955      # net/core/pktgen.c: primo byte 0xBE = model_id


class _AttrTestRun(ct.Structure):
    """union bpf_attr, ramo `test` (BPF_PROG_TEST_RUN), fino a batch_size."""
    _fields_ = [("prog_fd", ct.c_uint32), ("retval", ct.c_uint32),
                ("data_size_in", ct.c_uint32), ("data_size_out", ct.c_uint32),
                ("data_in", ct.c_uint64), ("data_out", ct.c_uint64),
                ("repeat", ct.c_uint32), ("duration", ct.c_uint32),
                ("ctx_size_in", ct.c_uint32), ("ctx_size_out", ct.c_uint32),
                ("ctx_in", ct.c_uint64), ("ctx_out", ct.c_uint64),
                ("flags", ct.c_uint32), ("cpu", ct.c_uint32),
                ("batch_size", ct.c_uint32), ("_pad", ct.c_uint32)]


assert ct.sizeof(_AttrTestRun) == 80

_libc = None


def _bpf(cmd, attr):
    global _libc
    import platform
    nr = _BPF_SYSCALL_NR.get(platform.machine())
    if nr is None:
        raise RuntimeError(f"bpf(2): numero di syscall ignoto per "
                           f"{platform.machine()}")
    if _libc is None:
        _libc = ct.CDLL("libc.so.6", use_errno=True)   # CDLL: rilascia il GIL
    return _libc.syscall(nr, cmd, ct.byref(attr), ct.sizeof(attr))


def _csum16(data):
    if len(data) % 2:
        data += b"\0"
    s = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def build_frame(frame_size, src_mac, dst_mac="02:00:00:00:00:02",
                src_ip="10.0.0.1", dst_ip="10.0.0.2", sport=1234, dport=9999,
                ttl=32):
    """Il frame che pktgen manda con i parametri del banco (pg_set_params):
    stessa lunghezza (pkt_size meno i 4 byte di FCS), stessi indirizzi e
    porte, TTL 32 come pktgen, checksum UDP a zero come pktgen senza
    UDPCSUM, e in testa al payload il suo header -- magic 0xBE9BE955 poi
    seq/tv a zero, che le pipeline non leggono."""
    length = frame_size - 4
    mac = lambda m: bytes(int(x, 16) for x in m.split(":"))   # noqa: E731
    eth = mac(dst_mac) + mac(src_mac) + b"\x08\x00"
    payload_len = length - 14 - 20 - 8
    if payload_len < 16:
        raise ValueError(f"frame {frame_size}B: troppo corto per l'header "
                         f"di pktgen")
    payload = struct.pack("!IIII", PKTGEN_MAGIC, 0, 0, 0)
    payload += b"\0" * (payload_len - len(payload))
    udp = struct.pack("!HHHH", sport, dport, 8 + payload_len, 0)
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + 8 + payload_len, 0, 0,
                     ttl, 17, 0, socket.inet_aton(src_ip),
                     socket.inet_aton(dst_ip))
    ip = ip[:10] + struct.pack("!H", _csum16(ip)) + ip[12:]
    frame = eth + ip + udp + payload
    assert len(frame) == length, (len(frame), length)
    return frame


GEN_SRC = r"""
#include <uapi/linux/bpf.h>
struct hdr_t { __u8 b[HDR_COPY]; };
BPF_ARRAY(gen_hdr, struct hdr_t, 1);
BPF_PERCPU_ARRAY(gen_runs, __u64, 1);   /* tentativi: uno per esecuzione */
int xdp_gen(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *end = (void *)(long)ctx->data_end;
    int k = 0;
    __u64 *n = gen_runs.lookup(&k);
    if (n) *n += 1;
    if (data + HDR_COPY > end) return XDP_ABORTED;
    struct hdr_t *h = gen_hdr.lookup(&k);
    if (!h) return XDP_ABORTED;
    /* il frame torna dalla page_pool com'e' stato lasciato dal DUT */
    __builtin_memcpy(data, h->b, HDR_COPY);
    return bpf_redirect(TARGET_IFINDEX, 0);
}
"""


def _mac_of(dev):
    with open(f"/sys/class/net/{dev}/address") as f:
        return f.read().strip()


def xmit_counters(dev):
    """(inviati, rifiutati) da veth_xdp_xmit verso il peer di `dev`, dai
    contatori ethtool per coda. Troppo lento (un processo) per le letture
    della finestra: serve da controprova sui totali. None se ethtool non ha
    quelle chiavi."""
    import bench_throughput as BT
    st = BT.ethtool_stats(dev)
    if not st:
        return None
    ok = sum(v for k, v in st.items() if k.endswith("xdp_xmit"))
    err = sum(v for k, v in st.items() if k.endswith("xdp_xmit_errors"))
    if not any(k.endswith("xdp_xmit") for k in st):
        return None
    return ok, err


class XdpGen:
    """Stessa interfaccia del Generator di bench_throughput per cio' che
    serve alla finestra stazionaria: steady(), run(), n_inst, names."""

    kind = "xdp"
    window_mode = "steady"
    clone = burst = 0
    rate_estimate = 0

    def __init__(self, target_dev, plan, window_s=0.3,
                 dst_mac="02:00:00:00:00:02", dst_ip="10.0.0.2"):
        from bcc import BPF
        self.target = target_dev
        self.ifindex = socket.if_nametoindex(target_dev)
        self.cpus = list(plan.gen) or [0]
        self.window_s = window_s
        self.dst_mac, self.dst_ip = dst_mac, dst_ip
        self.src_mac = _mac_of(target_dev)
        self.b = BPF(text=GEN_SRC, cflags=[f"-DHDR_COPY={HDR_COPY}",
                                          f"-DTARGET_IFINDEX={self.ifindex}"])
        self.fn = self.b.load_func("xdp_gen", BPF.XDP)
        self.last_run = None
        self._frame = None

    @property
    def names(self):
        return [f"xdpgen@cpu{c}" for c in self.cpus]

    @property
    def n_inst(self):
        return len(self.cpus)

    def attach(self, verbose=True):
        if verbose:
            print(f"  [INFO] generatore XDP (live frames): {self.n_inst} "
                  f"thread su cpu {','.join(map(str, self.cpus))} -> "
                  f"redirect su {self.target} (ifindex {self.ifindex})")
        return self

    def detach(self):
        pass

    def ensure(self):
        pass

    def delay_for(self, total_pps):
        return 0                      # nessuna cadenza: solo massima spinta

    def window_count(self, total_pps, seconds=None):
        return CALL_FRAMES

    def warmup(self, frame, delay=0, seconds=None):
        return None

    # -- il frame --------------------------------------------------------
    def _set_frame(self, frame_size):
        if self._frame is not None and self._frame[0] == frame_size:
            return self._frame[1]
        data = build_frame(frame_size, self.src_mac, self.dst_mac,
                           dst_ip=self.dst_ip)
        hdr = self.b["gen_hdr"]
        v = hdr.Leaf()
        ct.memmove(ct.byref(v), data[:HDR_COPY], HDR_COPY)
        hdr[ct.c_int(0)] = v
        buf = ct.create_string_buffer(data, len(data))
        self._frame = (frame_size, buf, len(data))
        return buf

    def _test_run(self, buf, size, frames):
        attr = _AttrTestRun(prog_fd=self.fn.fd, data_size_in=size,
                            data_in=ct.cast(buf, ct.c_void_p).value,
                            repeat=frames, flags=BPF_F_TEST_XDP_LIVE_FRAMES)
        if _bpf(BPF_PROG_TEST_RUN, attr) < 0:
            e = ct.get_errno()
            raise OSError(e, f"BPF_PROG_TEST_RUN live frames: "
                             f"{os.strerror(e)}")

    def _runs(self):
        vals = self.b["gen_runs"][ct.c_int(0)]
        return {c: int(vals[c]) for c in self.cpus if c < len(vals)}

    # -- una chiamata per thread (le sonde) ------------------------------
    def run(self, frame, count, delay):
        import bench_throughput as BT
        buf = self._set_frame(frame)
        size = self._frame[2]
        before = sum(self._runs().values())
        t0 = time.monotonic()
        errs = []

        def one(cpu):
            try:
                os.sched_setaffinity(0, {cpu})
                self._test_run(buf, size, max(1, count))
            except OSError as e:
                errs.append(e)
        ths = [threading.Thread(target=one, args=(c,)) for c in self.cpus]
        for t in ths:
            t.start()
        for t in ths:
            t.join()
        if errs:
            raise RuntimeError(str(errs[0]))
        secs = max(1e-9, time.monotonic() - t0)
        tx = sum(self._runs().values()) - before
        r = BT.GenRun(tx, int(tx / secs), secs, wall=secs)
        self.last_run = r
        return r

    def timed_run(self, frame, delay, seconds=None):
        return self.steady(frame, delay, seconds=seconds)

    # -- la finestra stazionaria -----------------------------------------
    def steady(self, frame, delay, probe=None, seconds=None):
        """Come Generator.steady. I respinti non si leggono nella finestra
        (sono solo in ethtool, troppo lento per una lettura da 3 ms): si
        stimano come tentativi meno HIT del DUT, se la sonda porta `hit`;
        `xmit_ethtool` porta la controprova sui totali di ethtool."""
        import bench_throughput as BT
        if delay:
            raise RuntimeError("il generatore XDP non ha cadenza: solo "
                               "massima spinta (delay 0)")
        seconds = self.window_s if seconds is None else seconds
        buf = self._set_frame(frame)
        size = self._frame[2]
        stop = threading.Event()
        errs = []

        def loop(cpu):
            try:
                os.sched_setaffinity(0, {cpu})
                while not stop.is_set():
                    self._test_run(buf, size, CALL_FRAMES)
            except OSError as e:
                errs.append(e)
                stop.set()

        eth0 = xmit_counters(self.target)
        base = self._runs()
        ths = [threading.Thread(target=loop, args=(c,), daemon=True)
               for c in self.cpus]
        t0 = time.monotonic()
        for t in ths:
            t.start()
        try:
            while True:
                now = self._runs()
                if all(now.get(c, 0) > base.get(c, 0) for c in self.cpus):
                    break
                if errs:
                    raise RuntimeError(f"generatore XDP: {errs[0]}")
                if time.monotonic() - t0 > BT.STEADY_START_TIMEOUT_S:
                    raise BT.PktgenEmptyRun(
                        "generatore XDP: non tutti i thread sono partiti")
                time.sleep(0.002)
            time.sleep(BT.STEADY_SETTLE_S)

            def snap():
                for _ in range(BT.STEADY_READ_TRIES):
                    a = time.monotonic()
                    g = self._runs()
                    d = probe() if probe else {}
                    z = time.monotonic()
                    if z - a <= BT.STEADY_READ_MAX_S:
                        return (a + z) / 2.0, g, d, z - a
                raise BT.PktgenEmptyRun("letture dei contatori mai "
                                        "istantanee")
            ta, ga, da, ra = snap()
            time.sleep(max(0.0, ta + seconds - time.monotonic()))
            tb, gb, db, rb = snap()
            vivi = all(t.is_alive() for t in ths)
        finally:
            stop.set()
            for t in ths:
                t.join(timeout=5.0)
        eth1 = xmit_counters(self.target)
        if errs:
            raise RuntimeError(f"generatore XDP: {errs[0]}")
        if not vivi:
            raise BT.PktgenEmptyRun("un thread del generatore XDP si e' "
                                    "fermato prima della seconda lettura")
        secs = tb - ta
        dut = {k: db[k] - da.get(k, 0) for k in db}
        offered = sum(gb[c] - ga.get(c, 0) for c in self.cpus)
        # Accettati = tutto cio' che il programma del DUT ha elaborato, con
        # qualunque esito (HIT, MISS, DROP): i respinti sono il resto dei
        # tentativi. La controprova e' in `xmit_ethtool`.
        if "hit" in dut:
            done = dut["hit"] + dut.get("miss", 0) + dut.get("drop", 0)
            errors = max(0, offered - done)
        else:
            errors = 0
        per_dev = [dict(dev=f"xdpgen@cpu{c}", tx=gb[c] - ga.get(c, 0),
                        pps=int((gb[c] - ga.get(c, 0)) / secs),
                        secs=round(secs, 4), errors=0) for c in self.cpus]
        run = BT.GenRun(offered - errors, int(offered / secs), secs,
                        per_dev=per_dev, wall=secs, errors=errors)
        run.steady = True
        run.dut = dut
        run.start_offset_ms = None
        run.read_ms = round(1000.0 * max(ra, rb), 2)
        run.xmit_ethtool = None
        if eth0 and eth1:
            ok, err = eth1[0] - eth0[0], eth1[1] - eth0[1]
            run.xmit_ethtool = (ok, err)
        self.last_run = run
        return run


# ==========================================================================
# Sonda di fattibilita': pktgen contro generatore XDP, stesso ricevitore
# ==========================================================================
def main():
    ap = argparse.ArgumentParser(description=__doc__.split("USO")[0].strip())
    ap.add_argument("--rounds", type=int, default=3)
    ap.add_argument("--frame", type=int, default=64)
    ap.add_argument("--duration", type=float, default=0.3)
    a = ap.parse_args()
    if os.geteuid() != 0:
        sys.exit("serve root")
    for s in (sys.stdout, sys.stderr):
        try:
            s.reconfigure(line_buffering=True)
        except (AttributeError, ValueError):
            pass

    import bench_throughput as BT
    from bcc import BPF
    from common import attach_xdp

    if not BT.pg_available():
        sys.exit("pktgen assente")
    BT.pg_reset()
    plan = BT.plan_cpus()
    plan.describe()
    rx_dev, tx_dev, _ = BT.make_shared_tg_link(len(plan.gen),
                                               max(len(plan.dut),
                                                   len(plan.gen)))
    cnt = BPF(text=BT.GEN_COUNTER_SRC % {"action": "XDP_DROP"})
    fn = cnt.load_func("xdp_gen_count", BPF.XDP)
    napi = []
    rows = []
    try:
        attach_xdp(cnt, fn, rx_dev)
        if BT.enable_threaded_napi([rx_dev], plan):
            napi = [rx_dev]
        probe = (lambda: {"rx": BT._percpu_sum(cnt["gen_rx"]),
                          "hit": BT._percpu_sum(cnt["gen_rx"])})
        pg = BT.Generator([tx_dev], plan, window_s=a.duration,
                          window_mode="steady").attach()
        xg = XdpGen(tx_dev, plan, window_s=a.duration).attach()
        print(f"\n  {'giro':>4s} {'generatore':10s} {'offerti':>9s} "
              f"{'accettati':>9s} {'RX':>9s} {'resp':>7s}  controprova ethtool")
        for rnd in range(1, a.rounds + 1):
            for name, g in (("pktgen", pg), ("xdp", xg)):
                try:
                    r = g.steady(a.frame, 0, probe)
                except Exception as e:
                    print(f"  {rnd:4d} {name:10s} FALLITO: "
                          f"{type(e).__name__}: {e}")
                    continue
                s = r.window
                off = (r.tx + r.errors) / s
                acc = r.tx / s
                rx = r.dut["rx"] / s
                resp = 100.0 * r.errors / max(1, r.tx + r.errors)
                eth = ""
                xe = getattr(r, "xmit_ethtool", None)
                if xe:
                    tot = xe[0] + xe[1]
                    eth = (f"xdp_xmit {xe[0]} errori {xe[1]} "
                           f"({100.0 * xe[1] / max(1, tot):.1f}%)")
                elif name == "xdp":
                    eth = "chiavi xdp_xmit non trovate in ethtool -S"
                print(f"  {rnd:4d} {name:10s} {off / 1e6:8.3f}M "
                      f"{acc / 1e6:8.3f}M {rx / 1e6:8.3f}M {resp:6.2f}%  {eth}")
                rows.append((name, rx))
        pg.detach()
        BT.pg_reset()
    finally:
        if napi:
            BT.disable_threaded_napi(napi)
        BT._detach(rx_dev)
        BT.del_tg_links(1)
    for name in ("pktgen", "xdp"):
        v = sorted(rx for n, rx in rows if n == name)
        if v:
            print(f"\n  {name:7s} RX mediana {v[len(v) // 2] / 1e6:.3f} Mpps "
                  f"[{v[0] / 1e6:.3f}-{v[-1] / 1e6:.3f}] su {len(v)} giri")
    print("\n  Stesso ricevitore (contatore che scarta, NAPI in thread sulle "
          "CPU DUT), stessa coppia veth, giri alternati: la differenza fra "
          "le due mediane e' il costo di skb e copia di headroom sul lato "
          "DUT, piu' cio' che cambia nel generatore.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
