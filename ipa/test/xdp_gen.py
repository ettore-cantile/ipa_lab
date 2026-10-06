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

LA CADENZA (2026-10-02). Il test_run spinge al massimo; il ritmo lo tiene il
programma generatore. Con un intervallo in gen_ctl[0] ogni esecuzione legge
l'orologio: prima dell'istante previsto il frame viene scartato (XDP_DROP: la
pagina torna subito alla page_pool, e il giro costa decine di ns), all'istante
previsto parte e il prossimo e' un intervallo piu' in la'. La spaziatura e'
quindi uniforme, alla risoluzione di un giro, e non a raffiche: una raffica
riempirebbe da sola la coda da 256 posti e farebbe perdere pacchetti sotto
capacita'. Se il thread resta indietro (la chiamata successiva, uno
scheduling) recupera al piu' CATCHUP frame di fila e poi riparte da adesso --
pktgen invece trasmette di fila fino a rimettersi in orario, a qualunque
distanza. Senza recupero (il primo run, 2026-10-02) non recuperava
niente: a ogni fine lotto il thread resta fermo qualche us, e spediva l'80-87%
del chiesto a rate basso, il 45-65% a rate alto. Il redirect accoda nel veth a gruppi (al piu' 16 frame,
DEV_MAP_BULK_SIZE, o a fine lotto): a rate alto i frame arrivano a gruppetti
di quella taglia, a rate basso uno per volta.

IL TIMBRO. Con gen_ctl[2] = 1 il programma scrive in testa al payload
l'intestazione di pktgen completa -- magic, seq, tv_sec, tv_usec in big-endian,
CLOCK_REALTIME in microsecondi (bpf_ktime_get_ns + gen_ctl[1], l'offset fra i
due orologi) -- nell'istante in cui il frame parte. Il contatore d'uscita di
bench_bitrate la legge senza modifiche, e non serve la correzione per
l'attesa fra timbro e trasmissione che pktgen richiede.

USO (sonda di fattibilita', confronta i due generatori sulla stessa coppia veth
e lo stesso ricevitore, nella stessa sessione):

    sudo python3 ipa/test/xdp_gen.py --rounds 3
"""
import argparse
import ctypes as ct
import errno
import os
import signal
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
# tutti; e' quindi anche la granularita' dello stop.
#
# IL POOL DI PAGINE. In modalita' live ogni chiamata crea la sua page_pool e
# la distrugge alla fine, e la pool ricicla al piu' `batch_size` pagine
# (net/bpf/test_run.c, xdp_test_run_setup: pool_size = batch_size; default
# 64, massimo TEST_XDP_MAX_BATCH = 256 -- dal sorgente del kernel, NON
# VERIFICABILE DAL REPOSITORY). Le pipeline tengono in volo piu' frame di cosi'
# (code d'ingresso e d'uscita, 256 posti l'una): le pagine in eccesso tornano
# dalla CPU del DUT e vengono liberate invece che riciclate, un costo che una
# NIC -- pool locale al DUT -- non ha. Primo run 2026-09-23 con 1<<16 e batch
# 64: offerto e RX accoppiati, baseline +156 ns sopra rxonly contro +40 con
# pktgen. Da qui batch al massimo e chiamate lunghe: la pool nasce e muore
# sedici volte meno spesso.
CALL_FRAMES = 1 << 20
BATCH_SIZE = 256
# LA FINESTRA IN UNA CHIAMATA (2026-10-02). Ogni test_run in modalita' live
# parte e finisce con una pausa del thread di ~12 ms dentro il kernel
# (preparazione e smontaggio: dispatcher XDP, page_pool). Con chiamate da
# CALL_FRAMES frame ce n'erano 2-4 per finestra: il generatore taceva il ~13%
# del tempo, il DUT svuotava la coda e dormiva (diagnostica: thread NAPI
# all'87%, 2-3 sonni per finestra quante le chiamate). Per questo il nodo risultava occupato all'~87% anche a coda
# piena, e la cadenza spediva l'~80% del chiesto. steady() fa quindi UNA
# chiamata lunga e la interrompe con un segnale a fine finestra: test_run
# controlla signal_pending e torna con EINTR. La pausa iniziale cade prima
# della prima lettura.
STEADY_CALL_FRAMES = 0xFFFFFFFF
STOP_SIGNAL = signal.SIGUSR1
# Frame che la cadenza puo' spedire di fila per rimettersi in orario: quanti
# il redirect ne accoda comunque insieme (DEV_MAP_BULK_SIZE).
CATCHUP = 16

PKTGEN_MAGIC = 0xBE9BE955      # net/core/pktgen.c: primo byte 0xBE = model_id
PKTGEN_HDR_OFF = 14 + 20 + 8   # l'intestazione di pktgen: subito dopo UDP

# sizeof(struct ipa_hdr) nelle pipeline (verify_prog_run.EBPF_BASELINE e
# compagne): 10 byte fissi + 4 feature x 2 + 1 + 2 output. Un payload piu'
# corto fa fallire il loro controllo sui limiti, e il pacchetto va in XDP_PASS
# senza essere contato: e' cio' che e' successo al primo run, con frame da 60
# byte invece di 64 (vedi build_frame).
IPA_HDR_LEN = 21


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
    stessa lunghezza, stessi indirizzi e porte, TTL 32 come pktgen, checksum
    UDP a zero come pktgen senza UDPCSUM, e in testa al payload il suo header
    -- magic 0xBE9BE955 poi seq/tv a zero.

    LA LUNGHEZZA E' `frame_size`, non frame_size - 4. Il `pkt_size` di pktgen
    e' gia' senza FCS (fill_packet_ipv4: datalen = pkt_size - 14 - 20 - 8), e
    il minimo e' ETH_ZLEN = 60. La prima versione toglieva 4 byte: a 64 il
    payload restava di 18 byte, meno dei 21 di struct ipa_hdr, e tutte le
    pipeline scartavano il frame in XDP_PASS (misurato 2026-09-23: sonda a HIT
    0 per le cinque, rxonly -- che non fa parse -- unica a passare)."""
    length = frame_size
    mac = lambda m: bytes(int(x, 16) for x in m.split(":"))   # noqa: E731
    eth = mac(dst_mac) + mac(src_mac) + b"\x08\x00"
    payload_len = length - 14 - 20 - 8
    if payload_len < max(16, IPA_HDR_LEN):
        raise ValueError(f"frame {frame_size}B: payload di {payload_len} "
                         f"byte, servono {max(16, IPA_HDR_LEN)} (header di "
                         f"pktgen / struct ipa_hdr)")
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


# TRAFFICO MISTO. Con un pacchetto sempre identico la pipeline decide sempre
# la stessa classe: una porta d'uscita, una voce di mac_table, cache e branch
# predictor sempre caldi, e i percorsi DROP / UNUSED mai esercitati. Con
# `ttls` il generatore scrive a ogni frame il TTL successivo della lista (per
# CPU, a giro), con la checksum IP gia' calcolata per quel TTL: il TTL e' una
# feature del modello, quindi le classi decise cambiano con lui.
MIX_MAX = 256

GEN_SRC = r"""
#include <uapi/linux/bpf.h>
struct hdr_t { __u8 b[HDR_COPY]; };
struct mix_t { __u8 ttl; __u8 csum[2]; };
BPF_ARRAY(gen_hdr, struct hdr_t, 1);
BPF_ARRAY(gen_mix, struct mix_t, MIX_SLOTS);
BPF_PERCPU_ARRAY(gen_runs, __u64, 1);   /* tentativi: uno per frame inoltrato */
/* 0 intervallo fra due frame dello stesso thread, ns (0 = massima spinta);
 * 1 CLOCK_REALTIME - CLOCK_MONOTONIC, ns; 2 timbro pktgen (1 = si') */
BPF_ARRAY(gen_ctl, __u64, 3);
BPF_PERCPU_ARRAY(gen_next, __u64, 1);   /* istante del prossimo frame, ns */
/* diagnostica della cadenza: 0 giri d'attesa, 1 azzeramenti (indietro oltre
 * CATCHUP), 2 somma del ritardo di partenza sull'istante previsto, ns */
BPF_PERCPU_ARRAY(gen_dbg, __u64, 3);
int xdp_gen(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *end = (void *)(long)ctx->data_end;
    int k = 0, k_off = 1, k_stamp = 2;
    __u64 now = 0;
    __u64 *iv = gen_ctl.lookup(&k);
    if (iv && *iv) {
        __u64 *nx = gen_next.lookup(&k);
        if (!nx) return XDP_DROP;
        now = bpf_ktime_get_ns();
        int k_spin = 0, k_reset = 1, k_late = 2;
        if (now < *nx) {                         /* non ancora: si gira */
            __u64 *c = gen_dbg.lookup(&k_spin);
            if (c) *c += 1;
            return XDP_DROP;
        }
        __u64 late = now - *nx;
        /* indietro: si recuperano al piu' CATCHUP frame di fila, poi si
         * riparte da adesso */
        if (late > CATCHUP * *iv) {
            *nx = now - CATCHUP * *iv;
            __u64 *c = gen_dbg.lookup(&k_reset);
            if (c) *c += 1;
            late = CATCHUP * *iv;
        }
        __u64 *ls = gen_dbg.lookup(&k_late);
        if (ls) *ls += late;
        *nx += *iv;
    }
    __u64 *n = gen_runs.lookup(&k);
    if (n) *n += 1;
    if (data + HDR_COPY > end) return XDP_ABORTED;
    struct hdr_t *h = gen_hdr.lookup(&k);
    if (!h) return XDP_ABORTED;
    /* il frame torna dalla page_pool com'e' stato lasciato dal DUT */
    __builtin_memcpy(data, h->b, HDR_COPY);
    if (MIX_N > 0 && n) {
        int i = (int)(*n % (MIX_N > 0 ? MIX_N : 1));
        struct mix_t *m = gen_mix.lookup(&i);
        if (m) {
            __u8 *d = data;
            d[22] = m->ttl;            /* 14 Ethernet + 8: iphdr.ttl */
            d[24] = m->csum[0];        /* 14 + 10: iphdr.check */
            d[25] = m->csum[1];
        }
    }
    __u64 *st = gen_ctl.lookup(&k_stamp);
    if (st && *st && n && data + PG_OFF + 16 <= end) {
        __u64 *off = gen_ctl.lookup(&k_off);
        if (!now) now = bpf_ktime_get_ns();
        __u64 us = (now + (off ? *off : 0)) / 1000;
        __u32 sec = (__u32)(us / 1000000), usec = (__u32)(us % 1000000);
        __u32 seq = (__u32)*n;
        __u8 *h = (__u8 *)data + PG_OFF;
        h[4] = seq >> 24; h[5] = seq >> 16; h[6] = seq >> 8; h[7] = seq;
        h[8] = sec >> 24; h[9] = sec >> 16; h[10] = sec >> 8; h[11] = sec;
        h[12] = usec >> 24; h[13] = usec >> 16; h[14] = usec >> 8;
        h[15] = usec;
    }
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
                 dst_mac="02:00:00:00:00:02", dst_ip="10.0.0.2", ttls=None,
                 batch_size=BATCH_SIZE):
        from bcc import BPF
        self.target = target_dev
        self.ifindex = socket.if_nametoindex(target_dev)
        self.cpus = list(plan.gen) or [0]
        self.window_s = window_s
        self.dst_mac, self.dst_ip = dst_mac, dst_ip
        self.src_mac = _mac_of(target_dev)
        self.ttls = list(ttls or [])
        # Il lotto del test_run: e' anche ogni quanti frame il redirect
        # sveglia il DUT (xdp_do_flush a fine lotto -> XDP_XMIT_FLUSH ->
        # veth sveglia la NAPI; i gruppi da 16 accodati a meta' lotto non la
        # svegliano) e la taglia della page_pool.
        if not 1 <= int(batch_size) <= 256:
            raise ValueError("batch_size: 1..256 (TEST_XDP_MAX_BATCH)")
        self.batch_size = int(batch_size)
        if len(self.ttls) > MIX_MAX or any(not 1 <= t <= 255
                                           for t in self.ttls):
            raise ValueError(f"ttls: al piu' {MIX_MAX} valori in 1..255")
        self.b = BPF(text=GEN_SRC, cflags=[
            f"-DHDR_COPY={HDR_COPY}", f"-DTARGET_IFINDEX={self.ifindex}",
            f"-DMIX_N={len(self.ttls)}",
            f"-DMIX_SLOTS={max(1, len(self.ttls))}",
            f"-DPG_OFF={PKTGEN_HDR_OFF}", f"-DCATCHUP={CATCHUP}"])
        self.fn = self.b.load_func("xdp_gen", BPF.XDP)
        # Il segnale che interrompe la chiamata lunga: serve un gestore (anche
        # vuoto), altrimenti SIGUSR1 termina il processo. Si installa dal
        # thread principale, dove nasce il generatore.
        try:
            signal.signal(STOP_SIGNAL, lambda *_: None)
        except ValueError:
            pass
        self.last_run = None
        self._frame = None
        self.base_ttl = 32
        # pause fuori da test_run, per thread: ns totali e numero di chiamate
        self._gap_ns = {c: 0 for c in self.cpus}
        self._calls = {c: 0 for c in self.cpus}

    def set_ttl(self, ttl):
        """Il TTL del frame di base (quello senza --ttl-mix). Serve a
        --per-class, dove ogni classe ha il suo (link_state, ttl)."""
        if not 1 <= int(ttl) <= 255:
            raise ValueError(f"ttl {ttl}")
        self.base_ttl = int(ttl)
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
            if self.ttls:
                print(f"  [INFO] traffico misto: TTL a giro su "
                      f"{len(self.ttls)} valori ({min(self.ttls)}-"
                      f"{max(self.ttls)})")
        return self

    def detach(self):
        pass

    def ensure(self):
        pass

    def delay_for(self, total_pps):
        """L'intervallo fra due frame di UN thread, in ns, per `total_pps`
        in tutto: e' il `delay` che steady() riceve. 0 = massima spinta."""
        if not total_pps:
            return 0
        return max(1, int(round(self.n_inst * 1e9 / float(total_pps))))

    def set_stamp(self, on=True):
        """Il timbro di pktgen in ogni frame (per la latenza end-to-end)."""
        self._ctl(2, 1 if on else 0)

    def _ctl(self, i, v):
        self.b["gen_ctl"][ct.c_int(i)] = ct.c_ulonglong(int(v))

    def _clock_offset(self):
        """CLOCK_REALTIME - CLOCK_MONOTONIC in ns, per il timbro."""
        return time.clock_gettime_ns(time.CLOCK_REALTIME) - \
            time.clock_gettime_ns(time.CLOCK_MONOTONIC)

    def window_count(self, total_pps, seconds=None):
        return CALL_FRAMES

    def warmup(self, frame, delay=0, seconds=None):
        return None

    # -- il frame --------------------------------------------------------
    def _set_frame(self, frame_size):
        if self._frame is not None and self._frame[0] == frame_size:
            return self._frame[1]
        data = build_frame(frame_size, self.src_mac, self.dst_mac,
                           dst_ip=self.dst_ip, ttl=self.base_ttl)
        hdr = self.b["gen_hdr"]
        v = hdr.Leaf()
        ct.memmove(ct.byref(v), data[:HDR_COPY], HDR_COPY)
        hdr[ct.c_int(0)] = v
        mix = self.b["gen_mix"]
        for i, ttl in enumerate(self.ttls):
            f = build_frame(frame_size, self.src_mac, self.dst_mac,
                            dst_ip=self.dst_ip, ttl=ttl)
            e = mix.Leaf()
            e.ttl = f[22]
            e.csum[0], e.csum[1] = f[24], f[25]
            mix[ct.c_int(i)] = e
        buf = ct.create_string_buffer(data, len(data))
        self._frame = (frame_size, buf, len(data))
        return buf

    def _test_run(self, buf, size, frames):
        """Una chiamata. False se interrotta da un segnale (EINTR)."""
        attr = _AttrTestRun(prog_fd=self.fn.fd, data_size_in=size,
                            data_in=ct.cast(buf, ct.c_void_p).value,
                            repeat=frames, flags=BPF_F_TEST_XDP_LIVE_FRAMES,
                            batch_size=self.batch_size)
        if _bpf(BPF_PROG_TEST_RUN, attr) < 0:
            e = ct.get_errno()
            if e == errno.EINTR:
                return False
            raise OSError(e, f"BPF_PROG_TEST_RUN live frames: "
                             f"{os.strerror(e)}")
        return True

    def diag(self):
        """Contatori cumulativi per la diagnostica della cadenza (somme sui
        thread): giri d'attesa, azzeramenti, ritardo di partenza (ns), pause
        fuori da test_run (ns), chiamate. Vanno letti nella stessa sonda dei
        contatori della finestra, che ne fa le differenze."""
        vals = [self.b["gen_dbg"][ct.c_int(i)] for i in range(3)]
        out = {}
        for i, name in enumerate(("gen_spin", "gen_reset", "gen_late_ns")):
            out[name] = sum(int(vals[i][c]) for c in self.cpus
                            if c < len(vals[i]))
        out["gen_gap_ns"] = sum(self._gap_ns.values())
        out["gen_calls"] = sum(self._calls.values())
        return out

    def _runs(self):
        vals = self.b["gen_runs"][ct.c_int(0)]
        return {c: int(vals[c]) for c in self.cpus if c < len(vals)}

    # -- una chiamata per thread (le sonde) ------------------------------
    def run(self, frame, count, delay):
        import bench_throughput as BT
        self._ctl(0, 0)               # le sonde: massima spinta, `count` frame
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
        self._ctl(0, delay or 0)
        self._ctl(1, self._clock_offset())
        seconds = self.window_s if seconds is None else seconds
        buf = self._set_frame(frame)
        size = self._frame[2]
        stop = threading.Event()
        errs = []

        def loop(cpu):
            try:
                os.sched_setaffinity(0, {cpu})
                last = None
                while not stop.is_set():
                    t0 = time.monotonic_ns()
                    if last is not None:
                        self._gap_ns[cpu] += t0 - last
                    self._test_run(buf, size, STEADY_CALL_FRAMES)
                    last = time.monotonic_ns()
                    self._calls[cpu] += 1
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
            deadline = time.monotonic() + 5.0
            while any(t.is_alive() for t in ths) and \
                    time.monotonic() < deadline:
                for t in ths:
                    if t.is_alive() and t.ident is not None:
                        try:
                            signal.pthread_kill(t.ident, STOP_SIGNAL)
                        except (ProcessLookupError, OSError):
                            pass
                for t in ths:
                    t.join(timeout=0.02)
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
        if "rx_xdp" in dut:
            # bench_bitrate: il contatore davanti alla pipeline vede tutto
            # cio' che la coda ha accettato, rxonly compreso.
            errors = max(0, offered - dut["rx_xdp"])
        elif "hit" in dut:
            done = dut["hit"] + dut.get("miss", 0) + dut.get("drop", 0)
            errors = max(0, offered - done)
        else:
            errors = 0
        per_dev = [dict(dev=f"xdpgen@cpu{c}", tx=gb[c] - ga.get(c, 0),
                        pps=int((gb[c] - ga.get(c, 0)) / secs),
                        secs=round(secs, 4), errors=0) for c in self.cpus]
        run = BT.GenRun(offered - errors, int((offered - errors) / secs),
                        secs, per_dev=per_dev, wall=secs, errors=errors)
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
    rx_dev, tx_dev, _ = BT.make_shared_tg_link(*BT.ingress_queues(plan))
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
