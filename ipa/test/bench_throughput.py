#!/usr/bin/env python3
"""
bench_throughput.py -- throughput END-TO-END misurato, non stimato.

Ogni altra cifra di throughput in questo progetto e' `1 / latenza` sotto
BPF_PROG_TEST_RUN: un ciclo sullo stesso buffer, senza scheda di rete, senza
driver, senza un pacchetto che arrivi davvero da qualche parte. E' un PICCO
TEORICO. Questo script genera traffico vero con pktgen, lo fa attraversare la
pipeline, e conta quanti pacchetti escono dall'altra parte.

La differenza fra i due numeri e' il punto dell'esperimento.

--------------------------------------------------------------------------
IL BANCO, E CHE COSA MISURA DAVVERO
--------------------------------------------------------------------------
    TG (pktgen)          DUT (la pipeline)           RX (contatore)
    ipa_in_peer  --veth-->  ipa_in                --veth-->  ipa<N>p
        TX              XDP: inferenza + redirect        XDP_DROP + contatore

TG, DUT e RX stanno sulla STESSA macchina: e' la macchina che c'e', e non se ne
aggiunge una seconda. Cio' che si puo' fare -- ed e' quello che questa versione
fa -- e' smettere di farli condividere le CPU:

    CPU del GENERATORE   i thread kpktgend_<cpu> di pktgen, scelti a mano
    CPU del DUT          i kernel thread napi/<dev>-<id> che eseguono XDP
    CPU 0                esclusa per default da entrambi (timer, RCU, IRQ)

Fatta la separazione, la frase "questo non misura il throughput della pipeline"
resta vera solo per meta': il costo del veth e della copia di headroom e'
ancora dentro la cifra, ma il generatore non ruba piu' il core al programma
sotto test, e la pipeline puo' finalmente SATURARE. Quando satura, il numero
che esce e' un limite della pipeline e non del generatore -- ed e' esattamente
la distinzione che questo script deve saper fare.

--------------------------------------------------------------------------
PERCHE' PRIMA IL GENERATORE SATURAVA SEMPRE PER PRIMO
--------------------------------------------------------------------------
Tre ragioni, tutte strutturali, tutte affrontate qui:

1. IN SOFTIRQ LA RX DEL PEER GIRA SULLA CPU CHE HA TRASMESSO. Un core faceva
   {genera + inferisce + redirige}: t_gen + t_pipeline sullo stesso core.
   RIMEDIO: /sys/class/net/<dev>/threaded sposta il poll NAPI in un kernel
   thread, che si pinna sulle CPU che pktgen non usa.

2. UN THREAD GENERATORE PER OGNI CORE DEL DUT. La versione precedente creava un
   veth -- quindi una NAPI, quindi un core DUT -- per OGNI thread pktgen: gen e
   DUT scalavano insieme e il rapporto fra i due non cambiava mai.
   RIMEDIO: topologia `shared`. Un solo veth d'ingresso, N istanze pktgen sullo
   STESSO device (sintassi ufficiale `dev@N`, quella dei sample del kernel) con
   `queue_map` distinta per non contendersi lo stesso txq. Il lato DUT ha le sue
   code RX e i suoi thread NAPI, in numero deciso separatamente. Cosi' si puo'
   chiedere 3 core di generatore contro 1 core di DUT, che e' la condizione in
   cui la pipeline satura.

3. CLONE_SKB E BURST NON ESISTONO SU VETH. Non e' una scelta di questo script:
   il kernel rifiuta entrambi quando il device non annuncia IFF_TX_SKB_SHARING
   (veth lo azzera, perche' consegna l'skb alla RX del peer dove XDP lo
   riscrive), e rifiuta clone_skb anche in xmit_mode netif_receive.
   RIMEDIO: nessuno -- si PROVA una volta, si riporta l'esito, e se il device li
   accetta si verifica che aumentino davvero il rate invece di darlo per
   scontato. L'unica manopola che su veth funziona sempre e' il numero di
   thread.

Cio' che NON si puo' togliere, e che va detto accanto ai numeri: XDP su veth
pretende XDP_PACKET_HEADROOM (256 byte) davanti al pacchetto, gli skb di pktgen
hanno NET_SKB_PAD (64), e pktgen riserva NET_SKB_PAD a mano invece di
`dev->needed_headroom`. Quindi veth_xdp_rcv_skb fa una COPIA per ogni pacchetto
prima di eseguire il programma. E' il costo di "XDP su veth alimentato da un
mittente non XDP" e nessun parametro di pktgen lo elimina.

--------------------------------------------------------------------------
TRE PUNTI DI CONTEGGIO, PERCHE' "PERSI" NON BASTA
--------------------------------------------------------------------------
  TX   quanti pktgen ne ha trasmessi          (dai suoi contatori)
  HIT  quanti la pipeline ne ha elaborati     (pkt_stats[0])
  RX   quanti sono arrivati a destinazione    (il contatore XDP sull'uscita)

TX - HIT e' quello che non e' nemmeno arrivato al programma (coda del veth,
softirq). HIT - RX e' quello che il programma ha elaborato ma non e' uscito
(redirect fallito, oppure la classe scelta era DROP). Un solo numero di
"perdita" confonderebbe cose diverse -- e con esse confonderebbe il collo di
bottiglia, che e' cio' che questo banco deve identificare.

--------------------------------------------------------------------------
IL BYTE CHE FA FALLIRE TUTTO IN SILENZIO
--------------------------------------------------------------------------
pktgen scrive la PROPRIA intestazione subito dopo UDP (magic 0xbe9be955), e il
primo byte di quel payload e' esattamente dove il dispatcher legge
`ipa->model_id`. Vale quindi 190, non 0: senza il modello registrato anche su
190 ogni pacchetto diventa MISS, il programma restituisce XDP_PASS e il test
misurerebbe il costo di NON fare inferenza.

Il modello viene percio' registrato su model_id 0 E 190, e una sonda da un
pacchetto verifica HIT prima di misurare qualunque cosa. Se la sonda fallisce
lo script si ferma invece di produrre numeri privi di senso.

--------------------------------------------------------------------------
LE DUE MODALITA'
--------------------------------------------------------------------------
Sono esperimenti diversi e rispondono a domande diverse. Tenerle separate e'
cio' che impedisce di confrontare pipeline misurate a rate diversi.

  --mode compare    CONFRONTO. Rate offerto IDENTICO per tutte le pipeline,
                    stessi parametri di pktgen, stessa durata, stesso frame.
                    Nessuna ricerca e nessun adattamento fra una pipeline e
                    l'altra. Risponde a: "a parita' di carico, chi perde?"
                    Il rate si sceglie con --offered-pps; senza, lo decide una
                    calibrazione fatta UNA volta e poi congelata per tutti.

  --mode saturate   SATURAZIONE. Rate offerto crescente su una scala
                    geometrica, ogni gradino confermato da piu' ripetizioni.
                    Risponde a: "dove comincia a perdere, e per colpa di chi?"
                    Niente bisezione: la perdita su questo banco non e'
                    monotona nel rate, e bisecare su un fenomeno non monotono
                    converge su qualunque punto sia uscito pulito per caso.

--------------------------------------------------------------------------
USO
--------------------------------------------------------------------------
    # confronto equo fra tutte le pipeline, stesso carico per tutte
    sudo python3 ipa/test/bench_throughput.py --mode compare --rounds 3 --out result/

    # dove satura ciascuna pipeline, e chi e' il collo di bottiglia
    sudo python3 ipa/test/bench_throughput.py --mode saturate --diag --out result/

    # CPU separate esplicite: generatore su 1-2, DUT su 3, CPU 0 fuori
    sudo python3 ipa/test/bench_throughput.py --gen-cpus 1,2 --dut-cpus 3 --mode saturate

    # percorso storico: latenza arrivo->ripartenza + throughput, a giri
    sudo python3 ipa/test/bench_throughput.py --latency --rounds 3 --out result/

    sudo python3 ipa/test/bench_throughput.py --cleanup        # se resta sporco

Per ogni pipeline il percorso --latency riporta TRE righe, che rispondono a tre
domande diverse:

    pieno         quanto passa spingendo al massimo. E' un sistema in
                  sovraccarico: la cifra dipende da quanto si e' spinto.
    zero-perdite  il rate piu' alto a cui non si perde NEMMENO UN pacchetto.
                  E' il throughput nel senso della RFC 2544, ed e' la riga da
                  citare.
    scarico       a 50 kpps, senza coda davanti: e' dove la latenza si misura,
                  perche' li' si confrontano programmi e non lunghezze di coda.

Serve Linux, root, BCC e il modulo pktgen (`sudo modprobe pktgen`).
"""
import io
import os
import re
import sys
import csv
import time
import argparse
import subprocess
import statistics
import threading
import ctypes as ct

_TEST_DIR = os.path.dirname(os.path.abspath(__file__))
SHARED_DIR = os.path.dirname(_TEST_DIR)
for _p in (SHARED_DIR, _TEST_DIR):
    if _p not in sys.path:
        sys.path.insert(0, _p)

GREEN, RED, YELLOW, GREY, NC = (
    "\033[0;32m", "\033[0;31m", "\033[1;33m", "\033[0;90m", "\033[0m")


class PktgenEmptyRun(RuntimeError):
    """Un run che non ha trasmesso nulla. Segnalato al chiamante, non fatale."""


PKTGEN_DIR = "/proc/net/pktgen"
PKTGEN_MAGIC_MODEL_ID = 0xBE      # vedi la docstring

# Quante volte riusare lo stesso buffer quando il device lo consente. Su veth
# non lo consente (vedi GenCaps), quindi in pratica questa costante serve solo
# sui device che annunciano IFF_TX_SKB_SHARING.
ESCALATE_CLONE = 100000

XMIT_MODES = ("start_xmit", "netif_receive", "queue_xmit")

# Retrocompatibilita': il vecchio codice consultava questi due globali per
# sapere se valeva la pena riprovare. La verita' adesso sta in GenCaps, che e'
# PER DEVICE, ma questi restano allineati perche' find_knee li legge ancora.
_BURST_SUPPORTED = True
_CLONE_SUPPORTED = True

# Frame sizes. 64 e' il minimo Ethernet; 1514 il massimo senza jumbo. Il frame
# IPA minimo di questo progetto e' 63 byte, quindi 64 li contiene tutti.
#
# Tre taglie e non sei: l'inferenza legge sempre gli stessi header, quindi il
# suo costo NON dipende dalla lunghezza del frame e le taglie intermedie
# ripetevano la stessa misura allungando il run. Restano il minimo, una di
# mezzo e il massimo. Le altre si chiedono con --frames.
DEFAULT_FRAMES = [64, 512, 1514]

# Sotto questa percentuale la perdita e' considerata rumore della macchina e non
# saturazione del datapath. Vedi find_knee per la misura che ha imposto questa
# scelta. Zero stretto resta riportato a parte.
DEFAULT_LOSS_THRESHOLD = 0.1

# Quante volte ripetere ogni punto. Non e' prudenza generica: tre misure della
# stessa identica configurazione hanno dato 0.06%, 19.52% e 0.00% di perdita.
# Vedi measure_point.
DEFAULT_REPEAT = 3

# Giri completi: in ogni giro si misurano TUTTI i metodi, poi si prende la
# mediana. Serve a togliere l'ordine dei metodi dalla misura -- vedi run_fair.
DEFAULT_ROUNDS = 3

# Durata BERSAGLIO di una finestra di misura, in secondi.
#
# pktgen conta PACCHETTI, non secondi: non esiste un parametro "dura T". La
# durata si ottiene quindi calibrando il `count` sul rate misurato, e si
# RILEGGE dai contatori di pktgen (campo `Result: OK: <usec>`), che e' la durata
# vera e non quella sperata. Una finestra uscita corta viene ricalibrata una
# volta sola: vedi Generator.window_count.
#
# QUESTO SCHEMA (count fisso, durata riletta) E' ORA QUELLO DI RISERVA
# (--window count). Il default e' la finestra STAZIONARIA, vedi sotto e
# Generator.steady. Il timore che la teneva fuori -- se lo `stop` non arriva
# pktgen trasmette per sempre -- e' chiuso da un count di sicurezza finito.
WINDOW_S = 0.30

# Come si misura una finestra: "steady" (default) o "count" (storico). Lo
# fissa main() da --window; Generator lo legge alla costruzione.
WINDOW_MODE = "steady"

# LA FINESTRA STAZIONARIA, e perche' esiste.
#
# `pgctrl start` blocca per un tempo che NON e' il tempo di trasmissione.
# In net/core/pktgen.c, pktgen_run_all_threads alza T_RUN sui thread senza
# svegliarli -- ognuno se ne accorge al suo prossimo risveglio, entro HZ/10,
# cioe' fino a 100 ms dopo -- poi dorme 125 ms fissi, poi controlla ogni
# 100 ms (msleep_interruptible) se i thread hanno finito. Il blocco dura
# quindi la trasmissione PIU' un tempo morto fra ~25 e ~225 ms, e i thread
# partono sfasati fino a 100 ms fra loro.
#
# Diviso per quel blocco (GenRun.window), RX esce sottostimato di una quantita'
# che non dipende dalla pipeline. Misurato il 2026-09-23 (compare, hardcoded):
# TX = RX = 549 532 in tutti e tre i giri, RX pps 1 240 424 / 1 238 514 /
# 1 240 533 -- lo stesso conteggio diviso lo stesso blocco quantizzato di
# ~0,443 s, per una trasmissione chiesta da 0,3 s. Lo "sfasamento del 75%" e
# lo "scarto del 99,8%" fra le due letture del rate, che il banco segnalava a
# ogni run, sono lo stesso tempo morto visto da due lati.
#
# La finestra stazionaria non divide per il blocco: aspetta che TUTTE le
# istanze stiano trasmettendo, lascia assestare la coda, legge i contatori
# (pktgen e DUT), aspetta WINDOW_S, li rilegge, e ferma pktgen. Rate =
# differenze diviso l'intervallo fra le due letture. Avvio, sfasamento e coda
# finale restano fuori per costruzione, e la durata non dipende piu' da una
# stima del rate.
STEADY_SETTLE_S = 0.10          # dopo che tutte le istanze sono partite
# Una LETTURA (contatori pktgen + contatori del DUT) deve essere istantanea
# rispetto alla finestra: l'istante che le si attribuisce e' quello preso
# attorno a lei, e se il processo viene sospeso a meta' lettura i contatori
# vanno avanti mentre l'orologio della finestra no. Misurato il 2026-09-23 al
# primo run vero: una finestra di calibrazione a 5,33 Mpps consegnati contro
# 3,37-3,45 in tutte le finestre dopo, stessa pipeline, stesso rate -- la
# firma di una sospensione di ~170 ms subito dopo la seconda marcatura. Una
# lettura piu' lunga di STEADY_READ_MAX_S si rifa' (fino a STEADY_READ_TRIES
# volte); l'istante e' il punto medio fra prima e dopo.
STEADY_READ_MAX_S = 0.003
STEADY_READ_TRIES = 50
STEADY_START_TIMEOUT_S = 1.0    # per vederle partire: HZ/10 + 125 ms, largo
# Il count di SICUREZZA: finito, cosi' che se lo stop non arrivasse (processo
# ucciso fra start e stop) pktgen si ferma da solo in pochi secondi invece di
# trasmettere per sempre. E' dimensionato su un rate per istanza che un veth
# non raggiunge, quindi nel percorso normale lo stop arriva prima; se non
# arriva prima, l'istanza risulta ferma alla seconda lettura e la finestra
# viene scartata, non usata.
STEADY_SAFETY_S = 3.0
STEADY_MAX_PPS_PER_INST = 10_000_000
# Pacchetti che alle due letture possono essere legittimamente "in volo" fra
# TX e HIT: il ptr_ring del veth (256) piu' un giro di NAPI (64), con margine.
# Una differenza HIT - TX sotto questa soglia e' la coda, non un residuo della
# finestra precedente.
STEADY_INFLIGHT = 512
_STARTED_RE = re.compile(r"started:\s*(\d+)us")

# Warm-up: una finestra buttata via PRIMA della misura. La prima raffica paga
# cache fredde, la prima allocazione delle code e l'avvio dei thread, e non
# descrive il regime. Separarla e' la ragione per cui i primi campioni non
# sporcano piu' la deviazione standard.
DEFAULT_WARMUP_S = 0.10

# Sotto questo numero di pacchetti la finestra e' troppo corta perche' i
# percentili vogliano dire qualcosa, anche se il tempo sarebbe sufficiente.
MIN_WINDOW_PKTS = 20000

# ... e sopra questo numero un punto a rate alto durerebbe molto piu' della
# finestra bersaglio senza aggiungere informazione. Tiene prevedibile il run.
MAX_WINDOW_PKTS = 4_000_000

# Una finestra uscita sotto questa frazione della durata bersaglio viene
# ricalibrata una volta: vuol dire che la stima del rate era troppo bassa.
WINDOW_SHORT_FRACTION = 0.5

# Una finestra che ha trasmesso meno di questa frazione dei pacchetti chiesti
# non e' una misura: e' un run troncato. Misurato il 2026-09-18, una riga e'
# uscita con 2 032 pacchetti su 542 870 chiesti in 0.14 s invece di 2 s, ed e'
# stata usata come punto della scala insieme alle altre.
WINDOW_MIN_TX_FRACTION = 0.5

# Dimensione bersaglio della coda RX del veth, in descrittori.
#
# QUESTO E' IL NUMERO CHE DECIDE LE PERDITE A RATE BASSO. Quando si attacca
# XDP a un veth, il kernel alloca un `ptr_ring` sul lato ricevente e
# `veth_xmit` risponde NET_XMIT_DROP appena quel ring e' pieno. Storicamente
# veth.c lo fissa a VETH_RING_SIZE = 256 descrittori, non configurabile.
#
# 256 descrittori a 1,5 Mpps sono 170 MICROSECONDI di traffico. Vuol dire che
# il kernel thread NAPI del DUT deve essere schedulato entro 170 us OGNI
# VOLTA, per sempre, altrimenti il ring trabocca e il generatore si vede
# respingere pacchetti. Su un guest VirtualBox, il cui vCPU l'host puo'
# deschedulare per millisecondi interi, questo e' impossibile: qualche punto
# percentuale di respinti a QUALUNQUE rate sopra il centinaio di kpps e'
# strutturale e non dice niente sulla pipeline.
#
# Il conto torna con le misure: a 74 kpps il ring copre 3,5 ms e la perdita
# era 0,10%; a 1,5 Mpps copre 0,17 ms e la perdita sta fra il 9 e il 18%.
#
# I kernel recenti espongono la dimensione via `ethtool -G <dev> rx N`. Non si
# da' per scontato che ci sia: si PROVA, si rilegge, e si riporta l'esito fra
# le condizioni del test -- la stessa regola gia' usata per clone_skb e burst.
VETH_RING_TARGET = 4096

# Pausa fra la fine della trasmissione e la lettura dei contatori.
#
# `pgctrl start` ritorna quando i THREAD DEL GENERATORE hanno finito, non
# quando il DUT ha finito di elaborare: i pacchetti ancora nel ptr_ring del
# veth e nella coda NAPI non sono ancora stati contati. Leggendo subito,
# quella coda diventa "perdita" -- e leggendo subito DOPO aver azzerato,
# diventa un conteggio della finestra precedente (si e' visto RX > HIT).
# Un drenaggio esplicito da entrambi i lati toglie tutti e due gli errori.
DRAIN_S = 0.05

# Finestre della calibrazione del generatore, e perche' se ne prende il MASSIMO.
#
# `rate_estimate` non e' un numero di comodo: da lui si ricava il `count` di
# ogni punto, e quindi la DURATA della finestra di misura. Sottostimarlo
# accorcia le finestre, e una finestra corta su questa macchina e' dominata da
# un singolo intoppo dello scheduler.
#
# Misurato il 2026-09-18 (commit d2aa8792): la calibrazione e' uscita a
# 127 988 pps quando il rate vero era ~570 000. Il count del punto a pieno
# regime e' diventato 127 988 x 2.0 = 255 976 pacchetti, che a 570 kpps durano
# 0.45 s invece dei 2.0 s chiesti. Il primo punto del run -- baseline a 64
# byte -- e' uscito a 567 563 pps contro gli 850-880 k delle altre misure, e il
# controllo di validita' ha bocciato il run perche' "la baseline non e' la piu'
# veloce". Non lo era: era stata misurata in una finestra lunga un quarto.
#
# Il MASSIMO e non la mediana: qui si stima di cosa e' CAPACE il generatore, e
# una finestra bassa e' un vCPU sospeso, non un generatore piu' lento. Per la
# perdita e per il confronto fra pipeline vale la regola opposta (mediana), e i
# due casi sono diversi apposta.
CALIB_WINDOWS = 3

# Passi di bisezione nella ricerca del ginocchio nel percorso storico
# (--latency). La modalita' saturate non biseca: vedi find_saturation.
KNEE_STEPS = 5

# Oltre questa dispersione fra le ripetizioni il punto non e' utilizzabile.
# Misurato: hardcoded ha dato +-75% fra tre misure della stessa cosa, e la
# baseline e' uscita il 26% PIU' LENTA di una pipeline che fa strettamente piu'
# lavoro -- cioe' il run misurava il carico della macchina, non il datapath.
MAX_SPREAD_PCT = 25.0

# Sotto questa differenza relativa due pipeline non sono distinguibili su questo
# banco, e un'inversione non e' un difetto del run. Vedi check_validity.
VALID_TOL = 0.10

# Ritardi fissi, usati solo se il chiamante li chiede con --delays.
DEFAULT_DELAYS = [0, 200, 500, 1000, 2000, 5000, 10000]

# Scala dei rate per --mode saturate: frazioni del rate CONSEGNATO a delay 0,
# crescenti. Si parte sotto la capacita' stimata e si sale, e ogni gradino e'
# confermato da piu' ripetizioni. Non e' una bisezione, ed e' voluto.
# Cinque frazioni e non otto. Ogni gradino costa `repeat` finestre, e da quando
# i rifiutati del generatore contano come perdita (vedi _measure_once) la scala
# viene percorsa davvero invece di fermarsi al primo punto: otto gradini per
# taglia per pipeline erano un run lungo il triplo per una risoluzione che il
# banco non ha. Fitti dove sta il ginocchio, radi lontano.
SATURATE_LADDER = (0.60, 0.80, 0.90, 1.00, 1.15)

# Frazioni SOTTO il gradino piu' basso della scala, usate solo quando anche
# quello perde.
#
# Senza questa discesa il banco concludeva "la perdita non dipende dal rate:
# e' rumore della macchina" senza aver mai provato sotto il 60% del rate
# consegnato a massima spinta. E' una conclusione che i dati non reggono: il
# ginocchio puo' benissimo stare al 30%, e li' nessuno era andato a guardare.
# Misurato il 2026-09-18, ogni taglia e ogni pipeline finivano cosi'.
SATURATE_DESCENT = (0.40, 0.25, 0.15, 0.08, 0.04)

# Sotto questo rate la finestra non contiene abbastanza pacchetti perche' la
# perdita voglia dire qualcosa, e scendere ancora misurerebbe solo il rumore
# del contatore. La discesa si ferma qui e lo dichiara.
MIN_LADDER_PPS = 20_000

# Quanto deve salire il rate offerto perche' clone_skb/burst valgano la perdita
# di rappresentativita'. Sotto questa soglia il parametro e' accettato dal
# device ma inutile, e si torna alla condizione di riferimento.
GEN_KNOB_MIN_GAIN = 0.10

# Sopra questa occupazione una CPU si considera satura. Serve SOLO alla
# diagnostica, e solo per etichettare: non entra in nessun calcolo di rate.
CPU_BUSY_PCT = 90.0

# Cinque gradini, e i due estremi servono a leggere i tre in mezzo.
#
#   baseline   XDP che parsa, decrementa il TTL e redirige su una classe FISSA.
#              Nessuna inferenza. E' il TETTO DEL BANCO: se satura anche lei a
#              X pacchetti/s, allora X e' il limite del veth e delle CPU, non
#              della pipeline, e ogni cifra sotto va letta rispetto a quello.
#   p1_static  pesi E indice del nodo compilati dentro: un binario per nodo.
#   hardcoded  pesi compilati, nodo da mappa (la "P1.5").
#   template   solo i soffitti compilati.
#   modular    anche la profondita' a runtime.
# P1 e P1.5 sono l'OGGETTO AOT (gen_full_c + loader_aot, via p1_aot), cioe'
# quello che va sui nodi; fino al 2026-09-23 erano il build BCC, che su un
# nodo non va mai (i due coincidono entro il rumore, claims.md B3).
METHODS = ("baseline", "p1_static", "hardcoded", "template", "modular")

# IL TETTO DI SOLA RICEZIONE, NELLA STESSA SESSIONE DELLE PIPELINE.
#
# `--mode generator` misura lo stesso tetto (pktgen -> veth -> contatore che
# scarta), ma in un run a parte. Fra un run e l'altro questa VM si sposta di
# circa il 10%: misurato il 2026-09-23, sola ricezione 4,32 e poi 3,92 Mpps,
# baseline 3,98 e poi 4,01 -- il rapporto fra le due usciva 0,92 o 1,02 a
# seconda di quali run si accostavano. `rxonly` e' lo stesso contatore
# caricato come un metodo di `--mode compare`: stessi giri, stesso generatore,
# stessa finestra, e il rapporto con le pipeline diventa una misura.
#
# Fa strettamente MENO lavoro della baseline: niente parse, niente TTL, niente
# redirect, niente veth d'uscita. Non e' una pipeline, quindi resta fuori dal
# controllo "la baseline e' la piu' veloce" e ne ha uno suo: se consegna MENO
# della baseline oltre la tolleranza, la sessione non e' confrontabile.
RX_ONLY = "rxonly"
RXONLY_SRC = """
#include <uapi/linux/bpf.h>
BPF_ARRAY(pkt_stats, __u64, 3);
BPF_ARRAY(cls_stats, __u64, 8);
int xdp_rxonly(struct xdp_md *ctx) {
    int k = 0;
    __u64 *v = pkt_stats.lookup(&k);
    if (v) __sync_fetch_and_add(v, 1);
    return XDP_DROP;
}
"""


def setup_rxonly():
    """Il contatore d'ingresso con la forma di un setup di pipeline. RX e' il
    suo HIT (`rx_is_hit`): il pacchetto non arriva mai al contatore d'uscita,
    per costruzione."""
    from bcc import BPF
    b = BPF(text=RXONLY_SRC)
    fn = b.load_func("xdp_rxonly", BPF.XDP)
    return {"b": b, "fn": fn, "disp": fn, "pipeline": 0, "rx_is_hit": True,
            "cls_stats": b["cls_stats"], "pkt_stats": b["pkt_stats"],
            "progs": {"xdp_rxonly": fn.fd}}

# Il nodo che la P1 specializzata si porta dentro. Lo stesso che installa
# test_fabric, cosi' le due misure parlano dello stesso nodo.
STATIC_NODE = 7

# Contatore sull'uscita: XDP_DROP, cosi' il conteggio non paga lo stack di rete
# e non falsa la misura con il costo di consegnare a un socket.
RX_COUNTER_SRC = r"""
#include <uapi/linux/bpf.h>
BPF_PERCPU_ARRAY(rx_count, __u64, 1);
int xdp_rx_count(struct xdp_md *ctx) {
    int k = 0;
    __u64 *v = rx_count.lookup(&k);
    if (v) *v += 1;
    return XDP_DROP;
}
"""


def ok(m):
    print(f"  {GREEN}[PASS]{NC} {m}")


def info(m):
    print(f"  {YELLOW}[INFO]{NC} {m}")


def warn(m):
    print(f"  {RED}[WARN]{NC} {m}")


def note(m):
    print(f"  {GREY}{m}{NC}")


# ==========================================================================
# CPU: CHI GENERA E CHI ELABORA -- LA MODIFICA PRINCIPALE
# ==========================================================================
# pktgen crea un kernel thread PER CPU, chiamato kpktgend_<cpu> e legato a
# quella CPU con kthread_bind. Scrivere `add_device X` dentro
# /proc/net/pktgen/kpktgend_3 vuol dire quindi, letteralmente, "genera questo
# traffico sulla CPU 3". L'affinita' del generatore non e' una cosa da chiedere
# a taskset: e' gia' nel nome del file.
#
# La versione precedente usava kpktgend_0..threads-1, cioe' partiva SEMPRE da
# CPU 0 -- che e' la CPU su cui il kernel mette per default i timer, il lavoro
# di RCU e buona parte degli IRQ. Il generatore ci perdeva cicli e il DUT pure.
#
# Qui le due liste sono esplicite e verificate:
#
#   --gen-cpus 1,2   i thread pktgen: uno per CPU elencata
#   --dut-cpus 3     dove vanno pinnati i kernel thread napi/<dev>-<id>
#   CPU 0            fuori da entrambe se non la si chiede con --allow-cpu0
#
# Nulla e' assunto sul numero di core: le liste si intersecano con le CPU
# davvero online e con i thread pktgen davvero esistenti, e cio' che avanza
# viene detto invece che ignorato.


def parse_cpu_list(spec):
    """"1,3-5" -> [1, 3, 4, 5]. None o stringa vuota -> None (cioe' 'decidi tu').

    Stesso formato che il kernel usa in /sys/devices/system/cpu/online, cosi'
    la lista che l'utente scrive e quella che il kernel stampa si leggono allo
    stesso modo."""
    if spec is None:
        return None
    spec = str(spec).strip()
    if not spec or spec.lower() == "auto":
        return None
    out = []
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, _, b = part.partition("-")
            try:
                lo, hi = int(a), int(b)
            except ValueError:
                raise ValueError(f"intervallo di CPU non valido: {part!r}")
            if hi < lo:
                raise ValueError(f"intervallo rovesciato: {part!r}")
            out.extend(range(lo, hi + 1))
        else:
            try:
                out.append(int(part))
            except ValueError:
                raise ValueError(f"CPU non valida: {part!r}")
    # Ordinate e senza ripetizioni: due volte la stessa CPU vorrebbe dire due
    # thread pktgen sullo stesso core, che pktgen non permette comunque.
    return sorted(set(out))


def online_cpus():
    """Le CPU davvero online, dal kernel. Non os.cpu_count(), che conta quelle
    presenti: una CPU offline ha il suo kpktgend_<n> assente e va esclusa."""
    try:
        with open("/sys/devices/system/cpu/online") as f:
            cpus = parse_cpu_list(f.read().strip())
        if cpus:
            return cpus
    except OSError:
        pass
    return list(range(os.cpu_count() or 1))


def pg_thread_path(cpu):
    return f"{PKTGEN_DIR}/kpktgend_{cpu}"


def pg_thread_exists(cpu):
    """C'e' un thread pktgen su questa CPU? Se il modulo e' stato caricato con
    la CPU offline, o la CPU e' isolata, il file non esiste e chiederne uno
    fallirebbe a meta' configurazione."""
    return os.path.exists(pg_thread_path(cpu))


class CpuPlan:
    """Chi genera, chi elabora, e cosa e' stato scartato per arrivarci."""

    def __init__(self, gen, dut, online, notes, shared=False):
        self.gen = list(gen)
        self.dut = list(dut)
        self.online = list(online)
        self.notes = list(notes)
        # True quando non e' stato possibile separare: generatore e DUT sulle
        # stesse CPU. Non e' un errore fatale -- e' il vecchio comportamento --
        # ma da quel momento la cifra assoluta misura la SOMMA dei due.
        self.shared = shared

    @property
    def threads(self):
        return len(self.gen)

    @property
    def excluded(self):
        return [c for c in self.online
                if c not in self.gen and c not in self.dut]

    def describe(self):
        print(f"\n{YELLOW}{'=' * 78}{NC}")
        print(f"{YELLOW} Piano CPU: generatore e DUT su questa macchina{NC}")
        print(f"{YELLOW}{'=' * 78}{NC}")
        fmt = lambda xs: ",".join(str(x) for x in xs) if xs else "(nessuna)"
        info(f"CPU online .............. {fmt(self.online)}")
        info(f"CPU generatore (pktgen) . {fmt(self.gen)}  "
             f"-> {self.threads} thread kpktgend")
        info(f"CPU DUT (XDP/NAPI) ...... {fmt(self.dut)}")
        info(f"CPU lasciate al sistema . {fmt(self.excluded)}")
        for n in self.notes:
            warn(n)
        if self.shared:
            warn("generatore e DUT condividono le CPU: la cifra assoluta "
                 "misura la somma dei due, non la pipeline.")
        else:
            note("generatore e DUT su core disgiunti: la perdita che si vede "
                 "e' della pipeline, non del generatore che le ruba il core.")


def plan_cpus(gen_spec=None, dut_spec=None, threads=None, allow_cpu0=False,
              check_pktgen=True):
    """Decide le due liste di CPU, verificandole contro la macchina vera.

    Regole, in ordine:
      1. si parte dalle CPU ONLINE;
      2. la CPU 0 esce, se non la si e' chiesta: e' dove finiscono timer, RCU
         e IRQ, e un thread pktgen li' genera a rate variabile;
      3. cio' che l'utente ha chiesto vince, ma intersecato con (1);
      4. quello che resta e' del DUT;
      5. se non resta niente, si dichiara la condivisione invece di fingere
         una separazione che non c'e'.

    Senza --threads il numero di thread generatore si sceglie da solo con una
    regola sola: PIU' core al generatore che al DUT. E' la condizione in cui la
    pipeline satura, che e' cio' che si vuole misurare; il caso opposto -- un
    core per parte -- e' quello in cui il generatore satura per primo e il
    banco non dice niente sulla pipeline."""
    notes = []
    online = online_cpus()
    pool = [c for c in online if allow_cpu0 or c != 0]
    if not pool:
        notes.append("una sola CPU online e CPU 0 esclusa: la riammetto, "
                     "non c'e' altro su cui girare.")
        pool = list(online)

    want_gen = parse_cpu_list(gen_spec)
    want_dut = parse_cpu_list(dut_spec)

    if want_gen is not None:
        gen = [c for c in want_gen if c in online]
        dropped = [c for c in want_gen if c not in online]
        if dropped:
            notes.append(f"CPU {dropped} chieste per il generatore ma non "
                         f"online: scartate.")
        # Una lista esplicita vince anche sull'esclusione della CPU 0: se
        # l'utente la scrive, la vuole, e --allow-cpu0 serve solo al caso
        # automatico.
        if 0 in gen and not allow_cpu0:
            notes.append("CPU 0 chiesta esplicitamente per il generatore: la "
                         "uso, ma li' girano timer, RCU e IRQ e il rate "
                         "offerto e' meno stabile.")
    else:
        n = len(pool)
        if threads and threads > 0:
            gen_n = min(threads, n)
            if threads > n:
                notes.append(f"chiesti {threads} thread generatore ma solo {n} "
                             f"CPU utilizzabili: ne uso {gen_n}. Due thread "
                             f"pktgen sulla stessa CPU non esistono -- il "
                             f"thread E' la CPU.")
        else:
            # Un terzo al DUT, il resto al generatore, minimo uno per parte.
            dut_n = max(1, n // 3)
            gen_n = max(1, n - dut_n)
        gen = pool[:gen_n]

    if want_dut is not None:
        dut = [c for c in want_dut if c in online]
        dropped = [c for c in want_dut if c not in online]
        if dropped:
            notes.append(f"CPU {dropped} chieste per il DUT ma non online: "
                         f"scartate.")
    else:
        dut = [c for c in pool if c not in gen]

    if check_pktgen and os.path.isdir(PKTGEN_DIR):
        missing = [c for c in gen if not pg_thread_exists(c)]
        if missing:
            notes.append(f"nessun thread pktgen su CPU {missing} "
                         f"(kpktgend_<cpu> assente): scartate dal generatore.")
            gen = [c for c in gen if c not in missing]

    if not gen:
        gen = pool[:1] or online[:1]
        notes.append(f"nessuna CPU utilizzabile per il generatore: ripiego "
                     f"su {gen}.")

    shared = False
    overlap = sorted(set(gen) & set(dut))
    if overlap:
        notes.append(f"CPU {overlap} chieste sia per il generatore sia per il "
                     f"DUT: su quei core i due si contendono il tempo.")
        shared = True
    if not dut:
        dut = list(gen)
        shared = True
        notes.append("nessuna CPU libera per il DUT: la NAPI restera' sui "
                     "core del generatore (comportamento storico).")
    return CpuPlan(gen, dut, online, notes, shared=shared)


# ==========================================================================
# pktgen: il livello basso
# ==========================================================================
def pg_write(path, cmd):
    """Write one pktgen command, and say which one if it fails.

    os.open(O_WRONLY) rather than open(path, "w"): the builtin adds O_TRUNC,
    and a procfs file with no truncate handler answers that with
    `OSError: [Errno 95] Operation not supported` -- an error about the OPEN
    that reads like an error about pktgen.

    The failure is wrapped because the bare OSError names neither the command
    nor the file, and pktgen has a dozen commands per configuration: without
    this the message says only "Operation not supported"."""
    try:
        fd = os.open(path, os.O_WRONLY)
    except OSError as e:
        raise RuntimeError(
            f"pktgen: non posso aprire {path} ({e.strerror}). "
            f"Se il file non esiste, `add_device` non ha avuto effetto.") from e
    try:
        os.write(fd, (cmd + "\n").encode())
    except OSError as e:
        raise RuntimeError(
            f"pktgen: comando '{cmd}' rifiutato da {path} "
            f"({e.strerror}). Questo kernel potrebbe non supportarlo.") from e
    finally:
        os.close(fd)


def pg_available():
    """Is pktgen loaded -- and if not, load it.

    The module unloads between sessions (a reboot, an autoclean), and the
    script already runs as root, so sending the user off to find `modprobe`
    is a stop for something it can do itself. Only the failure is worth
    reporting."""
    if os.path.isdir(PKTGEN_DIR):
        return True
    subprocess.run(["modprobe", "pktgen"], check=False, capture_output=True)
    if os.path.isdir(PKTGEN_DIR):
        info("modulo pktgen caricato")
        return True
    return False


def pg_reset():
    pg_write(f"{PKTGEN_DIR}/pgctrl", "reset")


def pg_stop():
    """Ferma i thread in corso. Usato solo in pulizia: il percorso normale
    aspetta che `start` ritorni, perche' start blocca fino all'ultimo thread."""
    try:
        pg_write(f"{PKTGEN_DIR}/pgctrl", "stop")
    except RuntimeError:
        pass


def pg_dev_path(name):
    """Il file di controllo di UN'ISTANZA. Il nome puo' contenere '@': pktgen
    toglie il suffisso per cercare il netdev (pktgen_dev_get_by_name si ferma
    alla '@') ma tiene il nome intero per il file, ed e' cosi' che lo stesso
    device sta su piu' thread -- vedi Generator."""
    return f"{PKTGEN_DIR}/{name}"


def probe_clone_support(dev):
    """Chiedi UNA volta se questo device accetta clone_skb, prima di misurare.

    Il rifiuto costa una misura: il tentativo mancato lascia il device in uno
    stato da cui `start` non parte -- pktgen riporta `pkts-sofar: 0` e
    `started: 0us` -- e quella misura andava a zero pacchetti in mezzo allo
    sweep. Scoprirlo prima, su un device gia' configurato per essere buttato,
    toglie il problema alla radice invece di gestirne le conseguenze.

    Il kernel rifiuta clone_skb quando il device non annuncia
    IFF_TX_SKB_SHARING (veth lo azzera) e in xmit_mode netif_receive."""
    global _CLONE_SUPPORTED
    if not os.path.exists(pg_dev_path(dev)):
        return _CLONE_SUPPORTED
    try:
        pg_write(pg_dev_path(dev), "clone_skb 1")
        pg_write(pg_dev_path(dev), "clone_skb 0")
    except RuntimeError:
        _CLONE_SUPPORTED = False
        info("clone_skb non supportato su questo device (veth consegna l'skb "
             "alla RX del peer e non puo' condividerlo): niente escalation")
    return _CLONE_SUPPORTED


def probe_burst_support(dev):
    """Come sopra per `burst`. Il kernel lo rifiuta esattamente negli stessi
    casi di clone_skb piu' xmit_mode queue_xmit: entrambi riusano lo stesso
    skb, ed e' proprio cio' che veth non puo' fare.

    Provarlo PRIMA e' la differenza fra "un esperimento in meno" e "un punto
    di misura a zero pacchetti in mezzo allo sweep"."""
    global _BURST_SUPPORTED
    if not os.path.exists(pg_dev_path(dev)):
        return _BURST_SUPPORTED
    try:
        pg_write(pg_dev_path(dev), "burst 2")
        pg_write(pg_dev_path(dev), "burst 0")
    except RuntimeError:
        _BURST_SUPPORTED = False
        info("burst non supportato su questo device: come clone_skb, "
             "richiede un skb condivisibile")
    return _BURST_SUPPORTED


class GenCaps:
    """Cosa accetta DAVVERO questo device in questo xmit_mode.

    Per device e per modalita', perche' sono condizioni diverse: clone_skb e'
    rifiutato in netif_receive anche su un device che altrove lo accetta. Il
    risultato e' in cache: senza, ogni punto di misura ristampa lo stesso
    avviso per ogni istanza, e a tre thread sono sei righe di rumore per
    misura."""

    _cache = {}

    def __init__(self, clone=False, burst=False, probed=False):
        self.clone = clone
        self.burst = burst
        self.probed = probed

    @classmethod
    def probe(cls, name, xmit_mode="start_xmit", quiet=False):
        dev = name.split("@")[0]
        key = (dev, xmit_mode)
        if key in cls._cache:
            return cls._cache[key]
        caps = cls()
        path = pg_dev_path(name)
        if not os.path.exists(path):
            return caps                 # niente device: niente da dichiarare
        for attr, cmd_on, cmd_off in (("clone", "clone_skb 1", "clone_skb 0"),
                                      ("burst", "burst 2", "burst 0")):
            try:
                pg_write(path, cmd_on)
                pg_write(path, cmd_off)
                setattr(caps, attr, True)
            except RuntimeError:
                setattr(caps, attr, False)
        caps.probed = True
        cls._cache[key] = caps
        global _CLONE_SUPPORTED, _BURST_SUPPORTED
        _CLONE_SUPPORTED, _BURST_SUPPORTED = caps.clone, caps.burst
        if not quiet:
            yn = lambda v: "si" if v else "no"
            info(f"{dev} ({xmit_mode}): clone_skb={yn(caps.clone)} "
                 f"burst={yn(caps.burst)}")
            if not caps.clone and not caps.burst:
                note("nessuna delle due: e' il caso normale su veth, che non "
                     "annuncia IFF_TX_SKB_SHARING. L'unica manopola che resta "
                     "per alzare il carico offerto e' il numero di thread.")
        return caps

    @classmethod
    def forget(cls):
        cls._cache.clear()


def pg_clear_threads(threads):
    """Stacca ogni device dai thread indicati.

    `threads` puo' essere un numero (i primi N thread, come faceva la versione
    precedente) o una lista di CPU. La seconda forma e' quella giusta adesso
    che le CPU del generatore non sono piu' 0..N-1."""
    cpus = range(threads) if isinstance(threads, int) else list(threads)
    for cpu in cpus:
        try:
            pg_write(pg_thread_path(cpu), "rem_device_all")
        except RuntimeError:
            continue        # meno thread che CPU, o CPU offline: niente da fare


def pg_ensure_device(dev, thread=0):
    """Attacca `dev` se pktgen non lo conosce (piu'). Idempotente."""
    if os.path.exists(pg_dev_path(dev)):
        return pg_dev_path(dev)
    return pg_add_device(dev, thread)


def pg_add_device(dev, thread=0):
    """Attacca `dev` al thread generatore `thread` (= CPU) e verifica che ci sia.

    `dev` puo' essere "ipa0p" oppure "ipa0p@2": la seconda forma e' la sintassi
    ufficiale di pktgen per mettere lo STESSO netdev su piu' thread, ed e'
    quella che i sample del kernel usano per generare da piu' core."""
    pg_write(pg_thread_path(thread), f"add_device {dev}")
    d = pg_dev_path(dev)
    if not os.path.exists(d):
        raise RuntimeError(
            f"pktgen: {d} non esiste dopo `add_device {dev}` sul thread "
            f"{thread}. L'interfaccia esiste ed e' UP? `ip link show "
            f"{dev.split('@')[0]}`")
    return d


def pg_set_params(dev, pkt_size, count, delay, dst_ip="10.0.0.2",
                  dst_mac="02:00:00:00:00:02", queue_map=None):
    """Cambia i parametri di un device GIA' attaccato, senza staccarlo.

    Separato da pg_configure perche' rimuovere e riaggiungere il device a ogni
    punto di misura faceva fallire `add_device` con EBUSY -- la rimozione non e'
    sincrona e il thread lo teneva ancora. Cambiare i parametri e' quello che
    serviva fin dall'inizio.

    `queue_map` fissa la coda di trasmissione usata da questa istanza. Con piu'
    istanze sullo stesso device e' cio' che impedisce loro di contendersi lo
    stesso txq lock: e' la manopola che rende utile il secondo thread."""
    d = pg_dev_path(dev)
    cmds = [f"count {count}", f"pkt_size {pkt_size}", f"delay {delay}",
            f"dst {dst_ip}", f"dst_mac {dst_mac}",
            "udp_src_min 1234", "udp_src_max 1234",
            "udp_dst_min 9999", "udp_dst_max 9999"]
    if queue_map is not None:
        cmds += [f"queue_map_min {queue_map}", f"queue_map_max {queue_map}"]
    for cmd in cmds:
        pg_write(d, cmd)


def pg_configure(dev, pkt_size, count, delay, dst_ip, dst_mac, clone=0,
                 thread=0, burst=0, xmit_mode="start_xmit", queue_map=None):
    """Put one device on one generator thread and configure it.

    One instance per thread. pktgen threads are pinned to a CPU each, so N
    instances on N threads is N generator cores -- which is the only way to
    raise the offered load on this bench when clone_skb is refused by veth (it
    modifies the skb, so it cannot advertise IFF_TX_SKB_SHARING)."""
    pg_write(pg_thread_path(thread), f"add_device {dev}")
    d = pg_dev_path(dev)
    # add_device creates this entry, and a failed add leaves it missing. Saying
    # so here beats an ENOENT from the first pgset, which points at the wrong
    # step.
    if not os.path.exists(d):
        raise RuntimeError(
            f"pktgen: {d} non esiste dopo `add_device {dev}`. "
            f"L'interfaccia esiste ed e' UP? `ip link show "
            f"{dev.split('@')[0]}`")
    if xmit_mode != "start_xmit":
        # Set before anything else: it changes which path the packets take, and
        # some settings are only meaningful on one of them.
        pg_write(d, f"xmit_mode {xmit_mode}")
    caps = GenCaps.probe(dev, xmit_mode, quiet=True)
    if burst:
        if caps.burst:
            try:
                pg_write(d, f"burst {burst}")
            except RuntimeError:
                warn("burst rifiutato da questo device, proseguo senza.")
        else:
            # Gia' saputo dalla sonda: non si riprova e non si ristampa.
            pass
    if clone:
        if caps.clone:
            try:
                pg_write(d, f"clone_skb {clone}")
            except RuntimeError:
                warn("clone_skb rifiutato da questo device: veth consegna "
                     "l'skb alla RX del peer e non puo' condividerlo.")
        else:
            pass
    pg_set_params(dev, pkt_size, count, delay, dst_ip, dst_mac,
                  queue_map=queue_map)


# pktgen's device file after a run looks like:
#
#   Result: OK: 1234567(c1234000+d567) usec, 200000 (64byte,0frags)
#     162000pps 82Mb/sec (82944000bps) errors: 0
#   Current:
#     pkts-sofar: 200000  errors: 0
#
# `pkts-sofar` is the count, the number inside Result's parentheses is the
# elapsed microseconds, and `pps` is pktgen's own rate. Taking the duration
# from pktgen rather than from a wall clock here matters: the write to pgctrl
# blocks, but it also covers thread startup and teardown, which at small
# packet counts is a large share of the wall time.
_SOFAR_RE = re.compile(r"pkts-sofar:\s*(\d+)")
_USEC_RE = re.compile(r"Result: OK:\s*(\d+)\(")
_PPS_RE = re.compile(r"(\d+)pps")
_ERR_RE = re.compile(r"errors:\s*(\d+)")


class GenRun(tuple):
    """L'esito di UNA finestra del generatore.

    E' una tupla di tre elementi (tx, pps, secs) perche' tutto il codice
    esistente fa `tx, pps, secs = pg_run_and_read(...)` e quella forma deve
    continuare a funzionare. Gli attributi in piu' servono alla diagnostica:
    per-istanza, skew fra i thread, errori riportati dal generatore.

    La DURATA aggregata e' il MASSIMO fra le istanze, non il minimo e non la
    media. `pgctrl start` blocca finche' l'ultimo thread ha finito, quindi la
    finestra vera e' lunga quanto il thread piu' lento; dividere il totale per
    una durata piu' corta gonfierebbe ogni pps della tabella.

    `window` e' la durata dell'INTERO blocco su pgctrl start. E' l'intervallo
    in cui i contatori del DUT accumulano -- si azzerano prima dello start e si
    leggono dopo il ritorno -- ed e' quindi l'unico divisore onesto per i pps
    in ricezione."""

    def __new__(cls, tx, pps, secs, per_dev=None, wall=0.0, errors=0):
        self = super().__new__(cls, (tx, pps, secs))
        self.tx = tx
        self.pps = pps
        self.secs = secs
        self.per_dev = per_dev or []
        self.wall = wall
        self.errors = errors
        # Solo per le finestre stazionarie (Generator.steady): le differenze
        # dei contatori del DUT, e quanto sono partite sfasate le istanze.
        self.steady = False
        self.dut = None
        self.start_offset_ms = None
        self.read_ms = None
        # La finestra dei contatori non e' la durata che un thread si
        # attribuisce: a thread sfasati i due intervalli non coincidono, e
        # dividere RX per la durata del thread piu' lungo dava rate piu' alti
        # del tetto del generatore -- misurato 6,5 Mpps a 128 byte contro 3,6
        # Mpps a 64, cioe' frame piu' grandi "piu' veloci", che e' impossibile.
        self.window = max(wall, secs)
        durs = [d["secs"] for d in self.per_dev if d.get("secs")]
        # Skew: quanto sono durate diversamente le istanze. Sopra il 20% i
        # thread non hanno lavorato nella stessa finestra e il rate aggregato
        # e' una media su periodi diversi -- va detto, non corretto in
        # silenzio.
        self.skew_pct = (round(100.0 * (max(durs) - min(durs)) / max(durs), 1)
                         if len(durs) > 1 and max(durs) > 0 else 0.0)
        # Coerenza: il totale trasmesso diviso la durata globale deve
        # assomigliare alla somma dei pps che pktgen riporta per istanza. Se non
        # ci assomiglia, uno dei due non descrive questa finestra.
        agg = (tx / self.window) if self.window else 0.0
        self.rate_mismatch_pct = (round(100.0 * abs(agg - pps) / pps, 1)
                                  if pps else 0.0)
        return self

    @property
    def tx_pps_aggregate(self):
        """TX totale diviso la durata GLOBALE. E' la cifra onesta da usare:
        sommare i pps per-istanza li somma su finestre che non coincidono."""
        return int(self.tx / self.window) if self.window else 0


def pg_run_and_read(devs):
    """Start every configured thread, wait, and sum what they sent.

    `pgctrl start` runs ALL threads at once and blocks until the last one
    finishes, so one call drives the whole generator."""
    if isinstance(devs, str):
        devs = [devs]
    wall0 = time.time()
    pg_write(f"{PKTGEN_DIR}/pgctrl", "start")     # blocks until all are done
    wall = time.time() - wall0

    sent = pps = errors = 0
    secs = 0.0
    per_dev = []
    for dev in devs:
        try:
            with open(pg_dev_path(dev)) as f:
                text = f.read()
        except FileNotFoundError:
            # pktgen ha smesso di conoscere questo device fra la
            # configurazione e la lettura. Succede quando il fabric viene
            # ricostruito fra un metodo e l'altro: l'interfaccia ha lo stesso
            # NOME ma e' un'altra, e lo stato di pktgen non sopravvive al giro.
            # Costa un punto di misura, non il run: il chiamante lo salta e
            # riaggancia il device al giro dopo.
            raise PktgenEmptyRun(
                f"pktgen non conosce piu' {dev} (fabric ricostruito?)")
        m = _SOFAR_RE.search(text)
        d_tx = int(m.group(1)) if m else 0
        m = _USEC_RE.search(text)
        d_secs = int(m.group(1)) / 1e6 if m else 0.0
        m = _PPS_RE.search(text)
        d_pps = int(m.group(1)) if m else 0
        # `errors:` compare due volte (nel Result e in Current): la seconda e'
        # il contatore corrente del device, ed e' quella che interessa.
        errs = _ERR_RE.findall(text)
        d_err = int(errs[-1]) if errs else 0
        sent += d_tx
        pps += d_pps
        errors += d_err
        secs = max(secs, d_secs)
        per_dev.append(dict(dev=dev, tx=d_tx, pps=d_pps, secs=round(d_secs, 4),
                            errors=d_err))
    secs = secs or wall
    pps = pps or (int(sent / secs) if secs else 0)
    if sent == 0:
        # Non fatale: un punto che non si misura e' un punto che non si
        # misura, non la fine dell'esperimento. Alzare qui buttava via anche
        # le misure gia' riuscite dello stesso run.
        raise PktgenEmptyRun(
            f"pktgen non riporta pacchetti per {devs}")
    return GenRun(sent, pps, secs, per_dev=per_dev, wall=wall, errors=errors)


# ==========================================================================
# IL GENERATORE COME OGGETTO: configurato una volta, riusato per ogni punto
# ==========================================================================
# Prima la configurazione di pktgen era sparsa fra measure_point, _fair_sweep e
# run_latency, ognuno con la sua idea di quanti thread usare (uno) e su quale
# CPU (la 0). Metterla in un oggetto solo serve a tre cose concrete:
#
#   1. i thread e le CPU si decidono UNA volta, dal CpuPlan, e valgono per
#      tutte le pipeline -- che e' il requisito del confronto equo;
#   2. le capacita' del device (clone_skb, burst) si sondano una volta e si
#      riportano una volta;
#   3. la durata della finestra diventa una proprieta' del generatore e non del
#      chiamante, quindi warm-up e misura usano lo stesso codice con due durate
#      diverse invece di due implementazioni che divergono.


def _num_queues(dev, kind="tx"):
    """Quante code ha davvero questo device. Serve a non chiedere una
    queue_map che non esiste: pktgen la accetterebbe e il kernel poi userebbe
    la coda 0, cioe' tutti i thread di nuovo sulla stessa."""
    path = f"/sys/class/net/{dev}/queues"
    try:
        n = len([x for x in os.listdir(path) if x.startswith(kind + "-")])
    except OSError:
        return 1
    return max(1, n)


class Generator:
    """pktgen su N CPU scelte, verso uno o piu' device.

    topology="shared": UN device, N istanze `dev@i`, una per CPU del
        generatore, ognuna sulla propria coda TX. E' il modo per avere piu'
        core di generatore che core di DUT -- la condizione in cui la pipeline
        satura. Il suffisso `@i` e' la sintassi di pktgen per lo stesso netdev
        su piu' thread: pktgen_dev_get_by_name si ferma alla '@' per cercare il
        device, e tiene il nome intero per il file di controllo.

    topology="links": un device per CPU (comportamento storico). Ogni device
        ha la sua NAPI e quindi il suo core DUT: gen e DUT scalano insieme.
    """

    def __init__(self, devs, plan, xmit_mode="start_xmit", topology="shared",
                 clone=0, burst=0, dst_ip="10.0.0.2",
                 dst_mac="02:00:00:00:00:02", window_s=WINDOW_S,
                 warmup_s=DEFAULT_WARMUP_S, window_mode=None):
        self.devs = [devs] if isinstance(devs, str) else list(devs)
        self.window_mode = window_mode or WINDOW_MODE
        self.plan = plan
        self.xmit_mode = xmit_mode
        self.topology = topology
        self.clone = clone
        self.burst = burst
        self.dst_ip = dst_ip
        self.dst_mac = dst_mac
        self.window_s = window_s
        self.warmup_s = warmup_s
        self.caps = GenCaps()
        self.rate_estimate = 0          # pps aggregati a delay 0, da calibrate
        self.last_run = None            # l'ultima finestra, per la diagnostica
        self.instances = []             # [{name, dev, cpu, queue_map}]
        self._build_instances()

    # -- costruzione ------------------------------------------------------
    def _build_instances(self):
        cpus = list(self.plan.gen) or [0]
        self.instances = []
        if self.topology == "links":
            # Un device per CPU; se i device sono meno delle CPU, si usano
            # tante CPU quanti sono i device: due thread sullo stesso device
            # senza il suffisso '@' pktgen li rifiuta (EBUSY).
            for i, dev in enumerate(self.devs[:len(cpus)]):
                self.instances.append(dict(name=dev, dev=dev, cpu=cpus[i],
                                           queue_map=None))
            if not self.instances:
                raise RuntimeError(
                    "topology='links' richiede almeno un device di ingresso"
                )
            return
        dev = self.devs[0]
        ntx = _num_queues(dev, "tx")
        for i, cpu in enumerate(cpus):
            name = dev if len(cpus) == 1 else f"{dev}@{i}"
            # Una coda per istanza finche' ce ne sono; oltre, si riparte da
            # capo e due istanze condividono il txq lock. Non e' un errore: e'
            # il motivo per cui il device d'ingresso viene creato con almeno
            # tante code TX quanti sono i thread generatore.
            qmap = None if ntx <= 1 else (i % ntx)
            self.instances.append(dict(name=name, dev=dev, cpu=cpu,
                                       queue_map=qmap))
        if not self.instances:
            raise RuntimeError("nessuna istanza pktgen costruita")

    @property
    def names(self):
        return [i["name"] for i in self.instances]

    @property
    def n_inst(self):
        return len(self.instances)

    # -- ciclo di vita ----------------------------------------------------
    def attach(self, verbose=True):
        """Aggancia ogni istanza al suo thread e applica la configurazione
        fissa (xmit_mode, queue_map, clone, burst)."""
        pg_clear_threads(self.plan.gen)
        for inst in self.instances:
            pg_add_device(inst["name"], inst["cpu"])
            self._configure(inst)
        self.caps = GenCaps.probe(self.instances[0]["name"], self.xmit_mode,
                                  quiet=not verbose)
        # La sonda lascia clone_skb/burst a zero: riapplicare le manopole dopo
        # e' cio' che evita che la sonda cancelli la configurazione.
        for inst in self.instances:
            self._apply_knobs(inst)
        if verbose:
            self.describe()
        return self

    def _configure(self, inst):
        d = pg_dev_path(inst["name"])
        if self.xmit_mode != "start_xmit":
            pg_write(d, f"xmit_mode {self.xmit_mode}")
        if inst["queue_map"] is not None:
            pg_write(d, f"queue_map_min {inst['queue_map']}")
            pg_write(d, f"queue_map_max {inst['queue_map']}")

    def _apply_knobs(self, inst):
        """clone_skb e burst, ma SOLO se il device li ha accettati in sonda.

        Insistere su un parametro rifiutato non e' gratis: il device resta in
        uno stato da cui `start` non parte, e la misura successiva esce a zero
        pacchetti."""
        d = pg_dev_path(inst["name"])
        if self.clone and self.caps.clone:
            try:
                pg_write(d, f"clone_skb {self.clone}")
            except RuntimeError:
                pass
        if self.burst and self.caps.burst:
            try:
                pg_write(d, f"burst {self.burst}")
            except RuntimeError:
                pass

    def ensure(self):
        """Riaggancia cio' che e' sparito. Costa una `stat` per istanza e
        toglie un'intera classe di fallimenti: il fabric ricostruito fra due
        metodi lascia device con lo stesso nome ma un altro ifindex, e pktgen
        non li conosce piu'."""
        for inst in self.instances:
            if not os.path.exists(pg_dev_path(inst["name"])):
                pg_add_device(inst["name"], inst["cpu"])
                self._configure(inst)
                self._apply_knobs(inst)

    def detach(self):
        pg_clear_threads(self.plan.gen)

    def describe(self):
        where = ", ".join(f"cpu{i['cpu']}:{i['name']}"
                          + (f"(q{i['queue_map']})"
                             if i["queue_map"] is not None else "")
                          for i in self.instances)
        info(f"generatore: {self.n_inst} thread -- {where}")
        info(f"xmit_mode {self.xmit_mode}, clone_skb "
             f"{self.clone if self.caps.clone else 0}, burst "
             f"{self.burst if self.caps.burst else 0}")
        if self.xmit_mode == "netif_receive":
            warn("netif_receive inietta nel percorso RX del device: XDP gira "
                 "in modo GENERIC e sulla CPU DEL GENERATORE. In questa "
                 "modalita' la separazione gen/DUT non esiste, e i numeri non "
                 "sono confrontabili con quelli in modo native.")

    # -- rate, conteggi, finestre -----------------------------------------
    def delay_for(self, total_pps):
        """Il `delay` (ns fra un pacchetto e il successivo, PER ISTANZA) che
        offre `total_pps` in aggregato. Il ritardo lo impone pktgen, cioe' il
        kernel: una pausa in Python non e' un rate, e' la granularita' dello
        scheduler -- misurato, chiedendo 200 kpps ne uscivano 11 k."""
        if total_pps <= 0:
            return 0
        per_inst = max(1.0, float(total_pps) / self.n_inst)
        return max(1, int(1e9 / per_inst))

    def window_count(self, total_pps, seconds=None):
        """Quanti pacchetti PER ISTANZA per una finestra di `seconds`.

        pktgen conta pacchetti, non secondi: la durata si ottiene cosi'. I due
        estremi sono a durata fissa per una ragione misurata: a NUMERO fisso
        (200 000) un punto a 11 kpps durava 17 secondi da solo."""
        seconds = self.window_s if seconds is None else seconds
        total = max(MIN_WINDOW_PKTS,
                    min(MAX_WINDOW_PKTS, int(max(0.0, total_pps) * seconds)))
        return max(1000, total // self.n_inst)

    def run(self, frame, count, delay):
        """Una finestra grezza. `count` e' PER ISTANZA, quindi il carico
        offerto scala con i thread e la durata per thread resta paragonabile."""
        self.ensure()
        for inst in self.instances:
            pg_set_params(inst["name"], frame, count, delay,
                          dst_ip=self.dst_ip, dst_mac=self.dst_mac,
                          queue_map=inst["queue_map"])
        # L'ultima finestra resta a disposizione della diagnostica: i pps per
        # ISTANZA si leggono solo da qui, e sono cio' che dice se un thread
        # generatore sta indietro rispetto agli altri.
        self.last_run = pg_run_and_read(self.names)
        return self.last_run

    def warmup(self, frame, delay=0, seconds=None):
        """Una finestra buttata via prima della misura. Il risultato si ignora
        di proposito: serve solo a scaldare cache e code.

        IL CONTEGGIO SI RICAVA DAL `delay` DEL PUNTO, non dal rate massimo del
        generatore. Due difetti, tutti e due misurati il 2026-09-18:

        1. DURATA. Il conteggio veniva da `rate_estimate` (il tetto del
           generatore, ~1.9 Mpps) mentre il `delay` era gia' quello del punto.
           A 74 kpps il warm-up chiedeva quindi 186 000 pacchetti pacchettati
           a 74 kpps: 2,5 secondi di "riscaldamento" da 0,1 secondi, per ogni
           punto della scala.

        2. CODA EREDITATA. Se invece il delay era 0, il warm-up sparava a
           piena velocita' e lasciava il ptr_ring del veth PIENO. La misura
           subito dopo cominciava con la coda gia' satura e i primi pacchetti
           venivano respinti -- perdita che finiva nel conto del punto e non
           dipendeva dal suo rate. E' la firma delle perdite del 4-10%
           osservate a rate bassissimi, dove il DUT aveva due ordini di
           grandezza di margine.

        Il drenaggio esplicito in `_measure_once` (DRAIN_S) chiude la (2) da
        valle; questo la chiude da monte, che e' dove nasce."""
        seconds = self.warmup_s if seconds is None else seconds
        if seconds <= 0:
            return None
        if self.window_mode == "steady":
            # La finestra stazionaria scarta gia' da se' l'avvio: misura solo
            # dopo che tutte le istanze trasmettono e la coda si e' assestata
            # (STEADY_SETTLE_S), e la coda della finestra prima si e' svuotata
            # durante lo stop. Un warm-up a conteggio costava invece un blocco
            # intero su `pgctrl start` -- ~0,35 s di cui ~0,25 di tempo morto
            # di pktgen -- a OGNI punto.
            return None
        if delay > 0:
            rate = (1e9 / delay) * self.n_inst
        else:
            rate = self.rate_estimate or 1_000_000
        try:
            return self.run(frame, self.window_count(rate, seconds), delay)
        except (PktgenEmptyRun, RuntimeError):
            return None

    def timed_run(self, frame, delay, seconds=None, expect_pps=None):
        """Una finestra che punta a durare `seconds`, e lo verifica.

        Se la finestra esce molto piu' corta del bersaglio vuol dire che la
        stima del rate era bassa: si ricalibra UNA volta sul rate appena
        misurato e si rifa'. Una volta sola, perche' due ricalibrazioni di
        fila vogliono dire che il rate non e' stabile, e allora il problema non
        e' il conteggio."""
        seconds = self.window_s if seconds is None else seconds
        if self.window_mode == "steady":
            # La durata e' quella chiesta per costruzione: niente da
            # ricalibrare.
            return self.steady(frame, delay, seconds=seconds)
        rate = expect_pps or self.rate_estimate or 1_000_000
        r = self.run(frame, self.window_count(rate, seconds), delay)
        if r.secs < seconds * WINDOW_SHORT_FRACTION and r.secs > 0:
            better = r.tx / r.secs
            r2 = self.run(frame, self.window_count(better, seconds), delay)
            return r2
        return r

    # -- la finestra stazionaria (vedi STEADY_SETTLE_S) --------------------
    def _running(self):
        """Le istanze che pktgen dichiara in trasmissione ADESSO: la riga
        `Running:` dei file kpktgend_<cpu>."""
        out = set()
        for cpu in {i["cpu"] for i in self.instances}:
            try:
                with open(pg_thread_path(cpu)) as f:
                    text = f.read()
            except OSError:
                continue
            for line in text.splitlines():
                if line.startswith("Running:"):
                    out.update(line.split(":", 1)[1].split())
        return out

    def _gen_counters(self):
        """{istanza: (pkts-sofar, errors, started_us)} letti a trasmissione in
        corso: la sezione `Current:` del file del device si aggiorna dal
        vivo."""
        out = {}
        for inst in self.instances:
            with open(pg_dev_path(inst["name"])) as f:
                text = f.read()
            m = _SOFAR_RE.search(text)
            errs = _ERR_RE.findall(text)
            st = _STARTED_RE.search(text)
            out[inst["name"]] = (int(m.group(1)) if m else 0,
                                 int(errs[-1]) if errs else 0,
                                 int(st.group(1)) if st else 0)
        return out

    def _snapshot(self, probe):
        """(istante, contatori pktgen, contatori DUT, durata della lettura).

        Rifatta finche' la lettura non dura meno di STEADY_READ_MAX_S: una
        lettura interrotta da una sospensione del processo attribuirebbe ai
        contatori un istante sbagliato di tutta la sospensione."""
        best = None
        for _ in range(STEADY_READ_TRIES):
            t0 = time.monotonic()
            g = self._gen_counters()
            d = probe() if probe else {}
            t1 = time.monotonic()
            if t1 - t0 <= STEADY_READ_MAX_S:
                return (t0 + t1) / 2.0, g, d, t1 - t0
            best = t1 - t0 if best is None else min(best, t1 - t0)
        raise PktgenEmptyRun(
            f"finestra stazionaria: nessuna lettura dei contatori sotto "
            f"{STEADY_READ_MAX_S * 1000:.0f} ms in {STEADY_READ_TRIES} "
            f"tentativi (la piu' breve {best * 1000:.1f} ms): la macchina "
            f"sospende il processo, la finestra non si puo' datare")

    def steady(self, frame, delay, probe=None, seconds=None):
        """Una finestra STAZIONARIA: i rate sono differenze fra due letture
        fatte mentre TUTTE le istanze trasmettono.

        `probe()` legge contatori CUMULATIVI del DUT (dict nome -> intero).
        Si chiama alle due letture subito dopo pktgen, nello stesso ordine:
        lo sfasamento fra le due letture e' lo stesso all'inizio e alla fine
        e nelle differenze si annulla. Nessun contatore va azzerato.

        Ritorna un GenRun (tx, pps, secs) con `steady` vero, `dut` (le
        differenze di `probe`) e `start_offset_ms` (sfasamento di partenza
        fra le istanze: diagnostica, non entra nei rate)."""
        seconds = self.window_s if seconds is None else seconds
        self.ensure()
        per_inst = (1e9 / delay) if delay else STEADY_MAX_PPS_PER_INST
        safety = max(1000, int(per_inst * (STEADY_START_TIMEOUT_S
                                           + STEADY_SETTLE_S + seconds
                                           + STEADY_SAFETY_S)))
        for inst in self.instances:
            pg_set_params(inst["name"], frame, safety, delay,
                          dst_ip=self.dst_ip, dst_mac=self.dst_mac,
                          queue_map=inst["queue_map"])
        failed = []

        def _start():
            # `start` blocca fino alla fine: gira in un thread, e il thread
            # principale legge i contatori nel frattempo.
            try:
                pg_write(f"{PKTGEN_DIR}/pgctrl", "start")
            except Exception as e:          # riportata dal thread principale
                failed.append(e)

        names = set(self.names)
        th = threading.Thread(target=_start, name="pgctrl-start", daemon=True)
        t0 = time.monotonic()
        th.start()
        try:
            while not names <= self._running():
                if failed or time.monotonic() - t0 > STEADY_START_TIMEOUT_S:
                    raise PktgenEmptyRun(
                        f"finestra stazionaria: non tutte le istanze sono "
                        f"partite entro {STEADY_START_TIMEOUT_S}s (in "
                        f"trasmissione: {sorted(self._running())}"
                        + (f"; start: {failed[0]}" if failed else "") + ")")
                time.sleep(0.005)
            time.sleep(STEADY_SETTLE_S)
            ta, ga, da, ra = self._snapshot(probe)
            time.sleep(max(0.0, ta + seconds - time.monotonic()))
            tb, gb, db, rb = self._snapshot(probe)
            fermi = sorted(names - self._running())
        finally:
            pg_stop()
            th.join(timeout=5.0)
        if th.is_alive():
            raise RuntimeError("pktgen: `start` non e' tornato dopo `stop`")
        if failed:
            raise RuntimeError(f"pktgen start: {failed[0]}")
        if fermi:
            raise PktgenEmptyRun(
                f"finestra stazionaria: {fermi} fermi prima della seconda "
                f"lettura (count di sicurezza esaurito?): la finestra non e' "
                f"tutta a regime, scartata")
        secs = tb - ta
        per_dev, tx, errors = [], 0, 0
        for inst in self.instances:
            n = inst["name"]
            d_tx = gb[n][0] - ga[n][0]
            d_err = gb[n][1] - ga[n][1]
            tx += d_tx
            errors += d_err
            per_dev.append(dict(dev=n, tx=d_tx, pps=int(d_tx / secs),
                                secs=round(secs, 4), errors=d_err))
        if tx == 0:
            raise PktgenEmptyRun(
                f"finestra stazionaria: nessun pacchetto trasmesso fra le due "
                f"letture ({self.names})")
        run = GenRun(tx, sum(d["pps"] for d in per_dev), secs,
                     per_dev=per_dev, wall=secs, errors=errors)
        run.steady = True
        run.dut = {k: db[k] - da.get(k, 0) for k in db}
        run.read_ms = round(1000.0 * max(ra, rb), 2)
        starts = [g[2] for g in gb.values() if g[2]]
        run.start_offset_ms = (round((max(starts) - min(starts)) / 1000.0, 1)
                               if len(starts) > 1 else 0.0)
        self.last_run = run
        return run

    def calibrate(self, frame=64, seconds=None):
        """Quanto offre questo generatore a delay 0, misurato e non assunto.

        E' il numero da cui partono sia la ricerca del ginocchio sia la scala
        della modalita' saturate: sapere il tetto del GENERATORE e' la
        premessa per dire se il tetto che si osserva e' suo o della pipeline.
        """
        seconds = self.window_s if seconds is None else seconds
        self.warmup(frame, 0, min(self.warmup_s, seconds))
        migliore = None
        for _ in range(max(1, CALIB_WINDOWS)):
            try:
                r = self.timed_run(frame, 0, seconds)
            except (PktgenEmptyRun, RuntimeError):
                continue
            if migliore is None or r.tx_pps_aggregate > migliore.tx_pps_aggregate:
                migliore = r
        if migliore is None:
            raise PktgenEmptyRun("calibrazione: nessuna finestra utilizzabile")
        self.rate_estimate = migliore.tx_pps_aggregate
        return migliore

    # -- ricerca automatica della configurazione del generatore ------------
    def tune(self, frame=64, seconds=None, verbose=True):
        """Prova le manopole che questo device accetta e TIENE solo quelle che
        alzano davvero il rate offerto.

        Non e' "metti tutto al massimo": clone_skb toglie di mezzo
        l'allocazione per pacchetto, quindi cambia cosa si misura, e burst
        consegna piu' pacchetti per chiamata, quindi cambia la forma del
        traffico. Pagarlo ha senso solo se in cambio il carico offerto sale di
        qualcosa che si vede -- sotto GEN_KNOB_MIN_GAIN si torna alla
        condizione di riferimento, che e' un buffer per pacchetto.

        Su veth nessuna delle due e' accettata, e questa funzione lo dice e
        non fa altro: e' il caso normale di questo banco."""
        seconds = self.window_s if seconds is None else seconds
        base = self.calibrate(frame, seconds)
        best = base.tx_pps_aggregate
        chosen = dict(clone=0, burst=0)
        if verbose:
            info(f"generatore a delay 0, condizione di riferimento: "
                 f"{best} pps offerti")
        if not (self.caps.clone or self.caps.burst):
            if verbose:
                note("nessuna manopola disponibile su questo device: il carico "
                     "offerto si alza solo con i thread (ne ho "
                     f"{self.n_inst}).")
            self.rate_estimate = best
            return chosen
        trials = []
        if self.caps.clone:
            trials.append(("clone", ESCALATE_CLONE))
        if self.caps.burst:
            trials.append(("burst", max(2, self.burst or 8)))
        for knob, value in trials:
            old = getattr(self, knob)
            setattr(self, knob, value)
            for inst in self.instances:
                self._apply_knobs(inst)
            try:
                r = self.timed_run(frame, 0, seconds)
            except (PktgenEmptyRun, RuntimeError) as e:
                warn(f"{knob}={value} ha rotto la generazione ({e}): scartato")
                setattr(self, knob, old)
                continue
            got = r.tx_pps_aggregate
            gain = (got - best) / best if best else 0.0
            if gain >= GEN_KNOB_MIN_GAIN:
                chosen[knob] = value
                best = got
                if verbose:
                    info(f"{knob}={value}: {got} pps ({gain:+.0%}) -- tenuto")
            else:
                setattr(self, knob, old)
                if verbose:
                    note(f"{knob}={value}: {got} pps ({gain:+.0%}), sotto la "
                         f"soglia del {GEN_KNOB_MIN_GAIN:.0%}: scartato, la "
                         f"condizione di riferimento e' piu' rappresentativa.")
        # Riapplica la configurazione scelta (il ciclo puo' averla cambiata).
        for inst in self.instances:
            self._apply_knobs(inst)
        self.rate_estimate = best
        return chosen


def _window_count(rate_pps):
    """Quanti pacchetti per una finestra di WINDOW_S a questo rate.

    Resta come funzione di modulo perche' il percorso storico (--latency) la
    usa con un solo thread; con piu' thread si passa da Generator.window_count,
    che divide per il numero di istanze."""
    return max(MIN_WINDOW_PKTS, min(MAX_WINDOW_PKTS, int(rate_pps * WINDOW_S)))


# ==========================================================================
# DIAGNOSTICA: chi e' il collo di bottiglia, con i numeri e non a occhio
# ==========================================================================
# Regola di questa sezione: si legge solo cio' che il kernel espone davvero, e
# se una metrica non c'e' si dice che non c'e'. Nessuna stima inventata -- una
# percentuale di CPU "dedotta" dal rate sarebbe il rate travestito, e verrebbe
# usata per spiegare il rate.
#
# Cosa si legge, e da dove:
#   /proc/stat                        tempo per CPU -> occupazione per core
#   /sys/class/net/<dev>/statistics   pacchetti, drop ed errori del device
#   /proc/net/softnet_stat            drop del backlog e time_squeeze per CPU
#   ethtool -S <dev>                  contatori XDP di veth, SE ethtool c'e'
#
# La raccolta e' agganciata FUORI dalla finestra di misura: si legge prima e
# dopo, mai durante. E si attiva solo con --diag, perche' leggere procfs fra
# un punto e l'altro costa tempo e quel tempo cade fra due finestre.


def _read_proc_stat():
    """{cpu: (busy_jiffies, total_jiffies)}. Solo le righe 'cpuN'."""
    out = {}
    try:
        with open("/proc/stat") as f:
            for line in f:
                if not line.startswith("cpu") or line.startswith("cpu "):
                    continue
                parts = line.split()
                try:
                    cpu = int(parts[0][3:])
                except ValueError:
                    continue
                vals = [int(v) for v in parts[1:]]
                total = sum(vals)
                idle = vals[3] + (vals[4] if len(vals) > 4 else 0)
                out[cpu] = (total - idle, total)
    except OSError:
        return {}
    return out


def cpu_util(before, after):
    """Occupazione per core fra due letture, in percento. Vuoto se /proc/stat
    non e' leggibile -- e in quel caso il chiamante lo dice, non lo stima."""
    out = {}
    for cpu, (busy1, tot1) in after.items():
        busy0, tot0 = before.get(cpu, (0, 0))
        dt = tot1 - tot0
        if dt > 0:
            out[cpu] = round(100.0 * (busy1 - busy0) / dt, 1)
    return out


_DEV_FIELDS = ("rx_packets", "tx_packets", "rx_dropped", "tx_dropped",
               "rx_errors", "tx_errors")


def _dev_counters(dev):
    """I contatori standard del device. Sono quelli che `ip -s link` stampa,
    letti direttamente per non dover parsare l'output di un comando."""
    base = f"/sys/class/net/{dev}/statistics"
    out = {}
    for f in _DEV_FIELDS:
        try:
            with open(os.path.join(base, f)) as fh:
                out[f] = int(fh.read().strip())
        except OSError:
            pass
    return out


def _softnet():
    """[(cpu, processed, dropped, time_squeeze)] da /proc/net/softnet_stat.

    `dropped` e' il backlog che ha traboccato (netdev_max_backlog), e conta
    soprattutto sul percorso netif_receive; `time_squeeze` e' quante volte il
    softirq ha esaurito il budget NAPI, che e' il sintomo di una RX che non sta
    dietro. Nessuno dei due e' attribuibile a un device: sono per CPU."""
    rows = []
    try:
        with open("/proc/net/softnet_stat") as f:
            for i, line in enumerate(f):
                c = line.split()
                if len(c) < 3:
                    continue
                rows.append((i, int(c[0], 16), int(c[1], 16), int(c[2], 16)))
    except OSError:
        return []
    return rows


def ethtool_stats(dev):
    """I contatori di ethtool, o None se ethtool non c'e'.

    veth espone qui i suoi contatori XDP (xdp_packets, xdp_drops,
    xdp_redirect, rx_drops per coda). Non sono garantiti: su un kernel vecchio
    o un device diverso la lista e' un'altra, quindi si restituisce quello che
    c'e' e si lascia al chiamante il compito di cercare le chiavi che gli
    servono, senza pretendere che esistano."""
    try:
        p = subprocess.run(["ethtool", "-S", dev], capture_output=True,
                           text=True, check=False)
    except OSError:
        return None             # ethtool non installato: si dichiara, non si stima
    if p.returncode != 0:
        return None
    out = {}
    for line in p.stdout.splitlines():
        if ":" not in line:
            continue
        k, _, v = line.partition(":")
        v = v.strip()
        if v.isdigit():
            out[k.strip()] = int(v)
    return out or None


class Diag:
    """Uno scatto prima e uno dopo. Niente campionamento durante la misura.

    `enabled=False` rende ogni metodo un no-op, cosi' il percorso di misura
    principale non paga nulla e non serve un `if` a ogni chiamata."""

    def __init__(self, devs=(), plan=None, enabled=False):
        self.devs = list(devs)
        self.plan = plan
        self.enabled = enabled
        self._t0 = None
        self._cpu0 = {}
        self._dev0 = {}
        self._eth0 = {}
        self._soft0 = []

    def start(self):
        if not self.enabled:
            return self
        self._t0 = time.time()
        self._cpu0 = _read_proc_stat()
        self._dev0 = {d: _dev_counters(d) for d in self.devs}
        self._eth0 = {d: (ethtool_stats(d) or {}) for d in self.devs}
        self._soft0 = _softnet()
        return self

    def stop(self):
        """{cpu_pct, dev, softnet_dropped, softnet_squeeze, secs} oppure {}."""
        if not self.enabled or self._t0 is None:
            return {}
        secs = time.time() - self._t0
        cpu = cpu_util(self._cpu0, _read_proc_stat())
        dev = {}
        for d in self.devs:
            now, before = _dev_counters(d), self._dev0.get(d, {})
            dev[d] = {k: now.get(k, 0) - before.get(k, 0) for k in now}
        # ethtool: su veth ci sono i contatori XDP (xdp_packets, xdp_drops,
        # xdp_redirect, rx_drops per coda). Non sono garantiti su ogni kernel,
        # quindi si riporta la differenza delle chiavi che ci sono e basta.
        eth = {}
        for d in self.devs:
            now = ethtool_stats(d)
            if now is None:
                continue
            before = self._eth0.get(d) or {}
            delta = {k: v - before.get(k, 0) for k, v in now.items()
                     if (v - before.get(k, 0)) != 0
                     and ("xdp" in k or "drop" in k or "err" in k)}
            if delta:
                eth[d] = delta
        soft_now = _softnet()
        drop = sum(r[2] for r in soft_now) - sum(r[2] for r in self._soft0)
        squeeze = sum(r[3] for r in soft_now) - sum(r[3] for r in self._soft0)
        return dict(secs=round(secs, 3), cpu_pct=cpu, dev=dev, ethtool=eth,
                    ethtool_available=bool(self._eth0 and
                                           any(self._eth0.values())),
                    softnet_dropped=drop, softnet_squeeze=squeeze)

    # -- lettura ----------------------------------------------------------
    def report(self, d, rate=None):
        if not d:
            return
        print(f"\n{YELLOW}  -- diagnostica ({d['secs']} s di finestra) "
              f"--{NC}")
        cpu = d.get("cpu_pct") or {}
        if not cpu:
            warn("occupazione per core non leggibile (/proc/stat): non la "
                 "stimo da altri numeri, semplicemente non c'e'.")
        else:
            gen = set(self.plan.gen) if self.plan else set()
            dut = set(self.plan.dut) if self.plan else set()
            for c in sorted(cpu):
                tag = ("gen" if c in gen else
                       "DUT" if c in dut else "sistema")
                bar = "#" * int(cpu[c] / 5)
                col = RED if cpu[c] >= CPU_BUSY_PCT else GREY
                print(f"    cpu{c:<3d} {tag:8s} {col}{cpu[c]:5.1f}%{NC} {bar}")
        for dev, ctr in (d.get("dev") or {}).items():
            if not ctr:
                continue
            bits = " ".join(f"{k}={v}" for k, v in sorted(ctr.items()) if v)
            print(f"    {dev:12s} {bits or 'nessun contatore mosso'}")
        if d.get("ethtool"):
            for dev, delta in d["ethtool"].items():
                bits = " ".join(f"{k}={v}" for k, v in sorted(delta.items()))
                print(f"    {dev:12s} [ethtool] {bits}")
        elif not d.get("ethtool_available"):
            note("ethtool non disponibile o senza contatori su questi device: "
                 "i contatori XDP di veth non sono leggibili qui, e non li "
                 "sostituisco con una stima.")
        print(f"    softnet     dropped={d.get('softnet_dropped', 0)} "
              f"time_squeeze={d.get('softnet_squeeze', 0)}")
        note("softnet dropped/time_squeeze sono PER CPU e non per device: "
             "dicono che una CPU non sta dietro, non quale device la riempie.")


def gen_cpu_load(diag_data, plan):
    """(carico medio delle CPU generatore, carico medio delle CPU DUT).

    None dove il dato non c'e'. Serve al verdetto sul collo di bottiglia, che
    senza queste due cifre resta comunque possibile ma piu' debole."""
    if not diag_data or not plan:
        return None, None
    cpu = diag_data.get("cpu_pct") or {}
    g = [cpu[c] for c in plan.gen if c in cpu]
    d = [cpu[c] for c in plan.dut if c in cpu]
    return (round(sum(g) / len(g), 1) if g else None,
            round(sum(d) / len(d), 1) if d else None)


# Etichette del verdetto. Sono anche i valori della colonna `bottleneck` nel
# CSV, quindi non si cambiano alla leggera.
BN_GEN = "generatore"
BN_IN = "pipeline-ingresso"
BN_OUT = "pipeline-uscita"
BN_PIPE = "pipeline"
BN_NOISE = "macchina"
BN_UNKNOWN = "indeterminato"


def classify_bottleneck(row, threshold=DEFAULT_LOSS_THRESHOLD, plan=None,
                        diag_data=None, noisy=False):
    """(etichetta, spiegazione) per UN punto di misura.

    L'inferenza principale non ha bisogno della diagnostica e vale sempre:

      perdita ~ 0  ->  il DUT NON e' saturo, quindi il limite osservato e' il
                       rate che il generatore e' riuscito a offrire. Questa
                       riga NON e' il throughput massimo della pipeline, e
                       chiamarlo cosi' sarebbe l'errore che tutto questo file
                       esiste per evitare.
      perdita > 0  ->  qualcosa satura, e i tre contatori dicono DOVE:
                       TX-HIT sono pacchetti mai arrivati al programma
                       (ingresso del DUT), HIT-RX sono pacchetti elaborati e
                       non usciti (uscita).

    La diagnostica, quando c'e', conferma o contraddice: CPU del generatore al
    100% con quelle del DUT scariche vuol dire generatore; il contrario vuol
    dire pipeline."""
    loss = row.get("loss_worst", row.get("loss_pct", 0.0)) or 0.0
    before = row.get("lost_before")
    after = row.get("lost_after")
    g_load, d_load = gen_cpu_load(diag_data, plan)
    tail = ""
    if g_load is not None and d_load is not None:
        tail = f" (cpu gen {g_load}%, cpu DUT {d_load}%)"

    if noisy:
        return BN_NOISE, ("la perdita non cresce col rate: e' rumore della "
                          "macchina, non saturazione" + tail)
    if loss <= threshold:
        if g_load is not None and g_load >= CPU_BUSY_PCT and (
                d_load is None or d_load < CPU_BUSY_PCT):
            return BN_GEN, ("le CPU del generatore sono sature e quelle del "
                            "DUT no: il tetto e' il generatore" + tail)
        return BN_GEN, ("nessuna perdita: il DUT non e' saturo, quindi questo "
                        "e' il rate che il generatore ha saputo offrire, non "
                        "il massimo della pipeline" + tail)
    if before is None or after is None:
        return BN_PIPE, ("si perde, ma questa riga non ha i contatori HIT: "
                         "non posso dire se all'ingresso o all'uscita" + tail)
    if after > before:
        return BN_OUT, (f"{after} pacchetti elaborati e non usciti contro "
                        f"{before} mai arrivati: satura l'uscita (il secondo "
                        f"veth e il contatore), non l'inferenza" + tail)
    if before > after:
        return BN_IN, (f"{before} pacchetti mai arrivati al programma contro "
                       f"{after} elaborati e non usciti: satura l'ingresso "
                       f"del DUT" + tail)
    return BN_UNKNOWN, "perdita presente ma non attribuibile" + tail


def report_generator(gen):
    """Che cosa ha fatto ogni THREAD del generatore nell'ultima finestra.

    E' la meta' mancante della diagnostica: l'occupazione per core dice se una
    CPU e' satura, questa dice se il thread che ci gira sopra sta consegnando
    quanto gli altri. Un'istanza molto sotto le altre vuol dire una coda TX
    contesa o una CPU che fa anche altro, e in entrambi i casi il rate
    aggregato non e' il massimo che il banco puo' offrire."""
    r = getattr(gen, "last_run", None)
    if r is None or not r.per_dev:
        note("nessuna finestra recente del generatore da riportare")
        return
    print("")
    print(f"{YELLOW}  -- generatore, ultima finestra --{NC}")
    cpu_of = {i["name"]: i["cpu"] for i in gen.instances}
    for d in r.per_dev:
        print(f"    {d['dev']:16s} cpu{cpu_of.get(d['dev'], '?'):<3} "
              f"tx={d['tx']:>9d} {d['pps']:>9d} pps  {d['secs']:>6.3f} s  "
              f"errori={d['errors']}")
    print(f"    {'AGGREGATO':16s}     tx={r.tx:>9d} "
          f"{r.tx_pps_aggregate:>9d} pps  {r.secs:>6.3f} s")
    if r.skew_pct > 20.0:
        warn(f"le istanze non hanno lavorato nella stessa finestra "
             f"(scarto {r.skew_pct}% fra la piu' lunga e la piu' corta): il "
             f"rate aggregato e' una media su periodi diversi.")
    if r.rate_mismatch_pct > 25.0:
        warn(f"TX/durata globale e somma dei pps per istanza differiscono del "
             f"{r.rate_mismatch_pct}%: uno dei due non descrive questa "
             f"finestra. La cifra usata e' sempre TX diviso la durata "
             f"GLOBALE, che e' quella che non puo' gonfiare il risultato.")


# ==========================================================================
# RX counter
# ==========================================================================
def _percpu_sum(table, key=0):
    vals = table[ct.c_int(key)]
    return sum(int(v) for v in vals)


# ==========================================================================
# un punto di misura
# ==========================================================================
def _read_u64(table, key):
    try:
        v = table[ct.c_int(key)]
        if isinstance(v, (bytes, bytearray)):      # a pinned map (aot)
            return int.from_bytes(v, "little")
        return int(v.value)
    except Exception:
        return 0


def _zero_counters(setup, rx_tab, n_out):
    for c in range(n_out):
        try:
            setup["cls_stats"][ct.c_int(c)] = ct.c_ulonglong(0)
        except Exception:
            break
    for k in range(len(setup["pkt_stats"])):
        setup["pkt_stats"][ct.c_int(k)] = ct.c_ulonglong(0)
    rx_tab.clear()


def _agg(values):
    """media, minimo, massimo, deviazione standard e coefficiente di
    variazione di una lista di misure.

    La deviazione standard su 3 campioni non e' una statistica seria, e non
    viene usata per decidere niente: e' riportata perche' e' cio' che permette
    di leggere una mediana sapendo quanto ballava. Il coefficiente di
    variazione (std/media) e' la forma confrontabile fra rate diversi."""
    vals = [v for v in values if v is not None]
    if not vals:
        return dict(mean=0, min=0, max=0, std=0.0, cv_pct=0.0)
    mean = sum(vals) / len(vals)
    std = statistics.pstdev(vals) if len(vals) > 1 else 0.0
    return dict(mean=int(mean), min=min(vals), max=max(vals),
                std=round(std, 1),
                cv_pct=round(100.0 * std / mean, 1) if mean else 0.0)


def measure_point(setup, rx_tab, fab, frame, delay, count, n_out, clone=0,
                  tg_devs=None, repeat=DEFAULT_REPEAT, burst=0,
                  xmit_mode="start_xmit", gen=None, warmup=True,
                  threshold=DEFAULT_LOSS_THRESHOLD, plan=None, diag=None,
                  steady=True):
    """`repeat` finestre dello stesso punto; ritorna la mediana per rx_pps,
    portandosi dietro la perdita PEGGIORE e la dispersione fra le finestre.

    Single samples are not usable here. Measured on this bench, three runs of
    one identical configuration -- same pipeline, same rate, same frame,
    clone_skb already known refused -- gave 0.06%, 19.52% and 0.00% loss. A
    knee search reading one of those decides on noise: the 19.52% made it
    conclude the datapath was saturating and restart the search.

    Median for the RATE, because a slow outlier is a busy machine and not the
    datapath. Worst for the LOSS, because a rate that drops packets on one run
    out of three is not a rate this datapath sustains, and calling it clean
    would be the optimistic lie this whole script exists to avoid.

    Il WARM-UP e' una finestra in piu', fatta una volta per punto e scartata:
    la prima raffica paga cache fredde e la prima allocazione delle code, e
    finiva dentro la deviazione standard delle ripetizioni."""
    if warmup and gen is not None:
        gen.warmup(frame, delay)
    runs = []
    if diag is not None:
        diag.start()
    for _ in range(max(1, repeat)):
        try:
            r = _measure_once(setup, rx_tab, fab, frame, delay, count,
                              n_out, clone, tg_devs, burst, xmit_mode, gen,
                              steady=steady)
        except PktgenEmptyRun as e:
            warn(f"misura scartata: {e}")
            continue
        # RX == 0 con del traffico offerto non e' "perdita del 100%": e' una
        # finestra in cui la misura non ha visto niente. Due casi, tutti e due
        # strumentali, tutti e due da scartare:
        #
        #   HIT > 0  il programma ha elaborato e il contatore d'uscita non e'
        #            stato aggiornato in tempo;
        #   HIT == 0 il programma non e' nemmeno partito nella finestra --
        #            thread NAPI non ancora schedulato dopo il pinning, o
        #            contatori riletti prima che la coda fosse drenata.
        #
        # Il secondo caso NON era coperto: la guardia chiedeva `hit > 0`, e
        # una finestra con hit == 0 passava e portava loss_pct = 100%. Siccome
        # la perdita del punto e' la PEGGIORE delle ripetizioni, una sola
        # finestra cosi' marcava 100.00% un punto che aveva consegnato milioni
        # di pacchetti -- misurato il 2026-09-18: `512 ... RX 2 169 116 ...
        # 100.00%`. Ed essendo il gradino piu' basso, mandava a vuoto tutta la
        # ricerca del rate a perdita nulla.
        if r["rx"] == 0 and r.get("offered_tx", 0) > 0:
            dove = (f"{r['hit']} elaborati e 0 contati in uscita"
                    if r["hit"] > 0 else
                    f"{r['offered_tx']} offerti e il programma non e' mai "
                    f"partito (hit 0)")
            warn(f"misura scartata: {dove} -- finestra strumentalmente vuota, "
                 f"non perdita del 100%")
            continue
        runs.append(r)
    diag_data = diag.stop() if diag is not None else {}
    if not runs:
        return None
    runs.sort(key=lambda r: r["rx_pps"])
    med = runs[len(runs) // 2]
    med["repeat"] = len(runs)
    med["loss_worst"] = max(r["loss_pct"] for r in runs)
    med["loss_best"] = min(r["loss_pct"] for r in runs)
    # La MEDIANA delle perdite, accanto alla peggiore.
    #
    # La peggiore resta la cifra riportata, ed e' la regola giusta: RFC 2544
    # definisce il throughput come il rate a cui NON si perde nemmeno un
    # frame, e una finestra sporca su cinque squalifica il rate.
    #
    # Ma RFC 2544 presuppone un DUT quieto e dedicato. Qui il DUT e' un guest
    # VirtualBox su un host a core ibridi: capita che il vCPU venga
    # deschedulato per l'INTERA finestra, e allora quella ripetizione non
    # descrive il rate, descrive l'host. Misurato: cinque ripetizioni dello
    # stesso punto con dispersione +-426%, perdita peggiore 98.11% e mediana
    # a una cifra.
    #
    # Quindi: si RIPORTA la peggiore, si DECIDE sulla mediana, e la deviazione
    # da RFC 2544 sta scritta qui e nel report invece di essere nascosta in
    # una soglia.
    med["loss_med"] = round(statistics.median([r["loss_pct"] for r in runs]), 3)
    med["rx_pps_min"] = runs[0]["rx_pps"]
    med["rx_pps_max"] = runs[-1]["rx_pps"]
    med["burst"] = burst
    med["xmit_mode"] = xmit_mode
    a = _agg([r["rx_pps"] for r in runs])
    med["rx_pps_mean"] = a["mean"]
    med["rx_pps_std"] = a["std"]
    med["rx_pps_cv_pct"] = a["cv_pct"]
    med["secs_mean"] = round(sum(r["secs"] for r in runs) / len(runs), 3)
    lo, hi = med["rx_pps_min"], med["rx_pps_max"]
    med["spread_pct"] = round(100.0 * (hi - lo) / lo, 1) if lo else None
    # DISPERSIONE ROBUSTA, accanto a quella fra gli estremi.
    #
    # `spread_pct` e' (max - min) / min: la statistica piu' sensibile che
    # esista a un singolo valore anomalo. Su questa macchina l'anomalo c'e' e
    # ha una causa nota: ogni tanto l'host sospende il vCPU per l'intera
    # finestra, e quella ripetizione esce vicina a zero. Misurato il
    # 2026-09-18 in softirq: baseline a 512 byte, quattro ripetizioni
    # d'accordo e la quinta a perdita 94.70%, `spread_pct` +-286%.
    #
    # Scartare l'anomala sarebbe barare. Misurare la dispersione su una
    # statistica che non le da' tutto il peso, e DIRE quante ce ne sono, no:
    # e' la stessa scelta gia' fatta per la perdita (si riporta la peggiore,
    # si decide sulla mediana).
    #
    # La soglia e' QUATTRO campioni, non cinque. Con quattro gli indici usati
    # qui (1, 2, 3) escludono il minimo, che e' esattamente l'anomalo da
    # spogliare del suo peso; con tre, l'indice q1 ricade sul minimo e non si
    # guadagna niente. Quattro non e' un caso raro: basta una finestra
    # troncata e un punto chiesto a cinque ripetizioni ne consegna quattro.
    # Misurato il 2026-09-18: p1_static a 1514 byte, quattro ripetizioni, e
    # la dispersione e' ricaduta sul min-max (141.6%) bocciando il run.
    pps_ord = sorted(r["rx_pps"] for r in runs)
    n = len(pps_ord)
    if n >= 4:
        q1, q2, q3 = (pps_ord[n // 4], pps_ord[n // 2], pps_ord[(3 * n) // 4])
        med["spread_iqr_pct"] = round(100.0 * (q3 - q1) / q2, 1) if q2 else None
        # Quante ripetizioni cadono fuori da 1.5 IQR: e' il conteggio delle
        # finestre in cui la macchina ha fatto altro, e va riportato perche'
        # e' una proprieta' della macchina, non del datapath.
        iqr = q3 - q1
        med["ripetizioni_anomale"] = sum(
            1 for v in pps_ord if v < q1 - 1.5 * iqr or v > q3 + 1.5 * iqr)
    else:
        med["spread_iqr_pct"] = None
        med["ripetizioni_anomale"] = 0
    # Una mediana su misure che oscillano del 75% non e' una misura: e' il
    # carico della macchina in tre momenti diversi. Marcarla e' l'unica cosa
    # onesta da farne.
    #
    # Due condizioni che qui NON entrano piu', perche' non dicono niente sulla
    # bonta' della riga:
    #   - gli errori di pktgen: sono la perdita in ingresso del DUT e adesso
    #     stanno dentro offered_tx e dentro la perdita (vedi _measure_once).
    #     Marcarli invalidi buttava via proprio le righe in cui la pipeline
    #     era satura, cioe' le uniche interessanti;
    #   - lo scarto fra le due letture del rate offerto: e' gia' risolto
    #     scegliendo quella che non gonfia, e i pps in ricezione si dividono
    #     comunque per la finestra del blocco su pgctrl, che nessuna delle due
    #     letture puo' accorciare.
    # La dispersione su cui si DECIDE: quella robusta dove esiste, altrimenti
    # min-max. Vedi sopra per il perche'.
    disp = (med["spread_iqr_pct"] if med.get("spread_iqr_pct") is not None
            else med["spread_pct"])
    med["spread_deciso_pct"] = disp
    med["unreliable"] = bool(
        (disp is not None and disp > MAX_SPREAD_PCT)
        or med.get("gen_skew_pct", 0.0) > 20.0
        or med.get("offered_pps") == 0 and med.get("tx", 0) > 0
    )
    med["invalid_reason"] = []
    if med.get("gen_skew_pct", 0.0) > 20.0:
        med["invalid_reason"].append("generator threads not synchronized")
    if med.get("offered_pps") == 0 and med.get("tx", 0) > 0:
        med["invalid_reason"].append("zero offered rate with nonzero TX")
    if disp is not None and disp > MAX_SPREAD_PCT:
        med["invalid_reason"].append(
            f"dispersione fra le ripetizioni {disp}% "
            f"(min-max {med['spread_pct']}%)")
    # Due avvisi che riguardano la MISURA e non il datapath: se scattano, la
    # riga resta ma va letta sapendo che la finestra non era pulita.
    # Non sulle sonde da un pacchetto (count 1): li' sfasamento e scarto sono
    # l'avvio di pktgen diviso per quasi niente, e riempivano l'inizio di ogni
    # run di avvisi senza significato.
    sonda = count < MIN_WINDOW_PKTS // max(1, gen.n_inst if gen else 1)
    if med.get("gen_skew_pct", 0) > 20.0 and not sonda:
        warn(f"thread del generatore sfasati del {med['gen_skew_pct']}%: non "
             f"hanno lavorato nella stessa finestra")
    if med.get("gen_rate_mismatch_pct", 0) > 25.0 and not sonda:
        warn(f"TX/durata e somma dei pps per istanza differiscono del "
             f"{med['gen_rate_mismatch_pct']}%: uso TX diviso la durata "
             f"globale, che e' la lettura che non gonfia")
    if med["unreliable"]:
        tag = "indeterminato"
        why = "misura non affidabile: " + "; ".join(med["invalid_reason"])
    else:
        tag, why = classify_bottleneck(med, threshold=threshold, plan=plan,
                                       diag_data=diag_data)
    med["bottleneck"] = tag
    med["bottleneck_why"] = why
    if diag_data:
        g, d = gen_cpu_load(diag_data, plan)
        med["cpu_gen_pct"] = g
        med["cpu_dut_pct"] = d
        med["softnet_dropped"] = diag_data.get("softnet_dropped")
        med["_diag"] = diag_data
    return med


def _measure_once(setup, rx_tab, fab, frame, delay, count, n_out, clone=0,
                  tg_devs=None, burst=0, xmit_mode="start_xmit", gen=None,
                  steady=True):
    """One (frame size, offered rate) point. Returns a dict of counters.

    `count` is per generator instance, so the offered load scales with the
    number of instances and the per-instance duration stays comparable.

    Con un `gen` (Generator) la configurazione del generatore e' gia' in piedi
    e si cambiano solo i parametri del punto. Senza, si ricade sul percorso
    storico -- aggiungi, configura, misura -- che serve ai chiamanti che non
    hanno un Generator."""
    if gen is not None and steady and gen.window_mode == "steady":
        # Finestra stazionaria: i contatori si leggono a differenza mentre
        # tutte le istanze trasmettono, quindi niente azzeramento, niente
        # drenaggio e niente controllo sul count (vedi Generator.steady).
        def probe():
            return dict(hit=_read_u64(setup["pkt_stats"], 0),
                        miss=_read_u64(setup["pkt_stats"], 1),
                        drop=_read_u64(setup["pkt_stats"], 2),
                        rx=(_read_u64(setup["pkt_stats"], 0)
                            if setup.get("rx_is_hit") else _percpu_sum(rx_tab)))
        run = gen.steady(frame, delay, probe)
        devs = gen.names
        tx, tx_pps, elapsed = run
        d = run.dut
        hit, miss, drop, rx = d["hit"], d["miss"], d["drop"], d["rx"]
        secs = run.window if run.window > 0 else 1e-9
    else:
        # PRIMA di azzerare: la coda della finestra precedente (warm-up o
        # ripetizione) deve essere atterrata, altrimenti i suoi pacchetti finiscono
        # nei contatori di questa. E' cosi' che si ottiene RX > HIT.
        time.sleep(DRAIN_S)
        _zero_counters(setup, rx_tab, n_out)
        if gen is not None:
            run = gen.run(frame, count, delay)
            devs = gen.names
        else:
            devs = tg_devs or [fab.ingress_peer]
            pg_clear_threads(len(devs))
            for i, dev in enumerate(devs):
                pg_configure(dev, frame, count, delay,
                             dst_ip="10.0.0.2", dst_mac="02:00:00:00:00:02",
                             clone=clone, thread=i, burst=burst,
                             xmit_mode=xmit_mode)
            run = pg_run_and_read(devs)
        tx, tx_pps, elapsed = run
        # Una finestra troncata non e' un punto di misura. Il `count` chiesto e'
        # per istanza, quindi il totale atteso e' count * numero di istanze.
        atteso = count * (gen.n_inst if gen is not None else len(devs))
        if atteso and tx < atteso * WINDOW_MIN_TX_FRACTION:
            raise PktgenEmptyRun(
                f"finestra troncata: {tx} trasmessi su {atteso} chiesti "
                f"({100.0 * tx / atteso:.1f}%) in {elapsed:.2f}s")
        # DOPO la trasmissione: `pgctrl start` ritorna quando il GENERATORE ha
        # finito, non quando il DUT ha drenato. Senza questa pausa la coda ancora
        # in volo non e' contata in RX e diventa "perdita" della pipeline.
        time.sleep(DRAIN_S)
        hit = _read_u64(setup["pkt_stats"], 0)
        miss = _read_u64(setup["pkt_stats"], 1)
        drop = _read_u64(setup["pkt_stats"], 2)
        rx = (hit if setup.get("rx_is_hit") else _percpu_sum(rx_tab))
        # La finestra dei contatori e' quella del blocco su pgctrl (GenRun.window),
        # non la durata che pktgen attribuisce al thread piu' lungo.
        secs = getattr(run, "window", 0.0) or elapsed
        secs = secs if secs > 0 else 1e-9
    # Il rate OFFERTO e' quello che pktgen ha chiesto al kernel; quello
    # AGGREGATO e' il totale diviso la durata globale. Il secondo e' la cifra
    # da usare: sommare i pps per-istanza li somma su finestre che non
    # coincidono, e a thread sfasati gonfia il numero.
    offered = int(1e9 / delay) * len(devs) if delay else None
    # Gli "errors" di pktgen su veth sono pacchetti PREPARATI e non accettati
    # dal device: la coda d'ingresso del DUT era piena. Non entrano in
    # pkts-sofar, quindi trattarli solo come guasto della strumentazione faceva
    # sparire dalla misura proprio la perdita del DUT: ogni riga usciva a
    # 0,00% con l'etichetta "non satura" mentre il generatore ne buttava
    # 670 000 su 976 000. Sono carico offerto e non consegnato, e come tali
    # entrano nel totale offerto e nella perdita.
    errors = getattr(run, "errors", 0)
    offered_tx = tx + errors
    return dict(frame=frame, delay=delay, secs=round(secs, 3),
                tx=tx, tx_pps=run.tx_pps_aggregate or int(tx / secs),
                tx_pps_sum=tx_pps, offered_pps=offered,
                gen_threads=len(devs),
                window_mode=("steady" if getattr(run, "steady", False)
                             else "count"),
                gen_start_offset_ms=getattr(run, "start_offset_ms", None),
                # Quando e' stata presa, e quanto e' durata la lettura piu'
                # lenta: servono a vedere se le finestre crollate cadono tutte
                # nello stesso momento (la macchina) o no (la pipeline).
                t_wall=round(time.time(), 2),
                read_ms=getattr(run, "read_ms", None),
                gen_skew_pct=getattr(run, "skew_pct", 0.0),
                # Coerenza fra le due letture del rate offerto. Vedi GenRun:
                # se TX/durata-globale e la somma dei pps per istanza non si
                # assomigliano, una delle due non descrive questa finestra, e
                # quella usata ovunque qui e' la prima -- che e' quella che non
                # puo' gonfiare il risultato.
                gen_rate_mismatch_pct=getattr(run, "rate_mismatch_pct", 0.0),
                gen_errors=errors,
                offered_tx=offered_tx,
                offered_real_pps=int(offered_tx / secs),
                hit=hit, miss=miss, drop=drop, rx=rx,
                rx_pps=int(rx / secs),
                # I TRE MODI DI PERDERE UN PACCHETTO, tenuti separati perche'
                # accusano tre colpevoli diversi:
                #
                #   respinti       veth_xmit ha detto NET_XMIT_DROP: il
                #                  ptr_ring della RX del peer era pieno. Il
                #                  pacchetto non e' MAI entrato nel DUT. E'
                #                  backpressure del trasporto.
                #   persi_in_coda  accettati dal veth e mai arrivati al
                #                  programma: la coda si e' svuotata male,
                #                  oppure NAPI non ha tenuto.
                #   persi_dopo     elaborati dal programma e non usciti:
                #                  redirect fallito, o classe DROP.
                #
                # Solo gli ultimi due sono perdita del DUT. Sommarli tutti e
                # tre in una colonna sola -- come faceva `lost_before` -- fa
                # sembrare che la pipeline butti via pacchetti che non ha mai
                # ricevuto.
                respinti=errors,
                persi_in_coda=max(0, tx - hit),
                persi_dopo=max(0, hit - rx),
                respinti_pct=(round(100.0 * errors / offered_tx, 3)
                              if offered_tx else 0.0),
                loss_dut_pct=(round(100.0 * (max(0, tx - hit)
                                             + max(0, hit - rx)) / offered_tx, 3)
                              if offered_tx else 0.0),
                # Throughput on the wire counts the frame, not the payload.
                rx_mbps=round(rx * frame * 8 / secs / 1e6, 2),
                lost_before=max(0, offered_tx - hit),
                lost_after=max(0, hit - rx),
                # RX maggiore dell'offerto non e' una perdita NEGATIVA: sono
                # residui in volo dal punto precedente. Si taglia a zero
                # invece di stampare -0,03%.
                loss_pct=(round(100.0 * max(0, offered_tx - rx) / offered_tx, 3)
                          if offered_tx else 0.0),
                # La perdita sui soli pacchetti davvero messi sul filo, cioe'
                # quella che si leggeva prima senza i rifiutati.
                loss_wire_pct=(round(100.0 * max(0, tx - rx) / tx, 3)
                               if tx else 0.0))


# ==========================================================================
# LATENZA ARRIVO -> RIPARTENZA, su traffico vero
# ==========================================================================
# E' l'unica voce dell'elenco che nessun'altra misura di questo progetto da'.
#
# test_suite cronometra il PROGRAMMA: dall'ingresso alla sua return. Non ci
# sono dentro ne' la consegna del pacchetto al programma, ne' la trasmissione
# vera, perche' bpf_redirect non spedisce -- accoda, e il pacchetto parte dopo
# che il programma e' finito. Il generatore, dall'altra parte, misura pacchetti
# al secondo e perdita, non il tempo di attraversamento.
#
# Qui si misura la cosa che interessa a un nodo che inoltra: quanto passa fra
# l'arrivo e il momento in cui il pacchetto e' davvero uscito.
#
# COME. Il dispatcher segna bpf_ktime_get_ns() in una cella PER-CPU; il
# programma d'uscita rilegge quella cella e fa la differenza. La cella per-CPU
# regge perche' il redirect avviene sullo stesso core, in modo sincrono: fra la
# scrittura e la lettura non si cambia CPU.
#
# PERCHE' IN UN OGGETTO SOLO. Due oggetti BPF distinti non condividono mappe
# (servirebbe il pinning su bpffs). Il programma d'uscita viene quindi compilato
# INSIEME alla pipeline, ed e' la ragione per cui questa modalita' ricostruisce
# il sorgente invece di riusare verify_prog_run.setup_*.
#
# IL PREZZO, DICHIARATO. E' una BUILD STRUMENTATA: la scrittura del timestamp
# non c'e' nel datapath di produzione. Aggiunge una scrittura di mappa per
# pacchetto, quindi la latenza misurata qui e' leggermente SUPERIORE a quella
# vera, e il throughput leggermente inferiore. Stessa scelta gia' fatta per il
# contatore dei lookup in test_suite, e per lo stesso motivo: una misura che
# non esiste vale piu' di una misura perfetta impossibile.

# Le DICHIARAZIONI vanno inserite prima del dispatcher che le usa: in C non si
# usa un simbolo prima di dichiararlo, e appendendo tutto in fondo al sorgente
# il dispatcher vedeva `ts_in` non dichiarata e clang si fermava -- errore che
# BCC riporta solo come "Failed to compile BPF module".
#
# Vanno anche DOPO gli #include della pipeline, perche' servono i tipi del
# kernel: il punto giusto e' quindi immediatamente sopra il dispatcher, cioe'
# lo stesso anchor usato per il timestamp.
LAT_DECLS_SRC = r"""
BPF_PERCPU_ARRAY(ts_in, __u64, 1);
/* T2: l'ultimo istante in cui il pacchetto e' ancora della pipeline, subito
 * prima del redirect. Vive nella stessa cella per-CPU di ts_in e per lo stesso
 * motivo: fra la scrittura e la lettura non si cambia core.
 *
 * Qui si SCRIVE e basta -- una ktime e una update, niente accumulo. I conti si
 * fanno in xdp_lat_count, che gira sul programma d'uscita e non sul percorso
 * misurato: mettere li' le somme tiene la pipeline al costo piu' basso
 * possibile, che e' il punto di tutta la misura. */
BPF_PERCPU_ARRAY(ts_mid, __u64, 1);
/* 0 = quanti, 1 = somma ns, 2 = minimo, 3 = massimo */
BPF_PERCPU_ARRAY(lat_acc, __u64, 4);      /* T3 - T1: end-to-end */
BPF_PERCPU_ARRAY(pipe_acc, __u64, 4);     /* T2 - T1: la pipeline */
BPF_PERCPU_ARRAY(xport_acc, __u64, 4);    /* T3 - T2: redirect + veth + NAPI */
/* Pacchetti arrivati all'uscita, CONTATI SEMPRE -- anche quando i timestamp
 * non ci sono. Senza questo, RX sarebbe "quanti ne ho cronometrati", e un
 * pacchetto arrivato ma non misurabile sarebbe finito in HIT-RX come se la
 * pipeline l'avesse perso. */
BPF_PERCPU_ARRAY(rx_n, __u64, 1);
/* Istogramma logaritmico: la cella i raccoglie [2^i, 2^(i+1)) ns. Serve per i
 * PERCENTILI, perche' media e massimo su una VM non dicono niente -- misurato:
 * media ~2000 ns con minimo 250 e massimo 10,6 ms, cioe' un singolo valore
 * enorme che trascina la media. */
BPF_PERCPU_ARRAY(lat_hist, __u64, LAT_BUCKETS);   /* log2: [2^i, 2^(i+1)) */
BPF_PERCPU_ARRAY(pipe_hist, __u64, LAT_BUCKETS);
BPF_PERCPU_ARRAY(xport_hist, __u64, LAT_BUCKETS);
"""

# Un accumulo (quanti / somma / min / max) piu' l'istogramma log2.
#
# Scritto come TEMPLATE PYTHON e non come macro C per un motivo preciso: BCC
# riscrive gli accessi alle mappe sull'AST, prima del preprocessore, e su
# `ACC.lookup(&k)` dentro una macro si ferma con
#
#     error: cannot use map function inside a macro
#
# Generarlo da qui conserva la proprieta' che serviva -- le tre misure trattate
# in modo identico, perche' vengono dallo stesso testo -- spostandola dalla
# compilazione alla generazione.
def _lat_accum(acc, hist, delta):
    return f"""
    {{ __u64 _d = {delta};
      __u32 _bk = bpf_log2l(_d);
      if (_bk >= LAT_BUCKETS) _bk = LAT_BUCKETS - 1;
      int _bi = (int)_bk;
      __u64 *_hb = {hist}.lookup(&_bi); if (_hb) *_hb += 1;
      int _k = 0;
      __u64 *_n = {acc}.lookup(&_k); if (_n) *_n += 1;
      _k = 1; __u64 *_sm = {acc}.lookup(&_k); if (_sm) *_sm += _d;
      _k = 2; __u64 *_mn = {acc}.lookup(&_k);
      if (_mn && (*_mn == 0 || _d < *_mn)) *_mn = _d;
      _k = 3; __u64 *_mx = {acc}.lookup(&_k); if (_mx && _d > *_mx) *_mx = _d; }}"""


LAT_COUNTER_SRC = """
int xdp_lat_count(struct xdp_md *ctx) {
    int z = 0;
    __u64 now = bpf_ktime_get_ns();

    /* Arrivato: contato comunque, timestamp o no. */
    __u64 *rn = rx_n.lookup(&z); if (rn) *rn += 1;

    __u64 *t0 = ts_in.lookup(&z);
    __u64 *t1 = ts_mid.lookup(&z);
    __u64 a = t0 ? *t0 : 0;
    __u64 m = t1 ? *t1 : 0;

    /* T3 - T1: end-to-end sul percorso reale. */
    if (a && now > a) %(e2e)s

    /* T2 - T1: la pipeline soltanto. */
    if (a && m && m > a) %(pipe)s

    /* T3 - T2: quello che viene DOPO la pipeline. */
    if (m && now > m) %(xport)s

    return XDP_DROP;
}
""" % {"e2e": _lat_accum("lat_acc", "lat_hist", "now - a"),
       "pipe": _lat_accum("pipe_acc", "pipe_hist", "m - a"),
       "xport": _lat_accum("xport_acc", "xport_hist", "now - m")}

# Iniettata subito dopo la graffa del dispatcher: il primo istante in cui il
# programma ha il pacchetto in mano.
LAT_STAMP = ("\n    { int _lz = 0; __u64 _lt = bpf_ktime_get_ns();\n"
             "      ts_in.update(&_lz, &_lt); }\n")

# T2: l'ultimo istante della pipeline. Va inserito PRIMA della riga del
# redirect, quindi dopo la riscrittura dei MAC e dopo ogni contatore -- cioe'
# dopo l'ultima operazione che la pipeline fa sul pacchetto.
#
# L'ancora e' `return bpf_redirect(`, che compare ESATTAMENTE UNA VOLTA nel
# sorgente generato di tutte e quattro le pipeline (verificato: baseline, P1,
# template, modular). Il conteggio viene asserito prima di sostituire, cosi'
# una pipeline che domani ne avesse due fa fallire la build strumentata invece
# di misurare meta' dei pacchetti.
#
# Il pacchetto non viene toccato: si scrive solo una cella per-CPU.
LAT_STAMP_MID = ("{ int _mz = 0; __u64 _mt = bpf_ktime_get_ns();\n"
                 "          ts_mid.update(&_mz, &_mt); }\n"
                 "        ")
LAT_REDIRECT_ANCHOR = "return bpf_redirect("

# Istogramma LOGARITMICO, 40 celle: la cella i raccoglie [2^i, 2^(i+1)) ns,
# quindi si copre da 1 ns a ~18 minuti.
#
# Il primo tentativo erano 256 celle lineari da 16 ns, scelte per separare 228
# da 243 da 267 -- le differenze fra le pipeline sono di quell'ordine. Sbagliato
# per la ragione opposta: quella finestra copre 4 us, e sotto carico p90 e p99
# stanno molto piu' in alto, quindi venivano riportati come ">4us", cioe' non
# riportati.
#
# La distinzione fine fra pipeline sta nel MINIMO, che e' esatto e non passa per
# l'istogramma. I percentili servono a descrivere la coda sotto carico, e la'
# la risoluzione logaritmica (1-2 us, 2-4 us, ...) e' quella giusta.
LAT_BUCKETS = 40

# Nome della funzione d'ingresso XDP per ciascun metodo: e' quella in cui
# infilare il timestamp, ed e' quella che si attacca all'interfaccia.
LAT_ENTRY = {
    "baseline": "xdp_baseline",
    # P1 / P1.5: l'oggetto AOT, strumentato da _instrument_aot_latency
    # (ingresso LAT_ENTRY_AOT), non da questo dizionario.
    "p1_static": "xdp_dispatch",
    "hardcoded": "xdp_dispatch",
    "template": "ipa_switch_template",
    "modular": "modular_dispatcher",
}


def _instrumented_source(method, model_path, node=STATIC_NODE):
    """(sorgente, pesi, scale) della pipeline col timestamp e il contatore."""
    import verify_prog_run as V
    weights, scale = V.load_weights(model_path)

    if method == "baseline":
        src = V.EBPF_BASELINE
    elif method in ("hardcoded", "p1_static"):
        raise RuntimeError("P1/P1.5 sono l'oggetto AOT: la loro build "
                           "strumentata e' _load_instrumented_aot")
    elif method == "template":
        from ebpf_template_arch import (EBPF_TEMPLATE_ARCH_DISPATCHER,
                                        EBPF_ARCH_GENERIC_2LAYER)
        src = ("#define IPA_ARCH_COMBINED 1\n" + EBPF_TEMPLATE_ARCH_DISPATCHER
               + "\n" + EBPF_ARCH_GENERIC_2LAYER)
    else:
        from ebpf_modular import EBPF_MODULAR_FULL
        src = EBPF_MODULAR_FULL

    anchor = f"int {LAT_ENTRY[method]}(struct xdp_md *ctx) {{"
    if src.count(anchor) != 1:
        raise RuntimeError(
            f"non trovo il punto d'ingresso '{anchor}' nel sorgente di "
            f"{method} (trovato {src.count(anchor)} volte). E' cambiata la "
            f"firma del dispatcher?")
    n_red = src.count(LAT_REDIRECT_ANCHOR)
    if n_red != 1:
        raise RuntimeError(
            f"il sorgente di {method} ha {n_red} siti di redirect, non 1: "
            f"T2 andrebbe messo in {n_red} punti e la misura coprirebbe solo "
            f"una parte dei pacchetti. Rivedi LAT_STAMP_MID prima di usare "
            f"questa modalita'.")
    # Le DICHIARAZIONI vanno prima di ogni funzione che le usa. Con il solo T1
    # bastava metterle davanti al dispatcher, perche' il marcatore stava li'.
    # T2 sta al redirect, e in `modular` il redirect e' dentro
    # ml_argmax_forward, che nel sorgente viene PRIMA del dispatcher: ancorarle
    # al dispatcher le avrebbe messe dopo il loro primo uso, e clang si sarebbe
    # fermato su `ts_mid undeclared` -- lo stesso inciampo gia' descritto sopra
    # per ts_in, in un punto diverso.
    #
    # Si ancorano quindi alla PRIMA funzione XDP del sorgente, che viene dopo
    # gli #include e i tipi del kernel (che servono) e prima di qualunque
    # corpo di funzione (che le usa).
    # NB: niente parentesi chiusa nel pattern. `ml_argmax_forward` di P3 ha
    # la firma spezzata su piu' righe -- `int f(struct xdp_md *ctx, void
    # *data, void *data_end,` -- e un pattern che pretendeva `)` la
    # saltava, ancorando le dichiarazioni al dispatcher, che in quel
    # sorgente viene DOPO il redirect. Cioe' esattamente il difetto che
    # questo blocco esiste per evitare.
    # DOPO L'ULTIMO #include, e non "prima della prima funzione XDP".
    #
    # Il secondo tentativo era quello, e su P3 rompeva: ml_argmax_forward e'
    # preceduta da `static inline __attribute__((always_inline))` su riga
    # propria, quindi inserire davanti all'`int` separava i qualificatori dalla
    # funzione -- clang usciva con "'inline' can only appear on functions" e
    # poi con "cannot call non-static helper function", che e' la stessa causa
    # vista due volte.
    #
    # Gli #include stanno tutti in cima e nessuno e' dentro un #ifdef
    # (verificato su tutte e quattro le pipeline): dopo l'ultimo ci sono i tipi
    # del kernel, che servono, e non c'e' ancora nessuna dichiarazione da
    # spezzare.
    #
    # "l'ultimo #include" non basta: il sorgente di P2 e' dispatcher + leaf
    # CONCATENATI, e il leaf porta i propri #include -- che stanno quindi dopo
    # il punto in cui il dispatcher usa gia' le mappe. Serve l'ultimo #include
    # che PRECEDE il primo uso, cioe' il piu' a sinistra fra l'ingresso e il
    # redirect.
    primo_uso = min(p for p in (src.find(anchor),
                                src.find(LAT_REDIRECT_ANCHOR)) if p >= 0)
    incs = [m for m in re.finditer(r"^#include .*$", src, re.M)
            if m.end() < primo_uso]
    if incs:
        at = incs[-1].end() + 1
    else:
        first_fn = re.search(r"^int \w+\(struct xdp_md ", src, re.M)
        if not first_fn:
            raise RuntimeError(
                f"nessuna funzione XDP nel sorgente di {method}: non so dove "
                f"mettere le dichiarazioni della strumentazione.")
        at = first_fn.start()
    defines = f"#define LAT_BUCKETS {LAT_BUCKETS}\n"
    src = src[:at] + defines + LAT_DECLS_SRC + "\n" + src[at:]

    # T1 all'ingresso, T2 al redirect.
    src = src.replace(anchor, anchor + LAT_STAMP, 1)
    src = src.replace(LAT_REDIRECT_ANCHOR,
                      LAT_STAMP_MID + LAT_REDIRECT_ANCHOR, 1)

    # Controllo finale: ogni mappa della strumentazione dev'essere dichiarata
    # prima del suo primo uso. E' il difetto che questa funzione ha gia' avuto
    # due volte, quindi non si lascia scoprire a clang.
    for m in ("ts_in", "ts_mid", "lat_acc", "pipe_acc", "xport_acc",
              "lat_hist", "pipe_hist", "xport_hist", "rx_n"):
        decl = src.find(f"BPF_PERCPU_ARRAY({m},")
        uso = src.find(f"{m}.")
        if decl < 0 or (uso >= 0 and uso < decl):
            raise RuntimeError(
                f"{method}: la mappa `{m}` verrebbe usata (offset {uso}) prima "
                f"di essere dichiarata (offset {decl}). clang si fermerebbe "
                f"con 'undeclared identifier'.")

    return src + "\n" + LAT_COUNTER_SRC, weights, scale


# --------------------------------------------------------------------------
# La stessa strumentazione per P1 e P1.5, che sono l'OGGETTO AOT (libbpf) e
# non un sorgente BCC: stesse mappe, stessi nomi, stessi tre punti T1/T2/T3,
# stesso istogramma log2 -- cambia solo il dialetto. Letta da Python
# attraverso le mappe pinnate (pinned_maps), con la stessa interfaccia.
# --------------------------------------------------------------------------
_LAT_MAPS = (("ts_in", "1"), ("ts_mid", "1"), ("lat_acc", "4"),
             ("pipe_acc", "4"), ("xport_acc", "4"), ("rx_n", "1"),
             ("lat_hist", "LAT_BUCKETS"), ("pipe_hist", "LAT_BUCKETS"),
             ("xport_hist", "LAT_BUCKETS"))

LAT_DECLS_LIBBPF = "\n".join(
    f"struct {{ __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY); "
    f"__uint(max_entries, {n}); __type(key, __u32); __type(value, __u64); }} "
    f"{name} SEC(\".maps\");" for name, n in _LAT_MAPS) + """
/* bpf_log2l: BCC's helper, which the libbpf dialect does not have. Same
 * definition, so the buckets are the same as in the BCC builds. */
static __always_inline unsigned int ipa_log2(unsigned int v) {
    unsigned int r, shift;
    r = (v > 0xFFFF) << 4; v >>= r;
    shift = (v > 0xFF) << 3; v >>= shift; r |= shift;
    shift = (v > 0xF) << 2; v >>= shift; r |= shift;
    shift = (v > 0x3) << 1; v >>= shift; r |= shift;
    r |= (v >> 1);
    return r;
}
static __always_inline unsigned int bpf_log2l(unsigned long v) {
    unsigned int hi = v >> 32;
    if (hi) return ipa_log2(hi) + 32 + 1;
    return ipa_log2(v) + 1;
}
"""


def _lat_accum_libbpf(acc, hist, delta):
    return f"""
    {{ __u64 _d = {delta};
      __u32 _bk = bpf_log2l(_d);
      if (_bk >= LAT_BUCKETS) _bk = LAT_BUCKETS - 1;
      __u32 _bi = _bk;
      __u64 *_hb = bpf_map_lookup_elem(&{hist}, &_bi); if (_hb) *_hb += 1;
      __u32 _k = 0;
      __u64 *_n = bpf_map_lookup_elem(&{acc}, &_k); if (_n) *_n += 1;
      _k = 1; __u64 *_sm = bpf_map_lookup_elem(&{acc}, &_k); if (_sm) *_sm += _d;
      _k = 2; __u64 *_mn = bpf_map_lookup_elem(&{acc}, &_k);
      if (_mn && (*_mn == 0 || _d < *_mn)) *_mn = _d;
      _k = 3; __u64 *_mx = bpf_map_lookup_elem(&{acc}, &_k); if (_mx && _d > *_mx) *_mx = _d; }}"""


LAT_COUNTER_LIBBPF = """
SEC("xdp")
int xdp_lat_count(struct xdp_md *ctx) {
    __u32 z = 0;
    __u64 now = bpf_ktime_get_ns();
    __u64 *rn = bpf_map_lookup_elem(&rx_n, &z); if (rn) *rn += 1;
    __u64 *t0 = bpf_map_lookup_elem(&ts_in, &z);
    __u64 *t1 = bpf_map_lookup_elem(&ts_mid, &z);
    __u64 a = t0 ? *t0 : 0;
    __u64 m = t1 ? *t1 : 0;
    if (a && now > a) %(e2e)s
    if (a && m && m > a) %(pipe)s
    if (m && now > m) %(xport)s
    return XDP_DROP;
}
""" % {"e2e": _lat_accum_libbpf("lat_acc", "lat_hist", "now - a"),
       "pipe": _lat_accum_libbpf("pipe_acc", "pipe_hist", "m - a"),
       "xport": _lat_accum_libbpf("xport_acc", "xport_hist", "now - m")}

LAT_STAMP_LIBBPF = ("\n    { __u32 _lz = 0; __u64 _lt = bpf_ktime_get_ns();\n"
                    "      bpf_map_update_elem(&ts_in, &_lz, &_lt, BPF_ANY); }\n")
LAT_STAMP_MID_LIBBPF = ("{ __u32 _mz = 0; __u64 _mt = bpf_ktime_get_ns();\n"
                        "          bpf_map_update_elem(&ts_mid, &_mz, &_mt, BPF_ANY); }\n"
                        "        ")
LAT_ENTRY_AOT = "int xdp_dispatch(struct xdp_md *ctx) {"


def _instrument_aot_latency(src):
    """T1 all'ingresso del dispatcher, T2 al redirect, T3 nel contatore
    d'uscita -- come _instrumented_source fa per i sorgenti BCC."""
    if src.count(LAT_ENTRY_AOT) != 1:
        raise RuntimeError(f"oggetto AOT: '{LAT_ENTRY_AOT}' trovato "
                           f"{src.count(LAT_ENTRY_AOT)} volte, atteso 1")
    n_red = src.count(LAT_REDIRECT_ANCHOR)
    if n_red != 1:
        raise RuntimeError(f"oggetto AOT: {n_red} siti di redirect, non 1: T2 "
                           f"coprirebbe solo una parte dei pacchetti")
    at = src.index('SEC("xdp")')
    src = (src[:at] + f"#define LAT_BUCKETS {LAT_BUCKETS}\n" + LAT_DECLS_LIBBPF
           + "\n" + src[at:])
    src = src.replace(LAT_ENTRY_AOT, LAT_ENTRY_AOT + LAT_STAMP_LIBBPF, 1)
    src = src.replace(LAT_REDIRECT_ANCHOR,
                      LAT_STAMP_MID_LIBBPF + LAT_REDIRECT_ANCHOR, 1)
    return src + "\n" + LAT_COUNTER_LIBBPF


def _load_instrumented_aot(method, model_path, fab, sem, node=STATIC_NODE):
    """P1 / P1.5 strumentate: l'oggetto AOT con la latenza, caricato e
    pinnato da loader_aot, cablato su questo fabric come _load_instrumented
    fa per le pipeline BCC."""
    import p1_aot
    import verify_prog_run as V
    import test_fabric as TF

    weights, scale = V.load_weights(model_path)
    src = p1_aot.p1_source([(0, weights, scale)],
                           static_node=(node if method == "p1_static" else None))
    src = _instrument_aot_latency(src)
    o_path, _ = p1_aot.compile_object(src)
    obj = p1_aot.AotObject(o_path, p1_aot._PROG_RE.findall(src))
    b = obj.b
    model_fn = obj.progs["xdp_model"]
    b["model_progs"][ct.c_int(PKTGEN_MAGIC_MODEL_ID)] = ct.c_int(model_fn.fd)
    setup = {"b": b, "disp": obj.progs["xdp_dispatch"], "fn": model_fn,
             "weights": weights, "scale": scale, "pipeline": 1,
             "cls_stats": b["cls_stats"], "pkt_stats": b["pkt_stats"],
             "owner": obj}
    V._seed_link_state(b, 1)
    TF._install_fabric_mac_table(b, "mac_table", fab, sem.logical_ports)
    b["ingress_port"][ct.c_uint32(fab.ingress_ifindex)] = \
        ct.c_uint32(TF.FABRIC_INGRESS_SLOT)
    if method != "p1_static":
        b["node_id"][ct.c_uint32(0)] = ct.c_uint32(TF.FABRIC_NODE_INDEX)
    return setup, obj.progs["xdp_lat_count"]


def _load_instrumented(method, model_path, fab, sem, node=STATIC_NODE):
    """Compila tutto insieme, carica, e cabla la pipeline su questo fabric."""
    if method in ("hardcoded", "p1_static"):
        return _load_instrumented_aot(method, model_path, fab, sem, node)
    from bcc import BPF
    import verify_prog_run as V
    import test_fabric as TF

    src, weights, scale = _instrumented_source(method, model_path, node)
    try:
        b = BPF(text=src)
    except Exception as e:
        # BCC riporta solo "Failed to compile BPF module": la diagnostica di
        # clang l'ha gia' stampata su stderr, SOPRA questa riga.
        raise RuntimeError(
            f"la build strumentata di {method} non compila. L'errore di clang "
            f"e' nelle righe SOPRA questa. ({e})") from e
    entry = b.load_func(LAT_ENTRY[method], BPF.XDP)
    lat_fn = b.load_func("xdp_lat_count", BPF.XDP)

    pl = {"baseline": 0, "p1_static": 1, "hardcoded": 1,
          "template": 2, "modular": 3}[method]
    setup = {"b": b, "disp": entry, "fn": entry, "weights": weights,
             "scale": scale, "pipeline": pl,
             "cls_stats": b["cls_stats" if pl in (0, 1) else
                            TF._MAC_NAME[pl].replace("mac_table", "cls_stats")],
             "pkt_stats": b["pkt_stats" if pl in (0, 1) else
                            TF._MAC_NAME[pl].replace("mac_table", "pkt_stats")]}

    # tail call / pesi, come fa il setup di produzione
    if pl == 1:
        model_fn = b.load_func("model_0", BPF.XDP)
        b["model_progs"][ct.c_int(0)] = ct.c_int(model_fn.fd)
        b["model_progs"][ct.c_int(PKTGEN_MAGIC_MODEL_ID)] = ct.c_int(model_fn.fd)
    elif pl == 2:
        from ebpf_template_arch import load_arch_weights
        leaf = b.load_func("arch_generic_2layer", BPF.XDP)
        b["arch_progs"][ct.c_int(0)] = ct.c_int(leaf.fd)
        for mid in (0, PKTGEN_MAGIC_MODEL_ID):
            load_arch_weights(b, weights, model_id=mid, scale=scale)
    elif pl == 3:
        from ebpf_modular import load_modular_weights
        first = b.load_func("layer_first", BPF.XDP)
        hidden = b.load_func("layer_hidden", BPF.XDP)
        b["layer_chain"][ct.c_int(0)] = ct.c_int(first.fd)
        for i in range(1, 16):
            b["layer_chain"][ct.c_int(i)] = ct.c_int(hidden.fd)
        for mid in (0, PKTGEN_MAGIC_MODEL_ID):
            load_modular_weights(b, weights, model_id=mid, scale=scale,
                                 layer_dims=[(65, 4), (4, 4), (4, 7)])

    V._seed_link_state(b, 1)
    mac_name = "mac_table" if pl in (0, 1) else TF._MAC_NAME[pl]
    TF._install_fabric_mac_table(b, mac_name, fab, sem.logical_ports)
    if pl != 0:
        b[TF._INGRESS_NAME[pl]][ct.c_uint32(fab.ingress_ifindex)] = \
            ct.c_uint32(TF.FABRIC_INGRESS_SLOT)
        if method != "p1_static":
            b[TF._NODEID_NAME[pl]][ct.c_uint32(0)] = \
                ct.c_uint32(TF.FABRIC_NODE_INDEX)
    return setup, lat_fn


def _map_extra_ingress(setup, ifindexes):
    """Fai riconoscere al programma anche gli ingressi aggiuntivi.

    Gli ingressi extra sono altri core di generatore che alimentano LO STESSO
    nodo, non altre porte del nodo: prendono percio' lo stesso slot logico
    dell'ingresso del fabric. Senza questa riga il pacchetto arriva, il
    programma gira, e la feature 'porta d'ingresso' vale zero -- cioe' si
    misura una decisione presa su un input diverso da quello dichiarato."""
    import test_fabric as TF
    pl = setup["pipeline"]
    if pl == 0:
        return          # la baseline non legge la porta d'ingresso
    ing = setup["b"][TF._INGRESS_NAME[pl]]
    for idx in ifindexes:
        ing[ct.c_uint32(idx)] = ct.c_uint32(TF.FABRIC_INGRESS_SLOT)


def _read_lat(b, acc="lat_acc", hist="lat_hist"):
    """Statistiche di latenza, sommando le celle per-CPU.

    `acc`/`hist` scelgono QUALE delle tre misure leggere: end-to-end
    (lat_*), pipeline (pipe_*) o trasporto (xport_*). Sono la stessa
    struttura, riempita dalla stessa macro, quindi si leggono con lo stesso
    codice -- ed e' il motivo per cui la macro esiste.

    Restituisce un dizionario con min, p50, p90, p99, media, max e quanti
    campioni hanno sforato l'istogramma. I percentili vengono dai bucket;
    minimo e massimo sono esatti.

    La MEDIA e' riportata ma non va usata per concludere: su questa VM un
    singolo valore da 10 ms fra 100 000 campioni la sposta di piu' di quanto la
    differenza fra due pipeline. I percentili no."""
    acc = b[acc]
    n = sum(int(v) for v in acc[ct.c_int(0)])
    if not n:
        return None
    tot = sum(int(v) for v in acc[ct.c_int(1)])
    mins = [int(v) for v in acc[ct.c_int(2)] if int(v) > 0]
    maxs = [int(v) for v in acc[ct.c_int(3)]]

    hist = b[hist]
    buckets = [sum(int(v) for v in hist[ct.c_int(i)])
               for i in range(LAT_BUCKETS)]
    over = buckets[-1]          # oltre 2^39 ns: praticamente mai

    def pct(q):
        """Il bordo SUPERIORE del bucket log2 in cui cade il quantile q.

        Un bucket i copre [2^i, 2^(i+1)), quindi il valore riportato e' un
        limite superiore: "il 99% sta sotto questa cifra". E' il modo in cui un
        percentile da istogramma si legge, e va detto perche' il numero non e'
        il percentile esatto ma il bordo che lo contiene."""
        target = q * n
        run = 0
        for i, c in enumerate(buckets):
            run += c
            if run >= target:
                return 1 << (i + 1)
        return None

    return dict(n=n, lat_min_ns=(min(mins) if mins else 0),
                lat_p50_ns=pct(0.50), lat_p90_ns=pct(0.90),
                lat_p99_ns=pct(0.99), lat_avg_ns=tot // n,
                lat_max_ns=max(maxs), over=over)


# Le tre misure, con i nomi che il report usa.
LAT_TRIPLE = (("pipe", "pipe_acc", "pipe_hist"),      # T2 - T1
              ("e2e", "lat_acc", "lat_hist"),         # T3 - T1
              ("xport", "xport_acc", "xport_hist"))   # T3 - T2


def _read_lat_all(b):
    """Le tre latenze piu' RX vero, in un colpo.

    RX viene da `rx_n`, non dal numero di campioni cronometrati: un pacchetto
    arrivato ma senza timestamp valido e' arrivato lo stesso, e contarlo fra i
    persi attribuirebbe alla pipeline una perdita del banco."""
    out = {"rx": sum(int(v) for v in b["rx_n"][ct.c_int(0)])}
    for nome, acc, hist in LAT_TRIPLE:
        st = _read_lat(b, acc, hist)
        out[nome] = st
    return out


def _clear_lat(b):
    for _, acc, hist in LAT_TRIPLE:
        b[acc].clear()
        b[hist].clear()
    b["rx_n"].clear()


def run_latency(method, model_path, frames, delays, count, threads,
                threaded_napi=True, plan=None, xmit_mode="start_xmit"):
    """Latenza arrivo -> ripartenza, a piu' dimensioni di frame e piu' rate.

    Percorso storico, tenuto perche' e' quello citato nel quaderno. La
    differenza rispetto a prima e' che il generatore passa dal CpuPlan: anche
    qui i thread pktgen stanno sulle CPU dichiarate e non piu' sulla 0."""
    from netns_fabric import NetnsFabric
    from common import attach_xdp

    print(f"\n{YELLOW}{'=' * 78}{NC}")
    print(f"{YELLOW} {method} -- latenza arrivo->ripartenza E throughput "
          f"(build strumentata){NC}")
    print(f"{YELLOW}{'=' * 78}{NC}")

    plan = plan or plan_cpus(threads=threads)
    sem, n_out = class_semantics()
    rows = []
    with NetnsFabric(n_ports=len(sem.logical_ports), verbose=False) as fab:
        setup, lat_fn = _load_instrumented(method, model_path, fab, sem)
        b = setup["b"]
        for peer in fab.peer_of.values():
            try:
                attach_xdp(b, lat_fn, peer)
            except Exception as e:
                warn(f"contatore latenza non agganciato a {peer}: {e}")
        attach_xdp(b, setup["disp"], fab.ingress)
        info("un oggetto BPF solo: ingresso e uscita condividono le mappe")

        napi_devs = []
        if threaded_napi:
            napi_devs = [fab.ingress]
            if enable_threaded_napi(napi_devs, plan):
                info("NAPI in thread: generatore e DUT su core separati")

        gen = Generator([fab.ingress_peer], plan, xmit_mode=xmit_mode,
                        topology="shared").attach()

        # Throughput E latenza nella stessa riga, perche' vengono dallo
        # STESSO pacchetto: il programma d'uscita conta e cronometra insieme,
        # quindi `campioni` e' esattamente RX. Riportarli separati avrebbe
        # significato due run e due stati della macchina per due numeri che
        # descrivono lo stesso evento.
        hdr = (f"  {'frame':>5s} {'delay':>6s} {'TX':>8s} {'RX':>8s} "
               f"{'RX pps':>9s} {'Mb/s':>7s} {'perdita':>8s} "
               f"{'min':>6s} {'p50<':>7s} {'p90<':>7s} {'p99<':>8s}")
        print(f"\n{hdr}")
        print("  " + "-" * (len(hdr) - 2))
        for frame in frames:
            for delay in delays:
                gen.warmup(frame, delay)
                b["lat_acc"].clear()
                b["lat_hist"].clear()
                try:
                    tx, tx_pps, secs = gen.run(frame, count, delay)
                except PktgenEmptyRun as e:
                    warn(f"punto scartato: {e}")
                    continue
                st = _read_lat(b)
                if st is None:
                    warn(f"frame {frame} delay {delay}: nessun campione -- il "
                         f"pacchetto non e' arrivato all'uscita")
                    continue

                rx = st["n"]
                secs = secs or 1e-9
                rx_pps = int(rx / secs)
                # Il throughput sul filo conta il frame intero, non il payload.
                mbps = round(rx * frame * 8 / secs / 1e6, 1)
                # RX > TX non e' una perdita negativa: sono pacchetti
                # arrivati all'uscita che questo punto non ha trasmesso --
                # residui in volo dal punto precedente, o traffico del kernel.
                # Misurato: 100 256 contati su 100 000 inviati dopo un punto
                # scartato. Riportarlo come -0,26% dava un numero senza senso.
                excess = max(0, rx - tx)
                loss = round(100.0 * max(0, tx - rx) / tx, 3) if tx else 0.0

                def _f(v):
                    return f"{v:5d}n" if v is not None else "  >4us"
                mark = GREEN if loss <= 0.1 else (RED if loss > 1 else YELLOW)
                tag = f" {GREY}+{excess}{NC}" if excess else ""
                print(f"  {frame:5d} {delay:6d} {tx:8d} {rx:8d} "
                      f"{rx_pps:9d} {mbps:7.1f} {mark}{loss:7.2f}%{NC}{tag} "
                      f"{_f(st['lat_min_ns'])} {_f(st['lat_p50_ns'])} "
                      f"{_f(st['lat_p90_ns'])} {_f(st['lat_p99_ns'])}")
                rows.append(dict(method=method, frame=frame, delay=delay,
                                 tx=tx, rx=rx, tx_pps=tx_pps, rx_pps=rx_pps,
                                 rx_mbps=mbps, loss_pct=loss,
                                 excess_rx=excess, samples=rx,
                                 gen_threads=gen.n_inst, **{
                                     k: st[k] for k in
                                     ("lat_min_ns", "lat_p50_ns",
                                      "lat_p90_ns", "lat_p99_ns",
                                      "lat_avg_ns", "lat_max_ns")},
                                 over_4us=st["over"]))
        gen.detach()
        pg_reset()
        if napi_devs:
            disable_threaded_napi(napi_devs)
    print(f"\n  {GREY}Latenza dal primo istante in cui il programma ha il "
          f"pacchetto al momento in cui e' uscito. Include la trasmissione, "
          f"che test_suite non misura, e la scrittura del timestamp, che il "
          f"datapath di produzione non fa.{NC}")
    print(f"  {GREY}Leggi il MINIMO e i percentili. La media resta nel CSV "
          f"per completezza, ma su questa VM un singolo campione da "
          f"millisecondi la sposta piu' della differenza fra due pipeline.{NC}")
    print(f"  {GREY}Il throughput qui e' della build STRUMENTATA, che paga una "
          f"scrittura di mappa per pacchetto in piu': e' quindi un limite "
          f"INFERIORE di quello di produzione, non lo stesso numero. Per il "
          f"throughput da citare usa il run senza --latency.{NC}")
    return rows


# ==========================================================================
# CONFRONTO EQUO: stesse condizioni per tutte le pipeline
# ==========================================================================
# Tre cose differivano fra un metodo e l'altro, e ognuna e' bastata da sola a
# rovinare un run:
#
# 1. OGNI METODO RICOSTRUIVA IL FABRIC. Veth nuove, ifindex nuovi, e lo stato di
#    pktgen che non sopravvive al giro -- da cui il device che spariva a meta'
#    sweep. Qui il fabric si costruisce UNA volta e lo usano tutti.
#
# 2. OGNI METODO CHIAMAVA CLANG SUBITO PRIMA DI MISURARE. template e modular
#    bruciano secondi di CPU che baseline non brucia, e la misura partiva su una
#    macchina in stati diversi. Qui si compila e si carica TUTTO prima, e durante
#    le misure nessun compilatore gira.
#
# 3. I METODI GIRAVANO IN SEQUENZA, una volta ciascuno. Qualunque deriva della
#    macchina -- pagine, frequenza, un processo che si sveglia -- si mappava
#    sull'ORDINE dei metodi, ed e' cosi' che la baseline e' uscita il 26% piu'
#    lenta di una pipeline che fa strettamente piu' lavoro. Qui si misura a
#    GIRI: in ogni giro tutti i metodi, e di ogni metodo si tiene la mediana fra
#    i giri. Una deriva colpisce allora tutti allo stesso modo invece di
#    premiare chi capita per primo.
#
# A queste tre si aggiunge adesso la quarta, che e' la ragione di questa
# revisione: il generatore e' lo STESSO OGGETTO per tutte le pipeline, sulle
# stesse CPU, con le stesse manopole gia' sondate. Prima ogni percorso si
# configurava pktgen per conto suo, sempre su un thread solo, sempre su CPU 0.


class _quiet:
    """Zittisce stdout. attach_xdp stampa una riga per interfaccia, e nel
    confronto a giri sono 6 interfacce x 5 pipeline x N giri: novanta righe di
    rumore in cui la tabella dei risultati si perde. La prima attaccatura resta
    visibile, le successive no."""

    def __enter__(self):
        self._old = sys.stdout
        sys.stdout = io.StringIO()
        return self

    def __exit__(self, *a):
        sys.stdout = self._old
        return False


def _detach(iface):
    subprocess.run(["ip", "link", "set", "dev", iface, "xdp", "off"],
                   check=False, capture_output=True)


def _noop():
    class _N:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False
    return _N()


def _fmt_ns(v):
    return f"{v:5d}n" if v is not None else "  n/d"


def _fmt_bucket(v):
    """Un percentile da istogramma log2, stampato per quello che e'.

    Il valore e' il bordo SUPERIORE del bucket [2^i, 2^(i+1)) in cui cade il
    quantile, quindi l'unica lettura corretta e' "sotto questa cifra". Senza il
    `<` la colonna si legge come una misura, e con bucket a potenze di 2 la
    risoluzione e' un fattore DUE: p50 e p99 non separano due pipeline che
    distano meno di cosi'. Il minimo, che viene dall'accumulatore e non
    dall'istogramma, resta esatto ed e' l'unica cifra di latenza confrontabile
    su questo banco."""
    return f"<{v:5d}n" if v is not None else "   n/d"


def run_fair(methods, model_path, frames, delays, count, threads,
             threaded_napi=True, repeat=DEFAULT_REPEAT, rounds=DEFAULT_ROUNDS,
             tol=0.0, plan=None, xmit_mode="start_xmit", diag=None,
             window_s=WINDOW_S, warmup_s=DEFAULT_WARMUP_S):
    """Tutte le pipeline sullo stesso fabric, compilate prima, misurate a giri."""
    from netns_fabric import NetnsFabric
    from common import attach_xdp

    plan = plan or plan_cpus(threads=threads)
    sem, n_out = class_semantics()
    raw = []

    with NetnsFabric(n_ports=len(sem.logical_ports), verbose=False) as fab:
        # --- fase 1: compila e carica tutto. Qui gira clang, una volta sola,
        #     e nessuna misura e' ancora partita.
        print(f"\n{YELLOW}{'=' * 78}{NC}")
        print(f"{YELLOW} Fase 1: compilo e carico {len(methods)} pipeline "
              f"(nessuna misura in corso){NC}")
        print(f"{YELLOW}{'=' * 78}{NC}")
        loaded = {}
        for m in methods:
            try:
                setup, lat_fn = _load_instrumented(m, model_path, fab, sem)
                loaded[m] = (setup, lat_fn)
                info(f"{m}: caricata")
            except Exception as e:
                warn(f"{m}: non caricata, la salto -- {type(e).__name__}: {e}")
        if not loaded:
            warn("nessuna pipeline caricata")
            return []

        gen = Generator([fab.ingress_peer], plan, xmit_mode=xmit_mode,
                        topology="shared", window_s=window_s,
                        warmup_s=warmup_s).attach()
        napi_devs = []

        # --- fase 2: misura a giri, tutti i metodi in ogni giro
        print(f"\n{YELLOW}{'=' * 78}{NC}")
        print(f"{YELLOW} Fase 2: {rounds} giri x {len(loaded)} pipeline, "
              f"stesso fabric, nessuna compilazione{NC}")
        print(f"{YELLOW}{'=' * 78}{NC}")
        hdr = (f"  {'giro':>4s} {'pipeline':10s} {'frame':>5s} "
               f"{'fase':12s} "
               f"{'RX pps':>9s} {'Mb/s':>7s} {'resp':>7s} {'perdita':>8s} "
               f"{'min':>6s} {'p50<':>7s} {'p99<':>8s}")
        print(hdr)
        print("  " + "-" * (len(hdr) - 2))

        first = True
        for rnd in range(1, rounds + 1):
            for m, (setup, lat_fn) in loaded.items():
                b = setup["b"]
                # SOSTITUISCE il programma, non lo stacca: attach_xdp non passa
                # UPDATE_IF_NOEXIST, quindi un attach su un'interfaccia che ne
                # ha gia' uno lo rimpiazza. Staccare avrebbe smontato la NAPI, e
                # con lei la modalita' a thread -- che e' esattamente perche' al
                # run precedente `threaded` veniva rifiutato.
                ctx = (lambda: _quiet()) if not first else (lambda: _noop())
                with ctx():
                    for peer in fab.peer_of.values():
                        try:
                            attach_xdp(b, lat_fn, peer)
                        except Exception:
                            pass
                    attach_xdp(b, setup["disp"], fab.ingress)
                if first:
                    # SOLO ORA la NAPI esiste: veth la usa quando c'e' un
                    # programma XDP attaccato. Abilitarla prima -- com'era --
                    # otteneva "Operation not supported", perche' non c'era
                    # nulla da mettere in thread.
                    if threaded_napi:
                        napi_devs = [fab.ingress]
                        if enable_threaded_napi(napi_devs, plan):
                            info("NAPI in thread: generatore e DUT su core "
                                 "separati")
                        else:
                            napi_devs = []
                    first = False
                # Scaldata scartata: la prima raffica paga cache fredde e la
                # prima allocazione, e non descrive il regime.
                gen.warmup(64, 0)
                for frame in frames:
                    for r in _fair_sweep(b, fab, frame, tol, gen=gen,
                                         plan=plan, diag=diag):
                        r.update(method=m, round=rnd, threads=gen.n_inst)
                        raw.append(r)
                        if r["phase"] == "ricerca":
                            continue        # i passi intermedi restano nel CSV
                        print(f"  {rnd:4d} {m:10s} {frame:5d} "
                              f"{r['phase']:12s} "
                              f"{r['rx_pps']:9d} {r['rx_mbps']:7.1f} "
                              f"{r.get('respinti_pct', 0.0):6.2f}% "
                              f"{r['loss_pct']:7.2f}% "
                              f"{_fmt_ns(r['lat_min_ns'])} "
                              f"{_fmt_bucket(r['lat_p50_ns'])} "
                              f"{_fmt_bucket(r['lat_p99_ns'])}")

        gen.detach()
        pg_reset()
        if napi_devs:
            disable_threaded_napi(napi_devs)
        _detach(fab.ingress)
        for peer in fab.peer_of.values():
            _detach(peer)
    return raw


# ==========================================================================
# IL RATE MASSIMO SENZA PERDITE (RFC 2544)
# ==========================================================================
# "Throughput" in senso di rete non e' quanti pacchetti passano quando si spinge
# al massimo: e' il rate PIU' ALTO a cui non se ne perde nessuno. Sono due numeri
# diversi e il secondo e' quello citabile, perche' il primo descrive un sistema
# in sovraccarico -- dove la cifra dipende da quanto si e' spinto, non da cosa
# regge il sistema.
#
# Il ritardo lo impone PKTGEN, cioe' il kernel, non un time.sleep() in Python.
# E' la ragione per cui questa ricerca e' accurata e un generatore frenato da
# Python non lo era: misurato, chiedendo 200 kpps con una pausa in Python ne
# uscivano 11 kpps, e il punto a 50 kpps ne dava 13 -- piu' del punto piu'
# veloce. Quei numeri erano la granularita' dello scheduler, non un rate.


def _fair_sweep(b, fab, frame, tol, steps=KNEE_STEPS, gen=None, plan=None,
                diag=None):
    """Tre punti per pipeline: a fondo, al limite senza perdite, e a vuoto.

    Ritorna righe gia' etichettate con `phase`, che e' cio' su cui il riepilogo
    raggruppa. Non si raggruppa piu' su `delay` perche' con la ricerca il
    ritardo e' diverso per ogni pipeline: e' il RISULTATO della ricerca, non
    una condizione dell'esperimento.
    """
    rows = []
    wc = (gen.window_count if gen is not None
          else (lambda r, s=None: _window_count(r)))

    # --- 1. a fondo: quanto offre il generatore e quanto ne sopravvive.
    #     Serve come estremo superiore della ricerca, e come cifra di
    #     sovraccarico da riportare accanto a quella pulita.
    full = _one_fair_point(b, fab, frame, 0, wc(3_000_000), gen=gen)
    if full is None:
        warn(f"frame {frame}: nessuna finestra utilizzabile a pieno regime, "
             f"questo giro non produce righe per questa pipeline (la mediana "
             f"finale sara' calcolata su meno giri).")
        return rows
    full["phase"] = "pieno"
    rows.append(full)

    if full["loss_pct"] <= tol:
        # Niente si perde gia' alla massima spinta: il generatore ha saturato
        # prima della pipeline. Non c'e' un ginocchio da cercare, e dirlo e' il
        # risultato -- cercarlo comunque restituirebbe un numero piu' basso di
        # quello gia' misurato.
        clean = dict(full)
        clean["phase"] = "zero-perdite"
        clean["gen_bound"] = 1
        rows.append(clean)
    else:
        # --- 2. la ricerca del limite, attorno a una stima che gia' abbiamo.
        #
        #     Il rate CONSEGNATO in sovraccarico e' quasi esattamente la
        #     capacita': se se ne offrono 2,4 M e ne passano 1,4 M, la pipeline
        #     ne regge circa 1,4 M. Quindi non serve bisecare [0, offerto]: si
        #     parte poco sotto la stima e si sale finche' si perde.
        #
        #     Una bisezione cieca su quell'intervallo trovava una pipeline da
        #     300 kpps a 225 k (-25%): cinque dimezzamenti di un intervallo che
        #     arriva a 2,4 M non hanno risoluzione in basso.
        #
        #     E anche partendo dalla stima, bisecare sbagliava del 6%, per un
        #     motivo che vale la pena ricordare: `int(1e9 / rate)` arrotonda il
        #     ritardo PER DIFETTO, quindi il primo tentativo offre un filo piu'
        #     della capacita', perde un pacchetto, e con lo zero stretto viene
        #     bocciato -- mandando la bisezione a ripartire da zero. Partire
        #     sotto la stima toglie il problema alla radice.
        SU = (0.98, 1.02, 1.05, 1.09, 1.14, 1.20)    # pulito: si prova a salire
        GIU = (0.92, 0.85, 0.75, 0.60, 0.40, 0.25)   # sporco: si scende
        est = float(full["rx_pps"])
        best = None
        rate = est * SU[0]
        i_su, i_giu = 1, 0
        for _ in range(steps):
            if rate < 1000:
                break
            r = _one_fair_point(b, fab, frame, _delay_for(rate, gen),
                                wc(rate), gen=gen)
            if r is None:
                break
            r["phase"] = "ricerca"
            rows.append(r)
            if r["loss_pct"] <= tol:
                best = r
                if i_su >= len(SU):
                    break
                rate, i_su = est * SU[i_su], i_su + 1
            else:
                if best is not None:
                    # Pulito al gradino prima, sporco a questo: il limite sta
                    # in mezzo e lo si e' gia' misurato. Continuare vorrebbe
                    # dire raffinare oltre il rumore del banco.
                    break
                if i_giu >= len(GIU):
                    break
                rate, i_giu = est * GIU[i_giu], i_giu + 1
        if best is not None:
            clean = dict(best)
            clean["phase"] = "zero-perdite"
            clean["gen_bound"] = 0
            rows.append(clean)

    # --- 3. a vuoto: la latenza senza coda davanti. E' il numero che separa le
    #     pipeline fra loro, e va preso dove nessuna e' in sovraccarico --
    #     altrimenti si confrontano lunghezze di coda invece che programmi.
    idle_rate = 50_000
    idle = _one_fair_point(b, fab, frame, _delay_for(idle_rate, gen),
                           wc(idle_rate), gen=gen)
    if idle is not None:
        idle["phase"] = "scarico"
        rows.append(idle)
    for r in rows:
        r.setdefault("gen_bound", 0)
        tag, why = classify_bottleneck(r, threshold=max(tol, 0.0), plan=plan)
        r["bottleneck"] = tag
        r["bottleneck_why"] = why
    return rows


def _delay_for(rate, gen=None):
    """Il ritardo per offrire `rate` in aggregato, tenendo conto che con N
    istanze ognuna trasmette a rate/N."""
    if gen is not None:
        return gen.delay_for(rate)
    return int(1e9 / rate) if rate > 0 else 0


def _one_fair_point(b, fab, frame, delay, count, gen=None):
    """Un punto: throughput e latenza dallo stesso pacchetto.

    QUESTO PERCORSO NON PASSA DA `_measure_once`, quindi le protezioni sulle
    finestre vanno ripetute qui. Non e' duplicazione per pigrizia: sono due
    strade diverse verso pktgen -- quella a contatori di pipeline e questa a
    istogramma di latenza -- e per mesi solo la prima e' stata irrobustita.

    Misurato il 2026-09-18 (b0447b3e, --rounds 5): al giro 5 la fase `scarico`
    di `hardcoded` ha consegnato **171 pacchetti** invece di ~100 000, e la
    riga e' entrata nella tabella con `min 5627n` contro i ~430 degli altri
    quattro giri. Da li' il controllo di riproducibilita' della latenza e'
    uscito a **1227%**, cioe' ha bocciato una misura che era buona in quattro
    giri su cinque per colpa di una finestra che non era una misura."""
    # Il drenaggio prima di azzerare: la coda della finestra precedente deve
    # essere atterrata, altrimenti i suoi campioni finiscono nell'istogramma
    # di questa.
    time.sleep(DRAIN_S)
    b["lat_acc"].clear()
    b["lat_hist"].clear()
    try:
        if gen is not None and gen.window_mode == "steady":
            # RX da `rx_n`, che il contatore d'uscita incrementa sempre: e' il
            # conteggio vero, non quello dei soli pacchetti cronometrati.
            run = gen.steady(frame, delay, lambda: {
                "rx": sum(int(v) for v in b["rx_n"][ct.c_int(0)])})
            tx, tx_pps, secs = run
            threads = gen.n_inst
            skew = run.skew_pct
        elif gen is not None:
            run = gen.run(frame, count, delay)
            tx, tx_pps, secs = run
            threads = gen.n_inst
            skew = run.skew_pct
        else:
            pg_ensure_device(fab.ingress_peer, thread=0)
            pg_set_params(fab.ingress_peer, frame, count, delay)
            run = pg_run_and_read([fab.ingress_peer])
            tx, tx_pps, secs = run
            threads, skew = 1, getattr(run, "skew_pct", 0.0)
    except PktgenEmptyRun as e:
        warn(f"punto scartato: {e}")
        return None
    # Stessa regola di `_measure_once`: una finestra che ha trasmesso una
    # frazione dei pacchetti chiesti e' un run troncato, non un punto.
    atteso = count * (gen.n_inst if gen is not None else 1)
    if (not getattr(run, "steady", False) and atteso
            and tx < atteso * WINDOW_MIN_TX_FRACTION):
        warn(f"punto scartato: finestra troncata, {tx} trasmessi su {atteso} "
             f"chiesti ({100.0 * tx / atteso:.1f}%) in {secs:.2f}s")
        return None
    # ...e il drenaggio dopo: `pgctrl start` ritorna quando il generatore ha
    # finito, non quando il DUT ha svuotato la coda. Senza, gli ultimi
    # campioni di latenza non sono ancora nell'istogramma.
    time.sleep(DRAIN_S)
    st = _read_lat(b)
    if st is None:
        return None
    rx = run.dut["rx"] if getattr(run, "steady", False) else st["n"]
    secs = secs or 1e-9
    # I RESPINTI SONO PERDITA. Questo percorso contava solo TX - RX, cioe'
    # ignorava i pacchetti che `veth_xmit` rifiuta a coda d'ingresso piena --
    # lo stesso difetto gia' corretto in _measure_once il 2026-09-18 e rimasto
    # qui. Effetto misurato il 2026-09-23: `--latency` riportava hardcoded a
    # 2 518 151 pps con "perdita 0,00%" a massima spinta, e la fase
    # zero-perdite ne era la copia, marcata "il generatore ha saturato prima
    # della pipeline"; a massima spinta, nella stessa sessione, --mode compare
    # contava il 57% di respinti.
    errors = getattr(run, "errors", 0)
    offered_tx = tx + errors
    return dict(frame=frame, delay=delay, tx=tx, rx=rx, tx_pps=tx_pps,
                rx_pps=int(rx / secs),
                rx_mbps=round(rx * frame * 8 / secs / 1e6, 1),
                secs=round(secs, 3), gen_threads=threads,
                gen_skew_pct=skew,
                window_mode=("steady" if getattr(run, "steady", False)
                             else "count"),
                offered_pps=(int(1e9 / delay) * threads if delay else None),
                gen_errors=errors, offered_tx=offered_tx,
                offered_real_pps=int(offered_tx / secs),
                loss_pct=(round(100.0 * max(0, offered_tx - rx) / offered_tx, 3)
                          if offered_tx else 0.0),
                respinti_pct=(round(100.0 * errors / offered_tx, 3)
                              if offered_tx else 0.0),
                loss_dut_pct=(round(100.0 * max(0, tx - rx) / offered_tx, 3)
                              if offered_tx else 0.0),
                excess_rx=max(0, rx - tx),
                **{k: st[k] for k in ("lat_min_ns", "lat_p50_ns", "lat_p90_ns",
                                      "lat_p99_ns", "lat_avg_ns",
                                      "lat_max_ns")})


def _give_back(*paths):
    """Ridai i file all'utente che ha lanciato il sudo.

    Senza questo i CSV restano di root: il run dopo non puo' sovrascriverli e
    nemmeno il plotter puo' leggerli comodamente."""
    uid = os.environ.get("SUDO_UID")
    if not uid:
        return
    gid = int(os.environ.get("SUDO_GID", uid))
    for base in paths:
        for root, dirs, files in os.walk(base):
            for name in list(dirs) + list(files):
                try:
                    os.chown(os.path.join(root, name), int(uid), gid)
                except OSError:
                    pass
        try:
            os.chown(base, int(uid), gid)
        except OSError:
            pass


def _latency_verdict(rows):
    """La latenza regge anche dove il throughput no: dirlo esplicitamente.

    Sullo stesso identico run, a pieno rate: il throughput di una pipeline
    varia del 137% fra i giri, la sua latenza minima di meno dell'1%. Sono due
    misure con due affidabilita' diverse e vanno riportate come tali, invece di
    lasciare che il lettore prenda la tabella per buona tutta insieme."""
    lat = [r for r in rows
           if r.get("lat_spread_pct") is not None and r.get("phase") == "scarico"]
    if not lat:
        # Nessuna riga a vuoto: si ripiega su tutte, dicendolo.
        lat = [r for r in rows if r.get("lat_spread_pct") is not None]
    if not lat:
        return
    worst = max(lat, key=lambda r: r["lat_spread_pct"])
    print(f"\n{YELLOW}{'=' * 78}{NC}")
    print(f"{YELLOW} Latenza: quanto e' riproducibile{NC}")
    print(f"{YELLOW}{'=' * 78}{NC}")
    if worst["lat_spread_pct"] <= 5.0:
        print(f"  {GREEN}[PASS]{NC} la latenza minima varia al massimo del "
              f"{worst['lat_spread_pct']:.1f}% fra i giri "
              f"({worst['method']}, frame {worst['frame']}, delay "
              f"{worst['delay']}).")
        print(f"  {GREY}E' la misura da citare: riproducibile anche dove il "
              f"throughput non lo e'.{NC}")
    else:
        print(f"  {RED}[FAIL]{NC} la latenza minima varia fino al "
              f"{worst['lat_spread_pct']:.1f}% fra i giri "
              f"({worst['method']}): alza --rounds.")


def summarise_fair(raw, methods):
    """Mediana fra i giri, per metodo e configurazione."""
    import statistics as stats
    if not raw:
        return []
    raw = [r for r in raw if r.get("phase") != "ricerca"]
    # Ordine LOGICO, non alfabetico. In ordine alfabetico le fasi escono
    # "pieno, scarico, zero-perdite" e le pipeline "baseline, hardcoded,
    # modular, p1_static, template": la riga che conta finisce in fondo e
    # l'ordine delle pipeline non e' piu' quello del costo crescente, che e'
    # il modo in cui questa tabella si legge.
    ordine_fase = {"pieno": 0, "zero-perdite": 1, "scarico": 2}
    ordine_met = {m: i for i, m in enumerate(METHODS)}
    keys = sorted({(r["method"], r["frame"], r["phase"]) for r in raw},
                  key=lambda k: (ordine_met.get(k[0], 99), k[1],
                                 ordine_fase.get(k[2], 99)))
    out = []
    print(f"\n{YELLOW}{'=' * 78}{NC}")
    print(f"{YELLOW} Riepilogo: mediana fra i giri{NC}")
    print(f"{YELLOW}{'=' * 78}{NC}")
    hdr = (f"  {'pipeline':10s} {'frame':>5s} {'fase':12s} {'giri':>4s} "
           f"{'RX pps':>9s} {'Mb/s':>7s} {'resp':>7s} {'perdita':>8s} "
           f"{'min':>6s} {'p50<':>7s} {'p99<':>8s} {'collo':>18s}")
    print(hdr)
    print("  " + "-" * (len(hdr) - 2))
    for m, frame, phase in keys:
        pts = [r for r in raw if (r["method"], r["frame"], r["phase"])
               == (m, frame, phase)]
        delay = int(stats.median([r["delay"] for r in pts]))
        med = {k: stats.median([r[k] for r in pts if r[k] is not None] or [0])
               for k in ("rx_pps", "rx_mbps", "loss_pct", "respinti_pct",
                         "lat_min_ns", "lat_p50_ns", "lat_p99_ns")}
        # Dispersione FRA I GIRI, non dentro un punto. E' la cosa che dice se
        # la mediana significa qualcosa: misurato, hardcoded a pieno rate ha
        # dato 2,78 / 1,17 / 1,46 Mpps in tre giri -- 137% -- e la sua mediana
        # e' finita SOTTO template, che fa molto piu' lavoro. Una mediana su
        # misure cosi' non e' un risultato, ed e' il numero che va marcato.
        pps = [r["rx_pps"] for r in pts if r["rx_pps"]]
        spread = (100.0 * (max(pps) - min(pps)) / min(pps)) if pps else 0.0
        stat = _agg(pps)
        # La latenza ha la sua dispersione, e nei fatti e' un altro mondo:
        # pochi ns su tre giri contro decine di punti percentuali.
        lats = [r["lat_min_ns"] for r in pts if r["lat_min_ns"]]
        lat_spread = (100.0 * (max(lats) - min(lats)) / min(lats)) if lats else 0.0
        bad = spread > MAX_SPREAD_PCT
        # Il collo di bottiglia della maggioranza dei giri: se i giri non sono
        # d'accordo si riporta il piu' frequente, che e' cio' che una mediana
        # e' per una grandezza non numerica.
        tags = [r.get("bottleneck") for r in pts if r.get("bottleneck")]
        tag = max(set(tags), key=tags.count) if tags else BN_UNKNOWN
        row = dict(method=m, frame=frame, phase=phase, delay=delay,
                   rounds=len(pts),
                   pps_spread_pct=round(spread, 1),
                   rx_pps_mean=stat["mean"], rx_pps_min=stat["min"],
                   rx_pps_max=stat["max"], rx_pps_std=stat["std"],
                   rx_pps_cv_pct=stat["cv_pct"],
                   secs=round(stats.median([r.get("secs", 0) for r in pts]), 3),
                   bottleneck=tag,
                   lat_spread_pct=round(lat_spread, 1), unreliable=bad, **med)
        out.append(row)
        flag = f" {RED}pps +-{spread:.0f}%{NC}" if bad else ""
        # La riga senza perdite e' quella citabile: si vede.
        col = GREEN if phase == "zero-perdite" else ""
        end = NC if col else ""
        print(f"  {col}{m:10s} {frame:5d} {phase:12s}{end} {len(pts):4d} "
              f"{int(med['rx_pps']):9d} {med['rx_mbps']:7.1f} "
              f"{med['respinti_pct']:6.2f}% "
              f"{med['loss_pct']:7.2f}% "
              f"{int(med['lat_min_ns']):5d}n "
              f"<{int(med['lat_p50_ns']):5d}n "
              f"<{int(med['lat_p99_ns']):6d}n {tag:>18s}{flag}")
    return out


# ==========================================================================
# THREADED NAPI: separare davvero il generatore dal DUT
# ==========================================================================
# Questo e' il pezzo che rende il banco un banco TG/DUT invece di una misura
# della somma dei due.
#
# In modalita' softirq la RX di un veth gira sulla CPU che ha trasmesso: il
# generatore e la pipeline finiscono sullo stesso core, e il tempo per pacchetto
# e' t_gen + t_pipeline. Cosi' il generatore satura sempre per primo e la
# pipeline non arriva mai al suo limite -- il risultato e' che "throughput
# massimo" e "throughput a perdita nulla" coincidono, che e' un non-risultato.
#
# Dal kernel 5.12 /sys/class/net/<dev>/threaded sposta il poll NAPI in un
# KERNEL THREAD dedicato (`napi/<dev>-<id>`), che lo scheduler puo' mettere
# altrove e che si puo' pinnare a mano. Pinnando i thread NAPI sulle CPU del
# DUT, generatore e pipeline stanno davvero su core diversi:
#
#     CPU del generatore   pktgen genera (kpktgend_<cpu>)
#     CPU del DUT          napi/<dev>-*  esegue XDP, cioe' l'inferenza
#
# Da quel momento la domanda "a che rate la pipeline comincia a perdere" ha una
# risposta, perche' il generatore non le ruba piu' il core.
#
# Non e' gratis e va detto: i pacchetti attraversano una frontiera di cache fra
# il core che genera e quello che elabora, quindi il costo per pacchetto in
# assoluto puo' salire. In cambio diventa attribuibile, che e' il punto.


def _napi_threads(dev):
    """I PID dei kernel thread NAPI di `dev`, in ordine di napi id.

    L'ordine e' quello di creazione, che e' l'ordine delle code, ma il kernel
    NON garantisce la corrispondenza id->coda e questo codice non la pretende:
    quello che serve e' distribuire N thread su M CPU, non sapere quale coda
    serve quale thread. Dichiararlo qui evita che qualcuno legga il pinning
    come una mappa coda->CPU che non e'."""
    try:
        out = subprocess.run(["ps", "-eo", "pid,comm"], capture_output=True,
                             text=True, check=False).stdout
    except OSError:
        # Niente `ps` (container minimale): i thread esistono lo stesso, ma
        # non si possono pinnare. Dirlo invece di far esplodere il run.
        warn("`ps` non disponibile: non posso trovare i thread NAPI, quindi "
             "non posso pinnarli. Restano dove li mette lo scheduler.")
        return []
    found = []
    for line in out.splitlines():
        parts = line.split(None, 1)
        if len(parts) != 2:
            continue
        comm = parts[1].strip()
        if not comm.startswith(f"napi/{dev}-"):
            continue
        try:
            nid = int(comm.rsplit("-", 1)[1])
        except (IndexError, ValueError):
            nid = 0
        found.append((nid, parts[0].strip()))
    return [pid for _, pid in sorted(found)]


def enable_threaded_napi(devs, plan_or_first_cpu=None, ncpu=None):
    """Metti in modo thread la NAPI di `devs` e pinna i thread sulle CPU DUT.

    Il secondo argomento e' un CpuPlan (forma nuova) oppure la prima CPU da
    usare piu' il numero totale di CPU (forma storica, tenuta perche' un paio
    di chiamanti la usano ancora).

    COME SI DISTRIBUISCE. Un device con una sola coda ha un solo thread NAPI e
    va su una CPU sola: e' il caso del fabric. Un device con piu' code ne ha
    uno per coda, e allora si spalmano sulle CPU del DUT -- ed e' cio' che
    permette di avere piu' core di generatore che di DUT senza che i core del
    DUT restino inutilizzati.

    Va ricordato il modo in cui questo e' andato storto una volta: con DUE
    device d'ingresso, CINQUE contatori d'uscita e dieci thread schiacciati su
    due CPU, il generatore offriva 4,17 Mpps e il datapath ne consegnava 118 k.
    Non era saturazione, era un crollo da oversubscription. La regola che ne
    e' uscita, e che qui resta: si mettono in thread SOLO gli ingressi, e i
    contatori d'uscita restano in softirq.

    Restituisce [(dev, n_thread, [cpu, ...])] per quello che e' andato a
    posto."""
    if isinstance(plan_or_first_cpu, CpuPlan):
        dut = list(plan_or_first_cpu.dut)
    else:
        first = plan_or_first_cpu if isinstance(plan_or_first_cpu, int) else 0
        total = ncpu or (os.cpu_count() or 1)
        dut = [c for c in range(first, total)] or [first]
    if not dut:
        dut = [0]

    placed = []
    next_cpu = 0
    for dev in devs:
        path = f"/sys/class/net/{dev}/threaded"
        if not os.path.exists(path):
            warn(f"{dev}: /sys/.../threaded non c'e', resto in softirq "
                 f"(kernel < 5.12?)")
            continue
        try:
            with open(path, "w") as f:
                f.write("1\n")
        except OSError as e:
            warn(f"{dev}: threaded rifiutato ({e.strerror}), resto in softirq")
            continue
        pids = _napi_threads(dev)
        used = []
        for pid in pids:
            cpu = dut[next_cpu % len(dut)]
            next_cpu += 1
            try:
                r = subprocess.run(
                    ["taskset", "-pc", str(cpu), pid],
                    capture_output=True, text=True, check=False
                )
            except OSError:
                warn("`taskset` non disponibile (util-linux): i thread NAPI "
                     "sono in modo thread ma non pinnati, quindi la "
                     "separazione fra le CPU la decide lo scheduler.")
                break
            if r.returncode == 0:
                used.append(cpu)
            else:
                warn(f"{dev}: taskset su cpu{cpu} fallito per il pid {pid} "
                     f"({(r.stderr or '').strip() or 'motivo non riportato'})")
        if pids:
            placed.append((dev, len(pids), sorted(set(used))))
        else:
            warn(f"{dev}: modo thread attivo ma nessun thread napi/{dev}-* "
                 f"trovato: il poll potrebbe essere ancora in softirq")
    return placed


def disable_threaded_napi(devs):
    for dev in devs:
        path = f"/sys/class/net/{dev}/threaded"
        if os.path.exists(path):
            try:
                with open(path, "w") as f:
                    f.write("0\n")
            except OSError:
                pass


# ==========================================================================
# LINK D'INGRESSO DEDICATI: uno o piu', dimensionati sulle CPU
# ==========================================================================
TG_PREFIX = "ipatg"


def _ip(*args, check=True):
    return subprocess.run(["ip", *args], capture_output=True, text=True,
                          check=check)


def _make_pair(rx, tx, rx_queues, tx_queues):
    """Una coppia veth dimensionata: `rx` e' il lato DUT (XDP), `tx` quello su
    cui trasmette pktgen.

    IL VINCOLO CHE DECIDE I NUMERI. veth_xdp_set rifiuta l'attach con
    "XDP expects number of rx queues not less than peer tx queues": il lato che
    porta XDP deve avere ALMENO tante code RX quante sono le code TX del peer.
    Quindi le code TX del generatore fissano un minimo per le code RX del DUT,
    e il numero di CPU del DUT puo' solo alzarlo, mai abbassarlo. Sbagliarlo
    non da' un errore a runtime: da' un attach fallito, cioe' nessun programma
    e nessun HIT."""
    _ip("link", "del", rx, check=False)          # leftovers from a crash
    rxq = max(rx_queues, tx_queues)
    _ip("link", "add", rx, "numrxqueues", str(rxq), "numtxqueues", str(rxq),
        "type", "veth", "peer", tx,
        "numrxqueues", str(tx_queues), "numtxqueues", str(tx_queues))
    for dev in (rx, tx):
        _ip("link", "set", dev, "up")
        # IPv6 autoconf would put router solicitations on the same wire and
        # they would be counted as traffic that nobody generated.
        subprocess.run(["sysctl", "-qw",
                        f"net.ipv6.conf.{dev}.disable_ipv6=1"],
                       capture_output=True, check=False)
    # Il lato DUT e' quello che porta XDP, quindi e' il suo ring quello che
    # `veth_xmit` riempie dall'altra parte. Si alza QUI, cioe' prima che il
    # programma venga attaccato: il ring si alloca all'attach.
    raise_veth_ring(rx)
    idx = int(_ip("-o", "link", "show", rx).stdout.split(":")[0])
    return rx, tx, idx


# Esito dell'ultimo innalzamento, per le condizioni del test. Globale perche'
# _make_pair e' chiamata da tre percorsi diversi e il dato serve a capture_env,
# che non ne vede nessuno.
VETH_RING_STATE = {}

# Device per cui l'avviso e' gia' stato stampato: il fabric viene ricostruito
# per ogni pipeline, quindi senza questo l'avviso uscirebbe cinque volte.
_RING_DETTO = set()


def _ethtool_ring(dev):
    """(RX attuale, RX massima) dalla sezione giusta di `ethtool -g`.

    L'output ha DUE sezioni -- "Pre-set maximums" e "Current hardware
    settings" -- ognuna con una riga `RX:`. Prendere la prima che capita vuol
    dire leggere il massimo credendo di leggere l'attuale."""
    r = subprocess.run(["ethtool", "-g", dev], capture_output=True, text=True,
                       check=False)
    if r.returncode != 0:
        return None, None
    massimo = attuale = None
    sezione = None
    for line in r.stdout.splitlines():
        s = line.strip()
        if s.startswith("Pre-set maximums"):
            sezione = "max"
        elif s.startswith("Current hardware settings"):
            sezione = "cur"
        elif s.startswith("RX:") and sezione:
            val = s.split(":", 1)[1].strip()
            if val.isdigit():
                if sezione == "max":
                    massimo = int(val)
                else:
                    attuale = int(val)
    return attuale, massimo


def raise_veth_ring(dev, target=VETH_RING_TARGET):
    """Alza la coda RX del veth, PRIMA che XDP venga attaccato.

    L'ordine non e' un dettaglio: il ring viene allocato quando il programma
    XDP si attacca, quindi cambiarlo dopo non ha effetto su quello in uso."""
    attuale, massimo = _ethtool_ring(dev)
    stato = dict(dev=dev, supportato=attuale is not None,
                 prima=attuale, massimo=massimo, chiesto=target, dopo=attuale)
    if attuale is None:
        VETH_RING_STATE[dev] = stato
        if dev not in _RING_DETTO:
            _RING_DETTO.add(dev)
            warn(f"coda RX di {dev}: `ethtool -g` non la espone su questo "
                 f"kernel. veth.c la fissa a VETH_RING_SIZE (storicamente 256 "
                 f"descrittori) e non e' configurabile: i respinti a rate "
                 f"basso sono un pavimento del banco, non della pipeline.")
        return stato
    voluto = min(target, massimo) if massimo else target
    if attuale >= voluto:
        VETH_RING_STATE[dev] = stato
        return stato
    subprocess.run(["ethtool", "-G", dev, "rx", str(voluto)],
                   capture_output=True, text=True, check=False)
    stato["dopo"] = _ethtool_ring(dev)[0]
    VETH_RING_STATE[dev] = stato
    if stato["dopo"] and stato["dopo"] != attuale:
        info(f"coda RX di {dev}: {attuale} -> {stato['dopo']} descrittori "
             f"(massimo {massimo})")
    else:
        warn(f"coda RX di {dev} resta a {attuale} descrittori: "
             f"`ethtool -G rx {voluto}` non ha avuto effetto. A 1 Mpps "
             f"{attuale} descrittori sono {attuale} us di traffico, e i respinti a rate "
             f"basso sono strutturali.")
    return stato


def make_tg_links(n, gen_queues=1, dut_queues=1):
    """`n` coppie veth, ognuna ingresso di un thread generatore in piu'.

    Topologia "links", quella storica: ogni coppia ha la sua NAPI e quindi il
    suo core DUT, per cui generatore e DUT scalano insieme. Utile per
    riprodurre le misure vecchie e per vedere come si comporta la stessa
    pipeline su piu' code d'ingresso indipendenti.

    Tutte alimentano lo STESSO programma XDP, quindi il carico offerto scala
    con i core mentre la cosa sotto test resta un programma con le sue mappe --
    ed e' anche cio' che rende la misura interessante e non solo piu' grande:
    pkt_stats e cls_stats sono BPF_ARRAY condivisi incrementati con
    __sync_fetch_and_add, quindi piu' core che li martellano si contendono la
    stessa cache line.

    Returns [(rx_dev, tx_dev, rx_ifindex), ...]."""
    made = []
    for i in range(n):
        rx, tx = f"{TG_PREFIX}{i}", f"{TG_PREFIX}{i}p"
        made.append(_make_pair(rx, tx, dut_queues, gen_queues))
    return made


def make_shared_tg_link(gen_threads, dut_queues, index=0):
    """UNA coppia veth per la topologia "shared": tutti i thread generatore
    trasmettono qui, su code TX distinte, e il lato DUT ha le sue code RX.

    E' la modifica che permette di chiedere N core di generatore contro M core
    di DUT con N > M, cioe' l'unica configurazione in cui su una macchina sola
    la pipeline arriva a saturare.

    Returns (rx_dev, tx_dev, rx_ifindex)."""
    rx, tx = f"{TG_PREFIX}{index}", f"{TG_PREFIX}{index}p"
    return _make_pair(rx, tx, max(1, dut_queues), max(1, gen_threads))


def del_tg_links(n):
    for i in range(max(1, n)):
        _ip("link", "del", f"{TG_PREFIX}{i}", check=False)


# ==========================================================================
# setup
# ==========================================================================
def setup_p1_static(model_id, model_path, node=STATIC_NODE):
    """setup_hardcoded, ma con l'indice del nodo congelato nel sorgente.

    Non e' in verify_prog_run perche' la specializzazione e' nata qui: lo
    switch a n_nodi casi sulla one-hot del nodo sparisce e con lui la lettura
    della mappa node_id, restando n_h1 costanti che clang piega
    nell'accumulatore. Vedi _gen_feature_onehot_node in ebpf_program.py, e
    `bench_scaling.py --verify` per la prova che decide come la P1.5."""
    import p1_aot
    import verify_prog_run as V

    # L'oggetto AOT, come P1 si deploya (p1_aot), con il nodo congelato.
    weights, scale = V.load_weights(model_path)
    setup = p1_aot.load_p1([(model_id, weights, scale)], static_node=node)
    setup.update(weights=weights, scale=scale, static_node=node)
    V._seed_link_state(setup["b"], 1)
    V._install_mac_table(setup["b"], "mac_table")
    return setup


def class_semantics():
    """The declared class semantics, resolved the same way test_fabric does."""
    import model_meta as mm
    meta_path = os.path.join(SHARED_DIR, "weights.json")
    n_out = mm.derive_shape(
        mm.load_model_meta(meta_path),
        topology_config=mm.load_topology_config())["n_out"]
    return mm.load_class_semantics(meta_path, n_out), n_out


def build_pipeline(method, model_path, fab, sem):
    """Load the pipeline, point it at THIS fabric, and make it answer to the
    model_id pktgen actually puts on the wire.

    The three map writes below are the same ones test_fabric makes, done by
    hand rather than through common.install_*: those helpers resolve the node
    and the ports from a node configuration, and here both come from the
    fabric that was just built."""
    import verify_prog_run as V
    import test_fabric as TF

    if method == RX_ONLY:
        return setup_rxonly()
    if method == "baseline":
        setup = V.setup_baseline(0, model_path)
    elif method == "p1_static":
        setup = setup_p1_static(0, model_path)
    else:
        setup = getattr(V, TF._SETUP[method])(0, model_path)
    b, pl = setup["b"], setup["pipeline"]

    # mac_table serve a tutte: e' la catena porta logica -> ifindex, ed e' cio'
    # che fa uscire il pacchetto dal veth giusto. La baseline redirige su una
    # classe fissa, quindi le basta la porta 0, ma installarle tutte non costa.
    mac_name = "mac_table" if pl in (0, 1) else TF._MAC_NAME[pl]
    TF._install_fabric_mac_table(b, mac_name, fab, sem.logical_ports)

    if method == "baseline":
        # Nessuna feature: non c'e' ingress_port, non c'e' node_id, e il
        # programma non legge nemmeno ipa->model_id. Niente da cablare, ed e'
        # esattamente cio' che la rende il tetto del banco.
        return setup

    b[TF._INGRESS_NAME[pl]][ct.c_uint32(fab.ingress_ifindex)] = \
        ct.c_uint32(TF.FABRIC_INGRESS_SLOT)
    if method != "p1_static":
        # La specializzata ha l'indice del nodo compilato dentro: la mappa e'
        # ancora dichiarata nell'header condiviso ma nessuno la legge, e
        # scriverci darebbe l'impressione sbagliata che serva.
        b[TF._NODEID_NAME[pl]][ct.c_uint32(0)] = \
            ct.c_uint32(TF.FABRIC_NODE_INDEX)

    # The model under the id pktgen writes. See the docstring: this is the
    # difference between measuring inference and measuring XDP_PASS.
    _register_alias(method, setup, PKTGEN_MAGIC_MODEL_ID)
    return setup


def _register_alias(method, setup, model_id):
    b, w, scale = setup["b"], setup["weights"], setup["scale"]
    if method in ("hardcoded", "p1_static"):
        b["model_progs"][ct.c_int(model_id)] = ct.c_int(setup["fn"].fd)
    elif method == "template":
        from ebpf_template_arch import load_arch_weights
        load_arch_weights(b, w, model_id=model_id, scale=scale)
    else:
        from ebpf_modular import load_modular_weights
        load_modular_weights(b, w, model_id=model_id, scale=scale,
                             layer_dims=[(65, 4), (4, 4), (4, 7)])


def attach_rx_counter(fab):
    """Replace the fabric's XDP_PASS stubs with a counting XDP_DROP.

    The stubs exist so that bpf_redirect into a veth works at all
    (veth_xdp_xmit needs the receiving peer to have a program). Counting there
    instead of passing keeps the packet out of the network stack, so the
    number measured is delivery by the datapath and not the cost of handing
    frames to a socket."""
    from bcc import BPF
    from common import attach_xdp
    b = BPF(text=RX_COUNTER_SRC)
    fn = b.load_func("xdp_rx_count", BPF.XDP)
    attached = []
    for port, peer in fab.peer_of.items():
        try:
            # Anche qui prima dell'attach: `bpf_redirect` finisce in
            # `veth_xmit` verso QUESTO peer, quindi un ring d'uscita piccolo
            # fa fallire il redirect e produce `persi_dopo`.
            raise_veth_ring(peer)
            attach_xdp(b, fn, peer)
            attached.append(peer)
        except Exception as e:
            warn(f"contatore non agganciato a {peer}: {e}")
    return b, b["rx_count"], attached


class Ingress:
    """Dove entra il traffico: quale device porta XDP, quale usa pktgen.

    Esiste perche' la risposta dipende da tre cose che prima erano decise in
    posti diversi dello stesso file: la topologia (un device condiviso o uno
    per thread), il numero di CPU per parte, e l'xmit_mode (netif_receive
    inietta NEL device che riceve, non nel suo peer).

    Campi:
      dut_devs   i device su cui si attacca il programma e su cui si mette la
                 NAPI in thread
      gen_devs   i device che pktgen usa per trasmettere
      ifindexes  gli ifindex da mappare sullo slot logico d'ingresso
      created    i link creati qui, da rimuovere alla fine
    """

    def __init__(self, dut_devs, gen_devs, ifindexes, created=0,
                 topology="shared"):
        self.dut_devs = list(dut_devs)
        self.gen_devs = list(gen_devs)
        self.ifindexes = list(ifindexes)
        self.created = created
        self.topology = topology

    def cleanup(self):
        if self.created:
            del_tg_links(self.created)


def build_ingress(fab, plan, topology="shared", rx_side=False):
    """Costruisce la parte d'ingresso del banco secondo il piano CPU.

    shared, piu' di un thread generatore: una coppia veth nuova, dimensionata
        cosi' -- code TX sul lato generatore = numero di thread pktgen; code RX
        sul lato DUT = almeno tante quante quelle (vincolo di veth_xdp_set) e
        comunque non meno delle CPU del DUT. Ne esce un solo ifindex
        d'ingresso, N code di generazione e M thread NAPI da pinnare: gen e DUT
        scalano SEPARATAMENTE, che e' il punto di tutta questa revisione.

    links: il comportamento storico, una coppia per thread.

    un thread solo: si usa l'ingresso del fabric, senza creare niente.

    `rx_side` (xmit_mode netif_receive) cambia il device che pktgen usa: si
    inietta nel percorso RX del device che riceve, non nel peer."""
    n_gen, n_dut = len(plan.gen), len(plan.dut)
    if n_gen <= 1 and topology == "shared":
        dut, gen_dev = fab.ingress, fab.ingress_peer
        return Ingress([dut], [dut if rx_side else gen_dev], [], 0, "shared")
    if topology == "links":
        made = make_tg_links(n_gen - 1, gen_queues=1, dut_queues=1)
        dut_devs = [fab.ingress] + [m[0] for m in made]
        gen_devs = ([fab.ingress] + [m[0] for m in made]) if rx_side else \
                   ([fab.ingress_peer] + [m[1] for m in made])
        return Ingress(dut_devs, gen_devs, [m[2] for m in made],
                       max(0, n_gen - 1), "links")
    rx, tx, idx = make_shared_tg_link(n_gen, max(n_dut, n_gen))
    info(f"ingresso condiviso {rx}: {n_gen} code TX per il generatore, "
         f"{max(n_dut, n_gen)} code RX sul DUT "
         f"(veth pretende rx(DUT) >= tx(peer))")
    return Ingress([rx], [rx if rx_side else tx], [idx], 1, "shared")


# ==========================================================================
# UN METODO ALLA VOLTA: sonda, misura, riassumi
# ==========================================================================
def run_method(method, model_path, frames, delays, count, out_rows,
               clone=0, threads=1, threshold=DEFAULT_LOSS_THRESHOLD,
               repeat=DEFAULT_REPEAT, burst=0, xmit_mode="start_xmit",
               threaded_napi=True, plan=None, topology="shared",
               diag_enabled=False, offered_pps=None, window_s=WINDOW_S,
               warmup_s=DEFAULT_WARMUP_S, tune=False, search="ladder"):
    from netns_fabric import NetnsFabric
    from common import attach_xdp

    plan = plan or plan_cpus(threads=threads)
    print(f"\n{YELLOW}{'=' * 78}{NC}")
    print(f"{YELLOW} {method} -- throughput end-to-end, TG e DUT sulla stessa "
          f"macchina ma su core diversi{NC}")
    print(f"{YELLOW}{'=' * 78}{NC}")

    sem, n_out = class_semantics()
    rc = 0
    with NetnsFabric(n_ports=len(sem.logical_ports), verbose=False) as fab:
        rx_side = (xmit_mode == "netif_receive")
        rx_b, rx_tab, attached = attach_rx_counter(fab)
        info(f"contatore RX su {len(attached)} peer d'uscita (XDP_DROP)")

        setup = build_pipeline(method, model_path, fab, sem)
        ing = build_ingress(fab, plan, topology, rx_side)
        # netif_receive injects at netif_receive_skb, which is PAST the native
        # XDP hook: veth's native program runs in veth_poll, earlier. Attaching
        # native and injecting there means no program runs at all -- neither
        # HIT nor MISS, which is exactly what the probe reported. The generic
        # hook is the one on that path, so that is where the program has to go.
        xdp_mode = "generic" if rx_side else None
        for dev in ing.dut_devs:
            attach_xdp(setup["b"], setup["disp"], dev, mode=xdp_mode)
        _map_extra_ingress(setup, ing.ifindexes)
        info(f"pipeline agganciata a {', '.join(ing.dut_devs)}")

        gen_devs = ing.gen_devs if ing.topology == "links" else ing.gen_devs[:1]
        gen = Generator(gen_devs, plan, xmit_mode=xmit_mode,
                        topology=ing.topology, clone=clone, burst=burst,
                        window_s=window_s, warmup_s=warmup_s).attach()

        # Separazione vera fra generatore e DUT: i thread NAPI che eseguono
        # l'inferenza vanno sulle CPU del DUT.
        #
        # SOLO gli ingressi. I peer d'uscita portano il contatore, che e'
        # strumentazione e non il DUT: lasciarli in softirq li fa girare sul
        # core che ha elaborato il pacchetto, come farebbe l'uscita di un nodo
        # vero. Metterli in thread su CPU proprie li ha messi in concorrenza
        # con l'inferenza sulle stesse CPU.
        napi_devs = []
        if threaded_napi and not rx_side:
            napi_devs = list(ing.dut_devs)
            placed = enable_threaded_napi(napi_devs, plan)
            if placed:
                where = ", ".join(
                    f"{d}({n} thread)->cpu{','.join(str(c) for c in cs)}"
                    for d, n, cs in placed)
                info(f"NAPI in thread, pinnata: {where}")
                info(f"pktgen su cpu {','.join(str(c) for c in plan.gen)}, "
                     f"inferenza su cpu {','.join(str(c) for c in plan.dut)}")
            else:
                napi_devs = []
                warn("nessun thread NAPI pinnato: generatore e pipeline "
                     "restano sullo stesso core, e le cifre misurano la somma")
        elif rx_side:
            warn("xmit_mode netif_receive: XDP gira in modo GENERIC e sulla "
                 "CPU del generatore -- niente separazione, e numeri non "
                 "confrontabili con gli altri run")

        diag = Diag(devs=ing.dut_devs + attached[:1], plan=plan,
                    enabled=diag_enabled)

        # -- sonda: un pacchetto solo, per sapere se stiamo misurando
        #    inferenza o XDP_PASS.
        probe = measure_point(setup, rx_tab, fab, 64, 0, 1, n_out, clone,
                              repeat=1, burst=burst, xmit_mode=xmit_mode,
                              gen=gen, warmup=False, threshold=threshold,
                              plan=plan, steady=False)
        if probe is None:
            # Il fabric viene ricostruito per ogni pipeline, quindi il device
            # d'ingresso ha lo STESSO NOME ma un altro ifindex. `ensure`
            # copre il caso in cui pktgen se ne sia dimenticato (il file in
            # procfs sparisce), non quello in cui se lo ricordi SBAGLIATO: li'
            # il file c'e', pktgen accetta i comandi e non trasmette niente.
            #
            # Costava un'intera pipeline: misurato il 2026-09-18, `template`
            # e' uscito dal run con "pktgen non riporta pacchetti" e il report
            # ha riportato 12 configurazioni invece di 15. Un riaggancio
            # completo e una seconda sonda costano un secondo.
            warn("la sonda non ha trasmesso nulla: riaggancio il generatore "
                 "e riprovo (il fabric e' stato ricostruito e pktgen puo' "
                 "tenersi un ifindex vecchio).")
            gen.detach()
            time.sleep(0.2)          # la rimozione in pktgen non e' sincrona
            gen.attach(verbose=False)
            probe = measure_point(setup, rx_tab, fab, 64, 0, 1, n_out, clone,
                                  repeat=1, burst=burst, xmit_mode=xmit_mode,
                                  gen=gen, warmup=False, threshold=threshold,
                                  plan=plan, steady=False)
        if probe is None:
            warn("la sonda non ha trasmesso nulla nemmeno dopo il riaggancio: "
                 "pktgen non e' partito.")
            gen.detach()
            ing.cleanup()
            return 1
        if probe["hit"] == 0 and method == "baseline":
            warn("la baseline non ha prodotto HIT: non legge model_id, quindi "
                 "il problema e' a monte (il pacchetto non arriva o mac_table "
                 "e' vuota). Mi fermo.")
            gen.detach()
            ing.cleanup()
            return 1
        if probe["hit"] == 0:
            warn(f"la sonda non ha prodotto nessun HIT "
                 f"(tx={probe['tx']} miss={probe['miss']}).")
            warn("Il dispatcher scarta i pacchetti: probabilmente il byte "
                 "model_id sul filo non e' ne' 0 ne' 190.")
            warn("Misurare adesso darebbe il costo di NON fare inferenza. "
                 "Mi fermo.")
            gen.detach()
            ing.cleanup()
            return 1
        ok(f"sonda: {probe['hit']} HIT su {probe['tx']} inviato -- si sta "
           f"misurando inferenza vera")

        # Il TETTO DEL GENERATORE, misurato una volta e stampato: e' la cifra
        # rispetto a cui va letto tutto il resto. Se un risultato ci arriva
        # vicino, il limite e' qui e non nella pipeline.
        # Una calibrazione fallita non deve costare l'intera pipeline: si
        # riparte da una stima di comodo e si dice che e' di comodo. Il primo
        # punto a pieno regime la corregge da solo (vedi find_saturation).
        try:
            if tune:
                # tune() calibra da sola e lascia sul generatore le manopole
                # che hanno davvero alzato il rate.
                gen.tune(frames[0] if frames else 64)
            else:
                gen.calibrate(frames[0] if frames else 64)
        except (PktgenEmptyRun, RuntimeError) as e:
            gen.rate_estimate = gen.rate_estimate or 1_000_000
            warn(f"calibrazione fallita ({e}): parto da "
                 f"{gen.rate_estimate} pps di comodo, il primo punto la "
                 f"corregge.")
        info(f"tetto del generatore su questo banco: {gen.rate_estimate} pps "
             f"offerti da {gen.n_inst} thread su cpu "
             f"{','.join(str(c) for c in plan.gen)}")

        hdr = (f"  {'frame':>5s} {'offerto':>9s} {'TX':>9s} {'HIT':>9s} "
               f"{'RX':>9s} {'RX pps':>9s} {'Mb/s':>8s} {'s':>5s} "
               f"{'perd.pegg':>9s} {'perd.med':>9s} {'collo':>18s}")
        print(f"\n{hdr}")
        print("  " + "-" * (len(hdr) - 2))
        print(f"  {GREY}offerto = trasmessi + rifiutati dal device (coda "
              f"d'ingresso piena); la perdita e' calcolata su quello. "
              f"`perd.pegg` e' la peggiore delle ripetizioni (lettura stretta "
              f"RFC 2544), `perd.med` la mediana: si riporta la prima, si "
              f"decide sulla seconda, ed e' la seconda a essere colorata.{NC}")

        def printer(r):
            deciso = _loss_decide(r)
            mark = GREEN if deciso <= threshold else (
                RED if deciso > 1 else YELLOW)
            spread = ""
            if r.get("repeat", 0) <= 1:
                # "+-0%" su un campione solo e' la dispersione di se stesso con
                # se stesso, e si legge come "perfettamente riproducibile".
                # Meglio dire che non c'e' dispersione perche' non c'e' un
                # secondo campione.
                spread = f" {YELLOW}(1 sola finestra, nessuna dispersione){NC}"
            elif r.get("spread_pct") is not None:
                col = RED if r.get("unreliable") else GREY
                flag = " INAFFIDABILE" if r.get("unreliable") else ""
                disp = r.get("spread_deciso_pct", r["spread_pct"])
                # Se le due dispersioni divergono si stampano entrambe: la
                # differenza fra loro E' l'informazione (quanto pesa la coda).
                due = (f"+-{disp:.0f}%" if abs(disp - r["spread_pct"]) < 1
                       else f"+-{disp:.0f}% (min-max {r['spread_pct']:.0f}%)")
                fuori = r.get("ripetizioni_anomale", 0)
                anom = f", {fuori} anomala/e" if fuori else ""
                spread = f" {col}(x{r['repeat']}, {due}{anom}{flag}){NC}"
            # A delay 0 non c'e' un rate richiesto: si stampa quello davvero
            # offerto (trasmessi + rifiutati, diviso la finestra), che e' la
            # cifra rispetto a cui va letta la perdita. Prima la colonna
            # stampava 0 su ogni riga a massima spinta.
            off = r.get("offered_pps") or r.get("offered_real_pps") or 0
            med = r.get("loss_med")
            print(f"  {r['frame']:5d} {off:9d} {r['tx']:9d} "
                  f"{r['hit']:9d} {r['rx']:9d} "
                  f"{r['rx_pps']:9d} {r['rx_mbps']:8.1f} {r['secs']:5.2f} "
                  f"{GREY}{r['loss_worst']:8.2f}%{NC} "
                  f"{mark}{(f'{med:8.2f}%' if med is not None else ' ' * 9)}"
                  f"{NC} {r.get('bottleneck', ''):>18s}{spread}")

        for frame in frames:
            if delays:
                # Sweep manuale: il chiamante ha chiesto rate precisi, e qui
                # vale --count come nella versione precedente. Le altre
                # modalita' derivano il conteggio dalla durata (--duration),
                # ma uno sweep esplicito e' anche una riproduzione di misure
                # vecchie, e quelle erano a numero di pacchetti fisso.
                for delay in delays:
                    r = measure_point(setup, rx_tab, fab, frame, delay,
                                      count,
                                      n_out, clone, repeat=repeat, burst=burst,
                                      xmit_mode=xmit_mode, gen=gen,
                                      threshold=threshold, plan=plan,
                                      diag=diag)
                    if r is None:
                        continue
                    r["clone_skb"], r["method"] = gen.clone, method
                    r["threads"] = gen.n_inst
                    out_rows.append(r)
                    printer(r)
            elif offered_pps:
                # Modalita' confronto: un rate solo, uguale per tutti.
                r = _point_at_rate(setup, rx_tab, fab, frame, offered_pps,
                                   n_out, gen, repeat, threshold, plan, diag,
                                   xmit_mode)
                if r is not None:
                    r["method"], r["phase"] = method, "confronto"
                    out_rows.append(r)
                    printer(r)
            elif search == "bisect":
                find_knee(setup, rx_tab, fab, frame, count, n_out, clone,
                          out_rows, method, printer, tg_devs=gen.names,
                          threads=gen.n_inst, threshold=threshold,
                          repeat=repeat, burst=burst, xmit_mode=xmit_mode,
                          gen=gen)
            else:
                find_saturation(setup, rx_tab, fab, frame, n_out, gen,
                                out_rows, method, printer, threshold, repeat,
                                plan, diag, xmit_mode)
            _summarise(method, frame, out_rows, threshold)

        if diag_enabled:
            # Una finestra in piu', FUORI dalle misure, solo per fotografare la
            # macchina: occupazione per core, contatori dei device, softnet, e
            # cosa ha consegnato ogni thread del generatore.
            diag.start()
            gen.timed_run(frames[0] if frames else 64, 0)
            diag.report(diag.stop())
            report_generator(gen)

        gen.detach()
        pg_reset()
        if napi_devs:
            disable_threaded_napi(napi_devs)
        for dev in ing.dut_devs:
            _detach(dev)
        ing.cleanup()
        for peer in attached:
            _detach(peer)
        del rx_b
    return rc


def _point_at_rate(setup, rx_tab, fab, frame, rate_pps, n_out, gen, repeat,
                   threshold, plan, diag, xmit_mode="start_xmit"):
    """Un punto a rate OFFERTO fissato, con la finestra di durata bersaglio.

    E' il mattone della modalita' confronto: il rate lo decide il chiamante e
    non la pipeline, quindi tutte le pipeline vedono lo stesso carico."""
    delay = gen.delay_for(rate_pps)
    count = gen.window_count(rate_pps)
    r = measure_point(setup, rx_tab, fab, frame, delay, count, n_out,
                      gen.clone, repeat=repeat, burst=gen.burst,
                      xmit_mode=xmit_mode, gen=gen, threshold=threshold,
                      plan=plan, diag=diag)
    if r is not None:
        r["offered_pps"] = rate_pps
        r["threads"] = gen.n_inst
        r["clone_skb"] = gen.clone
    return r


# ==========================================================================
# SATURAZIONE: salire per gradini, non bisecare
# ==========================================================================
def _loss_decide(row):
    """La perdita su cui si DECIDE se un rate e' pulito.

    Mediana delle ripetizioni quando ce ne sono almeno tre, altrimenti la
    peggiore -- che con una o due ripetizioni e' anche l'unica cosa onesta.
    Vedi measure_point per il perche' la mediana e non il massimo."""
    if row.get("repeat", 1) >= 3 and row.get("loss_med") is not None:
        return row["loss_med"]
    return row.get("loss_worst", row.get("loss_pct", 0.0))


def find_saturation(setup, rx_tab, fab, frame, n_out, gen, out_rows, method,
                    printer, threshold=DEFAULT_LOSS_THRESHOLD,
                    repeat=DEFAULT_REPEAT, plan=None, diag=None,
                    xmit_mode="start_xmit", ladder=SATURATE_LADDER):
    """Il rate piu' alto che questa pipeline regge, e di chi e' il limite.

    IL PROCEDIMENTO
      1. delay 0, massima spinta. Da' due cose: il rate CONSEGNATO (che e'
         gia' quasi la capacita': se se ne offrono 2,4 M e ne passano 1,4 M, la
         pipeline ne regge circa 1,4 M) e la perdita in sovraccarico.
      2. Se a massima spinta non si perde niente, la pipeline NON e' satura: il
         limite e' il generatore. Si dichiara e ci si ferma, perche' qualunque
         numero piu' basso sarebbe solo un rate piu' basso, non un limite.
      3. Altrimenti si sale sulla scala geometrica dei rate, ogni gradino
         confermato da `repeat` finestre con la perdita PEGGIORE.

    PERCHE' NON SI BISECA. La bisezione presuppone la monotonia: sotto il
    ginocchio pulito, sopra sporco. Misurato su questo banco, la sequenza reale
    e' stata 0.00% a 343 kpps, 0.58% a 356 k, 0.57% a 369 k, 0.20% a 400 k e
    0.43% a 600 k -- sparsa, gia' con worst-of-three applicato. Su una
    sequenza cosi' la bisezione converge su qualunque punto sia uscito pulito
    per caso e lo pubblica come throughput.

    Qui invece si misurano TUTTI i gradini e poi si applica una regola che la
    non monotonia non rompe: il risultato e' il rate piu' alto che sia pulito
    E che abbia puliti TUTTI i gradini sotto di se'.

    E SE ANCHE IL GRADINO PIU' BASSO PERDE, si SCENDE (vedi
    SATURATE_DESCENT) invece di concludere. Dire "la perdita non dipende dal
    rate" avendo provato solo dal 60% in su e' una conclusione che i dati non
    reggono: sotto c'e' un intervallo intero mai misurato. Si scende
    dimezzando finche' un gradino esce pulito, e quel gradino viene CONFERMATO
    da uno ancora piu' basso -- perche' un punto pulito isolato su una
    sequenza non monotona e' esattamente il punto fortunato che questo banco
    esiste per non pubblicare."""
    est_count = gen.window_count(gen.rate_estimate or 3_000_000)
    full = measure_point(setup, rx_tab, fab, frame, 0, est_count, n_out,
                         gen.clone, repeat=repeat, burst=gen.burst,
                         xmit_mode=xmit_mode, gen=gen, threshold=threshold,
                         plan=plan, diag=diag)
    # `Generator.timed_run` ricalibra una volta la finestra uscita corta, ma
    # QUESTO percorso non passa di li': il `count` glielo si da' gia' fatto,
    # calcolato su una stima che puo' essere vecchia o sbagliata. Senza il
    # controllo, una stima bassa produceva una finestra lunga un quarto del
    # bersaglio e un punto non confrontabile con gli altri. Stessa regola,
    # applicata dove mancava.
    if full is not None and 0 < full["secs"] < gen.window_s * WINDOW_SHORT_FRACTION:
        vero = full.get("tx_pps") or 0
        if vero > 0:
            note(f"frame {frame}: finestra uscita a {full['secs']:.2f}s invece "
                 f"di {gen.window_s:.2f}s (stima del rate troppo bassa: "
                 f"{gen.rate_estimate} contro {vero} misurati). Rifaccio il "
                 f"punto con il conteggio giusto.")
            gen.rate_estimate = max(gen.rate_estimate, vero)
            rifatto = measure_point(
                setup, rx_tab, fab, frame, 0, gen.window_count(vero), n_out,
                gen.clone, repeat=repeat, burst=gen.burst,
                xmit_mode=xmit_mode, gen=gen, threshold=threshold, plan=plan,
                diag=diag)
            if rifatto is not None:
                full = rifatto
    if full is None:
        warn(f"frame {frame}: nessuna misura utilizzabile a pieno rate")
        return None, None
    full.update(method=method, phase="pieno", delay=0, clone_skb=gen.clone,
                threads=gen.n_inst, offered_pps=None)
    gen.rate_estimate = max(gen.rate_estimate, full["tx_pps"])
    out_rows.append(full)
    printer(full)

    if _loss_decide(full) <= threshold:
        clean = dict(full)
        clean.update(phase="zero-perdite", gen_bound=1)
        out_rows.append(clean)
        print(f"  {GREY}a massima spinta non si perde niente: la pipeline non "
              f"e' satura e questo NON e' il suo massimo. Il tetto e' il "
              f"generatore ({full.get('offered_real_pps') or full['tx_pps']}"
              f" pps offerti da "
              f"{gen.n_inst} thread). Per alzarlo: piu' CPU al generatore "
              f"(--gen-cpus), o meno al DUT (--dut-cpus).{NC}")
        return full, clean

    base = float(full["rx_pps"])
    steps = []
    for frac in ladder:
        rate = base * frac
        if rate < 1000:
            continue
        r = measure_point(setup, rx_tab, fab, frame, gen.delay_for(rate),
                          gen.window_count(rate), n_out, gen.clone,
                          repeat=repeat, burst=gen.burst, xmit_mode=xmit_mode,
                          gen=gen, threshold=threshold, plan=plan, diag=diag)
        if r is None:
            continue
        r.update(method=method, phase="ricerca", clone_skb=gen.clone,
                 threads=gen.n_inst, offered_pps=int(rate))
        out_rows.append(r)
        printer(r)
        steps.append(r)
        # Due gradini sporchi di fila: si e' oltre il limite e continuare a
        # salire misura solo quanto si butta.
        if len(steps) >= 2 and all(_loss_decide(s) > threshold
                                   for s in steps[-2:]):
            break

    if not steps:
        return full, None
    steps.sort(key=lambda r: r["offered_pps"])
    best = None
    giu = []                    # i gradini della discesa, se si scende
    for s in steps:
        if _loss_decide(s) > threshold:
            break               # il primo sporco chiude la parte monotona
        best = s

    if best is None:
        # Il gradino piu' basso della scala perde. Prima di dichiarare rumore
        # si scende: la scala parte dal 60% del rate consegnato a pieno
        # regime, e sotto quel 60% non e' stato misurato niente.
        print(f"  {GREY}anche il gradino piu' basso perde "
              f"({steps[0]['offered_pps']} pps offerti, "
              f"{steps[0]['loss_worst']:.2f}%): scendo, invece di concludere "
              f"su un intervallo mai misurato.{NC}")
        for frac in SATURATE_DESCENT:
            rate = base * frac
            if rate < MIN_LADDER_PPS:
                print(f"  {GREY}discesa fermata a {int(rate)} pps: sotto "
                      f"{MIN_LADDER_PPS} pps la finestra non contiene "
                      f"abbastanza pacchetti perche' la perdita significhi "
                      f"qualcosa.{NC}")
                break
            r = measure_point(setup, rx_tab, fab, frame, gen.delay_for(rate),
                              gen.window_count(rate), n_out, gen.clone,
                              repeat=repeat, burst=gen.burst,
                              xmit_mode=xmit_mode, gen=gen,
                              threshold=threshold, plan=plan, diag=diag)
            if r is None:
                continue
            r.update(method=method, phase="ricerca", clone_skb=gen.clone,
                     threads=gen.n_inst, offered_pps=int(rate))
            out_rows.append(r)
            printer(r)
            giu.append(r)
            # Il primo pulito non basta: serve che sia pulito anche quello
            # SOTTO. Su una sequenza non monotona un singolo punto pulito e'
            # il punto fortunato, non un limite.
            if len(giu) >= 2 and _loss_decide(giu[-1]) <= threshold \
                    and _loss_decide(giu[-2]) <= threshold:
                best = giu[-2]
                break
        if best is None and giu:
            puliti = [r for r in giu if _loss_decide(r) <= threshold]
            if puliti:
                print(f"  {YELLOW}punto pulito isolato a "
                      f"{puliti[-1]['offered_pps']} pps, non confermato dal "
                      f"gradino sotto: non lo riporto come limite.{NC}")

    if best is None:
        giu_txt = ""
        piu_basso = min((r["offered_pps"] for r in giu), default=None)
        if piu_basso:
            giu_txt = (f" La discesa e' arrivata fino a {piu_basso} pps "
                       f"offerti, cioe' al {100.0 * piu_basso / base:.0f}% del "
                       f"rate consegnato a pieno regime, e perde anche li'.")
        print(f"  {RED}nessun rate a perdita nulla determinabile{NC}{GREY}: si "
              f"perde gia' al gradino piu' basso ({steps[0]['offered_pps']} "
              f"pps offerti, {steps[0]['loss_worst']:.2f}%), cioe' molto sotto "
              f"la capacita' misurata a pieno rate.{giu_txt} La perdita qui "
              f"non dipende dal rate: e' rumore della macchina.{NC}")
        noisy = dict(full)
        noisy.update(phase="rumore", gen_bound=0)
        tag, why = classify_bottleneck(noisy, threshold=threshold, plan=plan,
                                       noisy=True)
        noisy["bottleneck"], noisy["bottleneck_why"] = tag, why
        out_rows.append(noisy)
        return full, None
    clean = dict(best)
    clean.update(phase="zero-perdite", gen_bound=0)
    out_rows.append(clean)
    print(f"  {GREEN}limite senza perdite{NC}{GREY}: {clean['rx_pps']} pps "
          f"consegnati con {clean['offered_pps']} offerti, perdita "
          f"{clean['loss_worst']:.2f}% su {clean['repeat']} finestre. Il "
          f"gradino successivo perde: e' saturazione della pipeline, non del "
          f"generatore.{NC}")
    return full, clean


def find_knee(setup, rx_tab, fab, frame, count, n_out, clone, out_rows,
              method, printer, max_delay=20000, steps=6, tg_devs=None,
              threads=1, threshold=DEFAULT_LOSS_THRESHOLD,
              repeat=DEFAULT_REPEAT, burst=0, xmit_mode="start_xmit",
              gen=None):
    """Ricerca del ginocchio per bisezione sul ritardo (percorso storico).

    Tenuta perche' e' quella con cui sono state prese le misure precedenti e
    `--search bisect` deve poterle riprodurre. Il difetto e' noto ed e'
    documentato in find_saturation: la bisezione presuppone che la perdita
    cresca col rate, e su questo banco non e' vero. Il controllo `dirty_below`
    in fondo esiste per accorgersene DOPO; find_saturation se ne accorge prima.

    Returns (peak_row, clean_row_or_None)."""
    full = measure_point(setup, rx_tab, fab, frame, 0, count, n_out, clone,
                         tg_devs, repeat, burst, xmit_mode, gen=gen,
                         threshold=threshold)
    if full is None:
        warn(f"frame {frame}: nessuna misura utilizzabile a pieno rate")
        return None, None
    full["method"], full["clone_skb"], full["delay"] = method, clone, 0
    full["threads"] = threads
    out_rows.append(full)
    printer(full)

    if full["loss_worst"] <= threshold and clone == 0 and _CLONE_SUPPORTED:
        # Nothing lost at the generator's best effort. Before concluding that
        # the pipeline has headroom, PUSH HARDER: with clone_skb pktgen reuses
        # one buffer instead of allocating per packet, which removes the cost
        # that dominates it here and can multiply the offered rate.
        #
        # This is an escalation, not the default condition: clone_skb changes
        # what is measured, so the rows it produces carry clone_skb != 0 and
        # stay distinguishable.
        hard = measure_point(setup, rx_tab, fab, frame, 0, count, n_out,
                             ESCALATE_CLONE, tg_devs, repeat, burst,
                             xmit_mode, gen=gen, threshold=threshold)
        if hard is None:
            return full, full
        hard["method"], hard["clone_skb"], hard["delay"] = \
            method, ESCALATE_CLONE, 0
        hard["threads"] = threads
        out_rows.append(hard)
        printer(hard)
        if hard["loss_worst"] > threshold:
            print(f"  {GREY}con clone_skb={ESCALATE_CLONE} la pipeline perde: "
                  f"il ginocchio esiste, lo cerco{NC}")
            return find_knee(setup, rx_tab, fab, frame, count, n_out,
                             ESCALATE_CLONE, out_rows, method, printer,
                             max_delay, steps, tg_devs, threads,
                             threshold, repeat, burst, xmit_mode, gen)
        print(f"  {GREY}nemmeno con clone_skb={ESCALATE_CLONE}: su questa "
              f"macchina satura il generatore, non la pipeline{NC}")
        return (hard if hard["rx_pps"] > full["rx_pps"] else full), hard

    if full["loss_worst"] <= threshold:
        return full, full          # generator-bound: peak IS the no-loss rate

    lo, hi = 0, max_delay           # lo loses, hi is assumed clean
    best_clean = None
    for _ in range(steps):
        mid = (lo + hi) // 2
        if mid in (lo, hi):
            break
        r = measure_point(setup, rx_tab, fab, frame, mid, count, n_out,
                          clone, tg_devs, repeat, burst, xmit_mode, gen=gen,
                          threshold=threshold)
        if r is None:
            break
        r["method"], r["clone_skb"], r["threads"] = method, clone, threads
        out_rows.append(r)
        printer(r)
        if r["loss_worst"] <= threshold:
            best_clean = r if (best_clean is None or
                               r["rx_pps"] > best_clean["rx_pps"]) else best_clean
            hi = mid                # under threshold: try to go faster
        else:
            lo = mid                # still losing: slow down
    # Is the loss actually driven by the rate? If a point LOSES at a rate
    # lower than one that stayed clean, it is not.
    if best_clean is not None:
        dirty_below = [r for r in out_rows
                       if r.get("method") == method and r["frame"] == frame
                       and r["loss_worst"] > threshold
                       and r["rx_pps"] < best_clean["rx_pps"]]
        if dirty_below:
            worst = min(dirty_below, key=lambda r: r["rx_pps"])
            print(f"  {RED}la perdita non dipende dal rate{NC}{GREY}: "
                  f"{worst['loss_worst']:.2f}% a {worst['rx_pps']} pps, "
                  f"pulito a {best_clean['rx_pps']}. Sotto saturazione qui "
                  f"si perde per ragioni della macchina, non del datapath: "
                  f"un rate 'a perdita nulla' non e' determinabile.{NC}")
            best_clean = None
    return full, best_clean


def _summarise(method, frame, rows, threshold=DEFAULT_LOSS_THRESHOLD):
    """Tre numeri, perche' due nasconderebbero cio' che conta.

    The peak alone overstates a datapath. The peak plus a "no loss" figure is
    the usual pair -- but on a machine that drops the odd packet for reasons of
    its own, strict zero is a lottery. So: the peak, the fastest rate under the
    declared threshold, and whether ANY point was strictly lossless."""
    pts = [r for r in rows if r.get("method") == method
           and r["frame"] == frame and r.get("phase") != "rumore"]
    if not pts:
        return
    peak = max(pts, key=lambda r: r["rx_pps"])
    under = [r for r in pts if _loss_decide(r) <= threshold]
    strict = [r for r in pts if r["loss_worst"] == 0.0]
    best = max(under, key=lambda r: r["rx_pps"]) if under else None
    print(f"  {GREY}frame {frame}: massimo {peak['rx_pps']} pps "
          f"({peak['rx_mbps']} Mb/s, perdita {peak['loss_pct']}%)")
    # WHERE the loss happens decides what the number means. Measured here at
    # three generator cores: 8.5% lost with TX == HIT, i.e. the program saw and
    # processed every packet and the drops were all on the way OUT. Reporting
    # only the total would read as "the datapath loses 8.5%", which is the
    # opposite of what happened.
    # La distinzione che conta: un pacchetto RESPINTO da veth_xmit non e'
    # entrato nel DUT, quindi non e' una perdita della pipeline. Se tutta la
    # perdita e' li', la pipeline non ha buttato via niente e va detto -- e'
    # la differenza fra "il DUT perde il 20%" e "il DUT e' saturo e il
    # trasporto rifiuta il 20% del carico offerto".
    resp = peak.get("respinti", 0)
    dut = peak.get("persi_in_coda", 0) + peak.get("persi_dopo", 0)
    if resp or dut:
        if dut == 0:
            print(f"  {GREY}  la pipeline non ha perso NIENTE: "
                  f"{peak['rx']} ricevuti su {peak['hit']} elaborati su "
                  f"{peak['tx']} accettati. I {resp} mancanti "
                  f"({peak.get('respinti_pct', 0)}%) sono stati RESPINTI da "
                  f"veth_xmit a coda piena e non sono mai entrati nel DUT: "
                  f"e' backpressure, cioe' il DUT e' saturo, non che perda."
                  f"{NC}")
        else:
            print(f"  {GREY}  perdita del DUT: {dut} pacchetti "
                  f"({peak.get('loss_dut_pct', 0)}%) su "
                  f"{peak.get('persi_in_coda', 0)} mai arrivati al programma "
                  f"e {peak.get('persi_dopo', 0)} elaborati e non usciti. "
                  f"Altri {resp} respinti da veth_xmit prima di entrare."
                  f"{NC}")
    if peak["lost_before"] or peak["lost_after"]:
        if peak["lost_after"] > peak["lost_before"]:
            print(f"  {GREY}  la perdita e' DOPO l'inferenza: "
                  f"{peak['lost_after']} pacchetti elaborati e non usciti "
                  f"({peak['lost_before']} non erano nemmeno arrivati). "
                  f"A saturare e' l'uscita, non la pipeline.{NC}")
        else:
            print(f"  {GREY}  la perdita e' PRIMA dell'inferenza: "
                  f"{peak['lost_before']} pacchetti mai arrivati al programma "
                  f"({peak['lost_after']} elaborati e non usciti). "
                  f"A saturare e' l'ingresso.{NC}")
    # Stessa regola di find_saturation, e per lo stesso motivo. Un punto
    # pulito vale solo se e' CONFERMATO da cio' che sta sotto:
    #
    #   a) niente di piu' lento deve aver perso, e
    #   b) qualcosa di piu' lento deve essere stato misurato.
    #
    # La (b) mancava, e le due parti del programma si contraddicevano sullo
    # stesso punto: find_saturation rifiutava "74 397 pps, pulito isolato, non
    # confermato dal gradino sotto" e due righe piu' giu' _summarise lo
    # stampava come "sotto 0.1% di perdita: 68 576 pps". Il punto piu' lento
    # dell'intervallo provato e' sempre "pulito e senza niente sotto che
    # perda", perche' sotto non c'e' niente.
    if best and any(_loss_decide(r) > threshold
                    and r["rx_pps"] < best["rx_pps"] for r in pts):
        print(f"  {GREY}  nessun rate a perdita nulla determinabile: si perde "
              f"anche a rate piu' bassi di quelli puliti, quindi la perdita "
              f"sotto saturazione e' rumore della macchina{NC}")
        best = None
    elif best and not any(r["rx_pps"] > best["rx_pps"] for r in pts):
        # Pulito e in cima: e' un LIMITE INFERIORE dell'NDR, non un limite
        # mancato. Si riporta con il maggiore-uguale e si dice di chi e' il
        # tetto.
        print(f"  {GREY}  a perdita nulla: >= {best['rx_pps']} pps "
              f"({best['rx_mbps']} Mb/s). E' un limite INFERIORE: a massima "
              f"spinta non si e' perso niente, quindi la pipeline non e' "
              f"satura e il tetto e' il generatore.{NC}")
    elif best and not any(r["rx_pps"] < best["rx_pps"] for r in pts):
        print(f"  {GREY}  {best['rx_pps']} pps e' pulito ma e' il punto piu' "
              f"lento provato: non c'e' nessun gradino sotto a confermarlo, "
              f"quindi non lo riporto come limite a perdita nulla{NC}")
        best = None
    if best:
        print(f"  {GREY}  sotto {threshold}% di perdita: {best['rx_pps']} pps "
              f"({best['rx_mbps']} Mb/s, perdita {best['loss_pct']}%)")
        print(f"  {GREY}  collo di bottiglia: {best.get('bottleneck', 'n/d')} "
              f"-- {best.get('bottleneck_why', '')}{NC}")
    if strict and best:
        b0 = max(strict, key=lambda r: r["rx_pps"])
        print(f"  {GREY}  a perdita esattamente zero: {b0['rx_pps']} pps "
              f"({b0['rx_mbps']} Mb/s){NC}")
    else:
        print(f"  {GREY}  nessun punto a perdita esattamente zero{NC}")


# ==========================================================================
# MODALITA' CONFRONTO: stesso carico, stesse manopole, stessa durata
# ==========================================================================
# La modalita' saturate adatta il rate a ogni pipeline -- e' il suo scopo. Ma
# proprio per questo le sue righe NON sono un confronto: due pipeline misurate
# a rate diversi hanno visto due esperimenti diversi.
#
# Qui il rate e' UNO, deciso prima e congelato: ogni pipeline vede lo stesso
# carico offerto, la stessa dimensione di frame, la stessa durata e le stesse
# manopole del generatore. Cambia solo il programma XDP, che e' esattamente la
# variabile indipendente che si vuole isolare.
#
# Il rate comune, se non lo si passa con --offered-pps, e' il 90% del PIU'
# BASSO fra i rate consegnati a massima spinta dalle pipeline in gara. Sotto
# quel valore nessuna e' in sovraccarico per costruzione, quindi le differenze
# che restano sono di elaborazione e non di lunghezza delle code.


def run_compare(methods, model_path, frames, offered_pps=None,
                threads=1, threshold=DEFAULT_LOSS_THRESHOLD,
                repeat=DEFAULT_REPEAT, rounds=DEFAULT_ROUNDS, plan=None,
                topology="shared", xmit_mode="start_xmit",
                threaded_napi=True, diag_enabled=False, window_s=WINDOW_S,
                warmup_s=DEFAULT_WARMUP_S, clone=0, burst=0):
    """Tutte le pipeline, stesso fabric, stesso generatore, stesso rate."""
    from netns_fabric import NetnsFabric
    from common import attach_xdp
    import statistics as stats

    plan = plan or plan_cpus(threads=threads)
    sem, n_out = class_semantics()
    raw = []

    with NetnsFabric(n_ports=len(sem.logical_ports), verbose=False) as fab:
        rx_side = (xmit_mode == "netif_receive")
        rx_b, rx_tab, attached = attach_rx_counter(fab)
        info(f"contatore RX su {len(attached)} peer d'uscita (XDP_DROP)")

        print(f"\n{YELLOW}{'=' * 78}{NC}")
        print(f"{YELLOW} Fase 1: compilo e carico {len(methods)} pipeline "
              f"(nessuna misura in corso){NC}")
        print(f"{YELLOW}{'=' * 78}{NC}")
        loaded = {}
        for m in methods:
            try:
                loaded[m] = build_pipeline(m, model_path, fab, sem)
                info(f"{m}: caricata")
            except Exception as e:
                warn(f"{m}: non caricata, la salto -- {type(e).__name__}: {e}")
        if not loaded:
            warn("nessuna pipeline caricata")
            return [], []

        ing = build_ingress(fab, plan, topology, rx_side)
        xdp_mode = "generic" if rx_side else None
        for setup in loaded.values():
            _map_extra_ingress(setup, ing.ifindexes)
        gen_devs = ing.gen_devs if ing.topology == "links" else ing.gen_devs[:1]
        gen = Generator(gen_devs, plan, xmit_mode=xmit_mode,
                        topology=ing.topology, clone=clone, burst=burst,
                        window_s=window_s, warmup_s=warmup_s).attach()
        diag = Diag(devs=ing.dut_devs, plan=plan, enabled=diag_enabled)

        def use(method):
            """Metti QUESTA pipeline sull'ingresso. attach_xdp sostituisce il
            programma senza staccare: staccare smonterebbe la NAPI e con lei
            il modo a thread, cioe' la separazione fra le CPU."""
            setup = loaded[method]
            with _quiet():
                for dev in ing.dut_devs:
                    attach_xdp(setup["b"], setup["disp"], dev, mode=xdp_mode)
            return setup

        # Il primo attach crea la NAPI: solo dopo si puo' metterla in thread.
        use(next(iter(loaded)))
        napi_devs = []
        if threaded_napi and not rx_side:
            napi_devs = list(ing.dut_devs)
            placed = enable_threaded_napi(napi_devs, plan)
            if placed:
                where = ", ".join(
                    f"{d}({n} thread)->cpu{','.join(str(c) for c in cs)}"
                    for d, n, cs in placed)
                info(f"NAPI in thread, pinnata: {where}")
            else:
                napi_devs = []
                warn("nessun thread NAPI pinnato: generatore e pipeline "
                     "restano sullo stesso core")

        # --- sonda per pipeline: si misura inferenza o XDP_PASS?
        alive = []
        for m in list(loaded):
            setup = use(m)
            p = measure_point(setup, rx_tab, fab, 64, 0, 1, n_out, gen.clone,
                              repeat=1, burst=gen.burst, xmit_mode=xmit_mode,
                              gen=gen, warmup=False, threshold=threshold,
                              plan=plan, steady=False)
            if p is None or p["hit"] == 0:
                warn(f"{m}: la sonda non produce HIT -- la escludo dal "
                     f"confronto invece di misurarle il costo di non fare "
                     f"inferenza")
                continue
            alive.append(m)
        if not alive:
            warn("nessuna pipeline ha superato la sonda")
            gen.detach()
            ing.cleanup()
            return [], []

        # --- DUE FASI per pipeline, a ogni giro, perche' rispondono a due
        #     domande diverse:
        #
        #   saturazione  delay 0. Il DUT e' in sovraccarico (respinti > 0) e
        #                l'RX e' la sua CAPACITA' su questo percorso: e' la
        #                fase che separa le pipeline, perche' chi fa piu'
        #                lavoro per pacchetto ne consegna meno.
        #   confronto    lo stesso rate offerto a tutte, sotto la capacita'
        #                del piu' lento. Se nessuna perde, l'RX e' uguale per
        #                costruzione e la fase dice "tutte reggono questo
        #                carico"; se qualcuna perde, lo dice riga per riga.
        #
        # Prima c'era solo la seconda, con il rate al 90% di UNA finestra a
        # massima spinta e la nota "sotto questo carico nessuna pipeline e' in
        # sovraccarico" stampata senza controllarla. Misurato il 2026-09-23:
        # hardcoded a 1 831 777 pps offerti, respinti fra l'11 e il 30% in
        # tutti e tre i giri -- la nota era falsa, e la tabella attribuiva "al
        # programma XDP" differenze che erano della coda d'ingresso.
        frame0 = frames[0] if frames else 64
        full_count = gen.window_count(gen.rate_estimate or 3_000_000)
        if not offered_pps:
            print(f"\n{YELLOW} Calibrazione del rate comune (una volta, poi "
                  f"congelato){NC}")
            delivered = {}
            for m in alive:
                setup = use(m)
                r = measure_point(setup, rx_tab, fab, frame0, 0, full_count,
                                  n_out, gen.clone, repeat=1,
                                  burst=gen.burst, xmit_mode=xmit_mode,
                                  gen=gen, threshold=threshold, plan=plan)
                if r is not None:
                    delivered[m] = r["rx_pps"]
                    info(f"{m}: {r['rx_pps']} pps consegnati a massima spinta "
                         f"(respinti {r.get('respinti_pct', 0.0):.2f}%)")
            if not delivered:
                warn("calibrazione fallita: nessun rate consegnato")
                gen.detach()
                ing.cleanup()
                return [], []
            slowest = min(delivered, key=delivered.get)
            offered_pps = int(0.9 * delivered[slowest])
            note(f"rate comune = 90% di quanto il piu' lento ({slowest}) ha "
                 f"consegnato in UNA finestra a massima spinta: {offered_pps} "
                 f"pps. Che a questo carico nessuna perda non e' assunto: lo "
                 f"verifica la fase `confronto`.")

        phases = (("saturazione", 0), ("confronto", offered_pps))
        print(f"\n{YELLOW}{'=' * 78}{NC}")
        print(f"{YELLOW} Fase 2: {rounds} giri x {len(alive)} pipeline x 2 "
              f"(massima spinta; {offered_pps} pps offerti), frame "
              f"{frames}{NC}")
        print(f"{YELLOW}{'=' * 78}{NC}")
        hdr = (f"  {'giro':>4s} {'pipeline':10s} {'frame':>5s} "
               f"{'fase':11s} {'chiesto':>9s} {'offerti':>9s} "
               f"{'RX pps':>9s} {'resp':>7s} {'dopo':>7s} {'perdita':>8s} "
               f"{'collo':>18s}")
        print(hdr)
        print("  " + "-" * (len(hdr) - 2))
        for rnd in range(1, rounds + 1):
            for m in alive:
                setup = use(m)
                for frame in frames:
                    for phase, rate in phases:
                        if rate:
                            r = _point_at_rate(setup, rx_tab, fab, frame, rate,
                                               n_out, gen, repeat, threshold,
                                               plan, diag, xmit_mode)
                        else:
                            r = measure_point(setup, rx_tab, fab, frame, 0,
                                              full_count, n_out, gen.clone,
                                              repeat=repeat, burst=gen.burst,
                                              xmit_mode=xmit_mode, gen=gen,
                                              threshold=threshold, plan=plan,
                                              diag=diag)
                            if r is not None:
                                r.update(offered_pps=None, threads=gen.n_inst,
                                         clone_skb=gen.clone)
                        if r is None:
                            continue
                        r.update(method=m, round=rnd, phase=phase)
                        raw.append(r)
                        if rate:
                            mark = GREEN if r["loss_worst"] <= threshold else (
                                RED if r["loss_worst"] > 1 else YELLOW)
                        else:
                            mark = ""       # a massima spinta si perde apposta
                        print(f"  {rnd:4d} {m:10s} {frame:5d} {phase:11s} "
                              f"{(str(rate) if rate else 'max'):>9s} "
                              f"{r.get('offered_real_pps', 0):9d} "
                              f"{r['rx_pps']:9d} "
                              f"{r.get('respinti_pct', 0.0):6.2f}% "
                              f"{r.get('loss_dut_pct', 0.0):6.2f}% "
                              f"{mark}{r['loss_worst']:7.2f}%"
                              f"{NC if mark else ''} "
                              f"{r.get('bottleneck', ''):>18s}")

        if diag_enabled:
            diag.start()
            gen.timed_run(frame0, gen.delay_for(offered_pps))
            diag.report(diag.stop())
            report_generator(gen)

        gen.detach()
        pg_reset()
        if napi_devs:
            disable_threaded_napi(napi_devs)
        for dev in ing.dut_devs:
            _detach(dev)
        ing.cleanup()
        for peer in attached:
            _detach(peer)
        del rx_b

    # --- riepilogo: mediana fra i giri
    summary = []
    if raw:
        print(f"\n{YELLOW}{'=' * 78}{NC}")
        print(f"{YELLOW} Riepilogo confronto: mediana fra i giri, per "
              f"pipeline e fase{NC}")
        print(f"{YELLOW}{'=' * 78}{NC}")
        hdr = (f"  {'pipeline':10s} {'frame':>5s} {'fase':11s} {'giri':>4s} "
               f"{'offerti':>9s} {'RX pps':>9s} {'min':>9s} {'max':>9s} "
               f"{'resp':>7s} {'dopo':>7s} {'perdita':>8s} {'collo':>18s}")
        print(hdr)
        print("  " + "-" * (len(hdr) - 2))
        ordine = {m: i for i, m in enumerate((RX_ONLY,) + tuple(METHODS))}
        ordine_fase = {"saturazione": 0, "confronto": 1}
        keys = sorted({(r["method"], r["frame"], r["phase"]) for r in raw},
                      key=lambda k: (ordine.get(k[0], 99), k[1],
                                     ordine_fase.get(k[2], 9)))
        for m, frame, phase in keys:
            pts = [r for r in raw if (r["method"], r["frame"], r["phase"])
                   == (m, frame, phase)]
            pps = [r["rx_pps"] for r in pts]
            a = _agg(pps)
            loss = stats.median([r["loss_worst"] for r in pts])
            tags = [r.get("bottleneck") for r in pts if r.get("bottleneck")]
            tag = max(set(tags), key=tags.count) if tags else BN_UNKNOWN
            spread = (100.0 * (a["max"] - a["min"]) / a["min"]) if a["min"] else 0
            row = dict(method=m, frame=frame, phase=phase,
                       rounds=len(pts),
                       offered_pps=(offered_pps if phase == "confronto"
                                    else None),
                       offered_real_pps=int(stats.median(
                           [r.get("offered_real_pps", 0) for r in pts])),
                       rx_pps=int(stats.median(pps)), rx_pps_mean=a["mean"],
                       rx_pps_min=a["min"], rx_pps_max=a["max"],
                       rx_pps_std=a["std"], rx_pps_cv_pct=a["cv_pct"],
                       loss_pct=round(loss, 3),
                       # La PEGGIORE delle perdite fra i giri, non la mediana:
                       # e' la convenzione usata ovunque altrove nel banco, e
                       # un giro pulito su tre non e' un rate pulito.
                       loss_worst=round(max(r["loss_worst"] for r in pts), 3),
                       respinti_pct=round(stats.median(
                           [r.get("respinti_pct", 0.0) for r in pts]), 3),
                       loss_dut_pct=round(stats.median(
                           [r.get("loss_dut_pct", 0.0) for r in pts]), 3),
                       # I conteggi, non solo i rate: "quanti pacchetti sono
                       # arrivati" e' una domanda a cui un pps non risponde,
                       # e senza offerti/persi la perdita non e' verificabile
                       # a mano dal CSV.
                       rx=int(stats.median([r["rx"] for r in pts])),
                       tx=int(stats.median([r["tx"] for r in pts])),
                       offered_tx=int(stats.median([r["offered_tx"]
                                                    for r in pts])),
                       lost_before=int(stats.median([r["lost_before"]
                                                     for r in pts])),
                       lost_after=int(stats.median([r["lost_after"]
                                                    for r in pts])),
                       rx_mbps=round(stats.median([r["rx_mbps"]
                                                   for r in pts]), 2),
                       secs=round(stats.median([r["secs"] for r in pts]), 3),
                       window_mode=pts[0].get("window_mode", "count"),
                       pps_spread_pct=round(spread, 1),
                       unreliable=spread > MAX_SPREAD_PCT,
                       threads=len(plan.gen), bottleneck=tag)
            summary.append(row)
            flag = f" {RED}+-{spread:.0f}%{NC}" if row["unreliable"] else ""
            print(f"  {m:10s} {frame:5d} {phase:11s} {len(pts):4d} "
                  f"{row['offered_real_pps']:9d} "
                  f"{row['rx_pps']:9d} {a['min']:9d} {a['max']:9d} "
                  f"{row['respinti_pct']:6.2f}% {row['loss_dut_pct']:6.2f}% "
                  f"{row['loss_pct']:7.2f}% {tag:>18s}{flag}")
        _compare_verdict(summary, offered_pps, threshold)
    return raw, summary


# I FAIL di _rxonly_verdict. Lista propria, non VERDICT: check_validity, che
# gira dopo, svuota VERDICT per primo. main() li riaggiunge dopo di lui.
RXONLY_FAILS = []


def _rxonly_verdict(sat, cmp_, threshold):
    """Le pipeline rispetto al tetto di sola ricezione misurato INSIEME a loro.

    Per taglia di frame: quota del tetto, costo per pacchetto sopra il tetto
    (1/RX - 1/RX_rxonly), e il controllo che il contatore -- che fa
    strettamente meno lavoro di tutte -- non consegni meno della baseline."""
    RXONLY_FAILS.clear()
    for frame in sorted({r["frame"] for r in sat}):
        top = next((r for r in sat if r["frame"] == frame
                    and r["method"] == RX_ONLY), None)
        if top is None or not top["rx_pps"]:
            continue
        cap = top["rx_pps"]
        print(f"\n  {YELLOW}Rispetto al tetto di sola ricezione ({RX_ONLY}, "
              f"{frame}B, stessa sessione): {cap} pps{NC}")
        for r in sat:
            if r["frame"] != frame or r["method"] == RX_ONLY or not r["rx_pps"]:
                continue
            extra = 1e9 / r["rx_pps"] - 1e9 / cap
            print(f"    {r['method']:10s} {r['rx_pps']:9d} pps  "
                  f"{100.0 * r['rx_pps'] / cap:5.1f}% del tetto  "
                  f"{extra:+7.1f} ns/pacchetto")
        base = next((r for r in sat if r["frame"] == frame
                     and r["method"] == "baseline"), None)
        if base is not None and base["rx_pps"] > cap * (1 + VALID_TOL):
            RXONLY_FAILS.append(("FAIL", f"{frame}B: {RX_ONLY} {cap} pps "
                                         f"sotto la baseline "
                                         f"{base['rx_pps']}: la sessione "
                                         f"misura la macchina"))
            print(f"  {RED}[FAIL]{NC} {RX_ONLY} ({cap}) consegna meno della "
                  f"baseline ({base['rx_pps']}) oltre il {VALID_TOL:.0%}: fa "
                  f"strettamente meno lavoro, quindi la sessione misura la "
                  f"macchina, non i programmi.")
        elif base is not None and base["rx_pps"] > cap:
            print(f"  {GREY}La baseline supera {RX_ONLY} entro il "
                  f"{VALID_TOL:.0%}: indistinguibili, cioe' il redirect e il "
                  f"veth d'uscita non si vedono nel throughput.{NC}")
    cont = [r for r in cmp_ if r["method"] == RX_ONLY
            and r["respinti_pct"] > threshold]
    for r in cont:
        note(f"fase confronto -- anche {RX_ONLY} respinge il "
             f"{r['respinti_pct']:.2f}% a questo rate ({r['frame']}B): una "
             f"parte dei respinti sotto capacita' e' del trasporto (coda del "
             f"veth, risveglio del thread NAPI), non delle pipeline. La parte "
             f"delle pipeline e' quella SOPRA questa cifra.")


def _compare_verdict(summary, offered_pps, threshold):
    """Che cosa si puo' dire della tabella, deciso sui numeri e non scritto
    prima di averli.

    Sostituisce due frasi che il banco stampava SEMPRE: "sotto questo carico
    nessuna pipeline e' in sovraccarico" e "le differenze in questa tabella
    sono del programma XDP". Il 2026-09-23 erano false tutte e due."""
    sat = [r for r in summary if r["phase"] == "saturazione"]
    cmp_ = [r for r in summary if r["phase"] == "confronto"]
    _rxonly_verdict(sat, cmp_, threshold)
    if sat:
        piene = [r for r in sat if r["respinti_pct"] > threshold]
        vuote = [r for r in sat if r["respinti_pct"] <= threshold]
        if piene:
            note("fase saturazione -- respinti > 0 su: "
                 + ", ".join(f"{r['method']}/{r['frame']}B" for r in piene)
                 + ". La coda d'ingresso trabocca, quindi il DUT e' in "
                   "sovraccarico e l'RX e' la sua capacita' su questo "
                   "percorso veth: fra queste righe le differenze di RX "
                   "oltre la dispersione fra i giri sono di costo per "
                   "pacchetto.")
        if vuote:
            warn("fase saturazione -- nessun respinto su: "
                 + ", ".join(f"{r['method']}/{r['frame']}B" for r in vuote)
                 + ". Il DUT non e' saturo nemmeno a massima spinta: l'RX e' "
                   "quanto il generatore ha offerto, non la capacita' della "
                   "pipeline.")
    if cmp_:
        corti = [r for r in cmp_ if r["offered_real_pps"] < 0.9 * offered_pps]
        sporchi = [r for r in cmp_ if r["loss_worst"] > threshold]
        if corti:
            warn(f"fase confronto -- il generatore non ha offerto i "
                 f"{offered_pps} pps chiesti a: "
                 + ", ".join(f"{r['method']}/{r['frame']}B "
                             f"({r['offered_real_pps']})" for r in corti)
                 + ". Per queste righe il carico non e' identico.")
        if sporchi:
            warn(f"fase confronto -- a {offered_pps} pps offerti si perde: "
                 + "; ".join(f"{r['method']}/{r['frame']}B respinti "
                             f"{r['respinti_pct']:.2f}%, dopo l'ingresso "
                             f"{r['loss_dut_pct']:.2f}%" for r in sporchi)
                 + ". Il rate comune NON e' sotto la capacita' di tutte, "
                   "oppure la coda d'ingresso trabocca per il tempo di "
                   "risveglio del thread NAPI e non per il lavoro della "
                   "pipeline: in entrambi i casi le differenze di RX in "
                   "questa fase non sono del programma XDP.")
        elif not corti:
            note(f"fase confronto -- a {offered_pps} pps offerti nessuna "
                 f"pipeline perde piu' del {threshold}%: tutte reggono questo "
                 f"carico, e l'RX e' uguale per costruzione. Il confronto di "
                 f"capacita' e' nella fase saturazione.")


# ==========================================================================
# Il verdetto dell'ultimo check_validity, in chiaro. Esiste perche' il report
# markdown e' la cosa che si cita, e un report che non dice "questo run e'
# stato bocciato" e' peggio di nessun report: i CSV almeno nessuno li legge
# senza contesto. Lista di coppie (esito, motivo), riempita da check_validity.
VERDICT = []


# ==========================================================================
# RATE SWEEP: dove il sistema smette di stare dietro, e chi dei tre e' il collo
# ==========================================================================
# La domanda a cui questa modalita' risponde NON e' "quanti Mpps fa la
# pipeline". A massima spinta il generatore e il veth sono saturi, e il numero
# che esce descrive loro. La domanda e': fino a che rate offerto TX, HIT e RX
# restano allineati?
#
# Sotto quel rate il sistema non perde, e le tre latenze descrivono il
# percorso vero. Sopra, il massimo osservato non e' un throughput di pipeline:
# e' il tetto del banco, e va detto invece che citato.
DEFAULT_RATES_MPPS = (0.1, 0.2, 0.4, 0.6, 0.8, 1.0, 1.2, 1.5, 2.0)


def _sane(st):
    """Le tre statistiche in forma stampabile, anche quando mancano."""
    if not st:
        return dict(n=0, min=None, p50=None, p90=None, p99=None)
    return dict(n=st["n"], min=st["lat_min_ns"], p50=st["lat_p50_ns"],
                p90=st["lat_p90_ns"], p99=st["lat_p99_ns"])


def _median(vals):
    import statistics as _s
    vals = [v for v in vals if v is not None]
    return _s.median(vals) if vals else None


def run_rates(methods, model_path, frame=64, rates=None, rounds=DEFAULT_ROUNDS,
              threads=1, plan=None, threaded_napi=True,
              xmit_mode="start_xmit", threshold=DEFAULT_LOSS_THRESHOLD,
              window_s=WINDOW_S, warmup_s=DEFAULT_WARMUP_S,
              topology="shared", clone=0, burst=0):
    """Tutte le pipeline, stesso fabric e stesso generatore, a rate crescente.

    Usa le build STRUMENTATE: sono le uniche che portano T1, T2 e T3, quindi i
    numeri di throughput qui sono un limite INFERIORE di quelli di produzione.
    Il confronto fra pipeline resta valido perche' tutte pagano la stessa
    strumentazione.
    """
    from netns_fabric import NetnsFabric
    from common import attach_xdp

    plan = plan or plan_cpus(threads=threads)
    sem, n_out = class_semantics()
    rates = list(rates or [int(r * 1e6) for r in DEFAULT_RATES_MPPS])
    raw = []

    with NetnsFabric(n_ports=len(sem.logical_ports), verbose=False) as fab:
        print(f"\n{YELLOW}{'=' * 78}{NC}")
        print(f"{YELLOW} Fase 1: compilo e carico le pipeline strumentate "
              f"(nessuna misura in corso){NC}")
        print(f"{YELLOW}{'=' * 78}{NC}")
        loaded, lat_fns = {}, {}
        for m in methods:
            try:
                setup, lat_fn = _load_instrumented(m, model_path, fab, sem)
                loaded[m], lat_fns[m] = setup, lat_fn
                info(f"{m}: caricata (T1, T2, T3)")
            except Exception as e:
                warn(f"{m}: non caricata, la salto -- {type(e).__name__}: {e}")
        if not loaded:
            warn("nessuna pipeline caricata")
            return []

        ing = build_ingress(fab, plan, topology, False)
        for setup in loaded.values():
            _map_extra_ingress(setup, ing.ifindexes)
        gen_devs = ing.gen_devs if ing.topology == "links" else ing.gen_devs[:1]
        gen = Generator(gen_devs, plan, xmit_mode=xmit_mode,
                        topology=ing.topology, clone=clone, burst=burst,
                        window_s=window_s, warmup_s=warmup_s).attach()

        def use(method):
            """Questa pipeline sull'ingresso, e il SUO contatore sulle uscite.

            attach_xdp sostituisce senza staccare: staccare smonterebbe la
            NAPI e con lei il modo a thread, cioe' la separazione fra le CPU
            che rende comparabili i punti."""
            setup = loaded[method]
            with _quiet():
                for peer in fab.peer_of.values():
                    attach_xdp(setup["b"], lat_fns[method], peer)
                for dev in ing.dut_devs:
                    attach_xdp(setup["b"], setup["disp"], dev)
            return setup

        use(next(iter(loaded)))
        napi_devs = []
        if threaded_napi:
            napi_devs = list(ing.dut_devs)
            if enable_threaded_napi(napi_devs, plan):
                info("NAPI in thread: generatore e DUT su core separati")
            else:
                napi_devs = []
                warn("nessun thread NAPI pinnato: generatore e pipeline "
                     "restano sullo stesso core")

        # sonda: una pipeline che non fa HIT non sta facendo inferenza
        alive = []
        for m in list(loaded):
            setup = use(m)
            _zero_counters(setup, setup["b"]["rx_n"], n_out)
            _clear_lat(setup["b"])
            try:
                gen.run(frame, 1000, gen.delay_for(100_000))
            except PktgenEmptyRun:
                pass
            time.sleep(DRAIN_S)
            if _read_u64(setup["pkt_stats"], 0) == 0:
                warn(f"{m}: la sonda non produce HIT -- la escludo invece di "
                     f"misurarle il costo di non fare inferenza")
                continue
            alive.append(m)
        if not alive:
            warn("nessuna pipeline ha superato la sonda")
            gen.detach(); ing.cleanup()
            return []

        print(f"\n{YELLOW} Fase 2: sweep -- {len(rates)} rate x "
              f"{len(alive)} pipeline x {rounds} round, frame {frame} B{NC}")
        hdr = (f"  {'rate':>8s} {'pipeline':11s} {'TX':>9s} {'HIT':>9s} "
               f"{'RX':>9s} {'TX-HIT':>8s} {'HIT-RX':>8s} {'resp':>7s} "
               f"{'dopo':>8s} {'totale':>8s} "
               f"{'pipe':>7s} {'e2e':>7s} {'xport':>7s}")
        print(f"\n{hdr}")
        print("  " + "-" * (len(hdr) - 2))

        for rnd in range(rounds):
            # Ordine alternato: se una pipeline soffrisse solo per essere
            # sempre la prima (cache fredda) o sempre l'ultima (macchina
            # scaldata), invertendo l'ordine la differenza si vede.
            seq = alive if rnd % 2 == 0 else list(reversed(alive))
            for rate in rates:
                delay = gen.delay_for(rate)
                cnt = gen.window_count(rate)
                for m in seq:
                    setup = use(m)
                    b = setup["b"]
                    gen.warmup(frame, delay)
                    time.sleep(DRAIN_S)
                    _zero_counters(setup, b["rx_n"], n_out)
                    _clear_lat(b)
                    try:
                        if gen.window_mode == "steady":
                            run = gen.steady(frame, delay, lambda: dict(
                                hit=_read_u64(setup["pkt_stats"], 0),
                                rx=sum(int(v) for v in
                                       b["rx_n"][ct.c_int(0)])))
                        else:
                            run = gen.run(frame, cnt, delay)
                    except PktgenEmptyRun as e:
                        warn(f"rate {rate/1e6:.2f} Mpps {m}: punto scartato "
                             f"-- {e}")
                        continue
                    time.sleep(DRAIN_S)

                    tx = run[0]
                    errors = getattr(run, "errors", 0)
                    secs = (getattr(run, "window", 0.0) or run[2]) or 1e-9
                    # Hanno consegnato TUTTE le istanze del generatore? Il
                    # conteggio chiesto e' esatto e pktgen manda esattamente
                    # quello, quindi un TX inferiore vuol dire che un thread
                    # non ha lavorato -- non che la pipeline abbia perso.
                    #
                    # Misurato: `template` a 0,5 Mpps con TX 25 019 su 150 000
                    # chiesti e' uscito con il 46% di "perdita del DUT". Quei
                    # pacchetti alla pipeline non sono mai stati offerti.
                    # WINDOW_MIN_TX_FRACTION copre lo stesso caso ma vive in
                    # _measure_once, e questo percorso non ci passa.
                    atteso_tx = cnt * gen.n_inst
                    if not run.steady and tx < atteso_tx:
                        warn(f"rate {rate/1e6:.2f} Mpps {m}: punto scartato "
                             f"-- {tx} trasmessi su {atteso_tx} chiesti "
                             f"({100.0 * tx / atteso_tx:.0f}%), cioe' una o "
                             f"piu' istanze del generatore non hanno "
                             f"consegnato. Cio' che manca non e' stato offerto "
                             f"alla pipeline, quindi non e' una sua perdita.")
                        continue
                    st = _read_lat_all(b)
                    if run.steady:
                        hit, rx = run.dut["hit"], run.dut["rx"]
                    else:
                        hit = _read_u64(setup["pkt_stats"], 0)
                        rx = st["rx"]
                    offered = tx + errors
                    persi_coda = max(0, tx - hit)
                    persi_dopo = max(0, hit - rx)
                    # HIT > TX: il DUT ha elaborato piu' di quanto il
                    # generatore dichiari per questa finestra. Non e' una
                    # perdita negativa da tagliare a zero, e' la coda della
                    # finestra PRECEDENTE che non aveva finito di atterrare:
                    # DRAIN_S non basta a questo rate. La riga resta, marcata.
                    residui = max(0, hit - tx)
                    if run.steady and residui <= STEADY_INFLIGHT:
                        # a finestra stazionaria, HIT - TX piccolo e' la coda
                        # in volo alle due letture, non la finestra prima
                        residui = 0
                    loss = (round(100.0 * (persi_coda + persi_dopo) / offered, 3)
                            if offered else 0.0)
                    # La perdita TOTALE, respinti compresi: e' quella su cui
                    # si decide il rate sostenibile (vedi _report_rates).
                    loss_tot = (round(100.0 * (errors + persi_coda + persi_dopo)
                                      / offered, 3) if offered else 0.0)
                    resp = (round(100.0 * errors / offered, 3)
                            if offered else 0.0)
                    row = dict(
                        round=rnd, method=m, frame=frame,
                        rate_req_pps=rate, delay_ns=delay, secs=round(secs, 3),
                        tx=tx, hit=hit, rx=rx, gen_errors=errors,
                        offered_tx=offered, tx_minus_hit=persi_coda,
                        hit_minus_rx=persi_dopo, respinti_pct=resp,
                        loss_dut_pct=loss, loss_tot_pct=loss_tot,
                        window_mode="steady" if run.steady else "count",
                        residui_finestra=residui,
                        rx_pps=int(rx / secs), tx_pps=int(tx / secs),
                        rx_mbps=round(rx * frame * 8 / secs / 1e6, 2),
                        samples=st["pipe"]["n"] if st["pipe"] else 0)
                    for nome in ("pipe", "e2e", "xport"):
                        v = _sane(st[nome])
                        row[f"{nome}_min_ns"] = v["min"]
                        row[f"{nome}_p50_ns"] = v["p50"]
                        row[f"{nome}_p90_ns"] = v["p90"]
                        row[f"{nome}_p99_ns"] = v["p99"]
                        row[f"{nome}_n"] = v["n"]
                    raw.append(row)

                    if residui:
                        warn(f"rate {rate/1e6:.2f} Mpps {m}: HIT ({hit}) > TX "
                             f"({tx}) di {residui} pacchetti -- residui della "
                             f"finestra precedente, il drenaggio non basta a "
                             f"questo rate. La riga non e' confrontabile con "
                             f"le altre.")
                    mark = (GREEN if loss_tot <= threshold else
                            (RED if loss_tot > 1 else YELLOW))
                    print(f"  {rate/1e6:7.2f}M {m:11s} {tx:9d} {hit:9d} "
                          f"{rx:9d} {persi_coda:8d} {persi_dopo:8d} "
                          f"{resp:6.2f}% {loss:7.3f}% "
                          f"{mark}{loss_tot:7.3f}%{NC} "
                          f"{_fmt_ns(row['pipe_min_ns']):>7s} "
                          f"{_fmt_ns(row['e2e_min_ns']):>7s} "
                          f"{_fmt_ns(row['xport_min_ns']):>7s}")

        gen.detach()
        pg_reset()
        if napi_devs:
            disable_threaded_napi(napi_devs)
        ing.cleanup()

    _report_rates(raw, threshold)
    return raw


def _report_rates(raw, threshold=DEFAULT_LOSS_THRESHOLD):
    """Mediana fra i round, e il rate sostenibile per ciascuna pipeline."""
    if not raw:
        return
    per = {}
    for r in raw:
        per.setdefault((r["method"], r["rate_req_pps"]), []).append(r)

    print(f"\n{YELLOW}{'=' * 78}{NC}")
    print(f"{YELLOW} Mediana fra i round{NC}")
    print(f"{YELLOW}{'=' * 78}{NC}")
    hdr = (f"  {'chiesto':>8s} {'ottenuto':>9s} {'resa':>6s} {'pipeline':11s} "
           f"{'dopo':>8s} {'totale':>8s} {'pipe T2-T1':>11s} {'e2e T3-T1':>10s} "
           f"{'xport T3-T2':>12s} {'round':>6s}")
    print(f"\n{hdr}")
    print("  " + "-" * (len(hdr) - 2))

    # sostenibile[m] = (rate OTTENUTO, rate chiesto) del punto piu' alto senza
    # perdita. Si tiene l'ottenuto perche' e' l'unico dei due che il DUT ha
    # davvero visto.
    #
    # La perdita su cui si decide e' quella TOTALE, respinti compresi. Prima
    # era solo quella "dopo l'ingresso" (TX-HIT + HIT-RX), e un rate con il 20%
    # di respinti usciva sostenibile a perdita zero. Ma un respinto e' un
    # pacchetto che il nodo non ha preso perche' la sua coda d'ingresso era
    # piena: a quel rate il nodo NON regge, qualunque sia il motivo per cui la
    # coda non si svuota (costo della pipeline o risveglio del thread NAPI).
    # La perdita dopo l'ingresso resta in tabella, perche' e' lei a dire se la
    # pipeline butta via qualcosa che ha ricevuto.
    sostenibile, sost_dopo, offerto_gen, ottenuti = {}, {}, {}, {}
    for (m, rate) in sorted(per, key=lambda k: (k[0], k[1])):
        rs = per[(m, rate)]
        loss_dopo = _median([x["loss_dut_pct"] for x in rs])
        loss = _median([x.get("loss_tot_pct", x["loss_dut_pct"]) for x in rs])
        rxp = _median([x["rx_pps"] for x in rs]) or 0
        pipe = _median([x["pipe_min_ns"] for x in rs])
        e2e = _median([x["e2e_min_ns"] for x in rs])
        xp = _median([x["xport_min_ns"] for x in rs])
        resa = 100.0 * rxp / rate if rate else 0.0
        ok = loss is not None and loss <= threshold
        if ok and rxp > sostenibile.get(m, (0, 0))[0]:
            sostenibile[m] = (int(rxp), rate)
        if (loss_dopo is not None and loss_dopo <= threshold
                and rxp > sost_dopo.get(m, (0, 0))[0]):
            sost_dopo[m] = (int(rxp), rate)
        # Quanto il GENERATORE ha offerto (TX + respinti) rispetto al
        # chiesto: e' questo, non la resa, a dire se il carico e' partito.
        # Una resa bassa con l'offerto pieno sono respinti, cioe' il nodo.
        offp = _median([x["offered_tx"] / x["secs"] for x in rs
                        if x.get("secs")]) or 0
        offerto_gen.setdefault(m, {})[rate] = (100.0 * offp / rate
                                               if rate else 0.0)
        ottenuti.setdefault(m, []).append((rate, rxp))
        mark = GREEN if ok else RED
        rmark = GREEN if resa >= 90 else (YELLOW if resa >= 70 else RED)
        print(f"  {rate/1e6:7.2f}M {int(rxp)/1e6:8.2f}M "
              f"{rmark}{resa:5.0f}%{NC} {m:11s} "
              f"{loss_dopo if loss_dopo is not None else 0:7.3f}% "
              f"{mark}{loss if loss is not None else 0:7.3f}%{NC} "
              f"{_fmt_ns(pipe):>11s} {_fmt_ns(e2e):>10s} "
              f"{_fmt_ns(xp):>12s} {len(rs):6d}")

    print(f"\n{YELLOW} Throughput SOSTENIBILE -- rate OTTENUTO, non quello "
          f"chiesto (respinti + persi <= {threshold}% dell'offerto){NC}")
    print("  " + "-" * 68)
    metodi = sorted({r["method"] for r in raw})
    for m in metodi:
        v = sostenibile.get(m)
        if v:
            print(f"    {m:11s} {GREEN}>= {v[0]/1e6:.2f} Mpps{NC}  "
                  f"{GREY}(al punto chiesto {v[1]/1e6:.2f} Mpps){NC}")
        else:
            print(f"    {m:11s} {RED}nessun rate provato e' sostenibile{NC} "
                  f"{GREY}(gia' il piu' basso perde: abbassa --rates){NC}")
        d = sost_dopo.get(m)
        if d and (not v or d[0] > v[0]):
            print(f"    {'':11s} {GREY}contando solo la perdita DOPO "
                  f"l'ingresso sarebbe >= {d[0]/1e6:.2f} Mpps: la differenza "
                  f"sono respinti a coda d'ingresso piena, cioe' carico che il "
                  f"nodo non ha preso.{NC}")

    # La resa: quanto di cio' che si e' chiesto e' davvero arrivato. Se resta
    # bassa a OGNI rate, compreso il piu' basso, allora il tetto e' del
    # generatore e nessun punto di questo sweep ha messo il DUT sotto sforzo.
    # Il consegnato cresce col chiesto? Se no, non e' una funzione del carico
    # offerto: e' rumore del generatore, e allora il `sostenibile` qui sopra e'
    # il massimo fra punti rumorosi, cioe' il piu' fortunato dei sei.
    non_mono = []
    for m, coppie in ottenuti.items():
        v = [rx for _, rx in sorted(coppie)]
        if len(v) > 1 and not all(v[i] <= v[i + 1] for i in range(len(v) - 1)):
            non_mono.append(m)
    if non_mono:
        warn(f"il rate CONSEGNATO non cresce col rate chiesto su: "
             f"{', '.join(sorted(non_mono))}. Non e' quindi una funzione del "
             f"carico offerto ma rumore del generatore, e il `sostenibile` "
             f"qui sopra e' il massimo fra punti rumorosi -- il piu' "
             f"fortunato, non una soglia. Vale come \"il DUT ha retto almeno "
             f"questo\", non come capacita' misurata.")

    # Il generatore non ha offerto nemmeno il rate PIU' BASSO? Prima questo
    # avviso guardava la resa minima su TUTTI i rate -- quindi scattava
    # appena un rate alto veniva respinto, e diceva "nemmeno al rate piu'
    # basso" di un rate basso consegnato al 100% -- e attribuiva al
    # generatore anche i respinti, che sono del nodo.
    corti = {}
    for m, per_rate in offerto_gen.items():
        low = min(per_rate)
        if per_rate[low] < 90.0:
            corti[m] = (low, per_rate[low])
    if corti:
        warn("il generatore non ha offerto nemmeno il rate piu' basso a: "
             + ", ".join(f"{m} ({v:.0f}% di {low/1e6:.2f} Mpps)"
                         for m, (low, v) in sorted(corti.items()))
             + ". Per queste il tetto dello sweep e' il GENERATORE: i numeri "
               "dicono che il nodo regge almeno quel carico, non dove si "
               "romperebbe.")
    top = max((r["rate_req_pps"] for r in raw), default=0)
    if sostenibile and all(v[1] >= top for v in sostenibile.values()):
        warn(f"nessuna pipeline ha perso un pacchetto nemmeno al rate piu' "
             f"alto provato ({top/1e6:.2f} Mpps chiesti): il ginocchio non e' "
             f"stato raggiunto e ogni cifra di sostenibile e' un LIMITE "
             f"INFERIORE. Alza --rates, o aggiungi thread al generatore.")
    print(f"\n  {GREY}`chiesto` e' il rate offerto a pktgen, `ottenuto` "
          f"quello davvero consegnato, `resa` il rapporto fra i due. Una resa "
          f"bassa ha due cause che le righe grezze separano: carico che il "
          f"generatore non ha offerto (offered_tx sotto il chiesto), o "
          f"pacchetti che il nodo ha respinto a coda piena (resp).{NC}")
    print(f"  {GREY}Il massimo Mpps osservato NON e' il throughput della "
          f"pipeline se TX > HIT o HIT > RX: in quella zona il numero "
          f"descrive il generatore o il veth. La riga da citare e' il "
          f"sostenibile, e va letto come un >=.{NC}")
    print(f"  {GREY}pipe = T2-T1, la pipeline sul percorso reale. "
          f"e2e = T3-T1. xport = T3-T2, cioe' redirect + veth + NAPI. "
          f"Sono MINIMI: la mediana fra i round sta nella colonna, i "
          f"percentili nel CSV.{NC}")
    print(f"  {GREY}Build STRUMENTATA: due bpf_ktime_get_ns e due scritture "
          f"per pacchetto che il datapath di produzione non fa.{NC}")


# ==========================================================================
# MODALITA' GENERATOR: il tetto del banco, misurato senza il banco sotto test
# ==========================================================================
# E' un CONTROLLO, non una misura del datapath. Risponde a una domanda sola:
#
#     quanti pacchetti al secondo riesce davvero a consegnare
#     pktgen -> veth -> lato DUT, su questa macchina?
#
# Serve a leggere `--mode rates`. Li' nessuna pipeline ha mai perso un
# pacchetto fino a 4 Mpps CHIESTI, ma il consegnato si fermava fra 1,3 e 1,8
# Mpps: senza questo controllo non si puo' dire se quel tetto sia del
# generatore o delle pipeline. Qui le pipeline non ci sono proprio, quindi
# tutto cio' che resta e' generatore e veth.
#
# ISOLAMENTO. Non si costruisce il NetnsFabric, non si compila nessuna
# pipeline, non si registra nessun modello, non si scrive nessuna mac_table.
# Si crea la sola coppia veth d'ingresso e le si attacca un contatore di nove
# istruzioni. Il percorso misurato e' percio' un SOTTOINSIEME stretto di
# quello di `--mode rates`: qualunque pipeline vi aggiunge lavoro, mai lo
# toglie, quindi questo numero e' un limite SUPERIORE per tutte.
#
# IL NOME, corretto dopo il primo run vero. Non e' il tetto del GENERATORE:
# e' il tetto del PERCORSO DI RICEZIONE -- veth RX, NAPI su un core, e il
# consumatore piu' economico possibile.
#
# La differenza non e' terminologica, la dice la misura. Senza nessuna
# pipeline, `resp` -- cioe' `veth_xmit` che risponde NET_XMIT_DROP perche' il
# ring RX del peer e' pieno -- e' restato fra il 29 e il 49%. Ricostruendo
# l'offerto (TX + respinti) pktgen metteva sul filo ~5,5 Mpps e il ricevitore
# ne accettava ~3,4: il mittente aveva margine, il ricevitore no.
#
# Chiamarlo "generator ceiling" avrebbe attribuito al generatore un limite che
# e' del lato che riceve, ed e' esattamente l'errore di attribuzione che
# questa modalita' esiste per non fare. Il risultato NON e' "il throughput
# della pipeline", NON e' "il throughput della macchina", e NON e' "quanto
# sa generare pktgen": e' quanto questo percorso di ricezione sa assorbire.

# Il contatore: incrementa e basta. Il verdetto `%(action)s` e' l'unica cosa
# che cambia fra le due varianti.
GEN_COUNTER_SRC = """
#include <uapi/linux/bpf.h>
BPF_PERCPU_ARRAY(gen_rx, __u64, 1);
int xdp_gen_count(struct xdp_md *ctx) {
    int k = 0;
    __u64 *v = gen_rx.lookup(&k);
    if (v) *v += 1;
    return %(action)s;
}
"""

# Perche' il default e' XDP_DROP e non XDP_PASS.
#
# XDP_PASS consegna il pacchetto allo STACK DI RETE: allocazione dell'skb,
# netif_receive_skb, e da li' in su. E' lavoro che nel percorso vero non c'e'
# -- in `--mode rates` il pacchetto viene rediretto, mai passato allo stack --
# e costa piu' dell'inferenza di qualunque pipeline. Misurare il tetto con
# XDP_PASS darebbe quindi un numero PIU' BASSO di quello che le pipeline
# vedono, cioe' un "limite superiore" sotto ai valori che dovrebbe limitare:
# inutilizzabile come controllo.
#
# XDP_DROP libera il pacchetto subito ed e' la stessa scelta gia' fatta per
# attach_rx_counter, per la stessa ragione. Chi vuole comunque misurare col
# passaggio allo stack ha `--rx-action pass`, e sa che sta misurando un'altra
# cosa.
GEN_RX_ACTIONS = ("drop", "pass")


def _pct(a, b):
    return (100.0 * a / b) if b else 0.0


def run_generator(frame=64, rates=None, rounds=DEFAULT_ROUNDS, threads=1,
                  plan=None, threaded_napi=True, xmit_mode="start_xmit",
                  window_s=WINDOW_S, warmup_s=DEFAULT_WARMUP_S,
                  threshold=DEFAULT_LOSS_THRESHOLD, clone=0, burst=0,
                  rx_action="drop"):
    """pktgen -> veth -> contatore. Nessuna pipeline, nessuna inferenza."""
    from bcc import BPF
    from common import attach_xdp

    plan = plan or plan_cpus(threads=threads)
    rates = list(rates or [int(r * 1e6) for r in DEFAULT_RATES_MPPS])
    verdict = "XDP_DROP" if rx_action == "drop" else "XDP_PASS"

    print(f"\n{YELLOW}{'=' * 78}{NC}")
    print(f"{YELLOW} RECEIVE-PATH CEILING TEST{NC}")
    print(f"{YELLOW}{'=' * 78}{NC}")
    info("generator mode: NESSUNA pipeline DUT caricata")
    info(f"ricevitore: solo contatore RX minimale ({verdict})")
    info("percorso misurato: pktgen -> veth -> contatore RX")
    if rx_action == "pass":
        warn("--rx-action pass: il pacchetto va allo STACK DI RETE, che nel "
             "percorso vero non viene mai attraversato. Il tetto che ne esce "
             "e' piu' basso di quello che le pipeline vedono, e non e' un "
             "limite superiore per loro.")

    n_gen, n_dut = len(plan.gen), len(plan.dut)
    rx_dev, tx_dev, _ = make_shared_tg_link(n_gen, max(n_dut, n_gen))
    info(f"coppia veth {rx_dev} (lato DUT, porta il contatore) <- {tx_dev} "
         f"(lato generatore)")

    b = BPF(text=GEN_COUNTER_SRC % {"action": verdict})
    fn = b.load_func("xdp_gen_count", BPF.XDP)
    napi_devs, raw = [], []
    try:
        attach_xdp(b, fn, rx_dev)
        info(f"contatore agganciato a {rx_dev}: il conteggio avviene "
             f"ALL'INGRESSO del lato DUT, nello stesso punto in cui "
             f"`--mode rates` mette il dispatcher della pipeline")
        if threaded_napi:
            napi_devs = [rx_dev]
            if enable_threaded_napi(napi_devs, plan):
                info("NAPI in thread: generatore e ricevitore su core separati")
            else:
                napi_devs = []
                warn("nessun thread NAPI pinnato: generatore e ricevitore "
                     "restano sullo stesso core")

        gen = Generator([tx_dev], plan, xmit_mode=xmit_mode,
                        topology="shared", clone=clone, burst=burst,
                        window_s=window_s, warmup_s=warmup_s).attach()

        hdr = (f"  {'giro':>4s} {'target':>9s} {'TX':>10s} {'RX':>10s} "
               f"{'offerti':>8s} {'TX Mpps':>8s} {'RX Mpps':>8s} "
               f"{'resa':>6s} {'loss':>7s} {'resp':>7s} {'stato':>26s}")
        print(f"\n{hdr}")
        print("  " + "-" * (len(hdr) - 2))

        for rnd in range(1, rounds + 1):
            for rate in rates:
                delay = gen.delay_for(rate)
                cnt = gen.window_count(rate)
                # DUE aspettative, e servono tutte e due.
                #
                #   nominale  quanti ne implica il TARGET nella finestra
                #             bersaglio. E' il numero rispetto a cui ha senso
                #             chiedersi se il generatore ha tenuto il passo.
                #   chiesto   quanti se ne sono davvero ordinati a pktgen,
                #             cioe' il nominale dopo il clamp di
                #             window_count a MAX_WINDOW_PKTS.
                #
                # Confondere i due e' stato il difetto: `resa` girava sul
                # CHIESTO, e pktgen manda esattamente quello, quindi usciva
                # 100% a ogni target sopra MAX_WINDOW_PKTS / window_s
                # (13,3 Mpps con i valori di default). A 100 Mpps chiesti e
                # 3,4 consegnati la riga diceva "OK, resa 100%".
                expected_nominale = int(rate * gen.window_s)
                expected_chiesto = cnt * gen.n_inst
                # Il punto e' stato troncato dal clamp? Allora la finestra non
                # e' quella bersaglio, e va detto sulla riga.
                # A finestra stazionaria il count non decide la durata: il
                # clamp non tronca niente.
                capped = (gen.window_mode != "steady"
                          and expected_chiesto < expected_nominale)
                gen.warmup(frame, delay)
                time.sleep(DRAIN_S)
                b["gen_rx"].clear()
                try:
                    if gen.window_mode == "steady":
                        run = gen.steady(frame, delay, lambda t=b["gen_rx"]: {
                            "rx": _percpu_sum(t)})
                    else:
                        run = gen.run(frame, cnt, delay)
                except PktgenEmptyRun as e:
                    warn(f"giro {rnd} target {rate/1e6:.2f} Mpps: punto "
                         f"scartato -- {e}")
                    continue
                time.sleep(DRAIN_S)

                tx = run[0]
                errors = getattr(run, "errors", 0)
                secs = (getattr(run, "window", 0.0) or run[2]) or 1e-9
                # Hanno consegnato TUTTE le istanze? In questa modalita' il
                # conteggio chiesto e' esatto e pktgen manda esattamente
                # quello, quindi un TX inferiore vuol dire che un thread
                # generatore non ha lavorato. La finestra che ne esce e'
                # corta, i rate che se ne ricavano sono un conteggio diviso
                # un intervallo sbagliato, e la perdita che ne segue e' della
                # strumentazione -- non del percorso.
                if not run.steady and tx < expected_chiesto:
                    warn(f"giro {rnd} target {rate/1e6:.2f} Mpps: punto "
                         f"scartato -- {tx} trasmessi su {expected_chiesto} "
                         f"chiesti ({100.0 * tx / expected_chiesto:.0f}%), "
                         f"cioe' {gen.n_inst - round(gen.n_inst * tx / expected_chiesto)}"
                         f" istanza/e del generatore non ha consegnato. La "
                         f"finestra ({secs:.3f}s) non descrive questo rate.")
                    continue
                rx = run.dut["rx"] if run.steady else _percpu_sum(b["gen_rx"])
                tx_mpps = tx / secs / 1e6
                rx_mpps = rx / secs / 1e6
                # Quanto il generatore metteva DAVVERO sul filo: i trasmessi
                # piu' quelli che `veth_xmit` ha respinto perche' il ring RX
                # del peer era pieno. E' la cifra che dice se a fermarsi sia
                # stato il mittente o il ricevitore, e senza di essa `resp`
                # resta una percentuale che nessuno converte.
                offerti_mpps = (tx + errors) / secs / 1e6
                # La resa si calcola sui RATE, non sui conteggi: e' l'unica
                # forma indipendente dalla durata della finestra. Sotto il
                # clamp i due modi coincidono; sopra, la finestra si allunga
                # (4 milioni di pacchetti a 3,4 Mpps durano 1,18 s invece di
                # 0,3) e solo il rapporto fra i rate resta interpretabile.
                target_mpps = rate / 1e6
                resa = 100.0 * tx_mpps / target_mpps if target_mpps else 0.0
                loss = _pct(max(0, tx - rx), tx)
                resp = _pct(errors, tx + errors)

                # Lo stato dice DOVE si e' fermato, e i due lati si guardano
                # separati. La resa (TX/target) non basta: TX sono i pacchetti
                # ACCETTATI, quindi una resa bassa puo' essere il generatore
                # che non offre il target oppure il ricevitore che respinge.
                # Prima una resa bassa si chiamava sempre
                # "GENERATOR_BACKPRESSURE": misurato il 2026-09-23 a 4 Mpps di
                # target, 4,005 offerti e 3,58 accettati -- il generatore
                # seguiva il target, a respingere era il ricevitore.
                #
                #   GEN_LIMIT        offerti (TX + respinti) sotto il target
                #   RX_BACKPRESSURE  respinti oltre soglia: coda RX piena
                #   RX_LOSS          accettati e non contati
                gen_resa = 100.0 * offerti_mpps / target_mpps if target_mpps else 0.0
                cause = []
                if loss > threshold:
                    cause.append("RX_LOSS")
                if resp > threshold:
                    cause.append("RX_BACKPRESSURE")
                if gen_resa < 99.0:
                    cause.append("GEN_LIMIT")
                if capped:
                    cause.append("CAP_WINDOW")
                stato = "+".join(cause) or "OK"
                col = (RED if "RX_LOSS" in cause else
                       YELLOW if cause else GREEN)

                raw.append(dict(
                    mode="generator", rate_target_mpps=round(rate / 1e6, 3),
                    round=rnd, frames=frame, window_s=round(secs, 4),
                    TX=tx, RX=rx, tx_mpps=round(tx_mpps, 4),
                    rx_mpps=round(rx_mpps, 4),
                    offered_mpps=round(offerti_mpps, 4),
                    expected_packets=expected_nominale,
                    expected_chiesto=expected_chiesto,
                    window_capped=int(capped),
                    tx_achievement=round(resa / 100.0, 4),
                    gen_achievement=round(gen_resa / 100.0, 4),
                    loss_percent=round(loss, 4),
                    resp_percent=round(resp, 4), gen_errors=errors,
                    threads=gen.n_inst,
                    cpu_generator=",".join(str(c) for c in plan.gen),
                    cpu_dut=",".join(str(c) for c in plan.dut),
                    timestamp=time.strftime("%Y-%m-%d %H:%M:%S"),
                    commit=_cmd_line(["git", "-C", SHARED_DIR, "rev-parse",
                                      "--short", "HEAD"]),
                    rx_action=verdict, status=stato))
                # L'asterisco sul target segnala la finestra troncata: la
                # riga resta leggibile, ma non ha offerto il target per la
                # durata bersaglio.
                segno = "*" if capped else " "
                print(f"  {rnd:4d} {rate/1e6:7.2f}M{segno} {tx:10d} {rx:10d} "
                      f"{offerti_mpps:8.3f} {tx_mpps:8.3f} {rx_mpps:8.3f} "
                      f"{resa:5.0f}% {loss:6.2f}% {resp:6.2f}% "
                      f"{col}{stato:>26s}{NC}")

        gen.detach()
        pg_reset()
    finally:
        if napi_devs:
            disable_threaded_napi(napi_devs)
        _detach(rx_dev)
        del_tg_links(1)
        del b

    _report_generator(raw, rates, threshold)
    return raw


def _report_generator(raw, rates, threshold=DEFAULT_LOSS_THRESHOLD):
    """Mediane per target, il tetto osservato, e cosa NON dice."""
    if not raw:
        warn("nessun punto misurato")
        return
    print(f"\n{YELLOW}{'=' * 78}{NC}")
    print(f"{YELLOW} Receive-path ceiling summary{NC}")
    print(f"{YELLOW}{'=' * 78}{NC}")
    hdr = (f"  {'target':>8s} {'offerti':>9s} {'TX Mpps':>9s} "
           f"{'RX Mpps':>9s} {'min RX':>8s} {'max RX':>8s} "
           f"{'TX/target':>10s} {'loss':>7s} {'giri':>5s}")
    print(f"\n{hdr}")
    print("  " + "-" * (len(hdr) - 2))

    per_rate = {}
    for r in raw:
        per_rate.setdefault(r["rate_target_mpps"], []).append(r)

    best_rx = best_tx = 0.0
    best_rx_at = best_tx_at = None
    for t in sorted(per_rate):
        rs = per_rate[t]
        rxs = [x["rx_mpps"] for x in rs]
        txm = _median([x["tx_mpps"] for x in rs]) or 0.0
        offm = _median([x.get("offered_mpps") for x in rs]) or 0.0
        rxm = _median(rxs) or 0.0
        resa = _median([x["tx_achievement"] for x in rs]) or 0.0
        loss = _median([x["loss_percent"] for x in rs]) or 0.0
        if rxm > best_rx:
            best_rx, best_rx_at = rxm, t
        if txm > best_tx:
            best_tx, best_tx_at = txm, t
        rmark = GREEN if resa >= 0.99 else (YELLOW if resa >= 0.7 else RED)
        lmark = GREEN if loss <= threshold else RED
        print(f"  {t:7.2f}M {offm:9.3f} {txm:9.3f} {rxm:9.3f} "
              f"{min(rxs):8.3f} {max(rxs):8.3f} "
              f"{rmark}{resa * 100:9.0f}%{NC} "
              f"{lmark}{loss:6.2f}%{NC} {len(rs):5d}")

    print(f"\n  {YELLOW}Maximum achieved RX rate: {best_rx:.2f} Mpps{NC} "
          f"{GREY}(al target {best_rx_at:.2f} Mpps){NC}")
    print(f"  {YELLOW}Maximum achieved TX rate: {best_tx:.2f} Mpps{NC} "
          f"{GREY}(al target {best_tx_at:.2f} Mpps){NC}")
    print(f"  {GREY}E' il massimo OSSERVATO in questo test, non il limite "
          f"assoluto della macchina: fuori da questo intervallo di target "
          f"non e' stato misurato niente.{NC}")

    # Il tetto e' stato raggiunto? Lo dice l'ultimo target provato.
    top = max(per_rate)
    rs = per_rate[top]
    resa_top = _median([x["tx_achievement"] for x in rs]) or 0.0
    loss_top = _median([x["loss_percent"] for x in rs]) or 0.0
    top_capped = any(x.get("window_capped") for x in rs)
    print("")
    if top_capped:
        # Il target piu' alto e' stato troncato da MAX_WINDOW_PKTS: la
        # finestra e' durata piu' del bersaglio e il target non e' stato
        # offerto per intero. La resa sui rate resta valida -- ed e' quella
        # stampata -- ma "ceiling raggiunto o no" su questo punto non si
        # decide, e dirlo sarebbe concludere da una misura troncata.
        n_cap = sum(1 for t in per_rate
                    if any(x.get("window_capped") for x in per_rate[t]))
        warn(f"il target piu' alto ({top:.2f} Mpps) e' stato TRONCATO dal "
             f"tetto di {MAX_WINDOW_PKTS} pacchetti per finestra "
             f"(MAX_WINDOW_PKTS): sopra "
             f"{MAX_WINDOW_PKTS / WINDOW_S / 1e6:.2f} Mpps di target il banco "
             f"chiede sempre lo stesso numero di pacchetti e la finestra si "
             f"allunga. {n_cap} target su {len(per_rate)} sono in questa "
             f"condizione (marcati `*`).")
        print(f"  {GREY}La resa stampata resta valida -- e' il rapporto fra i "
              f"RATE, che non dipende dalla durata della finestra -- ma su un "
              f"punto troncato non si puo' dire se il tetto sia stato "
              f"raggiunto: quel target non e' mai stato offerto per la "
              f"durata bersaglio. Per provarlo davvero alza --duration, "
              f"oppure resta sotto "
              f"{MAX_WINDOW_PKTS / WINDOW_S / 1e6:.2f} Mpps di target.{NC}")
    elif resa_top >= 0.99 and loss_top <= threshold:
        warn(f"receive-path ceiling not reached; highest tested target "
             f"({top:.2f} Mpps) is still achievable. Increase --rates to "
             f"determine a higher ceiling.")
    else:
        off_top = _median([x.get("gen_achievement", 0.0) for x in rs]) or 0.0
        resp_top = _median([x.get("resp_percent", 0.0) for x in rs]) or 0.0
        dove = []
        if loss_top > threshold:
            dove.append("perdita sul lato RX")
        if resp_top > threshold:
            dove.append(f"il ricevitore respinge il {resp_top:.1f}% "
                        f"dell'offerto (coda RX piena)")
        if off_top < 0.99:
            dove.append(f"il generatore offre solo il {off_top * 100:.0f}% "
                        f"del target")
        print(f"  {GREEN}Saturazione osservata{NC}: al target piu' alto "
              f"({top:.2f} Mpps) la resa e' {resa_top * 100:.0f}% e la perdita "
              f"{loss_top:.2f}% -- {'; '.join(dove) or 'causa non isolata'}.")
        # Dove comincia ciascuno dei due limiti: il ricevitore che respinge,
        # e il generatore che non offre piu' il target. Sono due soglie
        # diverse, e confonderle e' l'errore corretto qui sopra.
        primo_rx = next((t for t in sorted(per_rate)
                         if (_median([x.get("resp_percent", 0.0)
                                      for x in per_rate[t]]) or 0)
                         > threshold), None)
        primo_gen = next((t for t in sorted(per_rate)
                          if (_median([x.get("gen_achievement", 1.0)
                                       for x in per_rate[t]]) or 0) < 0.99),
                         None)
        if primo_rx is not None:
            print(f"  {GREY}Il ricevitore respinge da {primo_rx:.2f} Mpps di "
                  f"target in su.{NC}")
        if primo_gen is not None:
            print(f"  {GREY}Il generatore smette di offrire il target da "
                  f"{primo_gen:.2f} Mpps in su.{NC}")

    print(f"\n  {GREY}`offerti` = (TX + respinti) / finestra, cioe' quanto "
          f"il generatore metteva davvero sul filo. TX = quanti ne ha "
          f"accettati il veth. La differenza fra le due colonne e' la "
          f"backpressure del RICEVITORE: se `offerti` supera stabilmente TX, "
          f"a fermarsi non e' il mittente.{NC}")
    print(f"  {GREY}TX = pacchetti che pktgen dichiara trasmessi. "
          f"RX = pacchetti contati all'ingresso del lato DUT. "
          f"`resp` = respinti da veth_xmit a coda piena: sono carico offerto "
          f"e MAI trasmesso, quindi restano fuori da TX e da loss.{NC}")
    print(f"  {GREY}TX < RX non e' possibile per costruzione; TX > RX e' "
          f"perdita del veth o del ricevitore -- NON di una pipeline, che in "
          f"questa modalita' non esiste.{NC}")


def _confronto_con_rates(out_dir, ceiling_rx):
    """Accosta il tetto ai valori gia' misurati da --mode rates, se ci sono.

    Legge `rates_raw.csv` e basta: nessuna classifica, nessun vincitore,
    nessun ricalcolo. Serve a vedere se le cifre delle pipeline stanno sotto
    il tetto -- cioe' se sono compatibili con l'ipotesi che a limitarle sia il
    generatore e non se stesse."""
    if not out_dir:
        return
    path = os.path.join(out_dir, "rates_raw.csv")
    if not os.path.exists(path):
        return
    try:
        with open(path, newline="", encoding="utf-8") as f:
            righe = list(csv.DictReader(f))
    except OSError:
        return
    per = {}
    for r in righe:
        try:
            if float(r.get("loss_tot_pct") or r.get("loss_dut_pct")
                     or 0) > DEFAULT_LOSS_THRESHOLD:
                continue
            m, v = r["method"], float(r["rx_pps"]) / 1e6
        except (KeyError, ValueError):
            continue
        per[m] = max(per.get(m, 0.0), v)
    if not per:
        return
    print(f"\n{YELLOW}{'=' * 78}{NC}")
    print(f"{YELLOW} Confronto con --mode rates (letto da {path}){NC}")
    print(f"{YELLOW}{'=' * 78}{NC}")
    print("\n  Receive-path control (nessuna pipeline):")
    print(f"      maximum achieved RX = {ceiling_rx:.2f} Mpps")
    print("\n  Pipeline benchmark (massimo RX senza perdita, respinti "
          "compresi):")
    for m in sorted(per, key=lambda k: -per[k]):
        print(f"      {m:11s} >= {per[m]:.2f} Mpps")
    print(f"\n  {GREY}Nessuna classifica e nessun vincitore: le due colonne "
          f"servono a una cosa sola, vedere se i valori delle pipeline sono "
          f"COMPATIBILI con il tetto del generatore. Se ci stanno tutti "
          f"sotto e nessuna pipeline perdeva, allora a limitarle era il "
          f"generatore e il loro ginocchio non e' stato raggiunto.{NC}")


def check_validity(rows):
    """La baseline deve essere la piu' veloce. Se non lo e', il run e' sporco.

    Non e' una convenzione: la baseline parsa, decrementa il TTL e redirige su
    una classe FISSA. Fa strettamente MENO lavoro di qualunque pipeline, quindi
    non puo' consegnare meno pacchetti. Se lo fa, la differenza fra le colonne
    e' il carico della macchina in momenti diversi e non il costo
    dell'inferenza, e pubblicare quella classifica sarebbe pubblicare rumore
    ordinato.

    Questo controllo esiste perche' e' successo: baseline 2 658 k contro
    p1_static 3 342 k, con dispersioni fino al 75%.

    IL CONFRONTO E' DENTRO UNA TAGLIA DI FRAME, mai fra taglie. Prendendo il
    massimo di ciascun metodo su TUTTE le taglie il controllo confrontava punti
    diversi: misurato il 2026-09-18, ha dichiarato "baseline 1 289 781 NON e'
    la piu' veloce: hardcoded 1 604 321" mettendo a confronto la baseline a
    1514 byte con hardcoded a 512. Per taglia, lo stesso run era coerente a 64
    e a 1514 e contaminato solo a 512 -- che e' una diagnosi, mentre l'altra
    era un artefatto del controllo."""
    VERDICT.clear()
    per_frame = {}
    for r in rows:
        m = r.get("method")
        if not m:
            continue
        # Le righe del percorso --latency non portano la taglia: finiscono
        # tutte nello stesso gruppo, che li' e' corretto perche' la taglia e'
        # una sola.
        best = per_frame.setdefault(r.get("frame"), {})
        if m not in best or r["rx_pps"] > best[m]["rx_pps"]:
            best[m] = r
    usable = {k: b for k, b in per_frame.items()
              if "baseline" in b and len(b) >= 2}
    if not usable:
        return 0
    order = sorted(usable, key=lambda k: (k is None, k))
    # Tolleranza: un'inversione ENTRO questa soglia non e' contaminazione, e'
    # rumore fra due pipeline che il banco non riesce a distinguere. Misurato:
    # baseline 1 377 k contro hardcoded 1 423 k, cioe' il 3% -- entrambe
    # limitate dal generatore, quindi il throughput non le separa. Chiamarlo
    # "run contaminato" avrebbe buttato via una misura che invece dice una cosa
    # vera: che sono indistinguibili.
    faster, close, clean_frames = {}, {}, []
    noisy, gen_bound = set(), set()
    for k in order:
        best = usable[k]
        base = best["baseline"]["rx_pps"]
        sopra = {m: r["rx_pps"] for m, r in best.items()
                 if m != "baseline" and r["rx_pps"] > base * (1 + VALID_TOL)}
        for m, v in sopra.items():
            faster[(k, m)] = (v, base)
        for m, r in best.items():
            if m != "baseline" and base < r["rx_pps"] <= base * (1 + VALID_TOL):
                close[(k, m)] = r["rx_pps"]
            if r.get("unreliable"):
                noisy.add(m)
            if r.get("bottleneck") == BN_GEN:
                gen_bound.add(m)
        if not sopra:
            clean_frames.append(k)
    noisy, gen_bound = sorted(noisy), sorted(gen_bound)

    def _fr(k):
        return "ogni taglia" if k is None else f"{k}B"

    print(f"\n{YELLOW}{'=' * 78}{NC}")
    print(f"{YELLOW} Controllo di validita'{NC}")
    print(f"{YELLOW}{'=' * 78}{NC}")
    if gen_bound:
        print(f"  {YELLOW}[NOTA]{NC} limitate dal GENERATORE, non da se "
              f"stesse: {', '.join(gen_bound)}.")
        print(f"  {GREY}Per queste righe il numero e' il tetto del banco. "
              f"Alza le CPU del generatore (--gen-cpus) o abbassa quelle del "
              f"DUT (--dut-cpus) finche' la perdita compare: solo allora il "
              f"numero e' della pipeline.{NC}")
    if not faster and not noisy:
        det = ", ".join(f"{_fr(k)} {usable[k]['baseline']['rx_pps']} pps"
                        for k in order)
        msg = (f"la baseline e' la piu' veloce entro {VALID_TOL:.0%} in ogni "
               f"taglia ({det}), come deve essere: fa strettamente meno "
               f"lavoro. Le differenze oltre la tolleranza sono attribuibili "
               f"alle pipeline.")
        VERDICT.append(("PASS", msg))
        print(f"  {GREEN}[PASS]{NC} {msg}")
        if close:
            det = ", ".join(f"{_fr(k)} {m} {v}" for (k, m), v
                            in sorted(close.items(), key=lambda kv: str(kv[0])))
            print(f"  {GREY}Indistinguibili da lei entro il rumore: {det}. "
                  f"Sono limitate dal generatore, non da se stesse: il "
                  f"throughput non le separa, la latenza si'.{NC}")
        return 0
    if faster:
        det = "; ".join(f"{_fr(k)}: {m} {v} contro baseline {b}"
                        for (k, m), (v, b) in sorted(faster.items(),
                                                     key=lambda kv: str(kv[0])))
        msg = (f"la baseline NON e' la piu' veloce -- {det}. La baseline fa "
               f"strettamente meno lavoro, quindi non puo' consegnare meno: "
               f"su quelle taglie il run misura il carico della macchina e "
               f"non il datapath, e le cifre non sono confrontabili fra "
               f"pipeline.")
        VERDICT.append(("FAIL", msg))
        print(f"  {RED}[FAIL]{NC} la baseline NON e' la piu' veloce: {det}.")
        print(f"  {GREY}La baseline fa strettamente meno lavoro, quindi non "
              f"puo' consegnare meno. Su quelle taglie il run misura il "
              f"carico della macchina, non il datapath.{NC}")
        # Quali taglie si sono salvate e' la meta' utile del referto: una
        # contaminazione che colpisce una taglia sola non e' una proprieta'
        # del banco, e' cio' che girava sulla macchina in quel momento.
        if clean_frames:
            det2 = ", ".join(_fr(k) for k in clean_frames)
            print(f"  {GREY}Coerenti invece a: {det2}.{NC}")
    if noisy:
        VERDICT.append(("FAIL", f"dispersione fra i giri oltre "
                                f"{MAX_SPREAD_PCT:.0f}% su: "
                                f"{', '.join(noisy)}. Una mediana su misure "
                                f"che oscillano cosi' non e' una portata, e' "
                                f"il carico della macchina in momenti "
                                f"diversi."))
        print(f"  {RED}[FAIL]{NC} dispersione fra i giri oltre "
              f"{MAX_SPREAD_PCT:.0f}% su: {', '.join(noisy)}.")
        print(f"  {GREY}Una mediana su misure che oscillano cosi' non e' una "
              f"portata: e' il carico della macchina in momenti diversi. "
              f"Misurato: una pipeline ha dato 2,78 / 1,17 / 1,46 Mpps in tre "
              f"giri, e la sua mediana e' finita SOTTO una che fa piu' lavoro. "
              f"Il throughput di queste righe non e' un risultato.{NC}")
        print(f"  {GREY}La latenza delle stesse righe e' un'altra misura con "
              f"un'altra dispersione. Un throughput inutilizzabile non la "
              f"invalida.{NC}")
    print(f"\n  {YELLOW}Che fare{NC}: chiudi tutto il resto, poi rilancia con "
          f"--rounds 7. Se la dispersione resta, questa VM non e' un banco di "
          f"misura per il throughput assoluto, e cio' che resta valido e' la "
          f"latenza piu' il confronto dentro un singolo metodo.")
    return 1


def _write_csv(path, rows):
    """Scrive l'unione delle chiavi, non quelle della prima riga.

    Fasi diverse portano campi diversi, e prendere la prima riga come schema
    faceva fallire la scrittura DOPO che tutto era stato misurato -- il modo
    peggiore di perdere un run. Le chiavi che cominciano con '_' sono interne
    (la diagnostica grezza) e non finiscono nel file."""
    if not rows:
        return 0
    cols = []
    for row in rows:
        for k in row:
            if not k.startswith("_") and k not in cols:
                cols.append(k)
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=cols, restval="", extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)
    print(f"  {GREEN}scritto{NC} {path}  ({len(rows)} righe)")
    return len(rows)


# ==========================================================================
# CONDIZIONI DEL TEST: l'unica parte della misura che non si puo' rifare dopo
# ==========================================================================
# Un pacchetti-al-secondo senza la macchina che l'ha prodotto non e' citabile.
# Su questo banco TG, DUT e contatore stanno sulla STESSA VM: il numero di
# vCPU, il governor della frequenza e perfino `mitigations=` sulla riga di
# comando del kernel entrano nel risultato quanto la pipeline sotto test.
#
# I CSV si riaprono e i grafici si rifanno; la configurazione della macchina
# no, perche' al giro dopo e' gia' un'altra. Va quindi scritta INSIEME ai
# numeri, nello stesso istante e nella stessa cartella -- non ricostruita a
# posteriori dalla memoria di chi ha lanciato il run.
#
# Niente qui puo' far fallire un run: la raccolta e' tutta best-effort e ogni
# campo mancante diventa "n/d". Perdere una misura gia' fatta perche' `clang`
# non era nel PATH sarebbe il modo peggiore di documentarla.


def _read_text(path, default=""):
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return f.read()
    except OSError:
        return default


def _first_line(path, default="n/d"):
    txt = _read_text(path).strip()
    return txt.splitlines()[0].strip() if txt else default


def _cmd_line(args, default="n/d"):
    """Prima riga dell'output di un comando, o il default. Mai un'eccezione."""
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.SubprocessError):
        return default
    out = (r.stdout or r.stderr or "").strip().splitlines()
    return out[0].strip() if out else default


def _cpu_model():
    for line in _read_text("/proc/cpuinfo").splitlines():
        if line.startswith("model name"):
            return line.split(":", 1)[1].strip()
    return "n/d"


def _mem_total_mb():
    for line in _read_text("/proc/meminfo").splitlines():
        if line.startswith("MemTotal:"):
            try:
                return str(int(line.split()[1]) // 1024)
            except (IndexError, ValueError):
                break
    return "n/d"


def _distro():
    for line in _read_text("/etc/os-release").splitlines():
        if line.startswith("PRETTY_NAME="):
            return line.split("=", 1)[1].strip().strip('"')
    return "n/d"


def _bcc_version():
    try:
        import bcc
    except ImportError:
        return "assente"
    v = getattr(bcc, "__version__", None)
    if v:
        return str(v)
    # bcc non espone sempre __version__: il pacchetto della distribuzione si',
    # ed e' quello che si e' davvero installato.
    return _cmd_line(["dpkg-query", "-W", "-f=${Version}", "python3-bpfcc"],
                     "presente, versione ignota")


def capture_env(a=None, plan=None, methods=(), frames=()):
    """Condizioni hardware, software e di run, come lista di coppie ordinata.

    Lista di coppie e non dizionario: l'ORDINE e' il documento. Si legge
    dall'alto -- macchina, kernel, strumenti, parametri del run -- e chi lo
    rilegge fra sei mesi non deve ricostruirlo."""
    u = os.uname()
    env = []

    def add(k, v):
        env.append((k, "n/d" if v is None or v == "" else str(v)))

    add("data", time.strftime("%Y-%m-%d %H:%M:%S"))
    add("commit", _cmd_line(["git", "-C", SHARED_DIR, "rev-parse", "--short",
                             "HEAD"]))

    # ---- macchina
    add("cpu", _cpu_model())
    add("cpu_online", len(online_cpus()))
    add("cpu_governor", _first_line(
        "/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor"))
    add("ram_mb", _mem_total_mb())
    # systemd-detect-virt manca su parecchie immagini minimali: l'assenza e'
    # essa stessa un'informazione, non un errore.
    add("virtualizzazione", _cmd_line(["systemd-detect-virt"], "sconosciuta"))

    # ---- kernel e software
    add("kernel", f"{u.sysname} {u.release} {u.machine}")
    add("distribuzione", _distro())
    add("cmdline_kernel", _first_line("/proc/cmdline"))
    add("python", sys.version.split()[0])
    add("clang", _cmd_line(["clang", "--version"]))
    add("bcc", _bcc_version())
    add("pktgen", "presente" if os.path.isdir(PKTGEN_DIR) else "assente")

    # ---- percorso dati: e' la riserva piu' importante sui numeri assoluti
    add("datapath", "veth (XDP nativo), TG e DUT sulla stessa macchina")
    # La coda del veth e' una condizione del test quanto il numero di core:
    # decide a che rate cominciano i respinti, indipendentemente dalla
    # pipeline. Riportarla e' cio' che permette di confrontare due run.
    if VETH_RING_STATE:
        for dev, st in VETH_RING_STATE.items():
            if not st["supportato"]:
                add(f"coda_rx_{dev}",
                    "non configurabile su questo kernel (ethtool -g rifiutato)"
                    " -- VETH_RING_SIZE fissa, storicamente 256 descrittori")
            else:
                add(f"coda_rx_{dev}",
                    f"{st['dopo']} descrittori (era {st['prima']}, massimo "
                    f"{st['massimo']})")
    add("copia_headroom",
        "si -- pktgen riserva NET_SKB_PAD (64B), XDP su veth pretende "
        "XDP_PACKET_HEADROOM (256B): una copia per pacchetto")

    # ---- parametri del run
    if plan is not None:
        add("cpu_generatore", ",".join(str(c) for c in plan.gen))
        add("cpu_dut", ",".join(str(c) for c in plan.dut))
    if a is not None:
        add("modalita", "latency" if getattr(a, "latency", False) else a.mode)
        add("napi_threaded", "no" if a.no_threaded_napi else "si")
        add("topologia_generatore", a.gen_topology)
        add("xmit_mode", a.xmit_mode)
        add("finestra_s", a.duration)
        add("finestra_modo", getattr(a, "window", WINDOW_MODE))
        add("warmup_s", a.warmup)
        add("ripetizioni_per_punto", a.repeat)
        add("giri", a.rounds)
        add("soglia_perdita_pct", a.loss_threshold)
        add("clone_skb", a.clone_skb)
        add("burst", a.burst)
    if frames:
        add("frame_byte", ",".join(str(f) for f in frames))
    if methods:
        add("pipeline", ",".join(methods))
    return env


def print_env(env):
    print(f"\n{YELLOW}== condizioni del test =={NC}")
    width = max(len(k) for k, _ in env)
    for k, v in env:
        print(f"  {GREY}{k:<{width}}{NC}  {v}")


def write_env(out_dir, env):
    """env.csv accanto ai numeri. Due colonne e non una riga larga: i campi
    cambiano da un run all'altro, e una tabella a colonne fisse invecchia."""
    path = os.path.join(out_dir, "env.csv")
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["campo", "valore"])
        w.writerows(env)
    print(f"  {GREEN}scritto{NC} {path}  ({len(env)} campi)")
    return path


# ==========================================================================
# IL REPORT: una riga per configurazione, con dentro cio' che si cita
# ==========================================================================
# I CSV hanno tutti i punti, ed e' giusto che sia cosi'. Ma la domanda a cui
# questo banco risponde -- "a che rate regge ciascuna pipeline, e quanto
# perde" -- si legge su POCHE righe: una per (pipeline, frame).
#
# Le due cifre di throughput non sono intercambiabili e vanno stampate
# insieme, perche' citarne una sola e' il modo classico di dire il falso:
#
#   massimo        il rate CONSEGNATO piu' alto osservato. E' un sistema in
#                  sovraccarico: significa qualcosa solo se accanto c'e' la
#                  perdita con cui e' stato ottenuto.
#   perdita nulla  il rate piu' alto sotto la soglia dichiarata. E' il
#                  throughput nel senso della RFC 2544, ed e' la riga da
#                  citare.


def _num(row, key, default=0):
    v = row.get(key, default)
    return default if v in (None, "") else v


def _loss_of(row):
    return float(_num(row, "loss_worst", _num(row, "loss_pct", 0.0)))


def report_rows(rows, threshold=DEFAULT_LOSS_THRESHOLD):
    """Riduce i punti grezzi a una riga per (pipeline, frame).

    Le fasi `ricerca` e `rumore` restano fuori: la prima e' l'impalcatura
    della salita, la seconda e' gia' stata marcata come non descrittiva del
    datapath. Tenerle dentro farebbe vincere la finestra fortunata."""
    ordine = {m: i for i, m in enumerate(METHODS)}
    keys = []
    for r in rows:
        k = (r.get("method"), r.get("frame"))
        if k[0] and k[1] and k not in keys:
            keys.append(k)
    keys.sort(key=lambda k: (ordine.get(k[0], 99), k[1]))

    out = []
    for meth, frame in keys:
        pts = [r for r in rows
               if r.get("method") == meth and r.get("frame") == frame
               and r.get("phase") not in ("rumore", "ricerca")]
        if not pts:
            continue
        peak = max(pts, key=lambda r: _num(r, "rx_pps"))
        # La riga a perdita nulla e' quella che il banco ha GIA' marcato come
        # tale dove esiste (saturate, latency); altrove la si ricava dalla
        # soglia. Non si ricalcola quando c'e': find_saturation ha gia'
        # applicato il controllo di monotonia, che qui non si potrebbe rifare.
        clean = [r for r in pts if r.get("phase") == "zero-perdite"]
        if not clean:
            clean = [r for r in pts if _loss_of(r) <= threshold]
        best = max(clean, key=lambda r: _num(r, "rx_pps")) if clean else None
        strict = [r for r in pts if _loss_of(r) == 0.0]
        zero = max(strict, key=lambda r: _num(r, "rx_pps")) if strict else None
        # La latenza si cita DA SCARICO. A pieno rate il numero e' dominato
        # dalla coda davanti al programma: due pipeline con code diverse
        # darebbero latenze diverse anche eseguendo lo stesso identico codice,
        # e il confronto misurerebbe la coda. Il percorso --latency produce
        # apposta una riga `scarico`; dove non c'e' si ripiega sul punto piu'
        # lento misurato, che e' il meno congestionato disponibile.
        lat_src = next((r for r in pts if r.get("phase") == "scarico"), None)
        if lat_src is None:
            with_lat = [r for r in pts if _num(r, "lat_p50_ns")]
            lat_src = (min(with_lat, key=lambda r: _num(r, "rx_pps"))
                       if with_lat else peak)
        out.append(dict(
            method=meth, frame=frame,
            max_rx_pps=int(_num(peak, "rx_pps")),
            max_rx_mbps=_num(peak, "rx_mbps"),
            max_loss_pct=round(_loss_of(peak), 3),
            max_loss_med_pct=_num(peak, "loss_med", ""),
            max_offered_pps=int(_num(peak, "offered_real_pps",
                                     _num(peak, "offered_pps"))),
            rx_pkts=int(_num(peak, "rx")),
            tx_pkts=int(_num(peak, "offered_tx", _num(peak, "tx"))),
            lost_before=int(_num(peak, "lost_before")),
            lost_after=int(_num(peak, "lost_after")),
            # La perdita spezzata per colpevole: respinta dal trasporto, o
            # persa dal DUT. E' la distinzione che decide se una riga dice
            # "la pipeline butta via pacchetti" oppure "la pipeline e' satura
            # e il veth rifiuta il carico in eccesso".
            respinti=int(_num(peak, "respinti")),
            respinti_pct=_num(peak, "respinti_pct"),
            persi_dut=int(_num(peak, "persi_in_coda")
                          + _num(peak, "persi_dopo")),
            persi_in_coda=int(_num(peak, "persi_in_coda")),
            persi_dopo=int(_num(peak, "persi_dopo")),
            loss_dut_pct=_num(peak, "loss_dut_pct"),
            noloss_rx_pps=int(_num(best, "rx_pps")) if best else 0,
            # Il rate a perdita nulla e' un limite INFERIORE quando a massima
            # spinta non si e' perso niente: la pipeline non era satura, quindi
            # il vero NDR sta piu' in alto e questo banco non lo raggiunge.
            noloss_gen_bound=bool(best and _num(best, "gen_bound")),
            noloss_rx_mbps=_num(best, "rx_mbps") if best else 0,
            noloss_loss_pct=round(_loss_of(best), 3) if best else "",
            zero_rx_pps=int(_num(zero, "rx_pps")) if zero else 0,
            lat_p50_ns=int(_num(lat_src, "lat_p50_ns")) or "",
            lat_min_ns=int(_num(lat_src, "lat_min_ns")) or "",
            lat_rx_pps=int(_num(lat_src, "rx_pps")) or "",
            bottleneck=(best or peak).get("bottleneck", "n/d"),
            unreliable=bool(peak.get("unreliable", False)),
            rounds=_num(peak, "rounds", _num(peak, "repeat", 1)),
        ))
    return out


def _costo_ns(pps):
    return round(1e9 / pps, 1) if pps else None


def aggiungi_costo(summ):
    """Aggiunge ns/pacchetto e il delta rispetto alla baseline, per taglia.

    Il confronto e' DENTRO una taglia di frame: il costo per pacchetto cambia
    con la lunghezza (la copia di headroom la paga per byte), quindi un delta
    calcolato fra taglie diverse non sarebbe il costo dell'inferenza."""
    base = {r["frame"]: r["max_rx_pps"] for r in summ
            if r["method"] == "baseline"}
    for r in summ:
        r["ns_pkt"] = _costo_ns(r["max_rx_pps"])
        b = _costo_ns(base.get(r["frame"]))
        if b is not None and r["ns_pkt"] is not None and r["method"] != "baseline":
            r["ns_pkt_vs_baseline"] = round(r["ns_pkt"] - b, 1)
        else:
            r["ns_pkt_vs_baseline"] = ""
    return summ


def write_report(out_dir, rows, env, threshold=DEFAULT_LOSS_THRESHOLD,
                 title="Throughput end-to-end, misurato"):
    """Un markdown con la tabella per configurazione e le condizioni sotto.

    Markdown e non solo CSV perche' questa e' la forma in cui il risultato
    viene letto e citato; il CSV resta accanto per rifare i grafici."""
    summ = aggiungi_costo(report_rows(rows, threshold))
    if not summ:
        return None
    # Il delta per pacchetto si cita solo se NON si e' perso niente: con code
    # di mezzo `1/rx_pps` e' il tempo di coda, non il costo del programma.
    costo_pulito = all(r["max_loss_pct"] <= threshold for r in summ)
    lat = any(r["lat_p50_ns"] for r in summ)
    path = os.path.join(out_dir, "throughput_report.md")
    L = []
    L.append(f"# {title}")
    L.append("")
    # IL VERDETTO PRIMA DELLA TABELLA, sempre. Il markdown e' la forma in cui
    # questi numeri vengono letti e citati; scriverlo senza dire che il
    # controllo di validita' ha bocciato il run vuol dire produrre una tabella
    # che sembra un risultato e non lo e'. Il terminale lo diceva, ma il
    # terminale si chiude e il file resta.
    # Un run a una o due finestre per punto non e' confrontabile fra pipeline,
    # e il markdown e' cio' che si cita: l'avviso a terminale scorre via, il
    # file resta. Misurato il 2026-09-18: a `--repeat 1` la baseline a 512 byte
    # e' uscita il 4.9% sopra la media dei run a repeat 5, e siccome e' il
    # denominatore di tutta la colonna ha gonfiato ogni costo -- P3 a 893 ns
    # contro i 697 stabili su tre run.
    rip = next((int(v) for k, v in env if k == "ripetizioni_per_punto"
                and str(v).isdigit()), None)
    if rip is not None and rip < 3:
        L.append(f"> **MISURATO A {rip} FINESTRA/E PER PUNTO -- non "
                 f"confrontabile fra pipeline.**")
        L.append(">")
        L.append("> Con meno di tre ripetizioni la mediana del rate, la "
                 "peggiore delle perdite e la dispersione non esistono. In "
                 "particolare la riga `baseline`, che fa da denominatore alla "
                 "colonna `ns/pkt vs baseline`, e' una finestra sola: il suo "
                 "errore si propaga a ogni costo della tabella. Serve almeno "
                 "`--repeat 3`, meglio 5.")
        L.append("")
    bad = [m for e, m in VERDICT if e == "FAIL"]
    if bad:
        L.append("> **RUN BOCCIATO DAL CONTROLLO DI VALIDITA' -- "
                 "le cifre qui sotto NON sono citabili.**")
        L.append(">")
        for m in bad:
            L.append(f"> - {m}")
        L.append(">")
        L.append("> La tabella resta scritta perche' serve a capire "
                 "*perche'* il run e' stato bocciato, non a "
                 "riportare una portata.")
        L.append("")
    elif VERDICT:
        for _, m in VERDICT:
            L.append(f"Controllo di validita': **PASS** -- {m}")
            L.append("")
    L.append("Traffico REALE: pktgen (TG) genera, la pipeline XDP (DUT) "
             "inferisce e redirige, un contatore XDP sull'uscita conta chi e' "
             "arrivato davvero. Nessuna cifra in questa tabella e' "
             "`1/latenza` sotto `BPF_PROG_TEST_RUN`.")
    L.append("")
    L.append(f"Soglia di perdita per la colonna \"perdita nulla\": "
             f"{threshold}%.")
    L.append("")
    L.append("**Due colonne di perdita, e una deviazione dichiarata da RFC "
             "2544.** La norma definisce il throughput come il rate a cui non "
             "si perde nemmeno un frame, e squalifica il rate se una sola "
             "finestra sporca. Presuppone pero' un DUT quieto e dedicato. "
             "Qui il DUT e' un guest su un host a core ibridi, e capita che "
             "il vCPU venga sospeso per l'intera finestra: quella ripetizione "
             "descrive l'host, non il rate. Si riporta quindi la perdita "
             "**peggiore** fra le ripetizioni, ma si **decide** sulla "
             "mediana. Chi vuole la lettura stretta RFC 2544 legge la colonna "
             "peggiore.")
    L.append("")
    head = ["pipeline", "frame B", "max RX pps", "max Mb/s", "ns/pkt",
            "ns/pkt vs baseline",
            "perdita @max % (peggiore)", "perdita @max % (mediana)",
            "RX pkt", "offerti pkt", "respinti (veth)", "persi dal DUT",
            "perdita DUT %", "perdita nulla pps", "perdita nulla Mb/s",
            "zero stretto pps", "collo di bottiglia"]
    if lat:
        head[-1:-1] = ["lat p50 ns", "lat misurata a pps"]
    L.append("| " + " | ".join(head) + " |")
    L.append("|" + "|".join("---" for _ in head) + "|")
    for r in summ:
        # L'asterisco sta sul NOME della pipeline, non in fondo alla riga:
        # in fondo finirebbe dentro l'ultima cella e sembrerebbe una nota sul
        # collo di bottiglia invece che sulla riga intera.
        name = r["method"] + (" *" if r["unreliable"] else "")
        cells = [name, r["frame"], r["max_rx_pps"], r["max_rx_mbps"],
                 r["ns_pkt"], r["ns_pkt_vs_baseline"],
                 r["max_loss_pct"], r["max_loss_med_pct"],
                 r["rx_pkts"], r["tx_pkts"],
                 r["respinti"], r["persi_dut"], r["loss_dut_pct"],
                 (f">= {r['noloss_rx_pps']}" if r["noloss_gen_bound"]
                  else (r["noloss_rx_pps"] or "non determinato")),
                 r["noloss_rx_mbps"] or "",
                 r["zero_rx_pps"] or "nessuno"]
        if lat:
            cells.append(r["lat_p50_ns"] or "")
            cells.append(r["lat_rx_pps"] or "")
        cells.append(r["bottleneck"])
        L.append("| " + " | ".join(str(c) for c in cells) + " |")
    L.append("")
    # I nomi in tabella sono quelli interni, perche' sono le chiavi con cui i
    # CSV si uniscono. La corrispondenza con i nomi della tesi va scritta
    # accanto, altrimenti la tabella non e' citabile senza il codice a fianco.
    L.append("Pipeline: `baseline` = nessuna inferenza, solo redirect (il "
             "pavimento del percorso); `p1_static` = P1, pesi e nodo "
             "compilati; `hardcoded` = versione intermedia (P1.5), pesi "
             "compilati e nodo letto da mappa; `template` = P2, solo i "
             "soffitti compilati; `modular` = P3, anche la profondita' a "
             "runtime.")
    L.append("")
    if costo_pulito:
        L.append("**`ns/pkt vs baseline` e' il costo dell'inferenza per "
                 "pacchetto**, misurato su traffico vero. Vale perche' qui "
                 "non si perde niente: senza code di mezzo `1/RX pps` e' il "
                 "tempo del percorso completo, e la baseline fa lo stesso "
                 "percorso meno l'inferenza. Se il generatore e' in softirq "
                 "il rate e' `1/(t_gen + t_pipeline)`, ma `t_gen` e' comune a "
                 "tutte le righe della stessa taglia e sottraendo la baseline "
                 "si cancella.")
        L.append("")
    else:
        L.append("**`ns/pkt vs baseline` NON e' citabile in questa tabella**: "
                 "ci sono righe con perdita, e con le code di mezzo "
                 "`1/RX pps` misura il tempo di attesa, non il costo del "
                 "programma. La colonna resta per confronto interno.")
        L.append("")
    if any(r["noloss_gen_bound"] for r in summ):
        L.append("`>=` nella colonna a perdita nulla vuol dire **limite "
                 "inferiore**: a massima spinta non si e' perso nemmeno un "
                 "pacchetto, quindi la pipeline non era satura e il tetto "
                 "misurato e' quello del GENERATORE. L'NDR vero sta piu' in "
                 "alto e questo banco, su questa macchina, non lo raggiunge. "
                 "Il confronto fra pipeline resta valido perche' tutte hanno "
                 "visto lo stesso generatore.")
        L.append("")
    L.append("**Le due perdite non sono la stessa cosa.** `respinti (veth)` "
             "sono pacchetti a cui `veth_xmit` ha risposto `NET_XMIT_DROP` "
             "perche' il ptr_ring della RX del DUT era pieno: non sono MAI "
             "entrati nel dispositivo sotto test, quindi non sono una perdita "
             "della pipeline -- sono la prova che la pipeline e' satura e sta "
             "facendo backpressure. `persi dal DUT` sono quelli accettati e "
             "poi non consegnati (coda d'ingresso, oppure elaborati e non "
             "usciti per redirect fallito o classe DROP), e quelli SI' sono "
             "perdita del datapath. La colonna `perdita @max %` li somma "
             "entrambi sul carico offerto, ed e' quindi la piu' pessimista "
             "delle tre.")
    if any(r["unreliable"] for r in summ):
        L.append("")
        L.append(f"`*` = dispersione fra le ripetizioni sopra "
                 f"{MAX_SPREAD_PCT}%: quella riga non e' utilizzabile per un "
                 f"confronto.")
    L.append("")
    L.append("## Condizioni del test")
    L.append("")
    L.append("| campo | valore |")
    L.append("|---|---|")
    for k, v in env:
        L.append(f"| {k} | {v} |")
    L.append("")
    L.append("TG, DUT e contatore stanno sulla stessa macchina e il percorso "
             "e' veth: il costo della traversata e della copia di headroom e' "
             "dentro ogni cifra. Il CONFRONTO fra pipeline a parita' di "
             "condizioni regge; le cifre assolute sono di questo percorso "
             "veth, non di una NIC.")
    L.append("")
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(L))
    print(f"  {GREEN}scritto{NC} {path}  ({len(summ)} configurazioni)")
    _write_csv(os.path.join(out_dir, "throughput_summary.csv"), summ)
    return path


# ==========================================================================
def _rates_from(a):
    """La lista dei rate in pps, da --rates o dal default. Una funzione sola
    perche' `rates` e `generator` devono accettare esattamente la stessa
    sintassi: confrontarli a liste diverse non avrebbe senso."""
    if not a.rates:
        return [int(r * 1e6) for r in DEFAULT_RATES_MPPS]
    try:
        rates = [int(float(x) * 1e6) for x in a.rates.split(",") if x.strip()]
    except ValueError:
        sys.exit(f"--rates: attesi numeri in Mpps separati da virgola, "
                 f"ricevuto {a.rates!r}")
    if not rates or min(rates) <= 0:
        sys.exit("--rates: servono rate positivi")
    return sorted(rates)


def main():
    # Riga per riga anche quando l'uscita va in una pipe (| tee, | grep): senza,
    # Python la bufferizza a blocchi da 8 KB e un run di minuti non mostra
    # niente finche' il blocco non si riempie.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(line_buffering=True)
        except (AttributeError, ValueError):
            pass
    p = argparse.ArgumentParser(
        description=__doc__.split("USO")[0].strip(),
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--method", choices=list(METHODS) + [RX_ONLY, "all"],
                   default="all",
                   help=f"all = le cinque pipeline; in --mode compare anche "
                        f"{RX_ONLY}, il tetto di sola ricezione misurato nella "
                        f"stessa sessione.")
    p.add_argument("--rates", default=None, metavar="LISTA",
                   help="modalita' rates: rate offerti in Mpps, separati da "
                        "virgola (default: 0.1,0.2,0.4,0.6,0.8,1,1.2,1.5,2)")
    p.add_argument("--rx-action", choices=GEN_RX_ACTIONS, default="drop",
                   help="modalita' generator: cosa fa il contatore RX col "
                        "pacchetto. drop (default) lo libera subito ed e' il "
                        "solo modo di ottenere un limite SUPERIORE; pass lo "
                        "consegna allo stack, che nel percorso vero non viene "
                        "mai attraversato.")
    p.add_argument("--mode", choices=("compare", "saturate", "rates",
                                      "generator"),
                   default="saturate",
                   help="compare: stesso rate offerto per tutte le pipeline, "
                        "e' il confronto. saturate (default): rate crescente "
                        "per trovare dove ciascuna comincia a perdere.")
    p.add_argument("--frames", default=None,
                   help="taglie di frame in byte, separate da virgola. Il "
                        "confronto ne usa una sola (64) se non si dice altro: "
                        "sei taglie moltiplicano per sei la durata del run "
                        "senza cambiare l'ordine fra le pipeline.")
    p.add_argument("--delays", default="",
                   help="ritardi fissi in ns, separati da virgola. Vuoto (il "
                        "default) cerca il punto di saturazione invece di "
                        "spazzolare: meno punti e centra la risposta")
    p.add_argument("--count", type=int, default=200000,
                   help="pacchetti per punto nel percorso --latency. Negli "
                        "altri il conteggio lo decide la durata (--duration), "
                        "perche' pktgen conta pacchetti e non secondi.")

    g = p.add_argument_group("CPU: separare generatore e DUT sulla stessa "
                             "macchina")
    g.add_argument("--gen-cpus", default=None, metavar="LISTA",
                   help="CPU del generatore, es. '1,2' o '1-3'. Una CPU = un "
                        "thread pktgen (kpktgend_<cpu>). Default: automatico, "
                        "piu' core al generatore che al DUT.")
    g.add_argument("--dut-cpus", default=None, metavar="LISTA",
                   help="CPU su cui pinnare i thread NAPI che eseguono XDP. "
                        "Default: quelle che restano.")
    g.add_argument("--allow-cpu0", action="store_true",
                   help="riammetti la CPU 0, esclusa per default perche' "
                        "porta timer, RCU e IRQ.")
    g.add_argument("--threads", type=int, default=None, metavar="N",
                   help="quanti thread generatore, se non si vogliono "
                        "elencare le CPU. E' l'unico modo di alzare il carico "
                        "offerto quando veth rifiuta clone_skb e burst.")
    g.add_argument("--gen-topology", choices=("shared", "links"),
                   default="shared",
                   help="shared: UN veth d'ingresso, N istanze pktgen su code "
                        "TX distinte -- gen e DUT scalano separatamente. "
                        "links: un veth per thread (comportamento storico), "
                        "ogni veth porta con se' un core di DUT.")
    g.add_argument("--no-threaded-napi", action="store_true",
                   help="lascia la RX in softirq sulla CPU che trasmette, "
                        "cioe' generatore e pipeline sullo stesso core. Serve "
                        "per riprodurre le misure vecchie, non per farne di "
                        "nuove.")

    m = p.add_argument_group("misura")
    m.add_argument("--duration", type=float, default=WINDOW_S, metavar="S",
                   help=f"durata bersaglio di una finestra di misura "
                        f"(default {WINDOW_S}s). pktgen conta pacchetti: il "
                        f"count viene calibrato su questa durata e la durata "
                        f"vera e' poi riletta dai suoi contatori.")
    m.add_argument("--warmup", type=float, default=DEFAULT_WARMUP_S,
                   metavar="S",
                   help=f"finestra di riscaldamento scartata prima di ogni "
                        f"punto (default {DEFAULT_WARMUP_S}s). 0 la disattiva.")
    m.add_argument("--rounds", type=int, default=DEFAULT_ROUNDS, metavar="N",
                   help="giri completi: in ogni giro si misurano TUTTE le "
                        "pipeline, poi si tiene la mediana. Toglie l'ordine "
                        "dei metodi dalla misura.")
    m.add_argument("--repeat", type=int, default=DEFAULT_REPEAT, metavar="R",
                   help="finestre per punto; si tiene la mediana del rate e la "
                        "PEGGIORE delle perdite")
    m.add_argument("--offered-pps", type=int, default=None, metavar="PPS",
                   help="rate della fase `confronto` (modalita' compare). "
                        "Senza, lo decide una calibrazione: 90%% di quanto il "
                        "piu' lento consegna a massima spinta. Che a quel "
                        "rate nessuna perda lo verifica la fase stessa.")
    m.add_argument("--window", choices=("steady", "count"), default="steady",
                   help="steady (default): rate letti a differenza mentre "
                        "tutte le istanze pktgen trasmettono, poi stop. "
                        "count: il percorso storico, count fisso e rate diviso "
                        "la durata del blocco su `pgctrl start`, che contiene "
                        "fino a ~225 ms di tempo morto di pktgen. Tenuto per "
                        "riprodurre le misure vecchie e per il confronto.")
    m.add_argument("--loss-threshold", type=float, default=None,
                   metavar="PCT",
                   help="sotto questa percentuale la perdita e' considerata "
                        "rumore della macchina, non saturazione. Il percorso "
                        "--latency parte da ZERO STRETTO; gli altri da "
                        f"{DEFAULT_LOSS_THRESHOLD}%%, che e' il pacchetto "
                        "perso ogni tanto da una VM condivisa.")
    m.add_argument("--search", choices=("ladder", "bisect"), default="ladder",
                   help="come cercare il punto di saturazione. ladder "
                        "(default) sale per gradini e verifica la monotonia; "
                        "bisect e' la bisezione storica sul ritardo, tenuta "
                        "per riprodurre le misure vecchie.")

    gk = p.add_argument_group("manopole del generatore")
    gk.add_argument("--burst", type=int, default=0, metavar="N",
                    help="consegna N pacchetti per chiamata (xmit_more). Su "
                         "veth il kernel lo rifiuta: si prova e si riporta.")
    gk.add_argument("--clone-skb", type=int, default=0, metavar="N",
                    help="riusa lo stesso skb N volte invece di allocarne uno "
                         "per pacchetto. Su veth il kernel lo rifiuta "
                         "(IFF_TX_SKB_SHARING assente).")
    gk.add_argument("--tune-generator", action="store_true",
                    help="prova le manopole supportate e tiene solo quelle "
                         f"che alzano il rate di almeno il "
                         f"{int(GEN_KNOB_MIN_GAIN * 100)}%%.")
    gk.add_argument("--xmit-mode", choices=XMIT_MODES, default="start_xmit",
                    help="netif_receive inietta nel percorso RX saltando la "
                         "traversata veth, ma XDP gira GENERIC e sulla CPU del "
                         "generatore: numeri non confrontabili con gli altri "
                         "modi, e niente separazione gen/DUT.")

    o = p.add_argument_group("uscita")
    o.add_argument("--diag", action="store_true",
                   help="raccoglie occupazione per core, contatori dei device "
                        "e softnet_stat attorno alle misure. Disattivata per "
                        "default: legge procfs fra un punto e l'altro.")
    o.add_argument("--out", default=None, help="dove scrivere i CSV")
    o.add_argument("--latency", action="store_true",
                   help="percorso storico: latenza arrivo->ripartenza con una "
                        "build strumentata, a giri, piu' throughput.")
    o.add_argument("--cleanup", action="store_true",
                   help="rimuovi un fabric rimasto da un run interrotto")
    a = p.parse_args()
    global WINDOW_MODE
    WINDOW_MODE = a.window

    if sys.platform != "linux":
        sys.exit(f"serve Linux, non {sys.platform}")
    if os.geteuid() != 0:
        sys.exit("serve root: sudo python3 ipa/test/bench_throughput.py")

    os.chdir(SHARED_DIR)
    if a.cleanup:
        from netns_fabric import cleanup
        cleanup()
        del_tg_links(16)
        if pg_available():
            pg_stop()
            pg_reset()
        return 0

    if not pg_available():
        sys.exit(f"{PKTGEN_DIR} non c'e' e `modprobe pktgen` non l'ha "
                 f"creato: questo kernel non ha il modulo.")
    if a.repeat <= 1:
        warn("--repeat 1: ogni punto e' UNA finestra. La mediana del rate, la "
             "peggiore delle perdite e la dispersione -- cioe' tutto cio' che "
             "rende confrontabili due pipeline su questa macchina -- si "
             "spengono. Le righe che ne escono non sono confrontabili fra "
             "metodi; servono solo a vedere se il banco gira.")
    pg_reset()

    # Il piano CPU si fa PRIMA di qualunque misura e si stampa: e' la
    # configurazione da cui dipende tutto il resto, e va letta insieme ai
    # numeri.
    plan = plan_cpus(a.gen_cpus, a.dut_cpus, a.threads, a.allow_cpu0)
    plan.describe()

    import model_meta as mm
    model_path = mm.default_checkpoint()
    # I percorsi vogliono default diversi, e un default sbagliato qui costa
    # minuti di run: dove si cerca il punto di saturazione una taglia di frame
    # basta; dove si spazzola, spazzolare una taglia sola non dice niente.
    if a.frames:
        frames = [int(x) for x in a.frames.split(",") if x.strip()]
    else:
        frames = [64] if (a.latency or a.mode == "compare") else \
            list(DEFAULT_FRAMES)
    delays = [int(x) for x in a.delays.split(",") if x.strip()]
    if a.loss_threshold is None:
        # Zero stretto dove il rate lo si cerca col percorso storico; soglia
        # tollerante altrove, dove la perdita sparsa di una VM condivisa
        # farebbe scartare punti buoni.
        a.loss_threshold = 0.0 if a.latency else DEFAULT_LOSS_THRESHOLD
    methods = list(METHODS) if a.method == "all" else [a.method]
    if a.mode == "compare" and not a.latency and a.method == "all":
        methods = [RX_ONLY] + methods
    if RX_ONLY in methods and (a.latency or a.mode != "compare"):
        sys.exit(f"{RX_ONLY} esiste solo in --mode compare; da solo, lo stesso "
                 f"tetto lo misura --mode generator.")

    # Le condizioni si leggono PRIMA di misurare e si stampano subito: se
    # il run viene interrotto a meta' resta comunque scritto su che
    # macchina stava girando, ed e' la meta' che non si puo' ricostruire.
    env = capture_env(a, plan, methods, frames)
    print_env(env)

    def env_finale():
        """Le condizioni RILETTE a fine run.

        `capture_env` gira prima di qualunque misura, ed e' giusto cosi': se il
        run si interrompe resta scritto su che macchina stava girando. Ma la
        coda RX del veth si conosce solo quando la coppia viene creata, cioe'
        dentro il primo run_method. Le condizioni che finiscono su disco vanno
        quindi rilette alla fine, quando tutto cio' che le compone esiste."""
        return capture_env(a, plan, methods, frames)

    rows = []
    rc = 0
    if a.latency:
        lat_delays = delays or [0, 5000, 20000]
        raw = run_fair(methods, model_path, frames, lat_delays, a.count,
                       plan.threads, not a.no_threaded_napi, a.repeat,
                       a.rounds, a.loss_threshold, plan=plan,
                       xmit_mode=a.xmit_mode, window_s=a.duration,
                       warmup_s=a.warmup)
        rows = summarise_fair(raw, methods)
        # Il confronto si fa sulle righe SENZA PERDITE, non su quelle a pieno
        # rate: a pieno rate si confrontano sistemi in sovraccarico, e chi ne
        # butta di piu' puo' sembrare piu' veloce.
        clean = [r for r in rows if r["phase"] == "zero-perdite"]
        rc |= check_validity([dict(method=r["method"], rx_pps=r["rx_pps"],
                                   unreliable=r["unreliable"],
                                   bottleneck=r.get("bottleneck"))
                              for r in (clean or rows)])
        _latency_verdict(rows)
        if a.out and rows:
            os.makedirs(a.out, exist_ok=True)
            # Anche i punti grezzi, non solo la mediana: la dispersione fra i
            # giri si legge solo da questi, ed e' cio' che dice se la mediana
            # significa qualcosa.
            for name, data in (("latency.csv", rows),
                               ("latency_raw.csv", raw)):
                if data:
                    _write_csv(os.path.join(a.out, name), data)
            write_env(a.out, env_finale())
            write_report(a.out, rows, env_finale(), a.loss_threshold,
                         "Throughput end-to-end e latenza, misurati")
            _give_back(a.out)
        # Il codice di uscita e' quello del controllo: un run in cui la
        # baseline non e' la piu' veloce, o in cui la dispersione sfonda, non
        # deve uscire 0 solo perche' il CSV e' stato scritto.
        return rc

    if a.mode == "generator":
        # Nessuna pipeline viene caricata: tutte le chiamate a build_pipeline
        # e _load_instrumented stanno dentro le ALTRE modalita', e questo ramo
        # ritorna prima di raggiungerle.
        raw = run_generator(
            frame=frames[0] if frames else 64, rates=sorted(_rates_from(a)),
            rounds=a.rounds, threads=plan.threads, plan=plan,
            threaded_napi=not a.no_threaded_napi, xmit_mode=a.xmit_mode,
            window_s=a.duration, warmup_s=a.warmup,
            threshold=a.loss_threshold, clone=a.clone_skb, burst=a.burst,
            rx_action=a.rx_action)
        if raw:
            _confronto_con_rates(a.out, max(r["rx_mpps"] for r in raw))
        if a.out and raw:
            os.makedirs(a.out, exist_ok=True)
            _write_csv(os.path.join(a.out, "generator_ceiling.csv"), raw)
            write_env(a.out, env_finale())
            _give_back(a.out)
        _closing_note(plan)
        return rc

    if a.mode == "rates":
        rates = _rates_from(a)
        raw = run_rates(
            methods, model_path, frame=frames[0] if frames else 64,
            rates=sorted(rates), rounds=a.rounds, threads=plan.threads,
            plan=plan, threaded_napi=not a.no_threaded_napi,
            xmit_mode=a.xmit_mode, threshold=a.loss_threshold,
            window_s=a.duration, warmup_s=a.warmup, topology=a.gen_topology,
            clone=a.clone_skb, burst=a.burst)
        if a.out and raw:
            os.makedirs(a.out, exist_ok=True)
            _write_csv(os.path.join(a.out, "rates_raw.csv"), raw)
            write_env(a.out, env_finale())
            _give_back(a.out)
        _closing_note(plan)
        return rc

    if a.mode == "compare":
        raw, rows = run_compare(
            methods, model_path, frames, offered_pps=a.offered_pps,
            threads=plan.threads, threshold=a.loss_threshold,
            repeat=a.repeat, rounds=a.rounds, plan=plan,
            topology=a.gen_topology, xmit_mode=a.xmit_mode,
            threaded_napi=not a.no_threaded_napi, diag_enabled=a.diag,
            window_s=a.duration, warmup_s=a.warmup, clone=a.clone_skb,
            burst=a.burst)
        # Il controllo "la baseline e' la piu' veloce" ha senso solo dove
        # l'RX e' una capacita', cioe' a massima spinta: nella fase confronto
        # tutte consegnano lo stesso rate per costruzione.
        # rxonly resta fuori: non e' una pipeline, e ha il suo controllo in
        # _rxonly_verdict.
        rc |= check_validity([r for r in rows
                              if r.get("phase") == "saturazione"
                              and r.get("method") != RX_ONLY] or rows)
        VERDICT.extend(RXONLY_FAILS)
        rc |= int(bool(RXONLY_FAILS))
        if a.out and (rows or raw):
            os.makedirs(a.out, exist_ok=True)
            if rows:
                _write_csv(os.path.join(a.out, "compare.csv"), rows)
            if raw:
                _write_csv(os.path.join(a.out, "compare_raw.csv"), raw)
            write_env(a.out, env_finale())
            # Sulle righe di SINTESI, cioe' sulle mediane dei giri: costruirlo
            # sulle righe grezze farebbe vincere il giro piu' fortunato, che a
            # rate offerto fisso e' esattamente l'errore da evitare.
            write_report(a.out, rows or raw, env_finale(), a.loss_threshold,
                         "Throughput end-to-end a carico identico")
            _give_back(a.out)
        _closing_note(plan)
        return rc

    for meth in methods:
        rc |= run_method(meth, model_path, frames, delays, a.count, rows,
                         clone=a.clone_skb, threads=plan.threads,
                         threshold=a.loss_threshold, repeat=a.repeat,
                         burst=a.burst, xmit_mode=a.xmit_mode,
                         threaded_napi=not a.no_threaded_napi, plan=plan,
                         topology=a.gen_topology, diag_enabled=a.diag,
                         offered_pps=a.offered_pps, window_s=a.duration,
                         warmup_s=a.warmup, tune=a.tune_generator,
                         search=a.search)

    # Il confronto si fa sulle righe a perdita nulla, non su quelle a pieno
    # rate: a pieno rate si confrontano sistemi in sovraccarico.
    clean = [r for r in rows if r.get("phase") == "zero-perdite"]
    rc |= check_validity(clean or rows)

    if a.out and rows:
        os.makedirs(a.out, exist_ok=True)
        _write_csv(os.path.join(a.out, "throughput.csv"), rows)
        write_env(a.out, env_finale())
        write_report(a.out, rows, env_finale(), a.loss_threshold)
        _give_back(a.out)

    _closing_note(plan)
    return rc


def _closing_note(plan):
    print(f"\n{YELLOW}{'=' * 78}{NC}")
    print(" Da ricordare leggendo questi numeri: TG, DUT e contatore stanno")
    print(" sulla STESSA macchina. Le CPU sono separate -- generatore su")
    print(f" {','.join(str(c) for c in plan.gen)}, DUT su "
          f"{','.join(str(c) for c in plan.dut)} -- quindi la perdita e'")
    print(" attribuibile, ma il costo del veth e della copia di headroom resta")
    print(" dentro la cifra. Il confronto fra pipeline regge; le cifre")
    print(" assolute sono di QUESTO percorso veth, non di una NIC.")
    print(f"{YELLOW}{'=' * 78}{NC}")


if __name__ == "__main__":
    sys.exit(main())