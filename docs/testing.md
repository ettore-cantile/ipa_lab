# Guida ai test — IPA/eBPF design space

Tre pipeline (P1 hardcoded, P2 template, P3 modular) verificate su due piani:

- **userspace** (numerico, PyTorch/NumPy e il C di P1 valutato dal testo) — estrazione dei pesi,
  quantizzazione, semantica delle classi, modelli sintetici, formule dei banchi;
- **kernel** — `BPF_PROG_TEST_RUN` sui programmi XDP reali (istruzioni, latenza, lookup,
  memoria, dispatch) e **traffico vero** su un fabric `veth` con XDP nativo (frame XDP grezzi
  da `xdp_gen`, pktgen come alternativa; contatori all'ingresso e all'uscita).

Tutti gli script di test vivono sotto `ipa/test/`; i comandi si eseguono dalla radice del
repository. Il motore sta in `ipa/`; i dati della topologia su cui il checkpoint depositato è
stato addestrato stanno in `topologies/germany50/`.

**Le cifre di questo documento vengono dalla campagna del 2026-10-06**
(`results/campagna_2026-10-06/`, sintesi in `sintesi.md`, log in `log/`), salvo T2−T1 sugli
assi (§10.8), dalla campagna del 2026-10-10 (`results/campagna_2026-10-10/`), sulla macchina e
nelle condizioni descritte in §0, con due script: `ipa/test/remeasure_campagna.sh` (il
traffico vero con `xdp_gen`, sui P-core, sugli E-core e sui LP E-core, e gli assi sotto
traffico) e `ipa/test/remeasure_all.sh` (tutto quello che non usa traffico vero, che la
campagna chiama nella sezione `kernel`). Le misure di traffico a un core e a due core sono
con l'alimentatore; gli assi sotto traffico (§10.8) e le misure `BPF_PROG_TEST_RUN` a
batteria, con la frequenza del banco misurata a 3,48–3,50 GHz e nessun throttling.

---

## 0. La macchina e le sue condizioni (`host_conditions.py`)

### 0.1 La macchina

| | |
|---|---|
| Macchina | Lenovo IdeaPad Slim 5 14IMH9 (83DA), BIOS N7CN32WW, alimentata da rete |
| CPU | Intel Core Ultra 7 155H, **ibrida**: P-core 0-11 (6 core fisici con SMT: coppie 0/5, 1/2, 3/4, 6/7, 8/9, 10/11), E-core 12-19, LP E-core 20-21 (fuori dalla L3) |
| Sistema | Ubuntu 24.04.4 LTS, kernel 6.8.0-142-generic, bare metal |
| Toolchain | clang 18.1.3, BCC 0.29.1, libbpf 1.3.0 (quella con cui si compila il loader AOT), bpftool 7.4 (con la sua libbpf 1.4) |
| Rete | nessuna scheda cablata: il datapath è un fabric `veth` (§3) |

Prerequisiti oltre a BCC: `sudo apt install clang libbpf-dev libelf-dev zlib1g-dev
libzstd-dev liblzma-dev` (l'oggetto AOT di P1 e il suo loader statico). Con `-target bpf`
clang non cerca `asm/types.h` nella cartella multiarch di Ubuntu: i flag BPF
(`p1_aot.BPF_CFLAGS`, `method4_hardcoded_aot.py`, `poc_aot/Makefile`) aggiungono
`-I/usr/include/<arch>-linux-gnu`.

### 0.2 Perché serve condizionare la macchina

Lasciato a sé stesso, questo portatile mette un processo dove capita (anche su un E-core),
fa girare desktop e browser sul fratello SMT del core che misura, cambia frequenza fra 0,4 e
4,8 GHz secondo carico e temperatura, e addormenta i core in C10 (risveglio 310 µs, più di
quanto il ring del `veth` — 256 descrittori — copra a 1 Mpps). E scalda: un solo P-core
salito a 4,5–4,8 GHz porta il pacchetto da 51 a 99 °C in due secondi, con centinaia di
eventi di throttling termico.

### 0.3 Che cosa fa `host_conditions.py`

Tutto reversibile e tutto scritto in `env.csv` accanto ai numeri.

| | |
|---|---|
| ruoli | DUT, uscita e generatore su P-core fisici **distinti**, un thread per core; il fratello SMT di ognuno resta a riposo; il core della CPU 0 resta al sistema. Fra i P-core vengono prima quelli con il turbo più basso (4,5 GHz): i due "preferiti" (1-4, 4,8 GHz) sono quelli che vanno in throttling |
| frequenza | sui core del banco e sui fratelli: governor `performance`, min = max = **3500 MHz** (`--freq`), poi **misurata** con APERF/MPERF |
| sistema | CPU del sistema con un tetto di 2500 MHz (`--system-max-mhz`): il loro turbo scalderebbe il pacchetto fino al throttling, che rallenta anche i core del banco |
| uncore | min = max = 3300 MHz (`--uncore`): L3 e anello non cambiano velocità a metà misura |
| idle | sulle CPU del banco spenti gli stati con uscita > 1 µs (C6, C10); restano POLL e C1E (`--cstate-max-us`) |
| isolamento | `user.slice`, `system.slice`, `init.scope` confinati sulle CPU del sistema (`AllowedCPUs`, runtime); sulle stesse CPU gli IRQ spostabili, le workqueue unbound e i kernel thread spostabili; il processo del banco in uno scope suo (`ipa-bench.slice`) |
| profilo | power-profiles-daemon su `performance` (`--profile`) |
| watchdog | NMI watchdog spento |

Con il piano automatico: **DUT cpu6, uscita cpu8, generatore cpu10, cpu1, cpu3**; fratelli a
riposo 2, 4, 7, 9, 11; sistema 0, 5, 12-21.

**I moduli degli E-core.** "Fratelli a riposo" sono tutte le CPU che dividono la L2 con una
CPU del banco (`cache/index2/shared_cpu_list`). Su un P-core è il fratello SMT; su un E-core
sono gli altri tre core del modulo (12-15, 16-19), che dividono con lui anche la frequenza.
Con il nodo su cpu12 restano a riposo 13-15: frequenza fissata con il banco, nessun
processo, nessun IRQ (§10.8).

**Il ripristino.** Ogni valore si salva in `/run/ipa-bench/host_state.json` prima di
cambiarlo. A fine run (anche con Ctrl-C, SIGTERM, SIGHUP o un'eccezione) si riscrive tutto
all'indietro. Un run ucciso con SIGKILL lascia il file: il run successivo ripristina per
primo, oppure `sudo python3 ipa/test/host_conditions.py --restore`.

**Il monitor.** Per finestra (colonne `host_*` di `bench_bitrate`) e per l'intero run
(`env.csv`): eventi di throttling di core e pacchetto, temperatura, frequenza reale del DUT
da APERF/MPERF, SMI, powerclamp, alimentazione; più un registro al secondo in
`host_monitor.csv`, scritto da un processo a parte. Una finestra con throttling, powerclamp,
batteria o frequenza del DUT fuori del 5% da quella misurata all'avvio è **disturbata**: si
conta e si riporta, non si scarta.

**La frequenza nel sysfs non è sempre quella vera.** Con min = max = 1400 MHz scritti nel
sysfs (la `base_frequency` dei P-core) il DUT gira stabilmente a **~2000 MHz** misurati
(1993–2003 su tutti i core del banco). Da 3000 MHz in su i due valori coincidono entro 10
MHz. Per questo il riferimento del monitor è sempre la frequenza **misurata** all'avvio, e
`env.csv` le riporta entrambe.

### 0.4 Perché 3500 MHz

Un giro da 30 s di `bench_bitrate` per frequenza, più due run completi (6 metodi, 5 giri,
~5 minuti), con il monitor di §0.3 acceso:

| frequenza reale | finestre disturbate | throttling | temperatura |
|---|---|---|---|
| 2,0 – 4,0 GHz, 30 s | 0/39 | 0 | 47–61 °C |
| 4,5 GHz, 30 s | **28/39** | 8 930 eventi | 65 °C |
| **run completo 4,0 GHz** | **11/260** | 219 sul **DUT** | registro fino a **98 °C** |
| **run completo 3,5 GHz** | **1/390** | 2 di pacchetto | registro max 85 °C |

A 4,5 GHz il throughput smette di crescere. A 4 GHz un run da 30 s è pulito, uno da 5
minuti no: il pacchetto arriva a 98 °C dopo ~100 s. **3500 MHz è la frequenza più alta che
la macchina regge per un run intero.**

La frequenza pesa quasi in proporzione, ma non del tutto: da 3 a 4 GHz il throughput sale
del 23% invece del 33%, perché la uncore è fissa e la cache condivisa e la memoria non
accelerano con il core. Il **rapporto fra pipeline** resta lo stesso a ogni frequenza pulita.
Le cifre assolute vanno citate insieme alla loro frequenza e al tipo di core (§10.8).

### 0.5 Comandi

```bash
python3 ipa/test/host_conditions.py --show           # topologia, piano, condizioni (niente root)
sudo python3 ipa/test/host_conditions.py --restore   # dopo un run ucciso
# un comando qualunque sul core del DUT, a condizioni applicate
sudo python3 ipa/test/host_conditions.py --run -- python3 ipa/test/test_suite.py --only kernel

python3 ipa/test/test_host_conditions.py             # 95 controlli su un /sys finto, niente root
sudo python3 ipa/test/test_host_kernel.py            # sul kernel vero: applica, misura, ripristina
sudo python3 ipa/test/test_host_kernel.py --bench    # + un giro corto di bench_bitrate

bash ipa/test/remeasure_campagna.sh                 # tutto (~1,5 h): traffico su P/E/LP E-core, assi (con T2−T1), kernel
bash ipa/test/remeasure_campagna.sh pcore ecore lpe # solo il traffico a massima spinta e le curve
bash ipa/test/remeasure_all.sh                      # solo BPF_PROG_TEST_RUN, fabric, modelli sintetici (~20 min)
```

`test_host_kernel.py` sul kernel vero: **25/25** con `--bench`. Rilegge dal kernel governor,
limiti, stati di idle, `AllowedCPUs`, IRQ e workqueue; verifica che un processo nuovo di
`user.slice` giri solo sulle CPU del sistema; misura che il DUT sotto carico tenga la
frequenza; confronta valore per valore la macchina prima e dopo il ripristino, anche dopo un
SIGKILL a condizioni applicate.

`bench_throughput` e `bench_bitrate` condizionano la macchina da soli (`--no-tune` per non
toccarla, `--freq`, `--no-isolate`, …: vedi `--help`). Gli altri banchi girano con
`host_conditions.py --run`.

---

## 1. Test locali (userspace) — nessun root, nessun kernel eBPF

Richiede `torch` e `numpy`: senza torch `test_suite.py` si ferma subito, e gira solo
`--only kernel`. Su Ubuntu 24.04 torch va installato in un virtualenv o con
`pip install --user --break-system-packages torch`.

```bash
python3 ipa/test/test_suite.py                    # extract + quant (kernel saltata senza BCC/root)
python3 ipa/test/test_suite.py --only quant       # accuratezza argmax vs scale_factor
python3 ipa/test/test_suite.py --only extract     # coerenza pesi / weights.json / dequant

python3 ipa/test/test_class_semantics.py          # 69 controlli, cinque layout di classi
python3 ipa/test/test_synth.py                    # 60 controlli sui modelli sintetici (58 senza torch)
python3 ipa/test/test_bitrate_math.py             # 100: formule e attribuzione di bench_bitrate
python3 ipa/test/test_steady_window.py            # 18: la finestra stazionaria (vedi sotto)
python3 ipa/test/test_host_conditions.py          # 95: ruoli, moduli E-core, applicazione e ripristino
python3 ipa/test/test_model_source.py             # 62: modelli, scenari, compatibilita', limiti delle pipeline
```

`test_steady_window` simula pktgen e i contatori del DUT con orologi veri: il controllo
"`loss_dut_pct` ~ 0 entro la coda in volo" (soglia 0,1%) esce a 0,11–0,16% su questa
macchina, perché fra la lettura del generatore e quella del DUT passa un tempo variabile.
È un limite della simulazione, non del banco: 17/18.

---

## 2. Test nel kernel (`--only kernel`)

Carica i programmi XDP reali ed esegue `BPF_PROG_TEST_RUN`: metriche del design space e
dispatch (redirect) per ogni TTL. La colonna **baseline** (parse + redirect, nessuna
inferenza) è il pavimento del framework XDP.

```bash
sudo python3 ipa/test/host_conditions.py --run -- python3 ipa/test/test_suite.py --only kernel
sudo python3 ipa/test/test_suite.py --only kernel --no-verify          # solo metriche
sudo python3 ipa/test/test_suite.py --only kernel --kernel-trials 15   # più trial
```

**Metodo.** Ogni pipeline gira `--kernel-trials` volte (default 7) e si riporta il
**minimo**: il rumore di sistema è a senso unico (interrupt e scheduling possono solo
rallentare un trial), lo stesso principio di hyperfine e Google Benchmark. La tabella
riporta anche p50, max e spread. Il frame si rinfresca ogni 200 esecuzioni partendo da TTL
255: `BPF_PROG_TEST_RUN` non ripristina il buffer, e il datapath decrementa il TTL.

Oltre al dispatch verifica:
- **corrispondenza di classe**: pre-installa `mac_table`, esegue e controlla che la classe
  scelta dal kernel sia quella del riferimento Python (`cls_stats[ref_cls] > 0`);
- **TTL**: TTL 5 esce a 4 con checksum valido, TTL 1 non viene inoltrato;
- **reroute su guasto**: con `link_state[k]=0` l'argmax cambia uscita (15/30 casi);
- **architetture alternative**: P1 `(8,)` e `(4,4,4)`; P2 65-6-5-7 e P3 65-5-6-4-7 registrati
  insieme al modello reale nello stesso oggetto.

**`ingress_iface`.** Le tre pipeline traducono l'ifindex del kernel in porta logica con una
mappa letta a runtime (`ingress_port`, `ingress_port_t2`, `ingress_port_t3`), riempita dal
piano di controllo con `common.ingress_port_slots`. Chiave = ifindex, valore = slot del
one-hot **1-based**, dove lo slot è il rango della porta fra quelle che il modello può
scegliere (`ClassSemantics.logical_ports`); la guardia nel datapath è `>= 1 && <= size`,
quindi l'assenza (0) si legge come "non è una mia porta". Sotto `BPF_PROG_TEST_RUN` il
sandbox espone `ingress_ifindex = 1` e nessuna porta risolve: il one-hot resta vuoto per
tutte e tre, e il riferimento dice la stessa cosa (`ref_ingress_port = 0`). La suite misura
quindi una configurazione in cui quella feature è spenta; il fabric (§3) la accende.

### P1 specializzata: le porte presenti sul nodo

`static_ports` dice al generatore di P1 quali colonne di `link_state` esistono davvero su
questo nodo: su un nodo di grado 3 su 6 `link_state[3..5]` vale sempre zero (quelle
interfacce non esistono) e quelle colonne non vengono generate. `link_state[i]` resta letto
a runtime per ogni porta che esiste; si congela la **struttura**. Solo la P1 specializzata
lo usa: il generatore rifiuta `static_ports` senza `static_node`, e `hardcoded` (P1.5) resta
identica byte per byte.

È esatto finché gli slot assenti valgono 0, e lo valgono per costruzione
(`link_state_monitor.carrier_state()` ritorna 0 per un'interfaccia che non esiste). Un banco
che semina tutti gli slot a 1 — come `verify_prog_run._seed_link_state` — fa divergere la
versione specializzata: chi confronta deve azzerare gli slot assenti nel riferimento.

```bash
sudo python3 ipa/test/bench_scaling.py --verify-ports      # equivalenza + controllo negativo
sudo python3 ipa/test/bench_scaling.py --axis degree --out results/
```

Esito: **80/80** casi identici (TTL 2-11 × 8 pattern realizzabili, porte {0,1,4}); accendendo
uno slot assente le due build divergono in **29** casi (seme 123 del pool), quindi il
controllo negativo morde e la condizione "slot assenti a 0" è portante.

**Asse `degree`** (65-4-4-7, stessi pesi in ogni punto):

| porte presenti | 2 | 3 | 4 | 5 | 6 |
|---|---:|---:|---:|---:|---:|
| `p1_static` istruzioni | 534 | 554 | 570 | 594 | 618 |
| `p1_static` latenza (ns) | 37 | 38 | 39 | 39 | 40 |

**~21 istruzioni per porta**, lineare; grado 2 contro grado 6: −14% di istruzioni e
**−3 ns** (−8%), con la latenza monotona. Fra grado 6 e grado 2 spariscono 16
moltiplicazioni-accumulo, circa 4,6 ns a 3,5 GHz se ne costasse una per ciclo: la misura
li vede. Il controllo regge: `hardcoded` 1 045, `template` 15 089, `modular` 12 288
istruzioni e latenze piatte (45–46, 188–193, 309–310 ns) su tutti e cinque i punti.

### Verifier standalone e semantica per modello

```bash
sudo python3 ipa/test/verify_prog_run.py --method hardcoded|template|modular   # 9/9 PASS, TTL 2-10
sudo python3 ipa/test/verify_multi_model.py                                     # PASS su P1/P2/P3
sudo python3 ipa/test/verify_per_model_semantics.py                             # 53/53 (§8-bis)
```

---

## 3. Il datapath reale (`netns_fabric.py`, `test_fabric.py`)

Il banco si costruisce con `veth` sull'host: una coppia per porta logica più un ingresso
dedicato, ognuna col peer che porta uno stub `XDP_PASS`.

```bash
sudo python3 ipa/test/netns_fabric.py --n-ports 5          # costruisci, mostra, smonta
sudo python3 ipa/test/netns_fabric.py --n-ports 5 --hold   # resta su, per deployarci sopra
sudo python3 ipa/test/netns_fabric.py --cleanup            # resti di un run ucciso
sudo python3 ipa/test/test_fabric.py                       # 29/29: P1/P2/P3, attach + redirect
sudo python3 ipa/test/test_fabric.py --method aot          # 11/11: la P1 come si deploya
sudo python3 ipa/test/test_fabric.py --sweep               # 34/34: cinque topologie + Germany50
```

`veth` supporta XDP **native**, quindi la modalità di attach è quella di deployment. Lo stub
sui peer serve: redirigere *verso* una veth passa da `veth_xdp_xmit()`, e il kernel alloca
le code che quel percorso richiede solo se il lato ricevente ha un programma XDP. Senza, il
redirect fallisce in silenzio e il pacchetto sparisce — identico a un modello che decide di
droppare tutto. L'ingresso è dedicato e non una porta logica: altrimenti una classe che
inoltra su quella porta rimanderebbe il frame fuori dall'interfaccia da cui è entrato, dove
la cattura non lo distingue da quello iniettato.

`test_fabric` inietta, cattura e confronta la decisione (`cls_stats`) con la porta d'uscita:
6 classi su 7 raggiunte (la settima è `UNUSED`, irraggiungibile per costruzione), DROP
verificato dal contatore e non dal silenzio.

Cosa la macchina regge lo dicono `python3 ipa/test/host_conditions.py --show` e
`sudo python3 ipa/test/test_host_kernel.py` (§0.5).

---

## 4. Attaccare una pipeline a un'interfaccia

Si attacca sull'interfaccia dove **entra** il traffico (XDP conta solo l'ingresso).

```bash
sudo python3 ipa/execute_pipeline.py --method template --iface ipain --model-id 0
sudo python3 ipa/execute_pipeline.py --method modular  --iface ipain --model-id 0
sudo python3 ipa/execute_pipeline.py --method hardcoded --iface ipain     # oggetto AOT
sudo python3 ipa/execute_pipeline.py --method hardcoded --verify-only     # solo il caricamento
sudo ip link set dev ipain xdp off                                         # un XDP rimasto appeso
```

Tutte e tre stampano `HIT | MISS | DROP` dal vivo e popolano `mac_table` (porta logica →
ifindex + MAC, da `NodeConfig`), `ingress_port`, `node_id` e `link_state` all'avvio con lo
**stesso** piano di controllo Python.

### P1: l'oggetto AOT è l'unico deploy

La P1 si deploya solo come oggetto AOT: build offline del `.o` (clang, sulla macchina di
build) e caricamento con `loader_aot`, linkato staticamente contro libbpf, sul nodo — che
non ha bisogno né di clang né di `libbpf.so`. BCC resta solo dentro i test.

Protocollo: `loader_aot --attach IFX --pin-dir /sys/fs/bpf/ipa_p1_<iface>` carica, collega
`model_progs`, pinna le mappe e stampa `READY`; il processo Python riempie le mappe (le
stesse funzioni di P2/P3, con `pinned_maps.PinnedObject`) e scrive `ATTACH`; il loader
attacca e stampa `ATTACHED`. Ctrl-C, `DETACH` o la morte del processo Python (EOF su stdin)
lo fanno staccare e togliere i pin. `--node-id` e `--ingress-port` sono opzioni del solo
bench.

```bash
python3 ipa/methods/method4_hardcoded_aot.py     # build del .o e del loader, come utente
sudo python3 ipa/methods/method4_hardcoded_aot.py  # bench: costo di deploy e per pacchetto
```

Il link statico di libbpf tira dentro anche `libelf`, `zlib`, `libzstd` e `liblzma`; lo
script prova la riga a 3 librerie e poi quella a 5. Il loader va costruito come utente
normale: file generati da root sotto `ipa/poc_aot/` fanno fallire un build successivo
(`sudo chown -R $USER:$USER ipa/poc_aot`).

`test_fabric --method aot` (11/11) prova la consegna del deploy vero: `mac_table` riletto
dopo il deploy con gli ifindex del fabric, le 5 classi FORWARD escono dalla porta attesa, la
classe DROP è contata e nulla esce, loader staccato con rc=0 e pin rimossi.

Le pipeline avviano il monitor `link_state` (polling del carrier reale delle interfacce
d'uscita). Dry-run senza eBPF:

```bash
sudo python3 ipa/link_state_monitor.py --ifaces eth0 eth1 eth2 eth3 eth4 eth5
```

---

## 5. Costo di aggiunta modello

Installare un modello nuovo su un nodo in servizio (`update_ms` di `bench_scaling`, §9):

| pipeline | sul nodo | una volta, fuori dal nodo o all'avvio |
|---|---|---|
| P1, P1.5 | carica l'oggetto AOT già compilato: **0,4–2,2 ms** (sul modello standard `open` 0,08 + verifica e JIT 0,97 ms) | clang, **57–121 ms**, sulla macchina di build |
| P2 | scrive in mappa pesi, descrittore e semantica: **10–12 ms** | BCC compila il programma generico: ~1,5 s |
| P3 | come P2: **10–11 ms** | ~1,2 s |

Nessun compilatore sul nodo per nessuna pipeline. La differenza che resta è qualitativa: P1
vuole un compilatore (sulla macchina di build) per ogni modello nuovo, P2 e P3 nessuno.
Limiti: `MAX_WEIGHT_ENTRIES=1024` in P2 (3 modelli dell'architettura 65-4-4-7),
`MAX_LAYER_WEIGHT_ENTRIES=2048` in P3 (6).

---

## 6. Larghezza contro profondità in P1 (`bench_depth_vs_width.py`)

P1 supporta un numero variabile di hidden layer. A parità di budget-pesi, conviene allargare
un layer o aggiungerne uno?

```bash
sudo python3 ipa/test/host_conditions.py --run -- python3 ipa/test/bench_depth_vs_width.py
```

**Metodo.** Tre tier a budget abbinato (A ~300, B ~1 200, C ~4 700 pesi), per ciascuno una
forma larga e tre profonde, con la larghezza **risolta per descrittore** perché il budget
sia centrato (lo scarto è stampato). Quattro descrittori (`default` 2 one-hot,
`big_onehot` una grande, `small_onehot` una piccola, `no_onehot` nessuna). Minimo su 7
trial. Ogni cella in un subprocess: un abort di clang o un rifiuto del verificatore marca
solo quella cella.

**Tier A (~300 pesi)**, ns/pacchetto:

| descrittore | n_in | larga | 2 layer | 4 layer | 8 layer |
|---|---:|---:|---:|---:|---:|
| `default` (2 one-hot) | 65 | **39** | 44 | 48 | 62 (+59%) |
| `big_onehot` (1 grande) | 59 | **33** | 40 | 50 | 56 (+70%) |
| `small_onehot` (1 piccola) | 13 | 83 | **72** | 82 | 86 |
| `no_onehot` (0) | 11 | 93 | 90 | 85 | **83 (−11%)** |

**Tier B (~1 200 pesi)**, ns/pacchetto:

| descrittore | n_in | larga | 2 layer | 4 layer | 8 layer |
|---|---:|---:|---:|---:|---:|
| `default` (2 one-hot) | 65 | **105** | 145 | 165 | 211 (+101%) |
| `big_onehot` (1 grande) | 59 | **116** | 139 | 166 | 209 (+80%) |
| `small_onehot` (1 piccola) | 13 | *stack* | 302 | 291 | **286** |
| `no_onehot` (0) | 11 | *stack* | *stack* | 330 | **295 (−11%)** |

*stack*: clang si ferma (abort di LLVM, stack eBPF oltre 512 byte). **Tier C (~4 700
pesi)**: nessuna forma compila, per lo stesso motivo.

**Che cosa dicono.**
1. Con un ingresso grande e dominato da one-hot (`default`, `big_onehot`, il caso di IPA)
   allargare batte approfondire: +59–70% a 8 strati a 300 pesi, +80–100% a 1 200.
2. Con un ingresso piccolo e denso (`no_onehot`) è il contrario: la versione a 8 strati è
   **più veloce dell'11%** e più piccola (1 323 contro 1 490 istruzioni a 300 pesi). Una
   one-hot costa poco perché il datapath ne legge una colonna; un ingresso denso moltiplica
   le letture per la larghezza del primo strato. La risposta dipende da com'è fatto il
   vettore d'ingresso.
3. Ogni neurone nascosto aggiunge tre istruzioni sempre eseguite (la ReLU senza salto,
   §8): le forme profonde le pagano tutte.
4. Oltre ~1 200 pesi il limite di P1 è lo stack, e ci arriva prima la forma larga (più
   valori intermedi vivi insieme).

---

## 7. Il costo del tail call (`bench_tailcall_overhead.py`)

Due varianti minime con lo stesso parse e lo stesso redirect, l'unica differenza è un hop
`PROG_ARRAY`: `xdp_baseline` contro `xdp_baseline_dispatch → xdp_baseline_action`.

```bash
sudo python3 ipa/test/host_conditions.py --run -- python3 ipa/test/bench_tailcall_overhead.py
```

| variante | min | mediana | max (ns) |
|---|---:|---:|---:|
| baseline (0 tail call) | 9 | 10 | 12 |
| baseline + 1 tail call | 10 | 11 | 11 |

**+1 ns per salto.** Il salto in sé costa quasi niente: quello che P3 paga per strato (§9) è
il resto — le letture di mappa che ricostruiscono il contesto a ogni hop.

---

## 8. Architetture alternative dentro `--only kernel`

`suite_kernel()` chiama anche `verify_alt_architectures()`: P1 con `(8,)` e `(4,4,4)`
compilati separatamente, verificati contro `ref_infer_sparse` (5/5 ciascuna); P2 65-6-5-7 e
P3 65-5-6-4-7 registrati **insieme** al modello reale nello stesso oggetto (PASS).

**Perché la ReLU non ha salti.** Scritta `x > 0 ? x : 0`, la ReLU diventa un salto
condizionale per neurone, e il verificatore esplora entrambi i lati di ciascuno senza
riuscire a riunirli: a tre strati nascosti `arch_generic_2layer` di P2 verrebbe rifiutato
(`BPF program is too large. Processed 1000001 insn`, `E2BIG`) pur avendo solo 16–18 000
istruzioni. `ipa_relu` calcola `x & ~(x >> 63)`: nessun salto, stesso risultato bit per bit.
Una barriera `asm volatile("")` impedisce a clang di riconoscere `smax(x, 0)` e di rifarne
un salto (senza, i salti tornano tutti). `diag_verifier.py` confronta le due scritture con
le statistiche del verificatore (`log_level = 4`):

```bash
sudo python3 ipa/test/diag_verifier.py      # variante `attuale` contro `salto`
```

| P2, istruzioni percorse (limite 1 000 000) | 1 strato | 2 | 3 | 4 | 5 | 6 |
|---|---:|---:|---:|---:|---:|---:|
| ReLU con salto (`salto`) | 799 563 | 417 292 | *rifiutato* | *rifiutato* | *rifiutato* | *rifiutato* |
| ReLU senza salto (`ipa_relu`) | 120 452 | 120 557 | 127 906 | 127 738 | 134 413 | 136 642 |

In P3 la stessa scelta porta `layer_hidden` da 186 489 a 27 979 istruzioni percorse e
`layer_first` da 27 183 a 26 755 (`diag_verifier.py --only p3`). Tutte e tre le pipeline usano
`ipa_relu`.

**Il limite di profondità** (larghezza 4, descrittore default). Il verificatore non è il
vincolo: 154 811 istruzioni percorse a 10 strati, 201 528 a 20 (~4 700 per strato).
Il primo muro è la **distanza di salto**: le istruzioni di salto eBPF hanno un offset a
16 bit (±32 767 istruzioni), e i controlli iniziali che escono con `XDP_PASS` saltano fino in
fondo al programma. A 20 strati il leaf ha 32 388 istruzioni e compila; a 37 e 50 clang si
ferma (`LLVM ERROR: Branch target out of insn range`). Il secondo muro è la tabella dei pesi
(`MAX_WEIGHT_ENTRIES` = 1 024): ogni strato in più costa `n_h2² + n_h2` pesi, quindi 37 strati
al massimo a larghezza 4 e 7 a larghezza 8, il soffitto `T2_MAX_H2`. Dichiarare le
larghezze a runtime `__u64` invece di `__u32` aiuta poco (490 044 a uno strato), e
azzerare anche i neuroni oltre la larghezza con una maschera fa sforare a clang lo stack
BPF: non servono.

---

## 8-bis. Semantica delle classi per modello

In P2 e P3 la tabella `class_action` ha chiave `(model_id, class_id)`: un programma solo per
architettura serve modelli con semantiche indipendenti.

```text
model_id ─► arch_registry / layer_registry   (lookup hash)
              {pesi, forma, n_out, sem_bank}
                  │
            inferenza P2/P3
                  │
               class_id
                  │   chiave = (model_id·2 + sem_bank)·32 + class_id
                  ▼
            class_action[chiave] ─► azione ─► porta logica ─► mac_table
```

- **Array, non hash**: `class_action_t2/_t3` è un `BPF_ARRAY` di 256 × 2 × 32 righe; il
  lookup resta uno, O(1) nel numero di modelli.
- **Perché non dentro l'entry del registry**: indicizzarne il valore con `best_cls` è
  aritmetica sul puntatore, e il verificatore dovrebbe tracciare `best_cls` con precisione
  attraverso l'argmax; `layer_hidden` di P3 non caricherebbe (`E2BIG`). Una chiave sullo
  stack no.
- **Due banchi per modello**: ricaricare un `model_id` scrive il banco inattivo, poi un solo
  update del registry installa insieme `n_out` e `sem_bank`. Un pacchetto vede la coppia
  vecchia o la nuova, mai una tabella scritta a metà.
- **La chiave senza allungare ciò che resta vivo**: in P2 subito dopo il lookup del registry
  (`sem_key0`); in P3 dentro `last_key`, che sostituisce `is_last` (bit 31 = ultimo strato,
  bit bassi = prima riga del banco), perché `layer_first` sta al limite dei 512 byte di
  stack nelle build strumentate.

```bash
sudo python3 ipa/test/verify_per_model_semantics.py [--pipeline p2|p3]
```

**Correttezza: 53/53** su P2 e P3 (casi A–F, ricaricamento R, rimozione). Controllo
negativo: con una tabella condivisa simulata A e B passano e C, D, F, R falliscono.

| Caso | Che cosa verifica |
|---|---|
| A | un modello: ogni classe dà l'azione dichiarata |
| B | due modelli, stessa semantica |
| C | semantiche diverse su **ogni** classe, pacchetti alternati (classe 0: FORWARD per A, DROP per B) |
| D | A, poi B, poi A; anche dopo aver ricaricato B |
| E | `model_id` mai registrato, o rimosso: non elaborato |
| F | `n_out` diversi (4 e 7): ogni argmax limitato dal proprio `n_out` |
| R | stesso `model_id` ricaricato con altra semantica e altro `n_out` (banco 0→1, altri intatti) |

**Costo per pacchetto**: nessuno misurabile. La chiave `(model_id, classe)` è una lettura come
la chiave per sola classe: 11 lookup in P2 e 29 in P3, e da 1 a 8 modelli registrati la
latenza non cambia. **Memoria: +131 072 byte per pipeline**, fissi: 256 `model_id` × 2
banchi × 32 classi preallocati. L'alternativa a pochi KB (uno slot per modello allocato dal
piano di controllo, come `weight_offset`) non è implementata.

---

## 9. Analisi parametrica (`bench_scaling.py`)

Come cambia il costo al variare della dimensione, e se le pipeline hanno **pendenze
diverse**.

**Quattro pipeline**, una scala di specializzazione:

| | cosa è compilato dentro | un binario per |
|---|---|---|
| `p1_static` | pesi **e** indice di questo nodo | **nodo** |
| `hardcoded` (P1.5) | pesi; il nodo si legge da mappa | modello |
| `template` (P2) | solo i soffitti | tutto |
| `modular` (P3) | anche la profondità è a runtime | tutto |

```bash
sudo python3 ipa/test/host_conditions.py --run -- python3 ipa/test/bench_scaling.py --axis all --out results/
sudo python3 ipa/test/host_conditions.py --run -- python3 ipa/test/bench_scaling.py --axis campaign --out results/
python3 ipa/test/bench_scaling.py --plot results/        # le figure (basta matplotlib)
```

I CSV citati in questa sezione sono in `results/campagna_2026-10-06/kernel/`
(`scaling_<asse>.csv`, `model_scaling_test_suite.csv`).

```bash
sudo python3 ipa/test/bench_scaling.py --verify          # 80/80: la P1 congelata decide come la P1.5
```

| asse | valori | fermo a |
|---|---|---|
| `nodes` | 10, 25, 52, 75, 100 nodi | `MAX_N_IN` = 128 in P2/P3 |
| `depth` | 1…6 hidden layer | — |
| `isoparam` | 1…5 hidden layer a **parametri fermi** (592 ± 2%) | famiglia a imbuto dentro i soffitti |
| `width` | 2, 4, 6, 8 neuroni | soffitto compilato 8 in P2 e P3 |
| `descriptor` | 4 composizioni del vettore d'ingresso | — |
| `sparsity` | 0, 25, 50, 75, 90% di pesi zero | — |
| `degree` | 2…6 porte presenti | §2 |

**Metodo.** Ogni cella in un subprocess (un abort di clang o un rifiuto del verificatore è
un dato, stampato `RIFIUTATO` o `CRASH`). Pesi da un pool fisso presi come prefisso: un
modello più grande **estende** il più piccolo, perché in P1 il conteggio istruzioni dipende
dai valori. Allarme di contaminazione: se lo stesso programma (stesse istruzioni e tail call)
varia oltre 2× lungo un asse, lo scarto è la macchina.

### Risultati per asse (latenza min, ns/pacchetto; istruzioni)

**`nodes`** (10 → 100 nodi):

| | 10 | 25 | 52 | 75 | 100 |
|---|---:|---:|---:|---:|---:|
| `p1_static` istruzioni | 602 | 611 | 618 | 602 | 603 |
| `hardcoded` istruzioni | 731 | 824 | 1 045 | 1 443 | 1 673 |
| `p1_static` ns | 40 | 40 | 41 | 42 | 39 |
| `hardcoded` ns | 46 | 45 | 46 | 47 | 46 |
| `template` ns | 189 | 188 | 192 | 188 | 189 |
| `modular` ns | 310 | 312 | 312 | 317 | 317 |

La taglia della rete entra nel programma solo in P1.5 (lo `switch` sulla one-hot del nodo si
srotola); congelando il nodo la dipendenza sparisce. A runtime nessuna pendenza: una one-hot
legge una sola colonna di pesi qualunque sia la sua larghezza.

**`depth`** (1 → 6 hidden layer):

| | 1 | 2 | 3 | 4 | 5 | 6 |
|---|---:|---:|---:|---:|---:|---:|
| `p1_static` ns | 33 | 41 | 46 | 50 | 56 | 61 |
| `hardcoded` ns | 40 | 46 | 51 | 57 | 61 | 67 |
| `template` ns | 171 | 193 | 220 | 241 | 270 | 300 |
| `modular` ns | 260 | 317 | 370 | 422 | 467 | 524 |
| `template` istruzioni | 14 604 | 15 089 | 16 813 | 16 945 | 17 939 | 18 937 |
| `modular` istruzioni | 12 288 | 12 288 | 12 288 | 12 288 | 12 288 | 12 288 |

**P3 ~53 ns per strato a istruzioni identiche**: srotola un layer generico e ci rientra con
un tail call, quindi la profondità non entra nel programma e si paga in tempo (tail call e
letture di mappa). **P2 ~26 ns per strato** e ~870 istruzioni: lo strato in più è codice in
linea. P1 ~6 ns per strato.

**`width`** (neuroni per hidden layer 2 → 8):

| | 2 | 4 | 6 | 8 |
|---|---:|---:|---:|---:|
| `p1_static` | 26 | 41 | 52 | 68 |
| `hardcoded` | 34 | 46 | 60 | 75 |
| `template` | 178 | 192 | 203 | 216 |
| `modular` | 280 | 314 | 343 | 386 |

Allargare i layer nascosti si paga su tutte: *la rete può crescere quanto vuole, il modello
no.*

**`isoparam`** (592 ± 2% parametri, 1 → 5 hidden layer):

| | 1 | 2 | 3 | 4 | 5 |
|---|---:|---:|---:|---:|---:|
| `p1_static` | 56 | 54 | 57 | 67 | 68 |
| `hardcoded` | 62 | 64 | 63 | 72 | 71 |
| `template` | 175 | 190 | 207 | 254 | **268 (+53%)** |
| `modular` | 284 | 328 | 358 | 445 | **490 (+73%)** |

A parità di parametri le due P1 crescono poco e non in modo monotono (+15–20% fra gli
estremi); P2 cresce del 53% e P3, a istruzioni identiche in tutti e cinque i punti, del 73%.

**`descriptor`** — istruzioni:

| | default | no_onehot | small_onehot | big_onehot |
|---|---:|---:|---:|---:|
| `p1_static` | 618 | 611 | 604 | 518 |
| `hardcoded` | 1 045 | 611 | 604 | 931 |
| `template` / `modular` | 15 089 / 12 288 | ← | ← | ← |

Cambiare la composizione del vettore d'ingresso ricompila P1, mentre P2 e P3 leggono il
descrittore da `model_desc`. È anche il **controllo** della specializzazione: dove il
descrittore non dichiara la feature `node` le due P1 sono identiche alla cifra (611/611,
604/604); dove la dichiara divergono.

**`sparsity`** (frazione di pesi zero):

| | 0% | 25% | 50% | 75% | 90% |
|---|---:|---:|---:|---:|---:|
| `p1_static` istruzioni | 618 | 564 | 484 | 401 | **243** |
| `hardcoded` istruzioni | 1 045 | 923 | 840 | 672 | **337** |
| `p1_static` ns | 40 | 36 | 28 | 23 | 19 |
| `hardcoded` ns | 45 | 41 | 35 | 31 | 25 |
| `template` / `modular` ns | 188 / 307 | 187 / 310 | 187 / 310 | 187 / 311 | 188 / 310 |

I pesi di P1 sono letterali nel C, quindi clang cancella i prodotti per zero: al 90% di zeri
P1 perde più di metà della latenza, mentre per P2/P3 uno zero è un byte in mappa come un
altro. Le due P1 convergono (il divario scende da 427 a 94 istruzioni): sparsità e nodo
congelato sono due strade alla stessa riduzione. Sotto traffico vero lo stesso (§10.8): al
90% di zeri P1 passa da 113 a 95 ns di CPU per pacchetto, P2 e P3 restano fermi.

### Congelare il nodo: P1 specializzata contro P1.5

| | 10 nodi | 52 nodi (Germany50) | 100 nodi |
|---|---:|---:|---:|
| istruzioni `p1_static` / `hardcoded` | 602 / 731 | 618 / 1 045 (−41%) | 603 / 1 673 (−64%) |
| codice nativo (B) | 2 709 / 3 332 | 2 754 / 5 112 (−46%) | 2 692 / 8 325 (−68%) |
| latenza (ns) | 40 / 46 | 41 / 46 (−11%) | 39 / 46 (−15%) |

La riga della specializzata è **piatta**: la feature più grossa del modello (52 dei 65
ingressi, 208 dei 319 pesi) smette di dipendere dalla taglia della rete. In tempo il
guadagno c'è ma è piccolo (5–7 ns): lo `switch` ha N casi ma ne esegue uno. Il prezzo è un
binario per nodo: `build_ms` ~70 ms (p1_static) e ~75-115 ms (hardcoded) per compilazione,
N volte su una rete di N nodi. Aggiornare il modello sul nodo (oggetto AOT già compilato)
costa ~1 ms per entrambe.

### Aggiornare il modello

`update_ms` (installare un modello nuovo su un nodo in servizio): P1 e P1.5 **0,4–2,2 ms**
(caricamento dell'oggetto AOT), P2 e P3 **10–12 ms** (scritture in mappa, compresa la
semantica). `build_ms` (una volta): P1 57–121 ms di clang sulla macchina di build, P2
~1,5 s e P3 ~1,2 s di BCC all'avvio del nodo. Nessun divario di ordini di grandezza fra le
pipeline: resta la differenza qualitativa, P1 richiede un compilatore (fuori dal nodo) per
ogni modello nuovo (§5).

### Campagna sulle architetture (`--axis campaign`)

Quattro assi, cinque pipeline inclusa la baseline, un CSV: `model_scaling_test_suite.csv`.

| Asse | Valori | Cosa muove |
|---|---|---|
| `iv_dense` | n_in 5, 9, 13, 17 | colonne d'ingresso dense |
| `iv_onehot` | n_in 16, 32, 65 | colonne d'ingresso in una one-hot |
| `width_camp` | 65-v-v-7, v = 4, 8, 16, 32 | neuroni per strato |
| `depth_camp` | 65-8…8-7, 1–4 strati | profondità a larghezza 8 |

Retta ai minimi quadrati sui quattro assi insieme:

| Pipeline | ns / MAC **eseguita** | r² | ns / MAC nominale | r² |
|---|---:|---:|---:|---:|
| p1_static | 0,287 | **0,99** | 0,071 | 0,63 |
| hardcoded | 0,292 | **0,98** | 0,076 | 0,69 |
| template | 0,574 | 0,71 | 0,092 | 0,24 |
| modular | 1,195 | **0,92** | 0,106 | 0,10 |

Con le MAC nominali il modello spiega poco; con quelle **eseguite** i quattro assi
collassano sulla stessa retta. Una one-hot occupa `size` colonne nella matrice dei pesi ma
nel datapath ne attiva una: contarla come `size × h1` sovrastima. **P3 costa 4,2× P1 per
MAC eseguita**: il prezzo di leggere i pesi da una tabella invece che averli come letterali.
Il template ha r² più basso perché ha un costo fisso alto rispetto alla pendenza, e il suo
residuo più grande sta su `width_camp`, dove i neuroni oltre la larghezza del modello
vengono calcolati comunque fino al soffitto.

L'asse `iv_onehot` lo mostra direttamente: n_in ×4, pesi ×2,4, latenza piatta su tutte
(p1_static e hardcoded 65/63/64, template 169/168/170, modular 361/364/367 ns) mentre le
istruzioni di P1 vanno da 1 099 a 1 587.

I muri: larghezza 16 e 32 su P2/P3 sfondano `T2_MAX_H1`/`ML1_MAX_H1` = 8 e il banco segna
`RIFIUTATO` prima di compilare (P3 risponderebbe `XDP_PASS` a runtime, cioè una misura di un
programma che non calcola). Larghezza 16 su P1 carica (166 ns p1_static, 171 hardcoded);
larghezza 32 non compila (stack).

**Calibrazione contro la suite kernel**, stesso modello 65-4-4-7: campagna 14 / 45 / 187 /
308 ns contro `test_suite` 14 / 52 / 194 / 318 ns (baseline, hardcoded, template, modular):
entro 0 / −13%, sempre nello stesso verso, e i programmi non sono identici (pesi sintetici
contro pesi del modello: 1 045 contro 1 019 istruzioni per P1.5).

---

## Risultati (kernel, `test_suite.py --only kernel`, modello 65→4→4→7, scala 24)

Un solo run (campagna del 2026-10-06, sezione `kernel`), sotto `host_conditions`, DUT a
3,49 GHz misurati, a batteria senza throttling; minimo su 7 trial con p50/max. P1 è la
specializzata (nodo 7 compilato dentro), P1.5 l'oggetto che si deploya.

| Metrica | baseline | P1 (p1_static) | P1.5 hardcoded | P2 template | P3 modular |
|---|---:|---:|---:|---:|---:|
| Istruzioni eBPF (xlated) | 135 | 606 | 1 019 | 15 089 | 12 288 |
| Codice jited (byte) | 625 | 2 700 | 5 000 | 68 307 | 57 501 |
| Tail call / pacchetto | 0 | 1 | 1 | 1 | **3** |
| Map lookup / pacchetto | 3 | 5 | 6 | 11 | **29** |
| Memoria mappe (byte) | 1 960 | 4 196 | 4 196 | 147 624 | 177 452 |
| **Latenza min (ns/pkt)** | **14** | **46** | **52** | **194** | **318** |
| ...p50 | 15 | 47 | 52 | 195 | 324 |
| ...max | 15 | 47 | 52 | 196 | 327 |
| ...spread (max−min)/min | 7% | 2% | 0% | 1% | 3% |
| Throughput teorico (Mpps, 1/latenza) | 71,4 | 21,7 | 19,2 | 5,2 | 3,1 |

| | dispatcher | leaf |
|---|---|---|
| baseline | — | `xdp_baseline` 135 |
| P1 (p1_static) | `xdp_dispatch` 29 | `xdp_model` 577 |
| P1.5 hardcoded | `xdp_dispatch` 29 | `xdp_model` 990 |
| P2 template | `ipa_switch_template` 41 | `arch_generic_2layer` 15 048 |
| P3 modular | `modular_dispatcher` 137 | `layer_first` 10 475 + `layer_hidden` 1 676 |

Correttezza, stesso run: dispatch TTL 2-6 **5/5** su tutte e quattro (P1, col nodo 7 compilato
dentro, decide la classe 1; le altre, senza nodo, la 2); TTL (decremento + checksum +
scadenza) **2/2** su tutte e quattro; `link_state` reroute **15/30** casi di link-down
cambiano uscita; architetture alternative (P1 65-8-7 e 65-4-4-4-7, P2 65-6-5-7, P3
65-5-6-4-7) PASS. Aggiornamento del modello di P1 sul nodo (open + caricamento dell'oggetto
AOT): **0,6–0,9 ms**.

**P1 contro P1.5**: 413 istruzioni in meno (lo switch sui 52 nodi della one-hot sparisce),
una lettura di tabella in meno (`node_id`), **6 ns** in meno. L'analisi parametrica, con
pesi sintetici, dà 5–7 ns (§9). La memoria delle mappe per-CPU si conta una volta per CPU
(22): da qui 1 960 byte per la baseline.

### La dimensione non predice la velocità

**P3 ha il 19% di istruzioni in meno di P2 ed è il 64% più lento** (12 288 contro 15 089;
318 contro 194 ns). Le righe che lo spiegano: **3 tail call** contro 1, **29 lookup** contro
11. Il conteggio `xlated` misura quanto è grande il programma, non quanto lavora.

P2 è più grande perché tiene la rete intera in un programma: `arch_generic_2layer` srotola
insieme fc1 (65→8), fc2 (8×8) e lo strato d'uscita (32×8, i soffitti). P3 srotola **un**
layer denso generico (`layer_hidden`, 1 676 istruzioni) e ci rientra per tail call a ogni
hop: la profondità non costa dimensione, e il riuso si paga in latenza (un salto più le
letture di `scratch_meta`, `scratch_acts`, `layer_shapes`, i pesi).

Le istruzioni sono un conteggio **statico**: in P1.5 lo switch della one-hot `node` ha 52
casi e ne esegue uno, e con i pesi letterali clang cancella i prodotti per zero e trasforma
in shift le potenze di due. 1 019 istruzioni in 52 ns sarebbero 5,6 istruzioni per ciclo a
3,5 GHz, sopra ogni processore reale: il percorso eseguito è una frazione del conteggio. In
P1 lo switch non c'è (606 istruzioni). I contatori hardware del traffico vero (§10.8) dicono
quante istruzioni si eseguono davvero.

### I soffitti compilati e il verificatore

In P3 il soffitto delle code (`IPA_MAX_QUEUES`) cambia le istruzioni senza cambiare il
percorso eseguito quando il descrittore non dichiara la feature coda:

| `IPA_MAX_QUEUES` | 1 | 2 | 4 | **8** |
|---|---:|---:|---:|---:|
| `layer_first` (istruzioni) | 7 003 | 7 628 | 8 729 | **10 528** |
| esito | carica | carica | carica | carica |

Il control plane protegge il soffitto: `load_modular_weights` rifiuta un descrittore che
chieda più slot di coda di quanti il datapath ne compili, invece di troncarlo.

**Istruzioni e complessità di verifica sono valute diverse.** Il verificatore percorre ogni
cammino del corpo srotolato, e il costo cresce col **prodotto** dei soffitti: con soffitti
larghi (`8 × 4 × 128`) P2 si ferma a `processed 1000001 insns (limit 1000000)` con ~14 900
istruzioni, cioè dentro il limite di dimensione ma oltre quello di complessità: lo stesso
limite che una ReLU con il salto farebbe toccare a P2 già a tre strati (§8). Questi limiti
sono scogliere, non pendenze: un soffitto si cambia e **si rimisura**.

BCC riporta i rifiuti come `Program too large (N insns), at most 4096 insns`: il 4096 è una
costante vecchia nella stringa d'errore di BCC (P2 carica a ~15 000). Va letto come "il
verificatore ha rinunciato". Il numero nel messaggio d'errore è il conteggio **grezzo** prima
del caricamento, quello delle tabelle è **xlated**: non vanno confrontati.

### I lookup si contano su tutte e quattro

La riga "Map lookup / pacchetto" viene da build strumentate con un contatore su ogni sito di
lookup (`count_lookups`): 6 siti per la baseline, 13 per P1 e 14 per P1.5 (oggetti AOT), 21
per P2 (`arch_generic_2layer` 19), 34 per P3 (`layer_first` 11, `layer_hidden` 6,
`ml_argmax_forward` 12, `modular_dispatcher` 3). P1.5 fa 6 letture per pacchetto, una delle
quali è `node_id`: il prezzo di far dire alla one-hot del nodo *quale nodo è questo*. P1 ne
fa 5, perché il nodo è compilato dentro.

### L'oggetto AOT di P1 (`method4_hardcoded_aot.py`)

| | |
|---|---|
| build offline (clang → `.o`) | 78 ms, una volta, sulla macchina di build |
| deploy sul nodo | **1,06 ms** (`open` 0,08 + verifica e JIT 0,97) |
| istruzioni | 1 019 (dispatch 29 + modello 990) |
| latenza | **52 ns/pkt** (percorso d'inoltro, retval 4), come in `test_suite` |

La strength reduction sui pesi letterali resta dentro l'oggetto, quindi il costo per pacchetto
non peggiora, e il compilatore sparisce dal nodo.

**L'indice del nodo cambia la decisione.** L'oggetto AOT non può portarsi dentro l'indice
del nodo: arriva al caricamento da `--node-id` o `$IPA_NODE_ID`. Lo stesso binario con e
senza `--node-id 7` sceglie classi diverse: la feature `node` (208 pesi su 319) contribuisce
davvero. Senza `--node-id` la one-hot resta spenta (la mappa è un `HASH`: il default è "non
lo so", non "sono il nodo 0").

---

## 10. Throughput end-to-end (`bench_throughput.py`)

Le cifre di throughput delle sezioni precedenti sono `1/latenza` sotto `BPF_PROG_TEST_RUN`:
picchi teorici. Qui un generatore produce traffico vero, la pipeline XDP lo elabora e lo
redirige, e un contatore XDP sull'interfaccia d'uscita conta quanti sono arrivati. Il
generatore è **`xdp_gen`** (`ipa/test/xdp_gen.py`): frame XDP grezzi da `BPF_PROG_TEST_RUN` in
modalità live frames, consegnati al DUT come da una NIC con XDP nativo. L'alternativa,
pktgen, è in §10.5.

### 10.1 Il banco

```
xdp_gen (cpu10) ──veth ipatg0p→ipatg0──► [XDP: pipeline] (DUT, cpu6)
    ──bpf_redirect──► ipaN ──veth──► ipaNp [XDP: contatore d'uscita] (cpu8)
```

- **CPU separate**: il thread di `xdp_gen` pinnato sulla CPU del generatore, il thread NAPI
  del DUT (`/sys/class/net/<dev>/threaded`) pinnato sulla CPU del DUT, l'uscita in thread su
  CPU sue (`--egress-cpu N|N,M|auto`): con una lista, la coda d'uscita del core i-esimo del DUT
  va sulla CPU i-esima; `auto` prende un core fisico libero per ogni core del DUT, finché ce ne
  sono (su questa macchina uno solo, cpu3 o cpu8: il core di cpu0 resta al sistema).
- **Una coda d'ingresso e un thread di generatore per core del DUT** (`--dut-queues auto`). Il
  redirect di `xdp_gen` nel veth sceglie la coda del DUT come CPU che trasmette modulo numero
  di code: un thread per coda, su CPU di resto diverso. Più scrittori sulla stessa coda
  (`veth` è LLTX, il `ptr_ring` serializza i produttori col suo `producer_lock`) la svuotano
  più lentamente e rallentano anche il core del nodo (§10.3). Il banco avvisa se due thread
  cadono nella stessa coda.
- **Una coda d'uscita per core del DUT** (`--egress-queues auto`). Stessa regola in uscita: `auto` sceglie il numero minimo di code per cui i core del DUT cadono in
  code diverse (con i core 6 e 8 sono 3: 6 → 0, 8 → 2; con 2 code cadrebbero entrambi nella
  0). Con un core del DUT è 1. `env.csv` riporta la mappa (`code_uscita`). Perché serve:
  §10.4.
- **Una chiamata per finestra.** Ogni chiamata a `test_run` in modalità live parte e finisce
  con una pausa del thread di ~12 ms dentro il kernel: con più chiamate per finestra il
  generatore tacerebbe una parte del tempo e il DUT svuoterebbe la coda e dormirebbe. La
  finestra è quindi una sola chiamata, interrotta da un segnale a fine misura
  (`STEADY_CALL_FRAMES`); le statistiche di scheduling del thread NAPI del DUT
  (`napi_run_pct`, §11.3) confermano che a coda piena il nodo lavora il 100% del tempo.
- **Tempo di CPU per pacchetto** (colonne `cpu_dut_pct`, `ns_cpu`, `ns_cpu_vs_baseline`):
  l'occupazione dei core del DUT letta da `/proc/stat` **nella stessa lettura** dei contatori
  della finestra stazionaria, × core / elaborati. Con il DUT al 100% coincide con
  1e9 / elaborati, ed è così in tutte le misure di questa sezione. La diagnostica è attiva per
  default (`--no-diag` la spegne); risoluzione ~3% (un jiffy di 10 ms su ~300 ms di finestra).
- **Istruzioni e cicli per pacchetto** (colonne `instr_pkt`, `cycles_pkt`, `ipc`, …): i
  contatori hardware dei core del nodo e dell'uscita, nella stessa lettura (§10.8).
- **Contatori per-CPU**: `pkt_stats` e `cls_stats`, in tutte le pipeline e nella baseline,
  sono `PERCPU_ARRAY`: ogni core incrementa la sua copia, senza istruzioni atomiche e senza
  contendersi una riga di cache quando i pacchetti arrivano su più code. I lettori sommano i
  core (`ipa/stats_maps.py`).
- **Tre punti di conteggio**: TX (tentativi del generatore), HIT (`pkt_stats[0]` della
  pipeline), RX (contatore d'uscita). TX − HIT è ciò che non è arrivato al programma, HIT − RX
  ciò che il programma ha elaborato e non è uscito.
- **Finestra stazionaria**: i rate sono differenze fra due letture dei contatori fatte mentre
  il generatore trasmette (lettura sotto 3 ms, rifatta se più lunga), poi stop. Avvio e coda
  finale restano fuori.
- **model_id 190**: il generatore scrive in testa al payload l'intestazione di pktgen (magic
  `0xbe9be955`), dove il dispatcher legge `ipa->model_id`. Il modello è registrato anche su
  190 e una sonda verifica HIT prima di misurare.
- **La coda del veth**: `VETH_RING_SIZE` = 256 descrittori, non configurabile su questo
  kernel (`ethtool -g` non la espone).

### 10.2 Saturazione con xdp_gen (`--mode compare --generator xdp`)

```bash
bash ipa/test/remeasure_campagna.sh pcore       # tutte le misure di questa sezione sul P-core
# un core, un thread di generatore, uscita su un core suo
sudo python3 ipa/test/bench_throughput.py --mode compare --generator xdp --rounds 3 \
    --gen-cpus 10 --dut-cpus 6 --egress-cpu 8 --out results/pcore_compare
sudo python3 ipa/test/bench_throughput.py --mode compare --generator xdp --rounds 3 \
    --gen-cpus 10 --dut-cpus 6 --egress-cpu 8 --per-class --out results/pcore_per_class
```

Costo del nodo = **tempo di CPU per pacchetto** (§10.1): dalla presa dalla coda di ricezione
alla decisione e al redirect, con l'uscita su una CPU sua (cpu8). Nodo su cpu6 a 3,5 GHz,
alimentatore, macchina non disturbata (`results/campagna_2026-10-06/pcore/compare/`):

| | elaborati (Mpps) | respinti | nodo occupato | **ns di CPU** | sopra la baseline | cicli / pk | istruzioni / pk | IPC |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| rxonly | 19,47 | 1% | 79% | 41 (non satura) | — | 161 | 384 | 2,4 |
| baseline | 15,27 | 0,4% | 100% | **66** | — | 225 | 606 | 2,7 |
| p1_static | 8,56 | 26% | 100% | **117** | **+51** | 402 | 1 220 | 3,0 |
| hardcoded | 8,04 | 29% | 100% | **124** | **+58** | 432 | 1 426 | 3,3 |
| template | 3,45 | 71% | 100% | **290** | **+224** | 1 013 | 4 556 | 4,5 |
| modular | 2,36 | 81% | 100% | **425** | **+359** | 1 483 | 6 573 | 4,4 |

**Il nodo lavora il 100% del tempo, e 1e9 / elaborati coincide con il tempo di CPU.** I
cicli per pacchetto coincidono con ns × 3,5 GHz (baseline 225 contro 231, P3 1 483 contro
1 487). Controllo di validità PASS (la baseline è la più veloce delle pipeline); l'ordine
P1 < P1.5 < P2 < P3 regge in ogni giro.

- **La baseline satura appena**: il generatore ne offre 15,3 Mpps, quanti il nodo ne regge.
  **rxonly non satura** (il nodo è al 79%): il suo tempo di CPU è indicativo.
- **P3 varia fra sessioni** più delle altre: lo stesso 65-4-4-7 dà 416–445 ns in misure
  diverse della stessa giornata (§10.8), con IPC fra 4,2 e 4,5.
- **Sotto capacità nessun respinto**: lo mostrano le curve (§11.6).
- **Taglia del frame**: 64 / 512 / 1514 B danno lo stesso costo entro l'1% su ogni pipeline
  (`pcore/frames/`): baseline 65–66, P1 118–120, P1.5 126–127, P2 284–287, P3 418–419 ns.
  Il nodo tocca solo le intestazioni.
- **Per classe** (`pcore/per_class/`, stato dei link e TTL cercati per ciascuna delle 6 classi
  raggiungibili, classe decisa verificata), ns di CPU:

  | | classi FORWARD (0–4) | classe DROP (5) | differenza |
  |---|---:|---:|---:|
  | P1 | 118–120 | 166 | +46–48 |
  | P1.5 | 124–127 | 176 | +49–52 |
  | P2 | 245–274 | 304 | +30–59 |
  | P3 | 416–426 | 467 | +41–51 |

  **Scartare costa ~50 ns più che inoltrare.** Con il DROP la pagina del pacchetto si
  restituisce sul core del nodo, con l'inoltro sul core d'uscita. L'IPC dello scarto è più
  basso (P1 1,8 contro 2,9–3,0).

**Il controllo di validità conta gli elaborati, non gli arrivati.** Se l'uscita non tiene il
passo del nodo si perde dopo XDP, e contando gli arrivati la pipeline più veloce sembrerebbe
la più lenta. `check_validity` confronta `node_pps` (elaborati, altrimenti HIT, altrimenti
RX), la stessa grandezza del costo.

### 10.3 Uno scrittore per coda

Il redirect di `xdp_gen` nel veth sceglie la coda del DUT come CPU che trasmette modulo
numero di code. Più thread sulla stessa coda (`veth` è LLTX, il `ptr_ring` serializza i
produttori col suo `producer_lock`) la svuotano più lentamente: lucchetto dei produttori e
righe di cache condivise passano da un core all'altro a ogni pacchetto, e il costo per
pacchetto sale anche per il core del nodo, tanto più quanto la pipeline è leggera.

**La regola**: un solo scrittore per coda, in ingresso e in uscita. Su un core del nodo è
**1 thread di generatore, uscita su un core suo** (§10.2). Con N core del nodo: N code
d'ingresso con un thread ciascuna, N code d'uscita (`--egress-queues auto`) e un core
d'uscita per coda (`--egress-cpu N,M`), §10.4. Il banco lo controlla: avvisa se due thread
finiscono sulla stessa coda e se più core del nodo inoltrano nella stessa coda d'uscita.

**Con una scheda di rete vera il problema non c'è.** La coda di ricezione la riempie la
scheda (DMA), e il core del nodo la svuota: un solo scrittore per costruzione. Resta il
fenomeno che conta: se il nodo è più lento del traffico la coda si riempie e la scheda
scarta (`rx_missed` in `ethtool -S`), cioè la perdita all'ingresso di §11. Con RSS ogni
coda ha il suo core e sempre un solo scrittore.

### 10.4 Due core: una coda e un core d'uscita per core

Il redirect sceglie anche la coda d'uscita come CPU che inoltra modulo numero di code: con
una coda sola i due core del nodo scriverebbero nello stesso `ptr_ring`, svuotato da un solo
thread NAPI d'uscita, che per ricevere, contare e restituire la pagina alla page_pool del
generatore spende ~70 ns a pacchetto. Per questo ogni core del nodo ha la sua coda d'uscita
(`--egress-queues auto`) e la sua CPU d'uscita.

```bash
sudo python3 ipa/test/bench_throughput.py --mode compare --generator xdp --rounds 3 \
    --gen-cpus 10,1 --dut-cpus 6,8 --egress-cpu 3,5 --out results/pcore_cores2      # 2 P-core
sudo python3 ipa/test/bench_throughput.py --mode compare --generator xdp --rounds 3 \
    --gen-cpus 10,1 --dut-cpus 12,16 --egress-cpu 6,8 --out results/ecore_cores2    # 2 E-core
```

Mpps elaborati (`pcore/cores2/`, `ecore/cores2/`), ns di CPU per core fra parentesi:

| | 1 P-core | **2 P-core** | % del doppio | 1 E-core | **2 E-core** | % del doppio |
|---|---:|---:|---:|---:|---:|---:|
| baseline | 15,27 (66) | **29,11 (67)** | 95 | 9,39 (106) | **19,09 (105)** | 102 |
| P1 | 8,56 (117) | **17,46 (114)** | 102 | 6,35 (158) | **12,74 (157)** | 100 |
| P1.5 | 8,04 (124) | **16,19 (124)** | 101 | 5,84 (171) | **11,71 (171)** | 100 |
| P2 | 3,45 (290) | **6,63 (301)** | 96 | 2,83 (354) | **5,60 (357)** | 99 |
| P3 | 2,36 (425) | **4,60 (434)** | 98 | 1,94 (515) | **3,84 (521)** | 99 |

**Due core elaborano il 95–102% del doppio di uno**, e il costo per core è quello di un core
entro 11 ns. Il numero da riportare per un nodo con N code è ~N × la capacità a 1 core,
finché il generatore e la scheda reggono. Il banco verifica la mappa coda → core d'uscita a
fine run (`thread NAPI d'uscita che hanno lavorato`). rxonly su due E-core dà il 117% del
doppio: riguarda solo il riferimento di sola ricezione, il più variabile fra i giri (11%).

### 10.5 L'alternativa: pktgen

`--generator pktgen` (richiesto da `--latency`, `--mode saturate` e `--mode generator`) usa i
thread `kpktgend_<cpu>` del kernel. pktgen crea skb con 64 byte di headroom; XDP su veth ne
pretende 256, quindi `veth_xdp_rcv_skb` **copia** ogni pacchetto prima del programma, sul
core del nodo, e la sola ricezione si ferma intorno a 4,6 Mpps. Su una NIC con XDP nativo la
copia non c'è: per questo il banco usa `xdp_gen`, e le cifre di questo documento sono tutte
con `xdp_gen`.

### 10.6 Tre marcature: la pipeline separata dal trasporto (`--mode rates`)

```bash
sudo python3 ipa/test/bench_throughput.py --mode rates --generator xdp --frames 64 --rounds 3 \
    --gen-cpus 10 --dut-cpus 6 --rates 0.05,0.5,1,1.5,2,2.5,3 --out results/pcore_rates
```

Build **strumentata**: il dispatcher marca T1, il programma marca T2 subito prima di
`bpf_redirect`, il contatore d'uscita T3. I timbri stanno in mappe per-CPU, quindi l'uscita
resta in softirq sulla CPU del DUT (niente `--egress-cpu`). T3−T1 al rate più basso è la
latenza minima arrivo → ripartenza.

Vale per qualunque modello: con `--model` la build strumentata passa da `pipeline_setup`,
lo stesso percorso di `--mode compare` (forma del modello, foglia di P2 per la sua
profondità, strati di P3, ingressi che portano a un inoltro), con i timbri inseriti nei
sorgenti. Senza `--model`, il checkpoint configurato. `rates_raw.csv` riporta per ciascuna
delle tre misure minimo, media, massimo e i percentili (bordi dei bucket log2): il minimo è
il caso migliore, la media il costo tipico con le mancate di cache, il massimo dice se una
sola attesa lunga sta spostando la media.

Minimi per finestra, mediana fra tre giri, da 0,5 a 3 Mpps (`pcore/rates/`, `ecore/rates/`):

| | baseline | P1 | P1.5 | P2 | P3 |
|---|---:|---:|---:|---:|---:|
| T2−T1, la sola pipeline, P-core (ns) | **26** | **60** | **69** | **216** | **331** |
| sopra la baseline | — | +34 | +43 | +190 | +305 |
| T3−T2, redirect + veth + ricezione (ns) | 206 | 207 | 208 | 218 | 222 |
| T3−T1 a 50 kpps, latenza minima (ns) | 221 | 259 | 274 | 442 | 609 |
| T2−T1 su E-core (ns) | 28 | 72 | 84 | 266 | 434 |
| T3−T2 su E-core (ns) | 240 | 243 | 240 | 253 | 256 |
| T3−T1 a 50 kpps su E-core (ns) | 282 | 329 | 346 | 555 | 727 |

T2−T1 è piatto sul rate (a 50 kpps qualche ns in più: cache più fredda). Il trasporto T3−T2 è
un costo comune di ~210 ns sul P-core (~245 sull'E-core) che non dipende dalla pipeline. Sul
E-core la sola pipeline costa dal 7% (baseline) al 31% (P3) in più.

**Il throughput di questa modalità non è una capacità.** Con la build strumentata e l'uscita
sulla CPU del DUT la coda d'ingresso respinge a rate più bassi che in §10.2. Le capacità sono
quelle di §10.2; la build strumentata aggiunge due letture dell'orologio e due scritture per
pacchetto.

### 10.7 Latenza arrivo → ripartenza

Con `xdp_gen` è T3−T1 al rate più basso di `--mode rates` (§10.6): **221 / 259 / 274 / 442 /
609 ns** sul P-core, sopra la baseline +38 / +53 / +221 / +388. `--latency` è il percorso con
pktgen (build strumentata, il dispatcher marca l'arrivo, il programma d'uscita rilegge e
sottrae). Solo il minimo è una misura: p50 e p99 vengono da un istogramma a potenze di due.
La **ricerca del rate a perdita nulla** disperde oltre il 25% fra i giri, perché al confine
basta un'esitazione di pochi µs per perdere un pacchetto: non è una cifra citabile; la
saturazione sì.

### 10.8 Il nodo sui core lenti, e le istruzioni per ciclo

**La domanda.** Quanto cambiano capacità e saturazione se il nodo gira su un E-core
(Crestmont) o su un LP E-core invece che su un P-core (Redwood Cove)? E perché: più cicli
per pacchetto a parità di istruzioni (IPC più basso), o anche più istruzioni?

**Il disegno: cambia solo il core del nodo.** Generatore (cpu10) e uscita (cpu8) restano su
P-core a 3500 MHz in tutte le configurazioni a un core: il generatore satura qualunque nodo, e
l'uscita non diventa il collo di bottiglia. L'E-core gira alla **stessa frequenza** del P-core
(3500 MHz; il suo massimo è 3800), quindi il rapporto fra le capacità è il rapporto fra i
cicli per pacchetto. Il LP E-core (fuori dalla L3, sul tile SoC) si ferma al suo massimo, 2500
MHz: `host_conditions` taglia la frequenza chiesta al massimo del core.

| | nodo | uscita | generatore | a riposo |
|---|---|---|---|---|
| P-core | cpu6 | cpu8 | cpu10 | 7, 9, 11 |
| E-core | cpu12 | cpu8 | cpu10 | 9, 11, **13-15** |
| LP E-core | cpu20 | cpu8 | cpu10 | 9, 11, **21** |
| 2 P-core | cpu6, 8 | cpu3, 5 | cpu10, 1 | fratelli SMT |
| 2 E-core | cpu12, 16 (un modulo ciascuno) | cpu6, 8 | cpu10, 1 | 13-15, 17-19, fratelli SMT |

I compagni di modulo degli E-core restano a riposo (§0.3): dividono L2 e frequenza con il
nodo.

**Istruzioni e cicli per pacchetto** (`ipa/test/hw_counters.py`). Un contatore hardware per
(CPU, evento) sui core del nodo e dell'uscita, in tutta la CPU (`perf_event_open`, pid −1,
utente + kernel, *pinned*): conta il thread NAPI, il programma XDP, gli interrupt, cioè
quello che il tempo di CPU attribuisce al pacchetto. Sui processori ibridi l'evento si apre
sul PMU del tipo di core (`cpu_core` / `cpu_atom`). Si legge **nella stessa lettura** dei
contatori dei pacchetti della finestra stazionaria, come `/proc/stat`. Con il watchdog NMI
spento nessun evento è multiplexato; uno multiplexato si scarta. Colonne in `compare.csv`,
`throughput_summary.csv`, `per_class.csv` e `bitrate.csv`:

| colonna | |
|---|---|
| `instr_pkt` | istruzioni per pacchetto elaborato, sui core del nodo |
| `cycles_pkt` | cicli non fermi per pacchetto: a frequenza fissa = ns di CPU × GHz |
| `ipc` | istruzioni per ciclo |
| `llc_miss_pkt`, `br_miss_pkt` | mancate dell'ultimo livello di cache, salti previsti male |
| `dut_ghz_busy` | cicli / (durata × core): frequenza × occupazione; al 100% è la controprova di APERF/MPERF |
| `egress_cycles_pkt`, `egress_ipc` | lo stesso per il core d'uscita, per pacchetto elaborato |

Valgono dove il nodo è saturo: sotto, i cicli contano anche l'attesa in POLL fra un pacchetto
e l'altro (le curve di §11 le riportano per ogni rate, da leggere solo oltre il ginocchio).
`--no-hw` li spegne. Le istruzioni per pacchetto non sono quelle del verificatore (§2): ci
sono dentro anche ricezione veth, redirect e restituzione della pagina.

**Risultati** (`results/campagna_2026-10-06/{pcore,ecore,lpe}/compare/`, alimentatore,
frequenza misurata 3 496 / 3 493 / 2 498 MHz):

| | P-core Mpps | E-core Mpps | LP E-core Mpps | E/P | ns CPU P / E / LP E | istruzioni / pk | IPC P / E / LP E |
|---|---:|---:|---:|---:|---:|---:|---:|
| rxonly | 19,47 | 12,78 | 4,11* | 0,66 | 41 / 78 / 176 | 384 / 368 / 398 | 2,4 / 1,4 / 0,9 |
| baseline | 15,27 | 9,39 | 3,29* | 0,61 | 66 / 106 / 283 | 606 / 607 / 620 | 2,7 / 1,7 / 0,8 |
| P1 | 8,56 | 6,35 | 3,10 | 0,74 | 117 / 158 / 322 | 1 220 / 1 223 / 1 225 | 3,0 / 2,3 / 1,5 |
| P1.5 | 8,04 | 5,84 | 2,91 | 0,73 | 124 / 171 / 343 | 1 426 / 1 430 / 1 432 | 3,3 / 2,4 / 1,7 |
| P2 | 3,45 | 2,83 | 1,57 | 0,82 | 290 / 354 / 636 | 4 556 / 4 556 / 4 557 | 4,5 / 3,7 / 2,9 |
| P3 | 2,36 | 1,94 | 1,10 | 0,82 | 425 / 515 / 908 | 6 573 / 6 573 / 6 576 | 4,4 / 3,7 / 2,9 |

\* rxonly e baseline sul LP E-core non saturano (nodo al 72% e al 93%): il generatore offre
solo 4,1 e 3,3 Mpps. Le loro cifre sono un limite inferiore della capacità.

**Che cosa dicono.**
1. **Le istruzioni per pacchetto sono le stesse su ogni core** (entro il 2%): il codice
   eseguito non cambia. Cambiano i cicli, cioè l'IPC.
2. **L'E-core paga soprattutto la parte fissa del nodo.** Ricezione veth, redirect e
   restituzione della pagina (la baseline) hanno IPC 2,7 sul P-core e 1,7 sull'E-core: +60%
   di tempo. L'aritmetica lineare della rete neurale tiene IPC alti su entrambi (P3 4,4 e
   3,7): l'inferenza di P3 sopra la baseline costa solo il 14% in più (409 contro 359 ns).
   Per questo il rapporto di capacità sale da 0,61 (baseline) a 0,82 (P2, P3).
3. **Il LP E-core** è fuori dalla L3: ha 14–19 mancate dell'ultimo livello di cache per
   pacchetto (P-core ed E-core ~0), perché i pacchetti scritti dal generatore gli arrivano
   dalla memoria. Con 2,5 GHz e IPC 0,8–2,9 regge il 36–47% del P-core sulle pipeline.
4. **Due E-core reggono il doppio di uno** (99–102%, §10.4), come due P-core.

**Saturazione** (le curve di §11.6 sull'E-core): stesso andamento del P-core, con il
ginocchio alla capacità dell'E-core (P1 6,2, P1.5 5,8, P2 2,8, P3 1,9 Mpps inoltrati) e la
perdita sempre all'ingresso. A basso carico il ritardo mediano è 12–16 µs, a coda piena
29–148 µs.

**Gli assi parametrici sotto traffico** (`ipa/test/traffic_models.py`). Larghezza (65-v-v-7,
v = 2…8), profondità (65-4×d-7, d = 1…6), pari pesi (le cinque forme a ~592 pesi di §9) e
sparsità (65-4-4-7 al 0 / 50 / 90 % di pesi a zero) sono cartelle di modello sintetico,
stesso descrittore del checkpoint, che `bench_throughput --model <cartella>` misura con
`xdp_gen`. Il seme è lo stesso per tutti i punti, salvo dove quel seme dà un modello che
decide DROP in ogni stato dei link per il pacchetto del generatore (width_6, depth_4,
isoparam_3: seme successivo). Per ogni punto la campagna misura anche T2−T1, la sola
pipeline con la build strumentata (§10.6), a 0,3 e 0,6 Mpps (`<punto>/rates/`; `ASSI_RATES`,
`ASSI_T2=0` per saltarla). Tre assi hanno una rete diversa per punto, scritta accanto al
modello (`<cartella>/topology_config.json`, passata con `--topology`): **nodi** ((13+n)-4-4-7,
n = 10, 25, 52, 75, 100: cambia solo la one-hot del nodo), **ingressi densi** (n-8-8-7,
n = 5, 9, 13, 17: `link_state`(k) + `queue_occupancy`(k) + ttl, ogni colonna moltiplicata) e
**ingressi one-hot** (n-8-8-7, n = 16, 32, 65: `node`(n−5) + ttl + `queue_occupancy`(4)).
L'asse one-hot di §9 allarga `ingress_iface`; sul fabric una rete con più di 8 interfacce
sfonda `IPA_MAX_IFACES`, quindi qui si allarga la one-hot del nodo, che nel datapath è la
stessa aritmetica (h1 addizioni a ogni larghezza). Prima degli assi la campagna misura T2−T1
del checkpoint agli stessi rate (`assi_<core>core/checkpoint/rates/`), e la sintesi rifà la
retta del costo per MAC eseguita (§9) sulle medie T2−T1 di ingressi densi, one-hot, larghezza
e profondità. ns di CPU
per pacchetto (`assi_Pcore/`, `assi_Ecore/`), P-core / E-core:

| profondità | 1 | 2 | 3 | 4 | 5 | 6 |
|---|---:|---:|---:|---:|---:|---:|
| P1 | 113 / 148 | 116 / 156 | 119 / 160 | 124 / 166 | 125 / 170 | 132 / 176 |
| P1.5 | 121 / 162 | 128 / 170 | 131 / 176 | 132 / 182 | 134 / 183 | 138 / 189 |
| P2 | 264 / 328 | 287 / 355 | 329 / 394 | 344 / 403 | 368 / 442 | 396 / 470 |
| P3 | 351 / 447 | 421 / 517 | 486 / 591 | 545 / 665 | 595 / 730 | 652 / 801 |

| larghezza | 2 | 4 | 6 | 8 |
|---|---:|---:|---:|---:|
| P1 | 104 / 142 | 115 / 156 | 124 / 168 | 145 / 187 |
| P1.5 | 114 / 155 | 124 / 170 | 138 / 181 | 158 / 199 |
| P2 | 282 / 340 | 295 / 359 | 301 / 372 | 315 / 394 |
| P3 | 391 / 496 | 445 / 519 | 452 / 555 | 496 / 588 |

| pari pesi (strati) | 1 | 2 | 3 | 4 | 5 |
|---|---:|---:|---:|---:|---:|
| P1 | 128 / 173 | 125 / 169 | 130 / 172 | 135 / 182 | 135 / 183 |
| P1.5 | 137 / 183 | 141 / 185 | 144 / 186 | 148 / 195 | 147 / 194 |
| P2 | 276 / 340 | 299 / 365 | 318 / 379 | 368 / 439 | 373 / 446 |
| P3 | 380 / 476 | 433 / 537 | 480 / 595 | 581 / 705 | 607 / 740 |

| pesi a zero | 0% | 50% | 90% |
|---|---:|---:|---:|
| P1 | 113 / 154 | 104 / 143 | 95 / 132 |
| P1.5 | 120 / 168 | 112 / 157 | 106 / 143 |
| P2 | 295 / 357 | 298 / 354 | 298 / 355 |
| P3 | 420 / 517 | 424 / 523 | 423 / 514 |

La baseline resta a 64–67 ns (P-core) e 105–107 ns (E-core) in ogni punto. Gli andamenti
sono quelli di §9 più il costo fisso del nodo: P3 paga **~60 ns per strato** (~70
sull'E-core), P2 ~26; a parità di pesi P2 sale del 35% e P3 del 60% da 1 a 5 strati, le P1
restano quasi ferme; i pesi a zero accelerano solo P1 e P1.5. Le istruzioni per pacchetto
lo confermano: P3 cresce di esattamente **1 096 istruzioni per strato** (5 488 → 10 952), su
entrambi i tipi di core; P2 di 300–600 a strato, a passi irregolari perché srotola e
ricompila; a pesi a zero le istruzioni di P1 scendono da 1 210 a 939 e quelle di P2 e P3 non
cambiano. Sull'E-core ogni punto costa il 20–35% in più.

**La sola rete neurale sotto traffico (T2−T1).** Per ogni punto la campagna misura anche
T2−T1 con la build strumentata (§10.6), a 0,3 e 0,6 Mpps, tre giri: il minimo per finestra
(il pacchetto che trova tutto in cache) e la media (il costo tipico), mediana fra giri e rate,
meno la stessa misura della baseline. Accanto, il programma da solo (`BPF_PROG_TEST_RUN`,
§9, minimo su 7 prove, meno la baseline). Campagna del 2026-10-10
(`results/campagna_2026-10-10/assi_*/<punto>/rates/`), a batteria come gli assi di sopra.
ns di rete neurale per pacchetto, P-core, da solo / minimo / media:

| profondità | 1 | 2 | 3 | 4 | 5 | 6 |
|---|---:|---:|---:|---:|---:|---:|
| P1 | 19 / 26 / 40 | 27 / 34 / 46 | 32 / 36 / 55 | 36 / 42 / 56 | 42 / 45 / 62 | 47 / 48 / 59 |
| P1.5 | 26 / 35 / 60 | 32 / 42 / 55 | 37 / 46 / 62 | 43 / 52 / 75 | 47 / 54 / 75 | 53 / 58 / 84 |
| P2 | 157 / 180 / 214 | 179 / 196 / 252 | 206 / 227 / 264 | 227 / 238 / 267 | 256 / 272 / 324 | 286 / 292 / 356 |
| P3 | 246 / 262 / 322 | 303 / 312 / 348 | 356 / 374 / 436 | 408 / 408 / 509 | 453 / 461 / 560 | 510 / 508 / 610 |

Media T2−T1 sugli altri assi, P-core / E-core (da solo fra parentesi):

| larghezza | 2 | 4 | 6 | 8 |
|---|---:|---:|---:|---:|
| P1 | 25 / 56 (12) | 40 / 52 (27) | 61 / 64 (38) | 79 / 100 (54) |
| P1.5 | 46 / 54 (20) | 58 / 80 (32) | 80 / 92 (46) | 97 / 103 (61) |
| P2 | 236 / 237 (164) | 233 / 270 (178) | 248 / 287 (189) | 275 / 318 (202) |
| P3 | 363 / 409 (266) | 363 / 432 (300) | 394 / 474 (329) | 457 / 525 (372) |

| pari pesi (strati) | 1 | 2 | 3 | 4 | 5 |
|---|---:|---:|---:|---:|---:|
| P1 | 54 / 64 (42) | 72 / 68 (40) | 60 / 80 (43) | 76 / 92 (53) | 76 / 88 (54) |
| P1.5 | 70 / 79 (48) | 79 / 94 (50) | 88 / 92 (49) | 86 / 104 (58) | 90 / 123 (57) |
| P2 | 232 / 250 (161) | 234 / 308 (176) | 258 / 280 (193) | 336 / 342 (240) | 319 / 354 (254) |
| P3 | 328 / 380 (270) | 390 / 443 (314) | 430 / 502 (344) | 539 / 630 (431) | 574 / 661 (476) |

| pesi a zero | 0% | 50% | 90% |
|---|---:|---:|---:|
| P1 | 42 / 50 (26) | 34 / 38 (14) | 23 / 42 (5) |
| P1.5 | 58 / 76 (31) | 48 / 50 (21) | 37 / 40 (11) |
| P2 | 260 / 272 (174) | 274 / 254 (173) | 224 / 265 (174) |
| P3 | 380 / 441 (293) | 387 / 426 (296) | 364 / 442 (296) |

| profondità, E-core | 1 | 2 | 3 | 4 | 5 | 6 |
|---|---:|---:|---:|---:|---:|---:|
| P1 | 38 / 58 | 42 / 48 | 50 / 73 | 56 / 76 | 58 / 77 | 66 / 87 |
| P1.5 | 55 / 68 | 58 / 79 | 61 / 78 | 68 / 91 | 72 / 92 | 79 / 99 |
| P2 | 212 / 230 | 240 / 281 | 278 / 322 | 289 / 309 | 326 / 358 | 356 / 374 |
| P3 | 340 / 368 | 404 / 433 | 478 / 514 | 542 / 573 | 625 / 656 | 688 / 718 |

Sul P-core il **minimo** sotto traffico coincide con il programma da solo (P3 e P2
entro 30 ns, P1 e P1.5 entro 12): la misura di §9 descrive il pacchetto che trova cache e
predittori caldi. La **media** sta sopra di 10–40 ns per P1 e P1.5 e di 40–110 ns per P2 e
P3, con gli stessi andamenti su ogni asse (P3 ~50 ns per strato, al 90% di zeri dimagriscono
solo P1 e P1.5). Sull'E-core lo scarto è circa doppio (P3 110–210 ns, P2 75–130). Sul
checkpoint la media di T2−T1 sopra la baseline (P1 44, P2 229, P3 364 ns,
`results/prova_t2_ckpt/`) coincide con il tempo di CPU per pacchetto meno la baseline di
§10.2 (51, 224, 359): due misure indipendenti dello stesso costo.

**Un caricamento sfavorevole.** In un run P3 a 1 strato sull'E-core ha dato 502 ns di
minimo, stabile su sei finestre, con le altre pipeline nella norma; un nuovo caricamento ha
dato 368 ns, in linea con la curva. La disposizione del codice in memoria cambia a ogni
caricamento e può spostare P3 di un terzo: un punto fuori curva si rifà
(`ASSI_SOLO=<punto> ASSI_CORES=<core>`) prima di citarlo.

**Nodi della rete e composizione dell'ingresso.** Stessa campagna (2026-10-10), una rete per
punto. ns di rete neurale per pacchetto (tempo di CPU meno la baseline), P-core / E-core, e fra
parentesi la media T2−T1 sul P-core:

| nodi della rete | 10 | 25 | 52 | 75 | 100 |
|---|---:|---:|---:|---:|---:|
| P1 | 49 / 52 (42) | 52 / 51 (48) | 49 / 50 (45) | 48 / 48 (40) | 45 / 50 (35) |
| P1.5 | 59 / 66 (58) | 57 / 62 (58) | 58 / 64 (46) | 55 / 64 (58) | 55 / 63 (52) |
| P2 | 221 / 264 (242) | 237 / 252 (258) | 235 / 255 (228) | 230 / 251 (231) | 232 / 250 (254) |
| P3 | 351 / 433 (394) | 351 / 427 (367) | 366 / 426 (382) | 364 / 431 (366) | 362 / 420 (362) |

| ingressi densi (n_in) | 5 | 9 | 13 | 17 |
|---|---:|---:|---:|---:|
| P1 | 74 / 64 (82) | 67 / 66 (76) | 77 / 83 (99) | 86 / 92 (99) |
| P1.5 | 73 / 63 (74) | 68 / 65 (84) | 76 / 86 (88) | 86 / 91 (109) |
| P2 | 213 / 244 (214) | 232 / 261 (220) | 244 / 283 (244) | 253 / 296 (268) |
| P3 | 416 / 451 (428) | 444 / 481 (450) | 475 / 514 (466) | 488 / 548 (492) |

| ingressi one-hot (n_in) | 16 | 32 | 65 |
|---|---:|---:|---:|
| P1 | 77 / 65 (81) | 73 / 59 (77) | 70 / 56 (80) |
| P1.5 | 77 / 76 (76) | 73 / 72 (80) | 73 / 76 (81) |
| P2 | 194 / 239 (222) | 197 / 237 (204) | 207 / 233 (226) |
| P3 | 410 / 476 (438) | 408 / 481 (464) | 402 / 477 (424) |

La taglia della rete non costa niente a nessuna pipeline: da 10 a 100 nodi P1 45–52 ns, P2
221–237, P3 351–366 sul P-core, con le stesse istruzioni eseguite (P3 6 573–6 577). Lo stesso per
la one-hot dell'ingresso da 16 a 65 colonne. Gli ingressi densi invece costano: da 5 a 17 colonne
P1 sale di 12 ns, P2 di 40, P3 di 72.

**Il costo per MAC eseguita sotto traffico.** Tempo di CPU meno la baseline contro le MAC
eseguite per pacchetto (una one-hot conta h1), su ingressi densi, ingressi one-hot e larghezza
(11 punti per pipeline, P-core):

| | P1 | P1.5 | P2 | P3 |
|---|---:|---:|---:|---:|
| ns per MAC eseguita | 0.22 | 0.18 | 0.11 | 0.69 |
| r² (MAC eseguite) | 0.89 | 0.71 | 0.09 | 0.94 |
| r² (MAC dalla forma) | 0.03 | 0.22 | 0.01 | 0.00 |

Contate dalla forma le MAC non spiegano niente; contate eseguite spiegano P1, P1.5 e P3. P2 non
sta su una retta sola: in ogni esperimento sale di ~0,2 ns per MAC, ma il costo di partenza
cambia con la composizione dell'ingresso. La profondità è fuori dalla retta per costruzione:
uno strato aggiunge 16 MAC e un salto fra programmi (P3 ~58 ns a strato). La sintesi calcola la
stessa retta anche sulla media T2−T1 (`campaign_report.py`, sezione "Costo per MAC eseguita").

**Il checkpoint, sola rete neurale** (`assi_<core>core/checkpoint/rates/`), T2−T1 minimo /
media, baseline sottratta: P-core P1 36 / 38, P1.5 44 / 57, P2 198 / 262, P3 320 / 365;
E-core 44 / 66, 56 / 78, 238 / 250, 401 / 439. La media di una finestra oscilla del ±15–20%
fra le finestre, il minimo del ±3%: per gli andamenti si usa il tempo di CPU meno la baseline,
che a nodo saturo ripete entro l'1–2%.

**Un caricamento sfavorevole anche in produzione.** Sull'E-core P3 a 25 nodi un caricamento ha
dato 699 ns di CPU, con le stesse istruzioni (6 576) e IPC 2,8 invece di 3,6, mentre T2−T1 e le
altre pipeline erano nella norma; un nuovo caricamento (`ASSI_CORES=E ASSI_SOLO=nodes_25`) ha
dato 533 ns, IPC 3,6, in linea con gli altri punti (531–538). La tabella riporta il secondo.
Succede quindi anche alla build di produzione, non solo a quella strumentata: un punto fuori
curva si rifà con un nuovo caricamento prima di citarlo.

```bash
bash ipa/test/remeasure_campagna.sh ecore lpe    # capacità, due core, tre marcature, curve
ASSI_CORES=P bash ipa/test/remeasure_campagna.sh assi
ASSI_SOLO="width_6 depth_4" bash ipa/test/remeasure_campagna.sh assi     # solo alcuni punti
ASSI_T2=0 bash ipa/test/remeasure_campagna.sh assi       # senza T2−T1 (solo capacità e ns di CPU)
ASSI_AXES="nodes iv_dense iv_onehot" bash ipa/test/remeasure_campagna.sh assi   # solo alcuni assi
python3 ipa/test/traffic_models.py --topology ipa/synth/traffic/nodes_10   # la rete di un modello
python3 ipa/test/campaign_report.py results/campagna_2026-10-06 > sintesi.md
sudo python3 ipa/test/hw_counters.py --cpu 6,12,20 --seconds 1    # i contatori, a mano
sudo python3 ipa/test/bench_throughput.py --mode compare --generator xdp --rounds 3 \
    --gen-cpus 10 --dut-cpus 12 --egress-cpu 8 --out results/ecore_compare
```

---

## 11. Al crescere del bit rate: ritardo, ricevuti, rilanciati (`bench_bitrate.py`)

La domanda: al crescere del bit rate inviato la coda si riempie, il tempo
end-to-end cresce e poi si perde; se si perde all'**uscita** del programma il collo di
bottiglia è trasmissivo, se si perde all'**ingresso** è il programma eBPF. Contare quanti
pacchetti il programma riceve e quanti ne rilancia, con due programmi sullo stesso XDP: uno
che conta soltanto, uno con la pipeline. Il generatore è `xdp_gen` (`--generator xdp`), con
cadenza e timbro nel suo programma (§11.4).

### 11.1 Come si legge su XDP

Un programma XDP gira dall'inizio alla fine su ogni pacchetto, dentro il poll NAPI: non ha
una coda sua. Se è lento si riempie la coda che sta **davanti** a lui (su veth il
`ptr_ring`, 256 descrittori): il ritardo cresce, poi la coda trabocca e i pacchetti si
perdono **prima di XDP**.

| si osserva | vuol dire |
|---|---|
| inviati > ricevuti da XDP | coda d'ingresso piena: collo il **programma** (o la ricezione — lo separa `rxonly`, il solo contatore allo stesso rate) |
| ricevuti > inoltrati, con HIT > inoltrati | il programma ha deciso l'inoltro ma il pacchetto non è arrivato: collo **trasmissivo** |
| ricevuti > inoltrati, con MISS/DROP | una **decisione** del modello, non una perdita |

### 11.2 I due programmi sullo stesso hook

```
hook XDP di ipatg0 ─► xdp_ing_count   ing_count[0] += 1   (mappa per-CPU)
                        │ bpf_tail_call(ing_next[0])
                        ▼
                      dispatcher della pipeline di produzione (P1/P1.5/P2/P3/baseline)
                        │ bpf_redirect
                        ▼
                      ipaN ──veth──► ipaNp: xdp_rx_lat   rx_count += 1  (+ latenza)
```

Se la tail call non parte il contatore incrementa `ing_count[1]` e scarta: un contatore che
deve restare a zero, controllato a ogni finestra. La tail call richiede programmi
compatibili (stesso tipo, JIT e `expected_attach_type`), quindi il contatore è caricato
dallo **stesso caricatore** della pipeline: un oggetto BCC per baseline, P2 e P3; per P1 e
P1.5 aggiunto in coda al sorgente dello stesso oggetto AOT. `rxonly` è il contatore con lo
slot vuoto: conta e scarta.

Il costo della catena si misura: la fase finale porta ogni pipeline a rate massimo con e
senza contatore davanti e legge dal kernel il tempo del programma attaccato
(`kernel.bpf_stats_enabled`, `run_time_ns / run_cnt`, tail call comprese). Con `xdp_gen`:
da −3,3 a +2,1 ns, dentro la dispersione.

### 11.3 Contatori e formule

| grandezza | dove si conta |
|---|---|
| inviati | tentativi del generatore (`gen_runs` di `xdp_gen`) |
| ricevuti da XDP | `ing_count[0]`, programma 1 |
| decisioni | `pkt_stats[0..2]` della pipeline (HIT, MISS, DROP) |
| inoltrati | `rx_count` sul nodo successivo |

Ogni punto è una finestra stazionaria (§10.1), default 0,3 s.

```
loss_before_xdp  = inviati − ricevuti            = respinti + persi fra veth e XDP
loss_in_pipeline = ricevuti − inoltrati          = (MISS + DROP) + (HIT − inoltrati) + residuo
packets_lost     = inviati − inoltrati           (le percentuali sono sugli inviati e si sommano)
bitrate_sent     = inviati / duration_s × frame × 8     (frame senza FCS: byte sul veth)
```

**Collo di bottiglia**: la perdita prima di XDP della pipeline meno quella di `rxonly` allo
stesso rate, contro la perdita all'uscita, con soglia `--loss-threshold` (default **0,1
punti**). **Inizio della perdita**: il rate più basso da cui *tutti* i rate più alti perdono;
una riga in perdita seguita da righe pulite è "sporadica". Finestre marcate: `gen_limited`
(generatore sotto il 95% del chiesto), `gen_burst` (oltre il 105%), `host_disturbed` (§0.3).
Le colonne diagnostiche `napi_*` (scheduling del thread NAPI del DUT) e `gen_*` (cadenza di
`xdp_gen`) sono in `bitrate_raw.csv` (§10.1).

### 11.4 Cadenza, timbro e latenza end-to-end

**La cadenza.** `xdp_gen` spinge al massimo; il ritmo lo tiene il suo programma: a ogni giro
legge l'orologio, prima dell'istante previsto scarta il frame (la pagina torna al pool, il giro
costa ~60 ns), poi lo spedisce e fissa il prossimo istante un intervallo più in là.
Spaziatura uniforme, non a raffiche (una raffica da 256 riempirebbe da sola la coda); dopo
una pausa recupera al più 16 frame di fila. Precisa fino a ~11 Mpps per thread (a 12 Mpps
chiesti ne partono 11,9 con rxonly, a 9,0–9,5 quando la coda respinge).

**Il timbro.** Nell'istante in cui il frame parte il programma scrive l'intestazione di pktgen
dopo UDP: magic, seq, `tv_sec`, `tv_usec` (`CLOCK_REALTIME`, µs). Il programma d'uscita la
confronta col proprio orologio:

```
lat_us = floor((bpf_ktime_get_ns() + off) / 1000) − (tv_sec·10⁶ + tv_usec)
off    = CLOCK_REALTIME − CLOCK_MONOTONIC, letto prima di ogni punto
```

Il percorso misurato è tutto il nodo, **attesa in coda compresa**. Il timbro coincide con
l'invio, quindi non serve correzione (con pktgen, che timbra e poi aspetta, si sottrae la sua
attesa: `e2e_spin_correction_us`). Istogramma a celle da 1 µs fino a 1 024 µs, poi da 64 µs
fino a 65,5 ms, più il trabocco; si cronometra un arrivo ogni `mask+1` (circa
`--lat-samples`, 20 000 per finestra).

**Il lotto** (`--xdp-batch`, default 256): a fine lotto il redirect sveglia il DUT
(`xdp_do_flush` → `XDP_XMIT_FLUSH`). A basso carico un frame può aspettare nel generatore
fino alla fine del lotto, ~12 µs: per questo la mediana del ritardo a basso carico è 17–19 µs
sul P-core. Un lotto più piccolo toglie quell'attesa, ma la cadenza regge rate più bassi.

### 11.5 Comandi e uscite

```bash
sudo python3 ipa/test/bench_bitrate.py --generator xdp --gen-cpus 10 --dut-cpus 6 \
    --egress-cpu 8 --out results/pcore_bitrate   # 0,5-12 Mpps (XDP_RATES_MPPS), 5 giri (~5 min)
python3 ipa/test/plot_bitrate.py results/pcore_bitrate                      # i grafici
python3 ipa/test/bench_bitrate.py --report results/pcore_bitrate            # riepilogo dai CSV
```

- **Scala**: `--rates` in Mpps (con `xdp_gen` il default è 0,5–12 Mpps, `XDP_RATES_MPPS`: la cadenza si ferma a ~12), oppure
  `--bitrates` in Gbit/s, oppure `auto`, calibrata su `rxonly` a massima spinta.
- **Uscita**: `--egress-cpu auto` (default) mette la ricezione del nodo successivo su un core
  fisico suo; `none` la lascia in softirq sulla CPU del DUT.
- **Contatori hardware**: colonne `instr_pkt`, `cycles_pkt`, `ipc` per finestra (§10.8).

| file | contenuto |
|---|---|
| `bitrate_raw.csv` | una riga per (metodo, rate, giro), riscritta dopo ogni finestra: conteggi, perdite scomposte, latenze, diagnostica, colonne `host_*` |
| `bitrate.csv` | mediana fra i giri, min/max, pavimento `rxonly`, collo di bottiglia, giri disturbati |
| `bitrate_overhead*.csv` | costo del contatore: ns del programma (statistiche BPF) e dal throughput |
| `host_monitor.csv` | la macchina al secondo |
| `env.csv` | macchina, condizioni, scala usata, soglia, generatore, lotto |
| `bitrate_latency`, `bitrate_pps`, `bitrate_loss` (.png/.pdf) | latenza (p50, p99), pacchetti/s, perdita; si rifanno dai CSV con `plot_bitrate.py` |

### 11.6 Risultati (`results/campagna_2026-10-06/pcore/bitrate/`, `ecore/bitrate/`)

6 metodi, 16 punti da 0,5 a 12 Mpps, 5 giri. Cadenza esatta fino a 11 Mpps; a 12 ne parte il
98% (con un thread la cadenza si ferma a ~12,7 Mpps). **P-core**:

| pipeline | inoltro max (Mpps) | 1 / ns di CPU (§10.2) | pulita fino a | perde da | ritardo a coda piena (p50) |
|---|---:|---:|---|---|---:|
| rxonly | ≥ 11,9 | — | 11 Mpps | 12 Mpps (0,1%) | — |
| baseline | 9,02* | 15,3 | 8 Mpps (4,05 Gbit/s) | *banco, nodo al 60%* | — |
| p1_static | 8,66 | 8,56 | 8 Mpps (4,04 Gbit/s) | 9 Mpps (4,56 Gbit/s) | 34–35 µs |
| hardcoded | 8,17 | 8,04 | 8 Mpps (4,08 Gbit/s) | 9 Mpps (4,56 Gbit/s) | 35–36 µs |
| template | 3,45 | 3,45 | 3 Mpps (1,54 Gbit/s) | 3,5 Mpps (1,79 Gbit/s) | 78–86 µs |
| modular | 2,37 | 2,36 | 2 Mpps (1,02 Gbit/s) | 2,5 Mpps (1,28 Gbit/s) | 116–126 µs |

"Pulita fino a" e "perde da" sono **punti della scala**: la soglia vera sta fra i due (P2:
3,45 Mpps = 1,77 Gbit/s a 64 B). **E-core**: inoltro massimo baseline 9,34, P1 6,24, P1.5
5,81, P2 2,81, P3 1,93 Mpps, pulite fino a 9 / 6 / 5 / 2,5 / 1,5 Mpps, ritardo a coda piena
29 / 45 / 49 / 103 / 148 µs. **LP E-core** (3 giri): P1 2,94, P1.5 2,90, P2 1,66, P3 1,18
Mpps.

- **Tutte e quattro le pipeline saturano sulla curva**, e si fermano alla capacità del nodo
  misurata a massima spinta (§10.2, §10.8), entro il 2%. Al ginocchio il thread NAPI del DUT
  lavora il 99,5–100% del tempo.
- Per le pipeline la perdita è **prima di XDP**: il collo di bottiglia è il programma eBPF.
  Dopo XDP al massimo lo 0,04% degli inviati, rumore di lettura. Sotto capacità nessuna
  perdita (≤ 0,05%).
- **\*La baseline non è un limite del programma.** Da 9 Mpps perde ~1,3% prima di XDP e
  0,1–0,2% dopo, ma il suo thread NAPI lavora il 59–62% del tempo: il nodo ha tempo libero.
  Con l'inoltro il generatore non va oltre ~9 Mpps (rxonly, che non inoltra, arriva a 11,9).
  Il banco lo classifica come `banco: nodo non saturo` (`napi_run_pct` sotto il 90%,
  `NAPI_SATURATED_PCT`). La sua capacità resta quella di §10.2. Sull'E-core, dove la
  capacità della baseline (9,4 Mpps) sta sotto il tetto del generatore, la baseline satura
  anche sulla curva.
- **rxonly non perde fino a 11 Mpps**; a 12 perde lo 0,1%, dove il generatore stesso cede.
  Tutta la perdita delle pipeline è del programma: al traffico più alto P3 76%, P2 63%, P1.5
  9%, P1 7% sul P-core.
- **Il ritardo a coda piena segue 256 ÷ capacità** più il tratto fino al nodo successivo: P1
  30 µs previsti contro 34–35, P1.5 32 contro 35–36, P2 74 contro 78–86, P3 108 contro
  116–126. A basso carico 17–19 µs (attesa a fine lotto nel generatore, §11.4).
- **Quando la coda respinge, il generatore rallenta**: oltre il ginocchio si chiedono fino a
  12 Mpps e ne partono meno.

## 12. Modelli e scenari diversi dal checkpoint (`--model`, `--topology`)

Tutti i test e i banchi del kernel e del traffico vero accettano un modello e una rete
diversi dal checkpoint depositato. Senza `--model` usano il checkpoint.

### 12.1 Scenario, modello, compatibilità

- **Scenario = la rete**: `topologies/<nome>/topology_config.json`, con `n_interfaces`,
  `n_nodes`, `n_queues` e `initial_ttl` (il TTL con cui i pacchetti entrano nella rete).
  Oltre a `germany50` ci sono le reti dei modelli sintetici: `germany50_ttl16`,
  `synth_small`, `synth_ones`, `synth_large`, `synth_mixed`.
- **Modello**: il checkpoint (`checkpoint`), un altro `.pt` (`checkpoint:<file>`, serve
  torch), un preset sintetico (`synth:ipa_like`, `synth:deep`, ...) o una cartella.
  `ipa/model_source.py` li carica tutti nella stessa forma: pesi int8, scala, feature con
  larghezza e scala, strati, semantica delle classi dichiarata dal modello.
- **Compatibilità**: ogni feature ha la larghezza della dimensione della rete da cui
  dipende (`link_state` e `ingress_iface` = interfacce, `node` = nodi, `queue_occupancy`
  = code) e la scala del TTL è uguale al TTL iniziale. Un modello con il one-hot del nodo
  a 52 su una rete da 30 nodi è escluso, con il motivo scritto.
- **Limiti delle pipeline** (`ipa/pipeline_limits.py`, costanti prese dai moduli che
  compilano): P2 al massimo 8 neuroni per strato, strati dal terzo in poi larghi come il
  secondo, 1024 pesi; P3 al massimo 8 neuroni per strato, 16 strati, 2048 pesi; P1
  nessuno. La profondità di P2 (circa 20 strati, distanza dei salti) non è una costante:
  un modello più profondo lo rifiuta il verificatore. Una pipeline che non regge il
  modello è **NON APPLICABILE**, non un errore.

| scenario | interfacce / nodi / code / TTL | modelli compatibili |
|---|---|---|
| germany50 | 6 / 52 / 4 / 30 | checkpoint, ipa_like, deep, sparse, sparse_hetero_11 |
| germany50_ttl16 | 6 / 52 / 4 / 16 | ipa_ttl16 |
| synth_small | 3 / 8 / – / 16 | small |
| synth_ones | 3 / 4 / – / 8 | ones |
| synth_large | 8 / 100 / – / 64 | large (P2 e P3 non applicabili) |
| synth_mixed | 4 / 12 / 1 / 30 | mixed |

### 12.2 Come passa nei test

- `--model REF` e `--topology NOME` (o `$IPA_MODEL` e `$IPA_TOPOLOGY_CONFIG` per un
  processo figlio). Senza `--topology` si prende lo scenario compatibile, germany50 se lo
  è. Un modello incompatibile si ferma prima di compilare, con il motivo.
- `ipa/test/model_under_test.py` tiene il modello scelto; `load_weights`, `setup_*`,
  `ref_infer` e `count_lookups` di `verify_prog_run` lo seguono passando per
  `ipa/test/pipeline_setup.py`, i costruttori comuni di baseline, P1, P1.5, P2 e P3 (gli
  stessi che usa `verify_synth_kernel`). `--model checkpoint` e nessun `--model` danno pesi,
  scala, semantica e riferimento identici (3000/3000 decisioni e logit), e sorgenti di P1 e
  della foglia di P2 identici byte per byte.
- **Riferimento**: quello generico (`ref_infer_sparse`), uguale a quello del 65-4-4-7 su
  20 000 ingressi casuali, classe e logit.
- **Azione della classe**: con un modello la verifica per TTL controlla anche l'azione:
  redirect per FORWARD, `XDP_DROP` per DROP, `XDP_PASS` per UNUSED. Il controllo del TTL
  decrementato usa il primo TTL che il modello inoltra.
- **Fabric**: porte, nodo, porta d'ingresso e larghezza di `link_state` dal modello. La
  ricerca dei casi, dopo stato dei link × TTL, prova anche porta d'ingresso, nodo e code
  per le classi mancanti (ogni caso scrive i suoi valori nelle mappe).
- **Banchi di traffico**: il pacchetto dei generatori ha TTL 32 fisso. Il banco cerca lo
  stato dei link (e delle code) con cui il modello **inoltra** quel pacchetto, lo scrive e
  lo stampa (`large`: `00111000` → classe 4). Si misura sempre un inoltro.
- **Saltati con un messaggio**: extract e quant (riguardano il `.pt` addestrato), le
  architetture alternative della suite (forme proprie), il deploy AOT di `test_fabric`
  (si costruisce da un checkpoint).

```bash
sudo python3 ipa/test/test_model_source.py --kernel      # ogni scenario x modello x pipeline
sudo python3 ipa/test/verify_synth_kernel.py --all --n 300 --pipeline p2
sudo python3 ipa/test/host_conditions.py --run -- python3 ipa/test/test_suite.py --only kernel --model synth:deep
sudo python3 ipa/test/test_fabric.py --model synth:small -q
sudo python3 ipa/test/bench_throughput.py --mode compare --generator xdp --egress-cpu 8 --rounds 3 \
     --gen-cpus 10 --dut-cpus 6 --model synth:deep --out results/deep_compare
sudo python3 ipa/test/bench_throughput.py --mode compare --generator xdp --egress-cpu 8 --rounds 3 \
     --gen-cpus 10 --dut-cpus 6 --model ipa/synth/traffic/depth_3 --out results/depth_3
```

### 12.3 Risultati

**Correttezza** (campagna del 2026-10-06), tutto PASS:

| controllo | esito |
|---|---|
| `test_model_source --kernel`: 6 scenari × modelli compatibili × 5 pipeline, 40 ingressi ciascuna, model_id 0 e 190 | 110/110; large su P2/P3 N/A |
| `verify_synth_kernel --all --pipeline p1` | 8/8, 300/300 decisioni identiche per modello |
| suite kernel con `--model`, 9 modelli | PASS su tutti |
| `verify_per_model_semantics` | 53/53 |

`remeasure_all.sh` fa anche `verify_synth_kernel` su P2 e P3 (7/7 più large N/A ciascuna),
`test_fabric --model` sui 9 modelli e lo sweep delle topologie.

Classi consegnate dal fabric con la ricerca allargata: checkpoint 0–5, ipa_like e
ipa_ttl16 2–5, small 0–3, mixed 0–3, large 1, 4, 6, 8, deep 0, 1, 4, sparse 1, 5, ones 0.
Per ipa_like, deep, sparse, small e ones sono tutte le classi che il modello decide su
200 000 ingressi casuali: le altre i suoi pesi non le producono mai.

**Kernel** (`BPF_PROG_TEST_RUN`, suite con `--model`), ns/pacchetto, minimo su 7 prove,
baseline 14–15 ovunque:

| modello | forma | P1 | P1.5 | P2 | P3 |
|---|---|---:|---:|---:|---:|
| checkpoint | 65-4-4-7 | 46 | 51 | 197 | 318 |
| ipa_like | 65-4-4-7 | 47 | 51 | 194 | 309 |
| ipa_ttl16 | 65-4-4-7 | 40 | 46 | 197 | 310 |
| sparse | 65-4-4-7 | 31 | 38 | 197 | 314 |
| deep | 65-4-4-4-7 | 52 | 56 | 226 | 375 |
| small | 15-4-4 | 30 | 37 | 139 | 226 |
| mixed | 18-6-5 | 36 | 43 | 155 | 257 |
| ones | 11-2-3 | 23 | 28 | 129 | 217 |
| large | 117-8-8-9 | 71 | 76 | N/A | N/A |

**Che cosa dicono**: P2 e P3 costano per la **forma**, non per i pesi (checkpoint,
ipa_like, ipa_ttl16 e sparse hanno la stessa forma e lo stesso costo, entro 10 ns); P1 per i
**valori** dei pesi (sparse, stessa forma, 31 ns contro 46). Uno strato in più costa circa
+29 ns a P2 e +57 ns a P3; ingressi più piccoli abbassano P2 e P3 di 40–100 ns. Sotto
traffico vero gli stessi andamenti sono negli assi di §10.8.

## Note e limiti

- **Ordine del design space**: costo (istruzioni, jited, tail call, lookup, memoria) e
  latenza crescono baseline → P1 → P2 → P3 su ogni banco.
- **Inferenza identica** nelle tre pipeline (stesso MLP, pesi, argmax): verificata dalla
  corrispondenza di classe kernel/riferimento e dall'equivalenza esatta sui modelli sintetici
  (`verify_synth_kernel`: P1 8/8, P2 7/7 e P3 7/7, con `large` non applicabile a P2 e P3 —
  1 097 pesi oltre `MAX_WEIGHT_ENTRIES` in P2).
- **Azione uniforme**: `argmax → class_action → porta logica → mac_table → bpf_redirect`.
- **Tutto sta su una macchina**: generatore, DUT e nodo successivo sono core diversi dello
  stesso processore, collegati da `veth`. Il costo del veth è dentro le cifre. Niente NIC,
  niente DMA: nessuna scheda cablata su questa macchina supporta XDP nativo. Il confronto fra
  pipeline regge; le cifre assolute sono di questo percorso, a 3,5 GHz, e del tipo di core
  del nodo (§10.8).
- **Nessun isolamento dal boot**: `isolcpus`, `nohz_full` e `rcu_nocbs` richiedono parametri
  di boot. Le CPU del banco restano soggette al tick e ai callback RCU; il resto
  dell'isolamento è a runtime (§0.3).
- **Frequenza**: fissata e misurata, ma il sysfs può dichiararne un'altra (§0.3). Le cifre
  assolute valgono a 3,5 GHz; a un'altra frequenza cambiano quasi in proporzione, i rapporti
  fra pipeline no.
- **Latenze sotto `BPF_PROG_TEST_RUN`**: esecuzione in un ciclo sullo stesso buffer, senza
  driver e senza pressione di cache da traffico vero. Il `Mpps` di quelle tabelle è un picco
  teorico; il costo sotto carico è quello di §10 e §11, più alto per P2 e P3.
