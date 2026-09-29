# Guida ai test — IPA/eBPF design space

Tre pipeline (P1 hardcoded, P2 template, P3 modular) verificate su due piani:

- **userspace** (numerico, PyTorch/NumPy e il C di P1 valutato dal testo) — estrazione dei pesi,
  quantizzazione, semantica delle classi, modelli sintetici, formule dei banchi;
- **kernel** — `BPF_PROG_TEST_RUN` sui programmi XDP reali (istruzioni, latenza, lookup,
  memoria, dispatch) e **traffico vero** su un fabric `veth` con XDP nativo (pktgen o frame
  XDP grezzi, contatori all'ingresso e all'uscita).

Tutti gli script di test vivono sotto `ipa/test/`; i comandi si eseguono dalla radice del
repository. Il motore sta in `ipa/`; i dati della topologia su cui il checkpoint depositato è
stato addestrato stanno in `topologies/germany50/`.

**Le cifre di questo documento sono state misurate il 2026-09-28**, con la ReLU senza salto
di §8, sulla macchina e nelle condizioni descritte in §0,
con `ipa/test/remeasure_all.sh` e
`ipa/test/remeasure_traffic.sh` (log in `/tmp/ipa_logs/`, `$IPA_LOG_DIR` per cambiarlo).

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

`bench_bitrate` (rxonly, baseline, template), inoltro massimo in Mpps a 64 B, un giro da
30 s per frequenza, più due run completi (6 metodi, 5 giri, ~5 minuti):

| frequenza reale | rxonly | baseline | template | finestre disturbate | throttling | temp. |
|---|---:|---:|---:|---|---|---|
| 2,0 GHz | 2,65 | 2,00 | 1,14 | 0/39 | 0 | 53 °C |
| 3,0 GHz | 3,93 | 2,89 | 1,66 | 0/39 | 0 | 47 °C |
| 3,5 GHz | 4,37 | 3,22 | 1,86 | 0/39 | 0 | 55 °C |
| 4,0 GHz | 4,84 | 3,55 | 2,09 | 0/39 | 0 | 61 °C |
| 4,5 GHz | 5,17 | 3,54 | 2,04 | **28/39** | 8 930 eventi | 65 °C |
| **run completo 4,0 GHz** | 4,87 | 3,56 | 2,07 | **11/260** | 219 sul **DUT** | registro fino a **98 °C** |
| **run completo 3,5 GHz** | 4,39 | 3,18 | 1,86 | **1/390** | 2 di pacchetto | registro max 85 °C |

A 4,5 GHz il throughput smette di crescere e l'inizio della perdita del template arretra. A
4 GHz un run da 30 s è pulito, uno da 5 minuti no: il pacchetto arriva a 98 °C dopo ~100 s.
**3500 MHz è la frequenza più alta che la macchina regge per un run intero.**

La frequenza pesa quasi in proporzione, ma non del tutto: da 3 a 4 GHz il throughput sale
del 23% invece del 33%, e i cicli per pacchetto crescono dell'8–13% fra 2 e 4 GHz (la
uncore è fissa, la cache condivisa e la memoria non accelerano con il core). Il **rapporto
fra pipeline** invece no: template/baseline vale 0,57–0,59 a ogni frequenza pulita. Le cifre
assolute vanno citate insieme alla loro frequenza.

### 0.5 Comandi

```bash
python3 ipa/test/host_conditions.py --show           # topologia, piano, condizioni (niente root)
sudo python3 ipa/test/host_conditions.py --restore   # dopo un run ucciso
# un comando qualunque sul core del DUT, a condizioni applicate
sudo python3 ipa/test/host_conditions.py --run -- python3 ipa/test/test_suite.py --only kernel

python3 ipa/test/test_host_conditions.py             # 93 controlli su un /sys finto, niente root
sudo python3 ipa/test/test_host_kernel.py            # sul kernel vero: applica, misura, ripristina
sudo python3 ipa/test/test_host_kernel.py --bench    # + un giro corto di bench_bitrate

bash ipa/test/remeasure_all.sh                      # tutte le misure BPF_PROG_TEST_RUN (~15 min)
bash ipa/test/remeasure_traffic.sh                   # tutte le misure di traffico (~15 min)
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
python3 ipa/test/test_bitrate_math.py             # 98: formule e attribuzione di bench_bitrate
python3 ipa/test/test_steady_window.py            # 18: la finestra stazionaria
python3 ipa/test/test_host_conditions.py          # 93: ruoli, applicazione e ripristino
python3 ipa/test/test_model_source.py             # 62: modelli, scenari, compatibilita', limiti delle pipeline
```

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
| `p1_static` istruzioni | 579 | 599 | 615 | 639 | 663 |
| `p1_static` latenza (ns) | 37 | 38 | 39 | 39 | 41 |

**21 istruzioni per porta**, lineare; grado 2 contro grado 6: −12,7% di istruzioni e
**−4 ns** (−10%), con la latenza monotona. Fra grado 6 e grado 2 spariscono 16
moltiplicazioni-accumulo, circa 4,6 ns a 3,5 GHz se ne costasse una per ciclo: la misura
li vede. Il controllo regge:
`hardcoded` 1 090, `template` 15 142, `modular` 12 394 istruzioni e latenze piatte (46–47,
187–189, 306–309 ns) su tutti e cinque i punti.

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

Installare un modello nuovo su un nodo in servizio (`update_ms` di `bench_scaling`, §9): P1
carica l'oggetto AOT già compilato, **0,7–2,1 ms** (§ Risultati: `open` 0,09 + verifica e JIT
1,03 ms sul modello standard), e clang (~76 ms) gira una volta sulla macchina di build; P2 e P3
scrivono in mappa pesi, descrittore e semantica, **10–12 ms**, senza compilare niente.
Limiti: `MAX_WEIGHT_ENTRIES=1024` in P2 (3 modelli dell'architettura 65-4-4-7),
`MAX_LAYER_WEIGHT_ENTRIES=2048` in P3 (6).

---|---:|---:|---:|---|
| hardcoded (BCC) | — | 75,6 | 78,9 | ricompilazione completa: BCC ~74 ms, caricamento ~2 ms |
| template | 1 516 ms | **0,505** | 0,695 | una `bpf_map_update_elem` sul blocco pesi |
| modular | 1 194 ms | **0,410** | 0,616 | una `bpf_map_update_elem` sul blocco pesi |

Ricompilare P1 con BCC costa 150-190× una scrittura in mappa. Ma il deploy di P1 è l'oggetto
AOT: sul nodo si paga solo il caricamento, **1,12 ms** (`open` 0,09 + verifica e JIT 1,03;
§ Risultati), e clang (76 ms) gira una volta sulla macchina di build. Si riporta il minimo:
con 3 modelli la media è dominata dal primo add, che paga il primo accesso alle pagine di
una mappa appena creata. Limiti: `MAX_WEIGHT_ENTRIES=1024` in P2 (3 modelli di questa
architettura), `MAX_LAYER_WEIGHT_ENTRIES=2048` in P3 (6).

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

Misurato il 2026-09-28, con `ipa_relu` (§8).

**Tier A (~300 pesi)**, ns/pacchetto:

| descrittore | n_in | larga | 2 layer | 4 layer | 8 layer |
|---|---:|---:|---:|---:|---:|
| `default` (2 one-hot) | 65 | **39** | 46 | 49 | 64 (+64%) |
| `no_onehot` (0) | 11 | 93 | 88 | 83 | **81 (−13%)** |
| `small_onehot` (1 piccola) | 13 | 81 | **71** | 79 | 84 |

**Tier B (~1 200 pesi)**, ns/pacchetto:

| descrittore | n_in | larga | 2 layer | 4 layer | 8 layer |
|---|---:|---:|---:|---:|---:|
| `default` (2 one-hot) | 65 | **110** | 150 | 176 | 219 (+99%) |
| `no_onehot` (0) | 11 | *stack* | *stack* | 320 | **291 (−9%)** |
| `small_onehot` (1 piccola) | 13 | *stack* | 295 | **286** | 288 |

(`big_onehot` nel log `depth_vs_width.log` di `remeasure_all.sh`.) *stack*: clang si ferma
(abort di LLVM, stack eBPF oltre 512 byte). **Tier C (~4 700 pesi)**: nessuna forma
compila, per lo stesso motivo.

**Fino al 2026-09-27** il tier B su `default` caricava solo la forma a 8 strati (230 ns):
larga, 2 e 4 strati venivano **rifiutate dal verificatore** (`BPF program is too large.
Processed 1000001 insn`, `E2BIG`), e su `small_onehot` non caricava nemmeno la larga del
tier A. La causa era la stessa di P2 (§8): un salto condizionale per ogni ReLU. Con
`ipa_relu` il verificatore percorre 5 698–8 516 istruzioni sul tier B, e il limite che
resta è lo stack.

**Che cosa dicono.**
1. Con un ingresso grande e dominato da one-hot (`default`, il caso di IPA) allargare batte
   approfondire: +64% a 8 strati a 300 pesi, il doppio a 1 200.
2. Con un ingresso piccolo e denso (`no_onehot`) è il contrario: la versione a 8 strati è
   **più veloce del 13%** e più piccola (1 368 contro 1 535 istruzioni). Una one-hot costa
   poco perché il datapath ne legge una colonna; un ingresso denso moltiplica le letture per
   la larghezza del primo strato. La risposta dipende da com'è fatto il vettore d'ingresso.
3. Con la ReLU senza salto le forme profonde pagano più di prima (8×3 a 300 pesi: 50 →
   64 ns): ogni neurone nascosto aggiunge tre istruzioni sempre eseguite, mentre sotto
   `BPF_PROG_TEST_RUN` il salto di prima era sempre predetto. La conclusione 1 si rafforza.
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
| baseline (0 tail call) | 10 | 10 | 11 |
| baseline + 1 tail call | 11 | 12 | 13 |

**+1 ns per salto.** Il salto in sé costa quasi niente: quello che P3 paga per strato (§9) è
il resto — le letture di mappa che ricostruiscono il contesto a ogni hop.

---

## 8. Architetture alternative dentro `--only kernel`

`suite_kernel()` chiama anche `verify_alt_architectures()`: P1 con `(8,)` e `(4,4,4)`
compilati separatamente, verificati contro `ref_infer_sparse` (5/5 ciascuna); P2 65-6-5-7 e
P3 65-5-6-4-7 registrati **insieme** al modello reale nello stesso oggetto (PASS).

**Il limite di profondità di P2, e la sua causa.** Fino al 2026-09-28 P2 caricava solo foglie
con **al più due strati nascosti**: da tre in su `arch_generic_2layer` veniva rifiutato
(`BPF program is too large. Processed 1000001 insn`, `E2BIG`). Il programma non era troppo
lungo (16–18 000 istruzioni): era il verificatore a percorrerne molte volte gli stessi
blocchi. La ReLU scritta `x > 0 ? x : 0` diventava un salto condizionale per neurone, e
il verificatore esplorava entrambi i lati di ciascuno senza riuscire a riunirli.
`diag_verifier.py` lo misura con le statistiche del verificatore (`log_level = 4`):

```bash
sudo python3 ipa/test/diag_verifier.py      # variante `attuale` contro `salto` (la ReLU di prima)
```

| P2, istruzioni percorse (limite 1 000 000) | 1 strato | 2 | 3 | 4 | 5 | 6 |
|---|---:|---:|---:|---:|---:|---:|
| ReLU con salto (prima) | 799 563 | 417 292 | *rifiutato* | *rifiutato* | *rifiutato* | *rifiutato* |
| ReLU senza salto (`ipa_relu`) | 120 452 | 120 557 | 127 906 | 127 738 | 134 413 | 136 642 |

P3 caricava anche prima; con la stessa `ipa_relu` (per un confronto alla pari fra le tre
pipeline) `layer_hidden` passa da 186 489 a 27 979 istruzioni percorse, `layer_first` da
27 183 a 26 755 (`diag_verifier.py --only p3`).

Già a uno strato P2 usava l'80% del limite: il margine era minimo, e per questo il confine
si spostava fra macchine e versioni del kernel. `ipa_relu` calcola `x & ~(x >> 63)`: nessun
salto, stesso risultato bit per bit. Una barriera `asm volatile("")` impedisce a clang di
riconoscere `smax(x, 0)` e di rifarne un salto (senza, i salti tornano tutti).

**Il limite di profondità di oggi** (larghezza 4, descrittore default). Il verificatore non è
più il vincolo: 154 811 istruzioni percorse a 10 strati, 201 528 a 20 (~4 700 per strato).
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
bash ipa/test/remeasure_traffic.sh     # contiene il confronto con l'albero precedente
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
| `p1_static` istruzioni | 647 | 656 | 663 | 647 | 648 |
| `hardcoded` istruzioni | 776 | 869 | 1 090 | 1 488 | 1 718 |
| `p1_static` ns | 41 | 40 | 41 | 41 | 38 |
| `hardcoded` ns | 48 | 45 | 46 | 47 | 45 |
| `template` ns | 188 | 186 | 188 | 187 | 187 |
| `modular` ns | 310 | 310 | 307 | 309 | 311 |

La taglia della rete entra nel programma solo in P1.5 (lo `switch` sulla one-hot del nodo si
srotola); congelando il nodo la dipendenza sparisce. A runtime nessuna pendenza: una one-hot
legge una sola colonna di pesi qualunque sia la sua larghezza.

**`depth`** (1 → 6 hidden layer):

| | 1 | 2 | 3 | 4 | 5 | 6 |
|---|---:|---:|---:|---:|---:|---:|
| `p1_static` ns | 33 | 41 | 46 | 51 | 56 | 60 |
| `hardcoded` ns | 40 | 46 | 51 | 57 | 62 | 68 |
| `template` ns | 166 | 187 | 213 | 235 | 266 | 289 |
| `modular` ns | 249 | 310 | 358 | 423 | 470 | 513 |
| `template` istruzioni | 14 657 | 15 142 | 16 866 | 16 998 | 17 992 | 18 990 |
| `modular` istruzioni | 12 394 | 12 394 | 12 394 | 12 394 | 12 394 | 12 394 |

**P3 ~53 ns per strato a istruzioni identiche**: srotola un layer generico e ci rientra con
un tail call, quindi la profondità non entra nel programma e si paga in tempo (tail call e
letture di mappa). **P2 ~25 ns per strato** e ~870 istruzioni: lo strato in più è codice in
linea. Fino al 2026-09-27 P2 oltre due strati non caricava (§8). P1 ~5 ns per strato.

**`width`** (neuroni per hidden layer 2 → 8):

| | 2 | 4 | 6 | 8 |
|---|---:|---:|---:|---:|
| `p1_static` | 27 | 42 | 51 | 67 |
| `hardcoded` | 34 | 47 | 61 | 75 |
| `template` | 174 | 190 | 201 | 212 |
| `modular` | 279 | 306 | 341 | 383 |

Allargare i layer nascosti si paga su tutte: *la rete può crescere quanto vuole, il modello
no.*

**`isoparam`** (592 ± 2% parametri, 1 → 5 hidden layer):

| | 1 | 2 | 3 | 4 | 5 |
|---|---:|---:|---:|---:|---:|
| `p1_static` | 52 | 54 | 55 | 67 | 66 |
| `hardcoded` | 60 | 65 | 62 | 75 | 71 |
| `template` | 169 | 189 | 206 | 261 | **268 (+59%)** |
| `modular` | 274 | 321 | 355 | 443 | **471 (+72%)** |

A parità di parametri le due P1 crescono poco e non in modo monotono (circa +25% fra gli
estremi); P2 cresce del 59% e P3, a istruzioni identiche in tutti e cinque i punti, del 72%.

**`descriptor`** — istruzioni:

| | default | no_onehot | small_onehot | big_onehot |
|---|---:|---:|---:|---:|
| `p1_static` | 663 | 656 | 649 | 563 |
| `hardcoded` | 1 090 | 656 | 649 | 976 |
| `template` / `modular` | 15 142 / 12 394 | ← | ← | ← |

Cambiare la composizione del vettore d'ingresso ricompila P1, mentre P2 e P3 leggono il
descrittore da `model_desc`. È anche il **controllo** della specializzazione: dove il
descrittore non dichiara la feature `node` le due P1 sono identiche alla cifra (656/656,
649/649); dove la dichiara divergono.

**`sparsity`** (frazione di pesi zero):

| | 0% | 25% | 50% | 75% | 90% |
|---|---:|---:|---:|---:|---:|
| `p1_static` istruzioni | 663 | 609 | 529 | 446 | **263** |
| `hardcoded` istruzioni | 1 090 | 968 | 885 | 717 | **357** |
| `p1_static` ns | 41 | 36 | 30 | 24 | 19 |
| `hardcoded` ns | 47 | 42 | 35 | 31 | 26 |
| `template` / `modular` ns | 189 / 307 | 186 / 307 | 186 / 311 | 188 / 310 | 188 / 310 |

I pesi di P1 sono letterali nel C, quindi clang cancella i prodotti per zero: al 90% di zeri
P1 perde più di metà della latenza, mentre per P2/P3 uno zero è un byte in mappa come un
altro. Le due P1 convergono (il divario scende da 427 a 94 istruzioni): sparsità e nodo
congelato sono due strade alla stessa riduzione.

### Congelare il nodo: P1 specializzata contro P1.5

| | 10 nodi | 52 nodi (Germany50) | 100 nodi |
|---|---:|---:|---:|
| istruzioni `p1_static` / `hardcoded` | 647 / 776 | 663 / 1 090 (−39%) | 648 / 1 718 (−62%) |
| codice nativo (B) | 2 884 / 3 507 | 2 929 / 5 294 (−45%) | 2 867 / 8 507 (−66%) |
| latenza (ns) | 41 / 48 | 41 / 46 (−11%) | 38 / 45 (−16%) |

La riga della specializzata è **piatta**: la feature più grossa del modello (52 dei 65
ingressi, 208 dei 319 pesi) smette di dipendere dalla taglia della rete. In tempo il
guadagno c'è ma è piccolo (5–7 ns): lo `switch` ha N casi ma ne esegue uno. Il prezzo è un
binario per nodo: `build_ms` ~70 ms (p1_static) e ~80-120 ms (hardcoded) per compilazione,
N volte su una rete di N nodi. Aggiornare il modello sul nodo (oggetto AOT già compilato)
costa ~1 ms per entrambe.

### Aggiornare il modello

`update_ms` (installare un modello nuovo su un nodo in servizio): P1 e P1.5 **0,7–2,1 ms**
(caricamento dell'oggetto AOT), P2 e P3 **10–12 ms** (scritture in mappa, compresa la
semantica). `build_ms` (una volta): P1 66–120 ms di clang sulla macchina di build, P2
~1,5 s e P3 ~1,2 s di BCC all'avvio del nodo. Con l'oggetto precompilato non c'è più un
divario di ordini di grandezza a favore di P2/P3: resta la differenza qualitativa, P1
richiede un compilatore (fuori dal nodo) per ogni modello nuovo.

### Campagna sulle architetture (`--axis campaign`)

Quattro assi, cinque pipeline inclusa la baseline, un CSV: `results/model_scaling_test_suite.csv`.

| Asse | Valori | Cosa muove |
|---|---|---|
| `iv_dense` | n_in 5, 9, 13, 17 | colonne d'ingresso dense |
| `iv_onehot` | n_in 16, 32, 65 | colonne d'ingresso in una one-hot |
| `width_camp` | 65-v-v-7, v = 4, 8, 16, 32 | neuroni per strato |
| `depth_camp` | 65-8…8-7, 1–4 strati | profondità a larghezza 8 |

Retta ai minimi quadrati sui quattro assi insieme:

| Pipeline | ns / MAC **eseguita** | r² | ns / MAC nominale | r² |
|---|---:|---:|---:|---:|
| p1_static | 0,287 | **0,99** | 0,070 | 0,62 |
| hardcoded | 0,290 | **0,98** | 0,076 | 0,70 |
| template | 0,548 | 0,71 | 0,085 | 0,22 |
| modular | 1,175 | **0,91** | 0,098 | 0,08 |

Con le MAC nominali il modello spiega poco; con quelle **eseguite** i quattro assi
collassano sulla stessa retta. Una one-hot occupa `size` colonne nella matrice dei pesi ma
nel datapath ne attiva una: contarla come `size × h1` sovrastima. **P3 costa 4,1× P1 per
MAC eseguita**: il prezzo di leggere i pesi da una tabella invece che averli come letterali.
Il template ha r² più basso perché ha un costo fisso alto rispetto alla pendenza, e il suo
residuo più grande sta su `width_camp`, dove i neuroni oltre la larghezza del modello
vengono calcolati comunque fino al soffitto.

L'asse `iv_onehot` lo mostra direttamente: n_in ×4, pesi ×2,4, latenza piatta su tutte
(p1_static 65/65/64, hardcoded 65/64/64, template 170/170/169, modular 363/367/367 ns) mentre
le istruzioni di P1 vanno da 1 144 a 1 632.

I muri: larghezza 16 e 32 su P2/P3 sfondano `T2_MAX_H1`/`ML1_MAX_H1` = 8 e il banco segna
`RIFIUTATO` prima di compilare (P3 risponderebbe `XDP_PASS` a runtime, cioè una misura di un
programma che non calcola). Larghezza 32 su P1 non compila (stack). Fino al 2026-09-27
anche larghezza 16 su P1 era rifiutata dal verificatore: con `ipa_relu` carica (166 ns
p1_static, 170 hardcoded).

**Calibrazione contro la suite kernel**, stesso modello 65-4-4-7: campagna 18 / 46 / 190 /
305 ns contro `test_suite` 18 / 52 / 195 / 315 ns (baseline, hardcoded, template, modular):
entro 0 / −12%, sempre nello stesso verso, e i programmi non sono identici (pesi sintetici
contro pesi del modello: 1 090 contro 1 064 istruzioni per P1.5).

---

## Risultati (kernel, `test_suite.py --only kernel`, modello 65→4→4→7, scala 24)

Un solo run, un solo stato del codice (2026-09-28, con `ipa_relu`, §8), DUT a 3 494 MHz;
minimo su 7 trial con p50/max.

| Metrica | baseline | P1 hardcoded (AOT) | P2 template | P3 modular |
|---|---:|---:|---:|---:|
| Istruzioni eBPF (xlated) | 155 | 1 064 | 15 142 | 12 394 |
| Codice jited (byte) | 706 | 5 179 | 68 510 | 57 767 |
| Tail call / pacchetto | 0 | 1 | 1 | **3** |
| Map lookup / pacchetto | 3 | 6 | 11 | **29** |
| Memoria mappe (byte) | 280 | 2 516 | 141 744 | 171 572 |
| **Latenza min (ns/pkt)** | **18** | **52** | **195** | **315** |
| ...p50 | 18 | 53 | 200 | 320 |
| ...max | 19 | 53 | 200 | 322 |
| ...spread (max−min)/min | 6% | 2% | 3% | 2% |
| Throughput teorico (Mpps, 1/latenza) | 55,6 | 19,2 | 5,1 | 3,2 |

| | dispatcher | leaf |
|---|---|---|
| baseline | — | `xdp_baseline` 155 |
| P1 hardcoded | `xdp_dispatch` 29 | `xdp_model` 1 035 |
| P2 template | `ipa_switch_template` 41 | `arch_generic_2layer` 15 101 |
| P3 modular | `modular_dispatcher` 137 | `layer_first` 10 528 + `layer_hidden` 1 729 |

Correttezza, stesso run: dispatch TTL 2-6 **5/5** su tutte e tre; TTL (decremento + checksum
+ scadenza) **2/2** su tutte e tre; `link_state` reroute **15/30** casi di link-down cambiano
uscita; architetture alternative PASS; `test_fabric` 29/29 e 11/11 (AOT). Aggiornamento del
modello di P1 sul nodo (open + caricamento dell'oggetto AOT): **1,07 ms**.

Lo spread fra minimo e massimo dei 7 trial sta fra il 2 e il 6%. I programmi più brevi
restano i più sensibili: su 18 ns un nanosecondo è il 6%.

**Rispetto al 2026-09-27** (22 / 47 / 199 / 323 ns): la baseline, che non ha ReLU, scende di
4 ns, e P2 e P3 con lei; P1 sale di 5 ns. La ReLU senza salto costa a P1 circa 9 ns sotto
`BPF_PROG_TEST_RUN`, dove il salto di prima era sempre predetto; sul traffico vero la
differenza sparisce (§10.2).

### La dimensione non predice la velocità

**P3 ha il 18% di istruzioni in meno di P2 ed è il 62% più lento** (12 394 contro 15 142;
315 contro 195 ns). Le righe che lo spiegano: **3 tail call** contro 1, **29 lookup** contro
11. Il conteggio `xlated` misura quanto è grande il programma, non quanto lavora.

P2 è più grande perché tiene la rete intera in un programma: `arch_generic_2layer` srotola
insieme fc1 (65→8), fc2 (8×8) e lo strato d'uscita (32×8, i soffitti). P3 srotola **un**
layer denso generico (`layer_hidden`, 1 729 istruzioni) e ci rientra per tail call a ogni
hop: la profondità non costa dimensione, e il riuso si paga in latenza (un salto più le
letture di `scratch_meta`, `scratch_acts`, `layer_shapes`, i pesi).

Le istruzioni sono un conteggio **statico**: in P1 lo switch della one-hot `node` ha 52 casi
e ne esegue uno, e con i pesi letterali clang cancella i prodotti per zero e trasforma in
shift le potenze di due. 1 064 istruzioni in 52 ns sarebbero 5,8 istruzioni per ciclo a 3,5
GHz, sopra ogni processore reale: il percorso eseguito è una frazione del conteggio.

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
istruzioni, cioè dentro il limite di dimensione ma oltre quello di complessità. È lo stesso
limite che fino al 2026-09-27 fermava P2 oltre due strati nascosti (§8) e P1 oltre ~300 pesi
(§6), prima della ReLU senza salto. Questi limiti sono scogliere, non pendenze: un soffitto
si cambia e **si rimisura**.

BCC riporta i rifiuti come `Program too large (N insns), at most 4096 insns`: il 4096 è una
costante vecchia nella stringa d'errore di BCC (P2 carica a ~15 000). Va letto come "il
verificatore ha rinunciato". Il numero nel messaggio d'errore è il conteggio **grezzo** prima
del caricamento, quello delle tabelle è **xlated**: non vanno confrontati.

### I lookup si contano su tutte e quattro

La riga "Map lookup / pacchetto" viene da build strumentate con un contatore su ogni sito di
lookup (`count_lookups`): 6 siti per la baseline, 14 per P1 (oggetto AOT), 21 per P2
(`arch_generic_2layer` 19), 34 per P3 (`layer_first` 11, `layer_hidden` 6,
`ml_argmax_forward` 12, `modular_dispatcher` 3). P1 fa 6 letture per pacchetto, una delle
quali è `node_id`: il prezzo di far dire alla one-hot del nodo *quale nodo è questo*.

### L'oggetto AOT di P1 (`method4_hardcoded_aot.py`)

| | |
|---|---|
| build offline (clang → `.o`) | 75,8 ms, una volta, sulla macchina di build |
| deploy sul nodo | **1,12 ms** (`open` 0,09 + verifica e JIT 1,03) |
| istruzioni | 1 064 (dispatch 29 + modello 1 035) |
| latenza | **51 ns/pkt** (percorso d'inoltro, retval 4), come in `test_suite` (52) |

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
picchi teorici. Qui pktgen (in-kernel) o frame XDP grezzi generano traffico vero, la
pipeline XDP lo elabora e lo redirige, e un contatore XDP sull'interfaccia d'uscita conta
quanti sono arrivati.

### 10.1 Il banco

```
pktgen (cpu10, cpu1, cpu3) ──veth ipatg0p→ipatg0──► [XDP: pipeline] (DUT, cpu6)
    ──bpf_redirect──► ipaN ──veth──► ipaNp [XDP: contatore d'uscita]
```

- **CPU separate**: i thread `kpktgend_<cpu>` sulle CPU del generatore, il thread NAPI del
  DUT (`/sys/class/net/<dev>/threaded`) pinnato sulla CPU del DUT, l'uscita in softirq sulla
  CPU del DUT oppure in thread su una CPU sua (`--egress-cpu N|auto`).
- **Una coda d'ingresso per core del DUT** (`--dut-queues auto`): i thread pktgen scrivono
  tutti sulla stessa coda. Con una coda per thread generatore (`--dut-queues gen`) il DUT
  avrebbe più thread NAPI sullo stesso core, e quale coda viene servita lo deciderebbe lo
  scheduler: a pieno carico ogni thread tiene la CPU per una fetta intera (millisecondi)
  mentre le altre code (256 descrittori) traboccano. `veth` è LLTX e il `ptr_ring` serializza
  i produttori col suo `producer_lock`: la contesa la paga il generatore, che ha margine.
- **Contatori per-CPU**: `pkt_stats` e `cls_stats`, in tutte le pipeline e nella baseline,
  sono `PERCPU_ARRAY`: ogni core incrementa la sua copia, senza istruzioni atomiche e senza
  contendersi una riga di cache quando i pacchetti arrivano su più code. I lettori sommano i
  core (`ipa/stats_maps.py`).
  Su un core solo il cambio vale poco: rispetto a `results/throughput_3500/` (stesso banco,
  contatori atomici) baseline, P1 e P1.5 guadagnano ~8 ns per pacchetto (3,31 → 3,40,
  2,94 → 3,01, 2,81 → 2,87 Mpps), P2 e P3 restano entro la dispersione (1,89 → 1,91,
  1,50 → 1,49). Sotto `BPF_PROG_TEST_RUN` la suite kernel dà 14 / 53 / 199 / 319 ns contro
  18 / 52 / 195 / 315: differenze di pochi ns in entrambi i versi, dentro la variazione fra
  i run. Le cifre di riferimento nel resto del documento restano quelle del 28-09.
- **Tre punti di conteggio**: TX (pktgen, più i respinti da `veth_xmit` a coda piena), HIT
  (`pkt_stats[0]` della pipeline), RX (contatore d'uscita). TX − HIT è ciò che non è
  arrivato al programma, HIT − RX ciò che il programma ha elaborato e non è uscito.
- **Finestra stazionaria** (default): i rate sono differenze fra due letture dei contatori
  fatte mentre tutte le istanze pktgen trasmettono (lettura sotto 3 ms, rifatta se più
  lunga), poi stop. Avvio, sfasamento dei thread e coda finale restano fuori.
- **model_id 190**: pktgen scrive la propria intestazione (magic `0xbe9be955`) subito dopo
  UDP, dove il dispatcher legge `ipa->model_id`. Il modello è registrato anche su 190 e una
  sonda verifica HIT prima di misurare.
- **La copia di headroom**: XDP su veth pretende 256 byte davanti al pacchetto, gli skb di
  pktgen ne hanno 64, quindi `veth_xdp_rcv_skb` copia ogni pacchetto prima del programma.
  Con `--generator xdp` (frame XDP grezzi da `BPF_PROG_TEST_RUN` live frames, `xdp_gen.py`)
  la copia non c'è, come da una NIC con XDP nativo.
- **La coda del veth**: `VETH_RING_SIZE` = 256 descrittori, non configurabile su questo
  kernel (`ethtool -g` non la espone).

### 10.2 Confronto a saturazione e a carico comune (`--mode compare`)

```bash
sudo python3 ipa/test/bench_throughput.py --mode compare --rounds 3 --out results/throughput_3500
```

3 giri × 3 ripetizioni, 64 B, uscita sulla CPU del DUT, `results/throughput_3500/`
(2026-09-28, con `ipa_relu`):

| pipeline | saturazione (Mpps) | [min–max] | variazione | a 1,375 Mpps offerti |
|---|---:|---|---:|---|
| rxonly (sola ricezione) | 4,61 | 4,60–4,62 | 0,2% | nessun respinto |
| baseline | 3,31 | 3,24–3,31 | 0,9% | nessun respinto |
| p1_static (P1) | 2,94 | 2,93–2,96 | 0,5% | nessun respinto |
| hardcoded (P1.5) | 2,81 | 2,78–2,82 | 0,6% | nessun respinto |
| template (P2) | 1,89 | 1,88–1,90 | 0,5% | nessun respinto |
| modular (P3) | 1,50 | 1,50–1,51 | 0,3% | nessun respinto |

Controllo di validità PASS (la baseline è la più veloce). A carico comune — 91% di quanto
consegna la più lenta — tutte e sei consegnano tutto: **nessun pacchetto respinto sotto
capacità**. Perdita totale ≤ 0,02% in ogni riga. Macchina: nessun evento di throttling,
DUT a 3 494 MHz.

**P1 e P1.5 si separano**: 2,94 contro 2,81 Mpps, con dispersioni dello 0,5% e dello 0,6%.
L'ordine P1 < P1.5 < P2 < P3 in costo per pacchetto regge in ogni giro. Costo sopra la
baseline (1/RX): **+38 / +53 / +226 / +364 ns**. Il 2026-09-27, prima di `ipa_relu`:
+38 / +53 / +224 / +368. Sul traffico vero la ReLU senza salto non costa niente di
misurabile, anche per P1 (sotto `BPF_PROG_TEST_RUN` le costava ~9 ns, § Risultati).

**Su due core** (`--dut-cpus 6,8`, una coda d'ingresso per core, stesso generatore a 3
thread; `results/throughput_cores1/` e `results/throughput_cores2/`, 2026-09-28, contatori
per-CPU):

```bash
sudo python3 ipa/test/bench_throughput.py --mode compare --rounds 3 --gen-cpus 10,1,3 --dut-cpus 6   --out results/throughput_cores1
sudo python3 ipa/test/bench_throughput.py --mode compare --rounds 3 --gen-cpus 10,1,3 --dut-cpus 6,8 --out results/throughput_cores2
```

| pipeline | 1 core (Mpps) | 2 core (Mpps) | rapporto |
|---|---:|---:|---:|
| rxonly | 4,62 | 7,50 | 1,62 |
| baseline | 3,40 | 6,50 | 1,91 |
| p1_static (P1) | 3,01 | 5,76 | 1,91 |
| hardcoded (P1.5) | 2,87 | 5,58 | 1,95 |
| template (P2) | 1,91 | 3,72 | 1,95 |
| modular (P3) | 1,49 | 2,95 | 1,98 |

Le pipeline crescono **quasi linearmente** (1,91–1,98): i core non si contendono niente di
scritto a ogni pacchetto, e le due code ricevono un carico simile anche con 3 thread
generatore su 2 code. `rxonly` cresce meno (1,62): a 7,5 Mpps il generatore offre 8,3 Mpps,
vicino al suo tetto, e la differenza fra le code pesa di più. Nessun throttling, macchina non
disturbata in entrambe le misure. Il costo per pacchetto per core resta quello di 1 core: il
numero da riportare per un nodo con N code è ~N × la capacità a 1 core, finché il
generatore e la scheda reggono.

### 10.3 Tre marcature: la pipeline separata dal trasporto (`--mode rates`)

```bash
sudo python3 ipa/test/bench_throughput.py --mode rates --frames 64 --rounds 3 \
    --rates 0.5,1,1.5,2,2.5,3 --out results/throughput_rates
```

Build **strumentata**: il dispatcher marca T1, il programma marca T2 subito prima di
`bpf_redirect`, il contatore d'uscita T3. Minimi per finestra, mediana fra tre giri, ns:

| | T2−T1 (pipeline) | T3−T2 (redirect + veth + NAPI) | sostenibile (perdita totale ≤ 0,1%) |
|---|---:|---:|---|
| baseline | 34–35 | 194–239 | ≥ 2,0 Mpps |
| p1_static | 68–69 | 195–244 | ≥ 2,0 Mpps |
| hardcoded | 77–78 | 195–251 | ≥ 2,0 Mpps |
| template | 228–233 | 200–257 | ≥ 1,5 Mpps |
| modular | 340–348 | 207–251 | ≥ 1,0 Mpps |

Il trasporto è un costo comune di ~195–255 ns che non dipende dalla pipeline; T2−T1 è
piatto sul rate. Sopra la baseline la sola pipeline costa **+34 / +43 / +194 / +306 ns**.
Sotto capacità i respinti restano allo 0,00–0,02%. I "sostenibili" sono gradini della scala
(0,5 Mpps): contando solo la perdita dopo l'ingresso salgono a 2,42 / 2,25 / 2,18 / 1,59 /
1,31 Mpps. La build strumentata aggiunge due letture dell'orologio e due scritture per
pacchetto: il suo throughput è più basso di quello di produzione (§10.2).

### 10.4 Il tetto di sola ricezione (`--mode generator`)

```bash
sudo python3 ipa/test/bench_throughput.py --mode generator --frames 64 --rounds 5 \
    --rates 8,10,12,15,20,25 --out results/throughput_generator
```

Contatore che scarta all'ingresso, nessuna pipeline: il generatore offre ~5,7 Mpps, il DUT ne
riceve **4,50–4,71** (30 finestre). È lo stesso tetto che `rxonly` misura dentro `--mode
compare` (4,61): la baseline sta al 72% del tetto di ricezione, P3 al 33%.

### 10.5 Frame XDP grezzi: il costo del nodo (`--generator xdp`)

```bash
sudo python3 ipa/test/bench_throughput.py --mode compare --generator xdp --egress-cpu auto \
    --rounds 5 --out results/throughput_xdp
sudo python3 ipa/test/bench_throughput.py --mode compare --generator xdp --egress-cpu auto \
    --frames 64,512,1514 --rounds 3 --out results/throughput_xdp_frames
sudo python3 ipa/test/bench_throughput.py --mode compare --generator xdp --egress-cpu auto \
    --per-class --rounds 3 --out results/throughput_per_class
```

Costo del nodo = 1e9 / pacchetti elaborati (HIT + MISS + DROP): dalla presa dalla coda di
ricezione alla decisione e al redirect, con l'uscita su una CPU sua (cpu8).

| | ns/pacchetto | elaborati (Mpps) | arrivati all'uscita (Mpps) |
|---|---:|---:|---:|
| baseline | 141 | 7,11 | 4,38 |
| p1_static | 158 | 6,34 | 4,78 |
| hardcoded | 161 | 6,23 | 4,87 |
| template | **296** | 3,38 | 3,38 |
| modular | **434** | 2,30 | 2,30 |

**Solo le righe di P2 e P3 sono costi del nodo.** Per baseline, P1 e P1.5 il nodo elabora
quanto il generatore produce: la sola ricezione (`rxonly`) si ferma a ~6,9 Mpps, il tetto del
generatore XDP a 3 thread, e la baseline la supera (7,1) proprio perché nessuna delle due è
il limite. Le loro cifre sono **limiti superiori** del costo. Per risolverle servono più
thread generatore.

**Il controllo di validità conta gli elaborati, non gli arrivati.** Il core d'uscita (cpu8,
che riceve per tutti e cinque i veth) consegna 4,4–4,9 Mpps e il resto si perde dopo XDP.
Contando gli arrivati la baseline (4,38) sembrerebbe più lenta di P1 (4,78): più pacchetti
spinge verso l'uscita già satura, più ne perde. `check_validity` confronta quindi
`node_pps` (elaborati, altrimenti HIT, altrimenti RX), la stessa grandezza con cui il banco
calcola il costo.

- **Taglia del frame**: 64 / 512 / 1514 B danno lo stesso costo entro il 3% su ogni pipeline
  (template 298–307, modular 433–444 ns): il nodo tocca solo le intestazioni.
- **Per classe** (stato dei link e TTL cercati per ciascuna delle 6 classi raggiungibili,
  classe decisa verificata): sulle 5 classi FORWARD P2 255–284 e P3 426–433 ns; **la classe
  DROP costa di più**, P1 260 contro ~158, P1.5 268 contro ~161, P2 330, P3 468 ns. Con il
  DROP la pagina si restituisce sulla CPU del DUT; con l'inoltro sulla CPU d'uscita.

### 10.6 Latenza arrivo → ripartenza (`--latency`)

```bash
sudo python3 ipa/test/bench_throughput.py --latency --frames 512 --rounds 3 --repeat 5 \
    --out results/throughput_latency
```

Build strumentata: il dispatcher marca l'arrivo, il programma d'uscita rilegge e sottrae.
Latenza minima **a scarico** (50 kpps, nessuna coda), mediana fra tre giri:

| | baseline | p1_static | hardcoded | template | modular |
|---|---:|---:|---:|---:|---:|
| min (ns) | 249 | 282 | 292 | 460 | 584 |
| sopra la baseline | — | +33 | +43 | +211 | +335 |

Solo la colonna `min` è una misura: p50 e p99 vengono da un istogramma `bpf_log2l` (bucket a
potenze di due) e cadono negli stessi due bucket per tutte le pipeline (1 024 ns per
baseline e P1, 2 048 per P2 e P3). Il minimo a scarico varia al massimo del 5% fra i giri.
La **ricerca del rate a perdita nulla** invece disperde oltre il 25% fra i giri (fino al
64%), perché al confine basta un'esitazione di pochi µs per perdere un pacchetto: il banco
la segnala con `rc=1` e non è una cifra citabile; la saturazione (§10.2) e il carico comune
sì.

---

## 11. Al crescere del bit rate: ritardo, ricevuti, rilanciati (`bench_bitrate.py`)

La domanda del relatore: al crescere del bit rate inviato la coda si riempie, il tempo
end-to-end cresce e poi si perde; se si perde all'**uscita** del programma il collo di
bottiglia è trasmissivo, se si perde all'**ingresso** è il programma eBPF. Contare quanti
pacchetti il programma riceve e quanti ne rilancia, con due programmi sullo stesso XDP: uno
che conta soltanto, uno con la pipeline.

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
(`kernel.bpf_stats_enabled`, `run_time_ns / run_cnt`, tail call comprese).

### 11.3 Contatori e formule

| grandezza | dove si conta |
|---|---|
| inviati | pktgen: `pkts-sofar` + `errors` (respinti a coda d'ingresso piena) |
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
punti**: sotto capacità `rxonly` perde lo 0,01–0,03%). **Inizio della perdita**: il rate più
basso da cui *tutti* i rate più alti perdono; una riga in perdita seguita da righe pulite è
"sporadica". Finestre marcate: `gen_limited` (generatore sotto il 95% del chiesto),
`gen_burst` (oltre il 105%), `host_disturbed` (§0.3).

### 11.4 La latenza end-to-end

pktgen scrive in ogni pacchetto, dopo UDP, magic, seq, `tv_sec` e `tv_usec`: l'istante in cui
ha costruito il pacchetto (`CLOCK_REALTIME`, µs). Il programma d'uscita lo confronta col
proprio orologio:

```
lat_us = floor((bpf_ktime_get_ns() + off) / 1000) − (tv_sec·10⁶ + tv_usec)
off    = CLOCK_REALTIME − CLOCK_MONOTONIC, letto prima di ogni punto
```

Il percorso misurato è tutto il nodo, **attesa in coda compresa**. pktgen timbra il pacchetto
e poi aspetta il momento di trasmetterlo: quell'attesa, accumulata nel suo contatore `idle`,
si sottrae per pacchetto (`e2e_spin_correction_us`); i valori non corretti restano nel CSV.
Istogramma a celle da 1 µs fino a 1 024 µs, poi da 64 µs fino a 65,5 ms, più il trabocco; si
cronometra un arrivo ogni `mask+1` (circa `--lat-samples`, 20 000 per finestra).

### 11.5 Comandi e uscite

```bash
sudo python3 ipa/test/bench_bitrate.py --out results/bitrate_3500        # tutte, 5 giri (~5 min)
sudo python3 ipa/test/bench_bitrate.py --method rxonly,baseline,template --rounds 1 \
    --overhead-reps 0 --no-plot --out /tmp/br                              # un giro corto
python3 ipa/test/plot_bitrate.py results/bitrate_3500                      # i grafici
python3 ipa/test/bench_bitrate.py --report results/bitrate_3500            # riepilogo dai CSV
```

- **Scala** (`--bitrates`): default `auto`, calibrata all'inizio su `rxonly` a massima spinta:
  frazioni 0,05–1,25 del tetto di ricezione, fermate al 95% del tetto del generatore.
  Oppure una lista in Gbit/s, o `--rates` in Mpps.
- **Uscita**: `--egress-cpu auto` (default) mette la ricezione del nodo successivo su un core
  fisico suo; `none` la lascia in softirq sulla CPU del DUT.
- **Code**: `--dut-queues auto` (una per CPU del DUT, §10.1).

| file | contenuto |
|---|---|
| `bitrate_raw.csv` | una riga per (metodo, rate, giro), riscritta dopo ogni finestra: conteggi, perdite scomposte, latenze, colonne `host_*` |
| `bitrate.csv` | mediana fra i giri, min/max, pavimento `rxonly`, collo di bottiglia, giri disturbati |
| `bitrate_overhead*.csv` | costo del contatore: ns del programma (statistiche BPF) e dal throughput |
| `host_monitor.csv` | la macchina al secondo |
| `env.csv` | macchina, condizioni, scala usata, soglia |
| `bitrate_latency`, `bitrate_pps`, `bitrate_loss` (.png/.pdf) | latenza (p50, p99), pacchetti/s, perdita; git li ignora, si rifanno dai CSV con `plot_bitrate.py` |

### 11.6 Risultati (`results/bitrate_3500/`)

6 metodi, 5 giri, 13 punti di scala (tetto di ricezione calibrato 4,68 Mpps = 2,40 Gbit/s a
64 B, generatore 6,13 Mpps), 390 finestre. DUT a 3 494 MHz, nessun evento di throttling né
sui core né sul pacchetto, nessuna finestra disturbata o con burst del generatore.

| pipeline | inoltro max (Mpps, mediana 5 giri) | variazione | pulita fino a | perde da |
|---|---:|---:|---|---|
| rxonly | 4,67 | 1,5% | — | — |
| baseline | 3,34 | 2,1% | 1,44 Gbit/s | 1,68 Gbit/s |
| p1_static | 2,94 | 2,5% | 1,20 Gbit/s | 1,44 Gbit/s |
| hardcoded | 2,84 | 2,0% | 1,20 Gbit/s | 1,44 Gbit/s |
| template | 1,89 | 1,6% | 0,72 Gbit/s | 0,96 Gbit/s |
| modular | 1,50 | 2,1% | 0,72 Gbit/s | 0,96 Gbit/s |

"Pulita fino a" e "perde da" sono **punti della scala**, spaziati di ~0,24 Gbit/s: la soglia
vera sta fra i due. P2 inoltra al massimo 1,89 Mpps ≈ 0,97 Gbit/s a 64 B, e il punto da
0,96 cade sul suo limite; P3 (1,50 Mpps ≈ 0,77 Gbit/s) perde allo stesso punto perché fra
0,72 e 0,96 la scala non ha valori. Le separa l'inoltro massimo. La scala si calibra a ogni
sessione sul tetto di `rxonly`, quindi i punti cambiano da un run all'altro.

- Per tutte e sei la perdita è **prima di XDP**: il collo di bottiglia è il programma eBPF.
  Dopo XDP al massimo lo 0,02% degli inviati.
- Latenza p50 al rate più basso 9–10 µs per tutte; all'ultimo punto pulito 6–30 µs; al primo
  in perdita 69–194 µs (la coda d'ingresso piena).
- **Costo del contatore** (statistiche BPF del kernel, tempo del programma attaccato):
  baseline 28,0 → 29,9 ns (+2,0), P1 68,0 → 70,3 (+2,3), P1.5 78,6 → 81,1 (+2,5), P2
  242,7 → 248,0 (+5,3), P3 380,4 → 378,5 (−1,9, dentro la dispersione di 10–15 ns).
- I due banchi concordano: `bench_throughput` (§10.2) dà cifre entro l'1% (3,31 contro 3,34
  per la baseline, 1,50 e 1,50 per P3), con la stessa macchina ma l'uscita sulla CPU del DUT
  e nessun contatore davanti.

---

## 12. Modelli e scenari diversi dal checkpoint (`--model`, `--topology`)

Tutti i test e i banchi del kernel e del traffico vero accettano un modello e una rete
diversi dal checkpoint depositato. Senza `--model` fanno esattamente quello che facevano
prima, per le stesse righe di codice.

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
  stessi che usa `verify_synth_kernel`). `--model checkpoint` manda il checkpoint per la
  strada nuova: pesi, scala, semantica e riferimento sono identici a quelli della strada
  vecchia (3000/3000 decisioni e logit), i sorgenti di P1 e della foglia di P2 identici
  byte per byte.
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
  (si costruisce da un checkpoint), `--mode rates` e `--latency` (build strumentate, per
  ora solo col checkpoint).

```bash
sudo python3 ipa/test/test_model_source.py --kernel      # ogni scenario x modello x pipeline
sudo python3 ipa/test/verify_synth_kernel.py --all --n 300 --pipeline p2
sudo python3 ipa/test/host_conditions.py --run -- python3 ipa/test/test_suite.py --only kernel --model synth:deep
sudo python3 ipa/test/test_fabric.py --model synth:small -q
sudo python3 ipa/test/bench_throughput.py --mode compare --rounds 3 --gen-cpus 10,1,3 --dut-cpus 6 \
     --model synth:deep --out results/models/throughput_deep
sudo python3 ipa/test/bench_bitrate.py --model synth:deep --rounds 3 --out results/models/bitrate_deep
```

### 12.3 Risultati (2026-09-29)

**Correttezza**, tutto PASS:

| controllo | esito |
|---|---|
| `test_model_source --kernel`: 6 scenari × modelli compatibili × 5 pipeline, 40 ingressi ciascuna, model_id 0 e 190 | 110/110; large su P2/P3 N/A |
| `verify_synth_kernel --all`, P1 / P2 / P3 | 8/8, 7/7 + large N/A, 7/7 + large N/A |
| suite kernel con `--model`, 9 modelli | PASS su tutti |
| `test_fabric --model`, 9 modelli | tutti i controlli PASS |

Classi consegnate dal fabric con la ricerca allargata: checkpoint 0–5, ipa_like e
ipa_ttl16 2–5, small 0–3, mixed 0–3, large 1, 4, 6, 8, deep 0, 1, 4, sparse 1, 5, ones 0.
Per ipa_like, deep, sparse, small e ones sono tutte le classi che il modello decide su
200 000 ingressi casuali: le altre i suoi pesi non le producono mai.

**Traffico vero**, `bench_throughput --mode compare`, 1 core (cpu6), generatore 10,1,3,
3 giri, macchina non disturbata, controllo di validità PASS in ogni run
(`results/models/throughput_*/`). Mpps a saturazione, fra parentesi ns/pacchetto sopra
la baseline:

| modello | forma | baseline | P1 | P1.5 | P2 | P3 |
|---|---|---:|---:|---:|---:|---:|
| checkpoint | 65-4-4-7 | 3,37 | 2,98 (+39) | 2,81 (+58) | 1,87 (+237) | 1,47 (+385) |
| deep | 65-4-4-4-7 | 3,31 | 2,87 (+46) | 2,76 (+60) | 1,78 (+261) | 1,35 (+438) |
| small | 15-4-4 | 3,30 | 3,01 (+29) | 2,88 (+45) | 2,11 (+172) | 1,74 (+271) |
| mixed | 18-6-5 | 3,28 | 3,02 (+27) | 2,90 (+40) | 2,06 (+181) | 1,67 (+293) |
| large | 117-8-8-9 | 3,30 | 2,61 (+80) | 2,54 (+90) | N/A | N/A |

Il checkpoint per la strada nuova dà 3,37 / 2,98 / 2,81 / 1,87 / 1,47 contro 3,40 / 3,01
/ 2,87 / 1,91 / 1,49 del 28-09: i programmi sono identici, e anche la baseline, che non
esegue modelli, perde l'1%. È variazione fra sessioni.

**Bit rate** su deep (`results/models/bitrate_deep/`): perdita sempre all'ingresso; pulite
fino a baseline 1,44, P1 1,44, P1.5 1,20, P2 0,72, P3 0,48 Gbit/s (col checkpoint P3 era
pulita fino a 0,72: lo strato in più la porta sotto 1,41 Mpps).

**Kernel** (`BPF_PROG_TEST_RUN`), ns/pacchetto, `results/models/kernel_battery.csv`:
misurate sotto `host_conditions` ma **a batteria**, quindi indicative finché non si
rimisurano con l'alimentatore. Baseline 14–15 ovunque; P1.5 / P2 / P3: checkpoint 51 /
198 / 322, ipa_like 51 / 194 / 314, sparse 38 / 196 / 312, deep 57 / 222 / 366, small 36 /
133 / 221, mixed 43 / 152 / 253, ones 28 / 126 / 209, large 75 / – / –.

**Che cosa dicono**: P2 e P3 costano per la **forma**, non per i pesi (checkpoint,
ipa_like, ipa_ttl16 e sparse hanno la stessa forma e lo stesso costo); P1 per i **valori**
dei pesi (sparse, stessa forma, 38 ns contro 51). Uno strato in più costa circa +24 ns a
P2 e +45–53 ns a P3, sia nel kernel sia sul traffico vero; ingressi più piccoli
abbassano P2 e P3 di 60–110 ns.

## Note e limiti

- **Ordine del design space**: costo (istruzioni, jited, tail call, lookup, memoria) e
  latenza crescono baseline → P1 → P2 → P3 su ogni banco.
- **Inferenza identica** nelle tre pipeline (stesso MLP, pesi, argmax): verificata dalla
  corrispondenza di classe kernel/riferimento e dall'equivalenza esatta sui modelli sintetici
  (`verify_synth_kernel`: P1 8/8, P2 7/7 e P3 7/7, con `large` non applicabile a P2 e P3 —
  1 097 pesi oltre `MAX_WEIGHT_ENTRIES` in P2).
- **Azione uniforme**: `argmax → class_action → porta logica → mac_table → bpf_redirect`.
- **Tutto sta su una macchina**: generatore, DUT e nodo successivo sono core diversi dello
  stesso processore, collegati da `veth`. Il costo del veth (e, con pktgen, della copia di
  headroom) è dentro le cifre. Niente NIC, niente DMA: nessuna scheda cablata su questa
  macchina supporta XDP nativo. Il confronto fra pipeline regge; le cifre assolute sono di
  questo percorso, a 3,5 GHz.
- **Nessun isolamento dal boot**: `isolcpus`, `nohz_full` e `rcu_nocbs` richiedono parametri
  di boot. Le CPU del banco restano soggette al tick e ai callback RCU; il resto
  dell'isolamento è a runtime (§0.3).
- **Frequenza**: fissata e misurata, ma il sysfs può dichiararne un'altra (§0.3). Le cifre
  assolute valgono a 3,5 GHz; a un'altra frequenza cambiano quasi in proporzione, i rapporti
  fra pipeline no.
- **Latenze sotto `BPF_PROG_TEST_RUN`**: esecuzione in un ciclo sullo stesso buffer, senza
  driver e senza pressione di cache da traffico vero. Il `Mpps` di quelle tabelle è un picco
  teorico; il costo sotto carico è quello di §10 e §11, più alto per P2 e P3.
