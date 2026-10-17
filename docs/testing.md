# Guida ai test — IPA/eBPF design space

Tre pipeline XDP che eseguono la stessa rete neurale intera, verificate e misurate su due
piani:

- **userspace** (PyTorch/NumPy e il C di P1 valutato dal testo): estrazione dei pesi,
  quantizzazione, semantica delle classi, modelli sintetici, formule dei banchi;
- **kernel**: `BPF_PROG_TEST_RUN` sui programmi XDP reali (istruzioni, latenza, lookup,
  memoria, dispatch) e **traffico vero** su un fabric `veth` con XDP nativo (frame XDP grezzi
  da `xdp_gen`; contatori all'ingresso e all'uscita).

| nome | pipeline | che cosa è compilato dentro | un binario per |
|---|---|---|---|
| P1 | `p1_static` | pesi **e** indice del nodo | nodo |
| P1.5 | `hardcoded` | pesi; il nodo si legge da mappa | modello |
| P2 | `template` | solo i soffitti; un programma per profondità | tutti i modelli |
| P3 | `modular` | solo i soffitti; uno strato per tail call | tutti i modelli |

`baseline` (parse + redirect, nessuna inferenza) e `rxonly` (solo ricezione) sono i
riferimenti del nodo senza rete neurale.

Gli script di test stanno in `ipa/test/`; i comandi si eseguono dalla radice del
repository. Il motore sta in `ipa/`; la topologia su cui è addestrato il checkpoint
depositato sta in `topologies/germany50/`.

**Le cifre della tesi vengono dalla campagna di popolazione** (§13,
`results/popolazione_2026-10/`, sintesi in `sintesi.md`, registro in `docs/claims.md`):
ogni banco su 109 modelli, ogni cifra un intervallo (mediana [minimo–massimo]) o una legge.
Le sezioni 0–12 descrivono i banchi uno per uno; gli esempi usano il modello depositato
65-4-4-7. Due script fanno tutto:

- `ipa/test/run_population_campaign.sh`: il traffico vero sulla popolazione (§13);
- `ipa/test/run_kernel_checks.sh`: tutto quello che non usa traffico vero (correttezza nel
  kernel, fabric, modelli sintetici, costi di tail call e verificatore, `bench_scaling`).

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
quanto il ring del `veth`, 256 descrittori, copra a 1 Mpps). E scalda: un P-core al turbo
porta il pacchetto vicino ai 100 °C in pochi secondi, con il throttling termico che rallenta
anche gli altri core.

### 0.3 Che cosa fa `host_conditions.py`

Tutto reversibile e tutto scritto in `env.csv` accanto ai numeri.

| | |
|---|---|
| ruoli | DUT, uscita e generatore su P-core fisici **distinti**, un thread per core; il fratello SMT di ognuno resta a riposo; il core della CPU 0 resta al sistema. Fra i P-core vengono prima quelli con il turbo più basso (4,5 GHz): i due "preferiti" (1-4, 4,8 GHz) sono quelli che vanno in throttling |
| frequenza | sui core del banco e sui fratelli: governor `performance`, min = max = **3500 MHz** (`--freq`), poi **misurata** con APERF/MPERF |
| sistema | CPU del sistema con un tetto di 2500 MHz (`--system-max-mhz`): il loro turbo scalderebbe il pacchetto fino al throttling |
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
processo, nessun IRQ.

**Il ripristino.** Ogni valore si salva in `/run/ipa-bench/host_state.json` prima di
cambiarlo. A fine run (anche con Ctrl-C, SIGTERM, SIGHUP o un'eccezione) si riscrive tutto
all'indietro. Un run ucciso con SIGKILL lascia il file: il run successivo ripristina per
primo, oppure `sudo python3 ipa/test/host_conditions.py --restore`.

**Il monitor.** Per finestra (colonne `host_*` di `bench_load_curve`) e per l'intero run
(`env.csv`): eventi di throttling di core e pacchetto, temperatura, frequenza reale del DUT
da APERF/MPERF, SMI, powerclamp, alimentazione; più un registro al secondo in
`host_monitor.csv`, scritto da un processo a parte. Una finestra con throttling, powerclamp,
batteria o frequenza del DUT fuori del 5% da quella misurata all'avvio è **disturbata**: si
conta e si riporta. Come la campagna tratta le misure disturbate: §13.4.

**La frequenza nel sysfs non è sempre quella vera.** Con min = max = 1400 MHz scritti nel
sysfs (la `base_frequency` dei P-core) il DUT gira a ~2000 MHz misurati; da 3000 MHz in su
i due valori coincidono entro 10 MHz. Per questo il riferimento del monitor è sempre la
frequenza **misurata** all'avvio, e `env.csv` le riporta entrambe.

### 0.4 Perché 3500 MHz

È la frequenza più alta che la macchina regge per un run intero: a 4 GHz e oltre il
pacchetto arriva al throttling dopo un paio di minuti, e a 4,5 GHz il throughput smette di
crescere. La frequenza pesa quasi in proporzione ma non del tutto, perché la uncore è fissa
e cache condivisa e memoria non accelerano con il core. Le cifre assolute vanno citate
insieme alla loro frequenza e al tipo di core del nodo (§10.8).

### 0.5 Comandi

```bash
python3 ipa/test/host_conditions.py --show           # topologia, piano, condizioni (niente root)
sudo python3 ipa/test/host_conditions.py --restore   # dopo un run ucciso
# un comando qualunque sul core del DUT, a condizioni applicate
sudo python3 ipa/test/host_conditions.py --run -- python3 ipa/test/test_weights_and_metrics.py --only kernel

python3 ipa/test/test_host_conditions.py                     # 95 controlli su un /sys finto, niente root
sudo python3 ipa/test/test_host_conditions_kernel.py         # sul kernel vero: applica, misura, ripristina
sudo python3 ipa/test/test_host_conditions_kernel.py --bench # + un giro corto di bench_load_curve

bash ipa/test/run_kernel_checks.sh          # tutto ciò che non usa traffico vero (~20 min)
bash ipa/test/run_population_campaign.sh    # la campagna di popolazione (§13)
```

`test_host_conditions_kernel.py` sul kernel vero: **25/25** con `--bench`. Rilegge dal kernel
governor, limiti, stati di idle, `AllowedCPUs`, IRQ e workqueue; verifica che un processo
nuovo di `user.slice` giri solo sulle CPU del sistema; misura che il DUT sotto carico tenga
la frequenza; confronta valore per valore la macchina prima e dopo il ripristino, anche
dopo un SIGKILL a condizioni applicate.

`bench_capacity` e `bench_load_curve` condizionano la macchina da soli (`--no-tune` per non
toccarla, `--freq`, `--no-isolate`, …: vedi `--help`). Gli altri banchi girano con
`host_conditions.py --run`.

---

## 1. Test locali (userspace): nessun root, nessun kernel eBPF

Richiede `torch` e `numpy`: senza torch `test_weights_and_metrics.py` si ferma subito, e gira
solo `--only kernel`. Su Ubuntu 24.04 torch va installato in un virtualenv o con
`pip install --user --break-system-packages torch`.

```bash
python3 ipa/test/test_weights_and_metrics.py                 # extract + quant (kernel saltata senza BCC/root)
python3 ipa/test/test_weights_and_metrics.py --only quant    # accuratezza argmax vs scale_factor
python3 ipa/test/test_weights_and_metrics.py --only extract  # coerenza pesi / weights.json / dequant

python3 ipa/test/test_class_semantics.py      # 69 controlli, cinque layout di classi
python3 ipa/test/test_synthetic_models.py     # 60 controlli sui modelli sintetici (58 senza torch)
python3 ipa/test/test_load_curve_math.py      # 100: formule e attribuzione di bench_load_curve
python3 ipa/test/test_capacity_window.py      # 18: la finestra stazionaria (vedi sotto)
python3 ipa/test/test_host_conditions.py      # 95: ruoli, moduli E-core, applicazione e ripristino
python3 ipa/test/test_model_source.py         # 62: modelli, scenari, compatibilità, limiti delle pipeline
```

`test_capacity_window` simula il generatore e i contatori del DUT con orologi veri: il
controllo "`loss_dut_pct` ~ 0 entro la coda in volo" (soglia 0,1%) può uscire poco sopra la
soglia, perché fra la lettura del generatore e quella del DUT passa un tempo variabile. È un
limite della simulazione, non del banco: 17/18 o 18/18 secondo il giro.

---

## 2. Test nel kernel (`--only kernel`)

Carica i programmi XDP reali ed esegue `BPF_PROG_TEST_RUN`: metriche del design space e
dispatch (redirect) per ogni TTL.

```bash
sudo python3 ipa/test/host_conditions.py --run -- python3 ipa/test/test_weights_and_metrics.py --only kernel
sudo python3 ipa/test/test_weights_and_metrics.py --only kernel --no-verify          # solo metriche
sudo python3 ipa/test/test_weights_and_metrics.py --only kernel --kernel-trials 15   # più trial
```

**Metodo.** Ogni pipeline gira `--kernel-trials` volte (default 7) e si riporta il
**minimo**: il rumore di sistema è a senso unico (interrupt e scheduling possono solo
rallentare un trial), lo stesso principio di hyperfine e Google Benchmark. La tabella
riporta anche p50, max e spread. Il frame si rinfresca ogni 200 esecuzioni partendo da TTL
255: `BPF_PROG_TEST_RUN` non ripristina il buffer, e il datapath decrementa il TTL.

Metriche per pipeline: istruzioni eBPF (xlated), codice jited, tail call e lookup di mappa
per pacchetto, memoria delle mappe, latenza. La memoria delle mappe per-CPU si conta una
volta per CPU. I lookup vengono da build strumentate con un contatore su ogni sito di
lookup (`count_lookups`).

Oltre al dispatch verifica:
- **corrispondenza di classe**: pre-installa `mac_table`, esegue e controlla che la classe
  scelta dal kernel sia quella del riferimento Python (`cls_stats[ref_cls] > 0`);
- **TTL**: TTL 5 esce a 4 con checksum valido, TTL 1 non viene inoltrato;
- **reroute su guasto**: con `link_state[k]=0` l'argmax cambia uscita;
- **architetture alternative** (§8).

**`ingress_iface`.** Le tre pipeline traducono l'ifindex del kernel in porta logica con una
mappa letta a runtime (`ingress_port`, `ingress_port_t2`, `ingress_port_t3`), riempita dal
piano di controllo con `common.ingress_port_slots`. Chiave = ifindex, valore = slot del
one-hot **1-based**, dove lo slot è il rango della porta fra quelle che il modello può
scegliere (`ClassSemantics.logical_ports`); la guardia nel datapath è `>= 1 && <= size`,
quindi l'assenza (0) si legge come "non è una mia porta". Sotto `BPF_PROG_TEST_RUN` il
sandbox espone `ingress_ifindex = 1` e nessuna porta risolve: il one-hot resta vuoto per
tutte e tre, e il riferimento dice la stessa cosa (`ref_ingress_port = 0`). Il fabric (§3)
accende la feature.

### P1 specializzata: le porte presenti sul nodo

`static_ports` dice al generatore di P1 quali colonne di `link_state` esistono davvero su
questo nodo: su un nodo di grado 3 su 6 `link_state[3..5]` vale sempre zero (quelle
interfacce non esistono) e quelle colonne non vengono generate. `link_state[i]` resta letto
a runtime per ogni porta che esiste; si congela la **struttura**. Solo P1 lo usa: il
generatore rifiuta `static_ports` senza `static_node`, e P1.5 resta identica byte per byte.

È esatto finché gli slot assenti valgono 0, e lo valgono per costruzione
(`link_state_monitor.carrier_state()` ritorna 0 per un'interfaccia che non esiste). Un banco
che semina tutti gli slot a 1, come `check_pipelines._seed_link_state`, fa divergere la
versione specializzata: chi confronta deve azzerare gli slot assenti nel riferimento.

```bash
sudo python3 ipa/test/bench_scaling.py --verify-ports      # 80/80 identici + controllo negativo
sudo python3 ipa/test/bench_scaling.py --axis degree --out results/
```

`--verify-ports` confronta 80 casi (TTL 2-11 × 8 pattern realizzabili, porte {0,1,4}) fra la
build con e senza `static_ports`, poi accende uno slot assente e controlla che le due build
divergano: il controllo negativo deve mordere.

### Verifier standalone e semantica per modello

```bash
sudo python3 ipa/test/check_pipelines.py --method hardcoded|template|modular   # 9/9 PASS, TTL 2-10
sudo python3 ipa/test/check_multi_model.py                                     # PASS su P1/P2/P3
sudo python3 ipa/test/check_semantics_per_model.py                             # 53/53 (§8-bis)
```

---

## 3. Il datapath reale (`netns_fabric.py`, `test_forwarding.py`)

Il banco si costruisce con `veth` sull'host: una coppia per porta logica più un ingresso
dedicato, ognuna col peer che porta uno stub `XDP_PASS`.

```bash
sudo python3 ipa/test/netns_fabric.py --n-ports 5          # costruisci, mostra, smonta
sudo python3 ipa/test/netns_fabric.py --n-ports 5 --hold   # resta su, per deployarci sopra
sudo python3 ipa/test/netns_fabric.py --cleanup            # resti di un run ucciso
sudo python3 ipa/test/test_forwarding.py                   # 29/29: P1/P2/P3, attach + redirect
sudo python3 ipa/test/test_forwarding.py --method aot      # 11/11: P1 come si deploya
sudo python3 ipa/test/test_forwarding.py --sweep           # 34/34: cinque topologie + Germany50
```

`veth` supporta XDP **native**, quindi la modalità di attach è quella di deployment. Lo stub
sui peer serve: redirigere *verso* una veth passa da `veth_xdp_xmit()`, e il kernel alloca
le code che quel percorso richiede solo se il lato ricevente ha un programma XDP. Senza, il
redirect fallisce in silenzio e il pacchetto sparisce, come se il modello decidesse di
scartare tutto. L'ingresso è dedicato e non una porta logica: altrimenti una classe che
inoltra su quella porta rimanderebbe il frame fuori dall'interfaccia da cui è entrato, dove
la cattura non lo distingue da quello iniettato.

`test_forwarding` inietta, cattura e confronta la decisione (`cls_stats`) con la porta
d'uscita: sul checkpoint 6 classi su 7 raggiunte (la settima è `UNUSED`, irraggiungibile per
costruzione), DROP verificato dal contatore e non dal silenzio.

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

P1 si deploya solo come oggetto AOT: build offline del `.o` (clang, sulla macchina di build)
e caricamento con `loader_aot`, linkato staticamente contro libbpf, sul nodo, che non ha
bisogno né di clang né di `libbpf.so`. BCC resta solo dentro i test.

Protocollo: `loader_aot --attach IFX --pin-dir /sys/fs/bpf/ipa_p1_<iface>` carica, collega
`model_progs`, pinna le mappe e stampa `READY`; il processo Python riempie le mappe (le
stesse funzioni di P2/P3, con `pinned_maps.PinnedObject`) e scrive `ATTACH`; il loader
attacca e stampa `ATTACHED`. Ctrl-C, `DETACH` o la morte del processo Python (EOF su stdin)
lo fanno staccare e togliere i pin. `--node-id` e `--ingress-port` sono opzioni del solo
bench.

```bash
python3 ipa/methods/method4_hardcoded_aot.py       # build del .o e del loader, come utente
sudo python3 ipa/methods/method4_hardcoded_aot.py  # bench: costo di deploy e per pacchetto
```

Il link statico di libbpf tira dentro anche `libelf`, `zlib`, `libzstd` e `liblzma`; lo
script prova la riga a 3 librerie e poi quella a 5. Il loader va costruito come utente
normale: file generati da root sotto `ipa/poc_aot/` fanno fallire un build successivo
(`sudo chown -R $USER:$USER ipa/poc_aot`).

**L'indice del nodo arriva al caricamento.** L'oggetto AOT di P1.5 non si porta dentro
l'indice del nodo: arriva da `--node-id` o `$IPA_NODE_ID`. Senza, la one-hot del nodo resta
spenta (la mappa è un `HASH`: il default è "non lo so", non "sono il nodo 0"), e lo stesso
binario con e senza `--node-id` sceglie classi diverse.

`test_forwarding --method aot` (11/11) prova la consegna del deploy vero: `mac_table` riletto
dopo il deploy con gli ifindex del fabric, le 5 classi FORWARD escono dalla porta attesa, la
classe DROP è contata e nulla esce, loader staccato con rc=0 e pin rimossi.

Le pipeline avviano il monitor `link_state` (polling del carrier reale delle interfacce
d'uscita). Dry-run senza eBPF:

```bash
sudo python3 ipa/link_state_monitor.py --ifaces eth0 eth1 eth2 eth3 eth4 eth5
```

---

## 5. Costo di aggiunta modello

Sulla popolazione (`bench_program_alone`, §13.3), mediana [minimo–massimo]:

| pipeline | installare un modello sul nodo in servizio | una volta, fuori dal nodo o all'avvio |
|---|---|---|
| P1, P1.5 | caricare l'oggetto AOT già compilato: P1 **0,6 [0,3–1,5] ms**, P1.5 0,9 [0,3–5,6] ms | generare e compilare il C con clang: P1 50 [34–114] ms, P1.5 61 [34–181] ms, sulla macchina di build |
| P2 | scrivere pesi, descrittore e semantica di un `model_id` nuovo: **0,3 [0,2–0,4] ms** | BCC compila il programma generico all'avvio: ~1,6 s |
| P3 | come P2: **0,3 [0,2–0,5] ms** | ~1,2 s |

Nessun compilatore sul nodo per nessuna pipeline. La differenza è qualitativa: P1 vuole un
compilatore (sulla macchina di build) per ogni modello nuovo, P2 e P3 nessuno. Limiti:
`MAX_WEIGHT_ENTRIES=1024` in P2, `MAX_LAYER_WEIGHT_ENTRIES=2048` in P3. `bench_scaling`
misura anche `update_ms` (§9), che comprende la lettura dei file del modello (il
significato delle classi): quella non è il costo di installazione.

---

## 6. Larghezza contro profondità in P1 (`bench_depth_vs_width.py`)

P1 supporta un numero variabile di hidden layer. A parità di budget-pesi, conviene allargare
un layer o aggiungerne uno?

```bash
sudo python3 ipa/test/host_conditions.py --run -- python3 ipa/test/bench_depth_vs_width.py
```

**Metodo.** Tre tier a budget abbinato (A ~300, B ~1 200, C ~4 700 pesi), per ciascuno una
forma larga e tre profonde, con la larghezza **risolta per descrittore** perché il budget
sia centrato (lo scarto è stampato). Quattro descrittori: `default` (2 one-hot),
`big_onehot` (una grande), `small_onehot` (una piccola), `no_onehot` (nessuna). Minimo su 7
trial. Ogni cella in un subprocess: un abort di clang o un rifiuto del verificatore marca
solo quella cella.

Che cosa si guarda: con un ingresso dominato da one-hot (il caso di IPA) una one-hot costa
poco, perché il datapath ne legge una colonna; con un ingresso denso ogni colonna moltiplica
le letture per la larghezza del primo strato, quindi la risposta dipende da com'è fatto il
vettore d'ingresso. Ogni neurone nascosto aggiunge tre istruzioni sempre eseguite (la ReLU
senza salto, §8). Oltre un certo budget il limite di P1 è lo stack eBPF (512 byte): clang si
ferma, e ci arriva prima la forma larga (più valori intermedi vivi insieme). La stessa
domanda sulla popolazione, per tutte le pipeline: sezione "Wide or deep, with the same
weights" di `sintesi.md` (§13.7).

---

## 7. Il costo del tail call (`bench_tail_call.py`)

Due varianti minime con lo stesso parse e lo stesso redirect, l'unica differenza è un hop
`PROG_ARRAY`: `xdp_baseline` contro `xdp_baseline_dispatch → xdp_baseline_action`.

```bash
sudo python3 ipa/test/host_conditions.py --run -- python3 ipa/test/bench_tail_call.py
```

Il salto in sé costa circa un nanosecondo. Quello che P3 paga per strato è il resto: le
letture di mappa che ricostruiscono il contesto a ogni hop (§13.7).

---

## 8. Architetture alternative dentro `--only kernel`

`suite_kernel()` chiama anche `verify_alt_architectures()`: P1 con `(8,)` e `(4,4,4)`
compilati separatamente, verificati contro `ref_infer_sparse` (5/5 ciascuna); P2 65-6-5-7 e
P3 65-5-6-4-7 registrati **insieme** al modello reale nello stesso oggetto (PASS).

**Perché la ReLU non ha salti.** Scritta `x > 0 ? x : 0`, la ReLU diventa un salto
condizionale per neurone, e il verificatore esplora entrambi i lati di ciascuno senza
riuscire a riunirli: a tre strati nascosti la foglia di P2 verrebbe rifiutata
(`BPF program is too large. Processed 1000001 insn`, `E2BIG`) pur avendo meno di 20 000
istruzioni. `ipa_relu` calcola `x & ~(x >> 63)`: nessun salto, stesso risultato bit per bit.
Una barriera `asm volatile("")` impedisce a clang di riconoscere `smax(x, 0)` e di rifarne
un salto. `check_verifier_stats.py` confronta le due scritture con le statistiche del
verificatore (`log_level = 4`), istruzioni percorse per profondità:

```bash
sudo python3 ipa/test/check_verifier_stats.py             # variante `branchless` contro `branch`
sudo python3 ipa/test/check_verifier_stats.py --only p3   # layer_first e layer_hidden di P3
```

Tutte e tre le pipeline usano `ipa_relu`.

**Il limite di profondità di P2.** Il verificatore non è il vincolo (circa 4 700 istruzioni
percorse per strato). Il primo muro è la **distanza di salto**: le istruzioni di salto eBPF
hanno un offset a 16 bit (±32 767 istruzioni), e i controlli iniziali che escono con
`XDP_PASS` saltano fino in fondo al programma; oltre una ventina di strati clang si ferma
(`LLVM ERROR: Branch target out of insn range`). Il secondo muro è la tabella dei pesi
(`MAX_WEIGHT_ENTRIES` = 1 024): ogni strato in più costa `n_h2² + n_h2` pesi.

**Soffitti e verificatore.** Istruzioni e complessità di verifica sono valute diverse: il
verificatore percorre ogni cammino del corpo srotolato, e il costo cresce col **prodotto**
dei soffitti. Con soffitti larghi (`8 × 4 × 128`) P2 si ferma a `processed 1000001 insns
(limit 1000000)` restando dentro il limite di dimensione. Un soffitto si cambia e si
rimisura. In P3 il control plane protegge il soffitto delle code (`IPA_MAX_QUEUES`):
`load_modular_weights` rifiuta un descrittore che chieda più slot di coda di quanti il
datapath ne compili, invece di troncarlo.

BCC riporta i rifiuti come `Program too large (N insns), at most 4096 insns`: il 4096 è una
costante fissa nella stringa d'errore di BCC (P2 carica programmi ben più grandi). Va letto
come "il verificatore ha rinunciato". Il numero nel messaggio è il conteggio **grezzo**
prima del caricamento, quello delle tabelle è **xlated**: non vanno confrontati.

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
  (`sem_key0`); in P3 dentro `last_key` (bit 31 = ultimo strato, bit bassi = prima riga del
  banco), perché `layer_first` sta al limite dei 512 byte di stack nelle build strumentate.

```bash
sudo python3 ipa/test/check_semantics_per_model.py [--pipeline p2|p3]
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

**Costo per pacchetto**: la chiave `(model_id, classe)` è una lettura come la chiave per sola
classe, e il numero di modelli registrati non cambia la latenza. **Memoria: +131 072 byte
per pipeline**, fissi: 256 `model_id` × 2 banchi × 32 classi preallocati.

---

## 9. Analisi parametrica (`bench_scaling.py`)

Come cambia il costo del programma (sotto `BPF_PROG_TEST_RUN`) al variare della dimensione
del modello, per le quattro pipeline.

```bash
sudo python3 ipa/test/host_conditions.py --run -- python3 ipa/test/bench_scaling.py --axis all --out results/
sudo python3 ipa/test/host_conditions.py --run -- python3 ipa/test/bench_scaling.py --axis campaign --out results/
sudo python3 ipa/test/bench_scaling.py --verify      # 80/80: P1 con il nodo congelato decide come P1.5
python3 ipa/test/bench_scaling.py --plot results/    # le figure (basta matplotlib)
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

`--axis campaign` misura quattro assi in un CSV (`model_scaling_test_suite.csv`):
`iv_dense` (n_in 5, 9, 13, 17, colonne dense), `iv_onehot` (n_in 16, 32, 65, colonne in una
one-hot), `width_camp` (65-v-v-7, v = 4, 8, 16, 32) e `depth_camp` (65-8…8-7, 1–4 strati).
Larghezza 16 e 32 su P2/P3 sfondano `T2_MAX_H1`/`ML1_MAX_H1` = 8 e il banco segna
`REFUSED` (compiled ceiling) prima di compilare (P3 risponderebbe `XDP_PASS` a runtime, cioè una misura di un
programma che non calcola).

**Metodo.** Ogni cella in un subprocess (un abort di clang o un rifiuto del verificatore è
un dato, stampato `REFUSED` o `CRASH`). Pesi da un pool fisso presi come prefisso: un
modello più grande **estende** il più piccolo, perché in P1 il conteggio istruzioni dipende
dai valori. Allarme di contaminazione: se lo stesso programma (stesse istruzioni e tail call)
varia oltre 2× lungo un asse, lo scarto è la macchina. `build_ms` è la compilazione,
`update_ms` installare il modello con la lettura dei suoi file.

Le istruzioni sono un conteggio **statico**: in P1.5 lo `switch` della one-hot del nodo ha un
caso per nodo e ne esegue uno, e con i pesi letterali clang cancella i prodotti per zero e
trasforma in shift le potenze di due. Quante istruzioni si eseguono davvero lo dicono i
contatori hardware sotto traffico (§10.8). Le leggi sul costo, stimate su tutta la
popolazione, sono in §13.7.

---

## 10. Throughput end-to-end (`bench_capacity.py`)

Sotto `BPF_PROG_TEST_RUN` il programma gira in un ciclo, senza driver e senza traffico. Qui
un generatore produce traffico vero, la pipeline XDP lo elabora e lo redirige, e un contatore
XDP sull'interfaccia d'uscita conta quanti sono arrivati. Il generatore è **`xdp_gen`**
(`ipa/test/xdp_gen.py`): frame XDP grezzi da `BPF_PROG_TEST_RUN` in modalità live frames,
consegnati al DUT come da una NIC con XDP nativo. L'alternativa, pktgen, è in §10.5.

### 10.1 Il banco

```
xdp_gen (cpu10) ──veth ipatg0p→ipatg0──► [XDP: pipeline] (DUT, cpu6)
    ──bpf_redirect──► ipaN ──veth──► ipaNp [XDP: contatore d'uscita] (cpu8)
```

- **CPU separate**: il thread di `xdp_gen` pinnato sulla CPU del generatore, il thread NAPI
  del DUT (`/sys/class/net/<dev>/threaded`) pinnato sulla CPU del DUT, l'uscita in thread su
  CPU sue (`--egress-cpu N|N,M|auto`): con una lista, la coda d'uscita del core i-esimo del
  DUT va sulla CPU i-esima; `auto` prende un core fisico libero per ogni core del DUT, finché
  ce ne sono.
- **Una coda d'ingresso e un thread di generatore per core del DUT** (`--dut-queues auto`). Il
  redirect di `xdp_gen` nel veth sceglie la coda del DUT come CPU che trasmette modulo numero
  di code: un thread per coda, su CPU di resto diverso (§10.3). Il banco avvisa se due thread
  cadono nella stessa coda.
- **Una coda d'uscita per core del DUT** (`--egress-queues auto`). Stessa regola in uscita:
  `auto` sceglie il numero minimo di code per cui i core del DUT cadono in code diverse (con
  i core 6 e 8 sono 3: 6 → 0, 8 → 2). Con un core del DUT è 1. `env.csv` riporta la mappa
  (`code_uscita`). Perché serve: §10.4.
- **Una chiamata per finestra.** Ogni chiamata a `test_run` in modalità live parte e finisce
  con una pausa del thread di ~12 ms dentro il kernel: con più chiamate per finestra il
  generatore tacerebbe una parte del tempo e il DUT svuoterebbe la coda e dormirebbe. La
  finestra è quindi una sola chiamata, interrotta da un segnale a fine misura
  (`STEADY_CALL_FRAMES`); le statistiche di scheduling del thread NAPI del DUT
  (`napi_run_pct`, §11.3) dicono se a coda piena il nodo lavora il 100% del tempo.
- **Tempo di CPU per pacchetto** (colonne `cpu_dut_pct`, `ns_cpu`, `ns_cpu_vs_baseline`):
  l'occupazione dei core del DUT letta da `/proc/stat` **nella stessa lettura** dei contatori
  della finestra stazionaria, × core / elaborati. Con il DUT al 100% coincide con
  1e9 / elaborati. La diagnostica è attiva per default (`--no-diag` la spegne); risoluzione
  ~3% (un jiffy di 10 ms su ~300 ms di finestra).
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
- **Il pacchetto che inoltra**: il pacchetto dei generatori ha TTL 32 fisso. Il banco cerca lo
  stato dei link (e delle code) con cui il modello **inoltra** quel pacchetto, lo scrive e lo
  stampa: si misura sempre un inoltro.
- **La coda del veth**: `VETH_RING_SIZE` = 256 descrittori, non configurabile su questo
  kernel (`ethtool -g` non la espone).

### 10.2 Saturazione con xdp_gen (`--mode compare --generator xdp`)

```bash
# un core, un thread di generatore, uscita su un core suo
sudo python3 ipa/test/bench_capacity.py --mode compare --generator xdp --rounds 3 \
    --gen-cpus 10 --dut-cpus 6 --egress-cpu 8 --out results/pcore_compare
sudo python3 ipa/test/bench_capacity.py --mode compare --generator xdp --rounds 3 \
    --gen-cpus 10 --dut-cpus 6 --egress-cpu 8 --per-class --out results/pcore_per_class
```

Costo del nodo = **tempo di CPU per pacchetto** (§10.1): dalla presa dalla coda di ricezione
alla decisione e al redirect, con l'uscita su una CPU sua. Costo della rete neurale = tempo
di CPU della pipeline meno quello della baseline nello stesso run. Uscite in `compare.csv`,
`compare_raw.csv` (un giro per riga), `throughput_summary.csv`, `throughput_report.md`.

Sulla popolazione, P-core, ns di rete neurale per pacchetto: P1 53 [19–155], P1.5 58
[19–156], P2 226 [129–446], P3 421 [240–852]; capacità del nodo (Mpps per core) P1 8,44
[4,52–11,72], P2 3,43 [1,95–5,11], P3 2,05 [1,09–3,26]; baseline 15,04 [14,48–15,38]
(sezione "What the neural network costs" di `sintesi.md`). L'ordine P1 ≤ P2 ≤ P3 regge su
tutti i 103 modelli che P2 sa eseguire.

**Il controllo di validità conta gli elaborati, non gli arrivati.** Se l'uscita non tiene il
passo del nodo si perde dopo XDP, e contando gli arrivati la pipeline più veloce sembrerebbe
la più lenta. `check_validity` confronta `node_pps` (elaborati, altrimenti HIT, altrimenti
RX), la stessa grandezza del costo, e boccia il run (`RUN BOCCIATO` in
`throughput_report.md`) se la baseline non è la più veloce.

- **Per classe** (`--per-class`): stato dei link e TTL cercati per ciascuna classe
  raggiungibile, classe decisa verificata, una sessione per classe. Sulla popolazione le
  classi FORWARD costano uguale (differenza 0 [0–9]%) e scartare costa 51 [17–63] ns in più:
  con il DROP la pagina del pacchetto si restituisce sul core del nodo, con l'inoltro sul
  core d'uscita. È un effetto del banco.
- **Taglia del frame** (`--frames 64,512,1514`): il nodo tocca solo le intestazioni;
  differenza fra 64 e 1514 byte 1,2 [0,3–3,1]%.
- **TTL misti**: un TTL diverso per ogni pacchetto, quindi classi diverse, DROP compreso,
  contro il pacchetto fisso: 0 [−6–4]% sul tempo del nodo.

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
thread NAPI d'uscita. Per questo ogni core del nodo ha la sua coda d'uscita
(`--egress-queues auto`) e la sua CPU d'uscita.

```bash
sudo python3 ipa/test/bench_capacity.py --mode compare --generator xdp --rounds 3 \
    --gen-cpus 10,1 --dut-cpus 6,8 --egress-cpu 3,5 --out results/pcore_cores2      # 2 P-core
sudo python3 ipa/test/bench_capacity.py --mode compare --generator xdp --rounds 3 \
    --gen-cpus 10,1 --dut-cpus 12,16 --egress-cpu 6,8 --out results/ecore_cores2    # 2 E-core
```

Sulla popolazione due core elaborano il **99 [94–103]% del doppio** di uno (80 coppie,
sezione "Two node cores"): il numero da riportare per un nodo con N code è ~N × la capacità
a un core, finché generatore e scheda reggono. Il banco verifica la mappa coda → core
d'uscita a fine run.

### 10.5 L'alternativa: pktgen

`--generator pktgen` (richiesto da `--latency`, `--mode saturate` e `--mode generator`) usa i
thread `kpktgend_<cpu>` del kernel. pktgen crea skb con 64 byte di headroom; XDP su veth ne
pretende 256, quindi `veth_xdp_rcv_skb` **copia** ogni pacchetto prima del programma, sul
core del nodo, e la sola ricezione si ferma intorno a 4,6 Mpps. Su una NIC con XDP nativo la
copia non c'è: per questo il banco usa `xdp_gen`, e le cifre di questo documento sono tutte
con `xdp_gen`.

### 10.6 Tre marcature: la pipeline separata dal trasporto (`--mode rates`)

```bash
sudo python3 ipa/test/bench_capacity.py --mode rates --generator xdp --frames 64 --rounds 3 \
    --gen-cpus 10 --dut-cpus 6 --rates 0.25,0.5 --out results/pcore_rates
```

Build **strumentata**: il dispatcher marca T1, il programma marca T2 subito prima di
`bpf_redirect`, il contatore d'uscita T3. I timbri stanno in mappe per-CPU, quindi l'uscita
resta in softirq sulla CPU del DUT (niente `--egress-cpu`). T2−T1 è la sola pipeline, T3−T2
il trasporto (redirect, veth, ricezione), T3−T1 al rate più basso la latenza minima
arrivo → ripartenza.

Vale per qualunque modello: con `--model` la build strumentata passa da `pipeline_setup`,
lo stesso percorso di `--mode compare` (forma del modello, foglia di P2 per la sua
profondità, strati di P3, ingressi che portano a un inoltro), con i timbri inseriti nei
sorgenti. `rates_raw.csv` riporta per ciascuna delle tre misure minimo, media, massimo e i
percentili (bordi dei bucket log2): il minimo è il caso migliore, la media il costo tipico
con le mancate di cache, il massimo dice se una sola attesa lunga sta spostando la media.

Sulla popolazione (sezioni "Light traffic against a saturated node" e "The transport to the
next node"): il trasporto minimo è un costo comune, 199 [187–221] ns sul P-core e 240
[226–274] sull'E-core, che non dipende dalla pipeline (differenza 4 [1–17]%). Il rapporto
fra la media T2−T1 a traffico leggero e il costo a nodo saturo è ~1 per P2 e P3 (1,03 e
1,02); per P1 e P1.5 è più disperso (0,77 [0,48–1,02], 0,83 [0,50–1,02]): la loro rete costa
poche decine di ns, e la differenza fra due misure grandi è rumorosa.

**Il throughput di questa modalità non è una capacità.** Con la build strumentata e l'uscita
sulla CPU del DUT la coda d'ingresso respinge a rate più bassi che in §10.2; la build
strumentata aggiunge due letture dell'orologio e due scritture per pacchetto.

### 10.7 Latenza arrivo → ripartenza

Con `xdp_gen` è T3−T1 al rate più basso di `--mode rates` (§10.6). `--latency` è il percorso
con pktgen (build strumentata, il dispatcher marca l'arrivo, il programma d'uscita rilegge e
sottrae). Solo il minimo è una misura: p50 e p99 vengono da un istogramma a potenze di due.
La **ricerca del rate a perdita nulla** disperde molto fra i giri, perché al confine basta
un'esitazione di pochi µs per perdere un pacchetto: non è una cifra citabile; la saturazione
sì.

### 10.8 Il nodo sui core lenti, e le istruzioni per ciclo

**La domanda.** Quanto cambia la capacità se il nodo gira su un E-core (Crestmont) o su un
LP E-core invece che su un P-core (Redwood Cove)? E perché: più cicli per pacchetto a parità
di istruzioni (IPC più basso), o anche più istruzioni?

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

```bash
sudo python3 ipa/test/hw_counters.py --cpu 6,12,20 --seconds 1    # i contatori, a mano
sudo python3 ipa/test/bench_capacity.py --mode compare --generator xdp --rounds 3 \
    --gen-cpus 10 --dut-cpus 12 --egress-cpu 8 --out results/ecore_compare
```

Sulla popolazione (sezioni "Instructions per packet do not depend on the core" e "What
changes on a slower core"):
1. **Le istruzioni per pacchetto sono le stesse su ogni core** (differenza massima 0,3% su
   534 coppie modello-pipeline, 0,7% sul LP E-core): cambiano i cicli, cioè l'IPC.
2. **L'E-core paga soprattutto la parte fissa del nodo**: i cicli della baseline costano
   1,56 [1,50–1,61] volte quelli del P-core, quelli della rete neurale ~1–1,1 volte. Per
   questo la capacità E/P sale da 0,63 (baseline) a 0,82–0,83 (P2, P3), e più la rete pesa
   sul pacchetto meno conta il core (ρ = 0,76).
3. **Il LP E-core** è fuori dalla L3: 13–21 mancate dell'ultimo livello di cache per
   pacchetto, perché i pacchetti scritti dal generatore gli arrivano dalla memoria. A 2,5 GHz
   regge 0,43 [0,32–0,53] volte la capacità del P-core.

---

## 11. Al crescere del bit rate: ritardo, ricevuti, rilanciati (`bench_load_curve.py`)

La domanda: al crescere del bit rate inviato la coda si riempie, il tempo end-to-end cresce
e poi si perde; se si perde all'**uscita** del programma il collo di bottiglia è
trasmissivo, se si perde all'**ingresso** è il programma eBPF. Contare quanti pacchetti il
programma riceve e quanti ne rilancia, con due programmi sullo stesso XDP: uno che conta
soltanto, uno con la pipeline. Il generatore è `xdp_gen` (`--generator xdp`), con cadenza e
timbro nel suo programma (§11.4).

### 11.1 Come si legge su XDP

Un programma XDP gira dall'inizio alla fine su ogni pacchetto, dentro il poll NAPI: non ha
una coda sua. Se è lento si riempie la coda che sta **davanti** a lui (su veth il
`ptr_ring`, 256 descrittori): il ritardo cresce, poi la coda trabocca e i pacchetti si
perdono **prima di XDP**.

| si osserva | vuol dire |
|---|---|
| inviati > ricevuti da XDP | coda d'ingresso piena: collo il **programma** (o la ricezione: lo separa `rxonly`, il solo contatore allo stesso rate) |
| ricevuti > inoltrati, con HIT > inoltrati | il programma ha deciso l'inoltro ma il pacchetto non è arrivato: collo **trasmissivo** |
| ricevuti > inoltrati, con MISS/DROP | una **decisione** del modello, non una perdita |

### 11.2 I due programmi sullo stesso hook

```
hook XDP di ipatg0 ─► xdp_ing_count   ing_count[0] += 1   (mappa per-CPU)
                        │ bpf_tail_call(ing_next[0])
                        ▼
                      dispatcher della pipeline (P1/P1.5/P2/P3/baseline)
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
(`kernel.bpf_stats_enabled`, `run_time_ns / run_cnt`, tail call comprese), in
`bitrate_overhead*.csv`.

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
una riga in perdita seguita da righe pulite è "sporadica". Una pipeline il cui thread NAPI
lavora meno del 90% del tempo (`NAPI_SATURATED_PCT`) mentre perde non è limitata dal
programma: il banco la classifica come nodo non saturo. Finestre marcate: `gen_limited`
(generatore sotto il 95% del chiesto), `gen_burst` (oltre il 105%), `host_disturbed` (§0.3).
Le colonne diagnostiche `napi_*` (scheduling del thread NAPI del DUT) e `gen_*` (cadenza di
`xdp_gen`) sono in `bitrate_raw.csv`.

### 11.4 Cadenza, timbro e latenza end-to-end

**La cadenza.** `xdp_gen` spinge al massimo; il ritmo lo tiene il suo programma: a ogni giro
legge l'orologio, prima dell'istante previsto scarta il frame (la pagina torna al pool, il
giro costa ~60 ns), poi lo spedisce e fissa il prossimo istante un intervallo più in là.
Spaziatura uniforme, non a raffiche (una raffica da 256 riempirebbe da sola la coda); dopo
una pausa recupera al più 16 frame di fila. Un thread regge una cadenza precisa fino a
~11 Mpps.

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
fino alla fine del lotto, ~12 µs, che entra nel ritardo mediano. Un lotto più piccolo toglie
quell'attesa, ma la cadenza regge rate più bassi. A coda piena il ritardo segue
256 ÷ capacità più il tratto fino al nodo successivo.

### 11.5 Comandi e uscite

```bash
sudo python3 ipa/test/bench_load_curve.py --generator xdp --gen-cpus 10 --dut-cpus 6 \
    --egress-cpu 8 --out results/pcore_bitrate   # 0,5-12 Mpps (XDP_RATES_MPPS), 5 giri
python3 ipa/test/plot_load_curve.py results/pcore_bitrate                # i grafici
python3 ipa/test/bench_load_curve.py --report results/pcore_bitrate      # riepilogo dai CSV
```

- **Scala**: `--rates` in Mpps (con `xdp_gen` il default è 0,5–12 Mpps, `XDP_RATES_MPPS`),
  oppure `--bitrates` in Gbit/s, oppure `auto`, calibrata su `rxonly` a massima spinta.
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
| `bitrate_latency`, `bitrate_pps`, `bitrate_loss` (.png/.pdf) | latenza (p50, p99), pacchetti/s, perdita; si rifanno dai CSV con `plot_load_curve.py` |

Sulla popolazione (sezione "Under growing traffic", 48 curve): il massimo inoltrato sotto
traffico crescente coincide con la capacità misurata a massima spinta (rapporto 0,99
[0,88–1,03]), e oltre la capacità i pacchetti si perdono prima del programma, in coda
(quota persa prima di XDP 1,000 [0,689–1,000]): il collo di bottiglia è il programma eBPF.

---

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
  nessuno. La profondità di P2 (circa 20 strati, distanza dei salti, §8) non è una
  costante: un modello più profondo lo rifiuta il compilatore. Una pipeline che non regge il
  modello è **non applicabile**, non un errore.

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
  `ref_infer` e `count_lookups` di `check_pipelines` lo seguono passando per
  `ipa/test/pipeline_setup.py`, i costruttori comuni di baseline, P1, P1.5, P2 e P3 (gli
  stessi che usano `check_kernel_vs_reference`, `bench_capacity` e
  `bench_program_alone`). `--model checkpoint` e nessun `--model` danno pesi, scala,
  semantica e riferimento identici, e sorgenti di P1 e della foglia di P2 identici byte per
  byte.
- **Riferimento**: quello generico (`ref_infer_sparse`), uguale a quello del 65-4-4-7 su
  20 000 ingressi casuali, classe e logit.
- **Azione della classe**: con un modello la verifica per TTL controlla anche l'azione:
  redirect per FORWARD, `XDP_DROP` per DROP, `XDP_PASS` per UNUSED. Il controllo del TTL
  decrementato usa il primo TTL che il modello inoltra.
- **Fabric**: porte, nodo, porta d'ingresso e larghezza di `link_state` dal modello. La
  ricerca dei casi, dopo stato dei link × TTL, prova anche porta d'ingresso, nodo e code
  per le classi mancanti (ogni caso scrive i suoi valori nelle mappe). Un modello consegna
  solo le classi che i suoi pesi producono.
- **Banchi di traffico**: il pacchetto con cui il modello inoltra (§10.1).
- **Saltati con un messaggio**: extract e quant (riguardano il `.pt` addestrato), le
  architetture alternative della suite (forme proprie), il deploy AOT di `test_forwarding`
  (si costruisce da un checkpoint).

```bash
sudo python3 ipa/test/test_model_source.py --kernel      # ogni scenario x modello x pipeline
sudo python3 ipa/test/check_kernel_vs_reference.py --all --n 300 --pipeline p2
sudo python3 ipa/test/host_conditions.py --run -- python3 ipa/test/test_weights_and_metrics.py --only kernel --model synth:deep
sudo python3 ipa/test/test_forwarding.py --model synth:small -q
sudo python3 ipa/test/bench_capacity.py --mode compare --generator xdp --egress-cpu 8 --rounds 3 \
     --gen-cpus 10 --dut-cpus 6 --model synth:deep --out results/deep_compare
sudo python3 ipa/test/bench_capacity.py --mode compare --generator xdp --egress-cpu 8 --rounds 3 \
     --gen-cpus 10 --dut-cpus 6 --model ipa/synth/population/m000 --out results/m000
```

Esiti attesi di `run_kernel_checks.sh`, tutti PASS:

| controllo | esito |
|---|---|
| `test_model_source --kernel`: 6 scenari × modelli compatibili × 5 pipeline, 40 ingressi ciascuna, model_id 0 e 190 | 110/110; large su P2/P3 non applicabile |
| `check_kernel_vs_reference --all` | P1 8/8, P2 e P3 7/7 più large non applicabile; 300/300 decisioni identiche per modello |
| suite kernel e `test_forwarding` con `--model`, 9 modelli | PASS su tutti |
| `check_semantics_per_model` | 53/53 |

---

## 13. La campagna di popolazione (`run_population_campaign.sh`)

Ogni banco delle sezioni precedenti gira qui su **109 modelli sintetici** invece che su
uno. Le conclusioni le tira `report_population.py`: intervalli sulla popolazione
(mediana [minimo–massimo]), leggi stimate su tutti i modelli con l'errore su modelli
lasciati fuori, e per ogni affermazione su quanti modelli regge.

```bash
bash ipa/test/run_population_campaign.sh                       # tutto, ~4 h 30
CAMPAGNA=results/prova_pop POP_SOLO="m000 m037" \
    bash ipa/test/run_population_campaign.sh                   # prova breve
bash ipa/test/run_population_campaign.sh pop solo              # alcune sezioni
python3 ipa/test/report_population.py results/popolazione_2026-10 > sintesi.md
```

### 13.1 La popolazione (`model_population.py`)

Tier `base`: 109 modelli in cinque famiglie. **base** (53): 7 composizioni dell'ingresso
(solo dense, solo one-hot, miste; 5–117 ingressi) × profondità 1, 2, 3, 4, 6 × larghezza
2, 4, 8, metà delle combinazioni, 3–7 uscite. **replica** (20): sei forme con tre semi in
più (uno a pesi normali). **sparsita** (8): quattro forme al 50 e al 90 % di pesi a zero.
**imbuto** (10): cinque forme a ~592 pesi su 1–5 strati, due composizioni. **strati**
(18): 1–6 strati nascosti a moltiplicazioni eseguite costanti (102–113) su tre composizioni
(dense17, mixed33, ipa65), in fondo al manifesto (id m091–m108). Seme fisso (la
popolazione rigenerata è identica byte per byte); un seme si scarta se il modello non
inoltra il pacchetto del generatore in nessuno stato dei link, o non raggiunge almeno due
classi. I modelli che P2 non sa eseguire (6, oltre 1 024 pesi) restano, e il manifesto
(`population.csv`) dice perché. I test lunghi girano su sottoinsiemi dal più leggero al
più pesante (6–14 modelli).

### 13.2 Le sezioni

| sezione | banco | che cosa misura |
|---|---|---|
| `genera` | `model_population.py` | genera la popolazione e il manifesto |
| `corretto` | `check_kernel_vs_reference.py` | riferimento intero contro eBPF, 200 ingressi, ogni modello e pipeline |
| `rif` | `bench_capacity.py` | rxonly e baseline senza modello, una volta per tipo di core |
| `pop` | `bench_capacity.py` | ogni modello su P-core ed E-core: capacità, tempo di CPU, contatori hardware, programmi caricati; T2−T1 e T3−T2 a 0,25 e 0,5 Mpps |
| `lpe`, `carico`, `core2` | `bench_capacity.py`, `bench_load_curve.py` | LP E-core, traffico crescente, due core |
| `classi`, `mix`, `taglie` | `bench_capacity.py` | una sessione per classe, TTL misti, 64/512/1 514 B |
| `solo` | `bench_program_alone.py` | programma da solo, letture di tabella e salti per pacchetto, installare un modello; `--compila` (senza root) generare e compilare P1 |
| `sintesi` | `report_population.py` | `$CAMPAGNA/sintesi.md` |

### 13.3 Il programma da solo (`bench_program_alone.py`)

Carica il modello con `pipeline_setup.build`, lo stesso costruttore dei banchi sotto
traffico, e lo esegue con `BPF_PROG_TEST_RUN` sul **pacchetto e con gli ingressi del
traffico**: TTL 32, il nodo e la porta del fabric, lo stato dei link che fa inoltrare il
modello (`bench_capacity._forwarding_inputs`). Con il TTL 255 di `bench_scaling` un
modello su quattro della popolazione decide di scartare, e il programma da solo
misurerebbe la strada dello scarto. Il kernel non ripristina il pacchetto fra una
ripetizione e l'altra e il datapath decrementa il TTL: quindi ogni esecuzione è una
chiamata con `repeat=1` (mediana di 1 000, minimo su 7 prove), e `fwd_pct` registra la
quota di esecuzioni inoltrate; il report usa solo le misure al 99 % o più. Le letture di
tabella si contano con la build strumentata (`lookup_ctr`), sullo stesso pacchetto.
Installare un modello: per P1 caricare l'oggetto compilato (`t_redirect_s` del loader),
per P2 e P3 scrivere le tabelle di un `model_id` nuovo (`register_model_id`). `--compila`
genera il C di P1 e lo compila con clang senza cache: non serve root, ma serve una cache
scrivibile (`IPA_AOT_CACHE`), perché `/tmp/ipa_aot_cache` la creano i banchi lanciati
con sudo.

### 13.4 Ripresa ed esclusioni

Una misura il cui CSV c'è già si salta; una bocciata dal controllo di validità del banco
(«RUN BOCCIATO» in `throughput_report.md`) si rifà a ogni ripresa. `report_population.py`
lascia fuori da ogni cifra le misure disturbate (`run_disturbed` in `env.csv`: throttling,
powerclamp, batteria, frequenza fuori target) e le bocciate, e le elenca in
`escluse.csv`; `POP_RIFAI_DISTURBATE=1` rifà esattamente quelle.

Su questo portatile un evento di throttling di pacchetto arriva circa una volta al minuto
anche con l'alimentatore: una curva a traffico crescente (~160 s) lo prende quasi sempre,
quindi il report la ricalcola dalle sole finestre pulite (`bitrate_raw.csv`, la `summarise`
del banco) se ogni punto conserva almeno 2 giri su 3. Lo stesso vale per una misura a
massima spinta (`compare_raw.csv`, ~30 s) disturbata solo da throttling: si tolgono i giri
la cui finestra cade entro 1 s da un evento registrato in `host_monitor.csv` (che campiona
al secondo), e le mediane si rifanno come le fa il banco se ogni pipeline conserva almeno 2
giri. Powerclamp, batteria o frequenza fuori target lasciano la misura fuori.
`host_conditions.py --run --env DIR` scrive le stesse colonne per un comando qualunque (lo
usa la sezione `solo`).

Una popolazione che aggiunge modelli in fondo al manifesto (una famiglia nuova) si accetta
nella stessa campagna: le righe dei modelli già misurati restano identiche, il manifesto
in `$CAMPAGNA` si aggiorna e le sezioni misurano solo i nuovi.

### 13.5 Cambiare modello senza fermare i pacchetti (`check_model_swap.py`)

```bash
sudo python3 ipa/test/check_model_swap.py [--pipeline template|modular] [--seconds 3]
```

Riscrivere le tabelle di un modello allo stesso `model_id` mentre i pacchetti lo usano non è
atomico: pesi, forme e descrizione cambiano una tabella alla volta. Il cambio si fa
**make-before-break**: `pipeline_setup.install_model` mette il modello nuovo sotto un id
nuovo, in una zona libera del blocco dei pesi, con il registro scritto per ultimo; i
mittenti passano al nuovo id; `retire_model` cancella il vecchio (una cancellazione da
tabella hash). La prova esegue il programma di continuo su un core e cambia modello su un
altro per 3 s (`results/popolazione_2026-10/cambio_modello/swap.json`): con la riscrittura
allo stesso id P3 ha 60 pacchetti non elaborati su 183 148 (10 156 cambi), P2 nessuno su
175 101; con make-before-break 0 pacchetti misti su 1 119 231 (6 458 cambi). Il modello
nuovo deve stare accanto al vecchio nel blocco dei pesi e, in P2, avere la profondità del
programma compilato.

### 13.6 Quanto costa installare un modello

Lo stesso modello registrato tre volte in un processo nuovo (`swap.json`, modo
`registration`): la prima 0,62 ms (P2) e 1,11 ms (P3), le successive ~0,2 ms. Sulla
popolazione: §5.

### 13.7 Il costo di uno strato e la legge del costo

**La legge** (sezione "A cost law, fitted on every model"): costo della rete = a + b × MAC +
c × strati, stimata ai minimi quadrati sui modelli densi, con l'errore su un modello lasciato
fuori. Con le MAC **eseguite** (una one-hot conta come una colonna, cioè h1 MAC) la legge
spiega il tempo di tutte le pipeline (r² 0,93–0,99 sul P-core); con le MAC contate dalla
forma no (r² 0,58–0,79). I pesi a zero accelerano solo P1 e P1.5, dove i pesi sono letterali
nel C e clang cancella i prodotti per zero (sezione "Zero weights").

**Lo strato a moltiplicazioni ferme** (famiglia `strati`). Istruzioni eseguite per
pacchetto, identiche su P-core ed E-core, da 1 a 6 strati nascosti con le stesse
moltiplicazioni: P3 sale in media di **~900 per strato** (790–910 secondo la
composizione), P2 di ~370 (270–450), P1 e P1.5 restano piatte. I gradini dentro una
composizione vanno da +270 a +1 350 istruzioni: il costo di uno strato dipende dalla sua
forma, come scrive il codice.

- **P3** (`EBPF_LAYER_HIDDEN`): ogni strato è un programma raggiunto con un tail call, che
  rilegge `scratch_meta`, `layer_registry`, `layer_shapes`, i pesi e le attivazioni. I cicli
  sono srotolati a `MLH_MAX_H` = 8 (il verificatore vuole un numero di giri costante): ogni
  neurone d'uscita esegue 8 controlli `i >= n_in`, i neuroni oltre `n_out` girano a vuoto.
- **P2** (`build_arch_leaf`): gli strati sono blocchi in fila nello stesso programma, senza
  salti né riletture. I cicli interni non hanno il controllo: ogni neurone fa sempre 8
  moltiplicazioni, per zero oltre la larghezza vera.
- In entrambe il primo strato è srotolato alla misura massima: il suo costo dipende dalla
  composizione dell'ingresso, non dalle moltiplicazioni eseguite.

Legge con questi termini (costo fisso per composizione + per strato + per neurone e per
moltiplicazione degli strati dopo il primo), stimata su tutti i modelli densi (101, P2 95),
errore su un modello lasciato fuori:

| istruzioni per | P3 | P2 |
|---|---|---|
| strato | 687 | 39 |
| neurone dopo il primo strato | 44 | 122 |
| moltiplicazione dopo il primo strato | 14 | ~0 |
| errore mediano fuori stima | **0,1 %** | 1,0 % |

La legge `a + b·MAC + c·strati` ha un termine per strato che è la media di questo costo sui
modelli della popolazione. Sui 18 modelli della famiglia `strati`, che non usa per la stima,
sbaglia il tempo sul P-core del 5 % (P2, P3), 6 % (P1) e 13 % (P1.5). A pesi fermi, da 1 a 5
strati, uno strato costa 3–4 ns a P1 e P1.5, 26–28 a P2 e 57–59 a P3 (sezione "Wide or deep,
with the same weights").

### 13.8 Risultati

In `results/popolazione_2026-10/sintesi.md`, schede in `docs/claims.md`; le cifre
riassuntive si ricalcolano con `python3 ipa/test/report_population_facts.py results/popolazione_2026-10`
(con `--figura` ridisegna `docs/figures/popolazione_legge.pdf`). Durata:
3 h 54 min per le sezioni di traffico, ~30 min per `solo`. Misure lasciate fuori dalle
conclusioni: 2 su 580 (`escluse.csv`).

## Note e limiti

- **Ordine del design space**: costo (istruzioni eseguite, tail call, lookup) e tempo per
  pacchetto crescono baseline → P1 → P2 → P3 su ogni modello. La dimensione del programma
  no: P2 è il programma più grande, P3 quello che esegue di più (103/103 modelli).
- **Inferenza identica** nelle tre pipeline (stesso MLP intero, pesi, argmax): verificata
  dalla corrispondenza di classe kernel/riferimento sul checkpoint, sui modelli sintetici e
  su tutta la popolazione (`check_kernel_vs_reference`: P1 109/109, P2 103/103, P3 109/109).
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
- **Ripetibilità**: la stessa misura ripetuta in un'altra sessione cambia dell'1,8 % in
  mediana, del 7 % al massimo: una differenza dentro questa variazione non è una differenza.
- **Latenze sotto `BPF_PROG_TEST_RUN`**: esecuzione in un ciclo sullo stesso buffer, senza
  driver e senza pressione di cache da traffico vero. Il costo sotto carico è quello di §10 e
  §11: per P1 e P1.5 circa 1,3 volte il ciclo caldo, per P2 e P3 1,1.
