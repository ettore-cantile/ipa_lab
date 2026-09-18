# Guida ai test — IPA/eBPF design space

Tre pipeline (P1 hardcoded, P2 template, P3 modular) verificate su due piani:

- **userspace** (numerico, PyTorch/NumPy) — accuratezza, quantizzazione, robustezza, struttura;
- **kernel** (`BPF_PROG_TEST_RUN` sui programmi XDP reali) — istruzioni eBPF, latenza (min/p50/max/spread), throughput, memoria mappe + dispatch reale.

Tutto è raccolto in un unico script: `ipa/test/test_suite.py`. Tutti gli script di test
(compreso `bench_model_add.py`, vedi §6) vivono sotto `ipa/test/`.

**Nota sul layout.** Il motore sta in `ipa/`; i dati della topologia su cui il
checkpoint depositato è stato addestrato stanno in `topologies/germany50/`. Tutti i
comandi qui sotto si eseguono dalla radice del repository.

---

## 1. Test locali (userspace) — nessun root, nessun kernel eBPF

Richiede solo `torch` + `numpy`. Girano ovunque: nessun kernel, nessun root.

```bash
# Tutte le suite (la suite kernel viene saltata se non c'è BCC/root)
python3 ipa/test/test_suite.py

# Una singola suite
python3 ipa/test/test_suite.py --only core       # struttura design-space + update latency
python3 ipa/test/test_suite.py --only quant       # accuratezza argmax vs scale_factor
python3 ipa/test/test_suite.py --only pktstats    # HIT/FAKE/MISS per pipeline
python3 ipa/test/test_suite.py --only extract     # coerenza pesi / weights.json / dequant
python3 ipa/test/test_suite.py --only robust      # input anomali, nessun crash

# Opzioni
python3 ipa/test/test_suite.py --only quant --samples 500
python3 ipa/test/test_suite.py --model ipa/frr_germany50_5_model_4x2.pt --verbose
```

---

## 2. Test nel kernel (`--only kernel`) — richiede Linux + BCC + root

Carica i programmi XDP reali ed esegue `BPF_PROG_TEST_RUN`. Misura le metriche del design
space direttamente dal kernel e verifica il dispatch (redirect) per ogni TTL. La tabella
include ora una colonna **baseline** (parse + redirect, nessuna inferenza) come pavimento di
riferimento — utile per capire quanto costa davvero l'inferenza rispetto al solo framework XDP.

```bash
# Su host Linux con BCC installato
sudo python3 ipa/test/test_suite.py --only kernel

# Solo metriche, senza il gate di dispatch
sudo python3 ipa/test/test_suite.py --only kernel --no-verify

# Più ripetizioni per una latenza più stabile (per-trial repeat)
sudo python3 ipa/test/test_suite.py --only kernel --kernel-repeat 200000

# Più trial indipendenti (default 7) se il risultato è ancora volatile
sudo python3 ipa/test/test_suite.py --only kernel --kernel-trials 15
```

**Volatilità corretta**: la tabella misurava latenza/throughput con un **singolo** campione
`BPF_PROG_TEST_RUN` — rumore di sistema a senso unico (scheduler/interrupt possono solo
rallentare un trial, mai accelerarlo) lo faceva oscillare anche 2-5× da un run all'altro
(es. hardcoded 10-25 Mpps, baseline 10-50 Mpps — esattamente il problema già trovato e
corretto in `bench_depth_vs_width.py`). Ora ogni pipeline gira `--kernel-trials` volte
(default 7) e riporta il **minimo** (la statistica giusta per rumore a senso unico, stesso
principio di hyperfine/Google Benchmark) — la tabella mostra anche p50 e max per
trasparenza, non solo il minimo.

Output atteso: tabella metriche (istruzioni/jited/tail-call/memoria/latenza min/p50/max/
spread/throughput) + `5 PASS / 0 FAIL` per ciascuna pipeline + il probe `link_state reroute`
(un link giù cambia l'uscita) + `kernel suite: PASS`.

Cosa verifica in più oltre al dispatch:
- **Corrispondenza di classe** (single-pass, uniforme sulle 3 pipeline): pre-installa `mac_table[0..5]`,
  esegue una volta e controlla che la classe scelta dal kernel = classe del riferimento Python
  (`cls_stats[ref_cls] > 0`). Nessun `ctx_in` custom: le semantiche di `ctx_in` per `xdp_md` non
  sono portabili fra kernel, quindi si usa l'`ingress_ifindex` di default del device di test.
- **Reroute su guasto**: per ogni TTL e interfaccia `k`, esegue P1 con tutti i link up e poi con
  `link_state[k]=0`, e conferma che l'argmax cambia uscita in almeno un caso.

> ⚠️ **`ingress_iface`: le tre pipeline NON concordano, e in laboratorio la feature è
> inerte.** P1 traduce l'ifindex del kernel in porta logica tramite `ifindex_table`
> (default `[2..7]`); P2/P3 usano l'ifindex **grezzo** con clamp `[1, n_interfaces]`.
>
> - Sotto `BPF_PROG_TEST_RUN` il sandbox espone `ingress_ifindex = 1`
>   (`verify_prog_run.TEST_RUN_DEFAULT_INGRESS_IFINDEX`): P1 non lo mappa → `_iface=0`,
>   P2/P3 lo accettano → colonna 0 della one-hot attiva. Il riferimento Python modella
>   correttamente le due semantiche con `ref_ifindex = 0 if pipeline == 1 else 1`, ed è
>   per questo che i `ref_val` stampati per P1 differiscono da quelli di P2/P3 pur
>   restando la stessa classe. **Non è un bug della suite** — è la suite che documenta
>   una divergenza reale fra le pipeline.
> - Su un nodo vero gli ifindex sono 201/209/217/223: non stanno né in `[2..7]`
>   né in `[1,6]`, quindi **tutte e tre** azzerano la feature. 6 dei 65 input sono
>   costantemente nulli e il modello non sa mai da quale porta è entrato il pacchetto.
>
> Ne segue un limite di validità esterna da dichiarare: la suite misura una
> configurazione dell'input vector che **in produzione non si verifica**. Sistemarlo
> significa risolvere gli ifindex reali all'avvio (`socket.if_nametoindex`) e dare a
> P2/P3 una mappa ifindex→porta; cambia l'output dell'inferenza e va rifatto anche il
> riferimento, quindi non è stato fatto.

### Verifier standalone (equivalente al gate di dispatch)

```bash
sudo python3 ipa/test/verify_prog_run.py --method hardcoded
sudo python3 ipa/test/verify_prog_run.py --method template
sudo python3 ipa/test/verify_prog_run.py --method modular
sudo python3 ipa/test/verify_prog_run.py --method modular --model-id 3
```

---

## 3. Costruire un datapath reale (`netns_fabric.py`)

Non c'è più un emulatore. Il banco si costruisce con `veth` sull'host: una coppia
per porta logica più un ingresso dedicato, ognuna col peer che porta uno stub
`XDP_PASS`.

```bash
sudo python3 ipa/test/netns_fabric.py --n-ports 5          # costruisci, mostra, smonta
sudo python3 ipa/test/netns_fabric.py --n-ports 5 --hold   # resta su, per deployarci sopra
sudo python3 ipa/test/netns_fabric.py --cleanup            # resti di un run ucciso
```

`veth` supporta XDP **native**, quindi la modalità di attach è quella di
deployment, non un surrogato. Lo stub sui peer non è decorazione: redirigere
*verso* una veth passa da `veth_xdp_xmit()`, e il kernel alloca le code che quel
percorso richiede solo se il lato ricevente ha un programma XDP. Senza, il
redirect fallisce in silenzio e il pacchetto sparisce — identico a un modello che
decide di droppare tutto.

L'ingresso è **dedicato**, non una porta logica: quando era la porta 0, una classe
che inoltra su quella porta rimandava il frame fuori dall'interfaccia da cui era
entrato, dove la cattura non lo distingue da quello appena iniettato.

Cosa la macchina regge lo dice `sudo bash ipa/test/probe_env.sh`.

---

## 4. Attaccare una pipeline a un'interfaccia (XDP reale sul fabric)

Attacca sull'interfaccia dove **entra** il traffico (XDP conta solo l'ingresso). In questo
lab il traffico per `frankfurt` (IP loopback `10.255.255.17`) entra su **eth1** — verifica con
`sudo tcpdump -i any -n udp port 9999`.

```bash
# sul nodo che fa da switch (es. frankfurt), su eth1
sudo python3 ipa/execute_pipeline.py --method template  --iface eth1 --model-id 0
sudo python3 ipa/execute_pipeline.py --method modular   --iface eth1 --model-id 0

# hardcoded: AOT-literal è l'UNICO backend di deploy (BCC live-attach rimosso su
# richiesta esplicita del relatore). Serve un .o prebuilt (build offline su host
# con clang) + loader_aot linkato staticamente contro libbpf (nessuna dipendenza
# runtime su libbpf.so sul nodo). BCC resta solo internamente ai test
# (verify_prog_run.py ecc.), mai per il deploy.
sudo python3 ipa/execute_pipeline.py --method hardcoded --iface eth1

# solo verifica del caricamento, senza restare in ascolto
sudo python3 ipa/execute_pipeline.py --method hardcoded --verify-only

# se un XDP resta appeso da un run precedente ("File exists"): staccalo
sudo ip link set dev eth1 xdp off
```

Tutte e tre stampano `HIT | MISS | DROP` dal vivo. Popolano `mac_table` (classe → ifindex +
MAC) e `link_state` da sole all'avvio; non serve un setup separato.

### AOT-literal deploy / bench (P1) — unico backend hardcoded per il deploy

Su richiesta del relatore, il deploy della pipeline hardcoded avviene **solo via
AOT-literal** (il vecchio live-attach BCC è stato rimosso). Il flusso è: build offline del
`.o` + del loader statico su un box con compilatore (l'host), poi attach del `.o` prebuilt
sul nodo datapath, che non ha bisogno di clang/cc/libbpf.

```bash
# bench (deploy-cost + perf, via BPF_PROG_TEST_RUN) -- richiede root sull'host
sudo python3 ipa/methods/method4_hardcoded_aot.py
# deploy LIVE su un'interfaccia (via execute_pipeline, backend AOT di default):
sudo ip link set dev eth1 xdp off
sudo python3 ipa/execute_pipeline.py --method hardcoded --iface eth1
```

**Verificato end-to-end** su nodo `frankfurt` (che NON ha clang, cc né `libbpf.so`
usabile per il link): il loader fully-static carica il `.o` prebuilt e attacca il programma
XDP; `ip link show dev eth1` mostra `prog/xdp id ... name xdp_dispatch ... jited`, cioè il
dispatcher AOT agganciato e JIT-compilato. Il comando di deploy resta resident (loop
`pause()`) finché non lo si interrompe con Ctrl-C, che stacca l'XDP. La correttezza
dell'inferenza è coperta separatamente da `test_suite --only kernel` (5/5 PASS per TTL).

Il modello AOT è **build offline** (macchina con clang) → deploy del `.o` prebuilt sul nodo
(nessun clang). Su un nodo senza clang, se `nn_aot_arch.o` è già presente viene riusato.

**`loader_aot` va costruito una volta sola su una macchina di build**, non sul nodo
che inoltra: un nodo stripped non ha né `clang` né `cc`. Costruiscilo come utente
normale, non con `sudo` — il build non richiede root, solo l'attach XDP finale lo
richiede:
```bash
# dev-lib per il link statico (una volta):
sudo apt-get install -y libbpf-dev libelf-dev zlib1g-dev libzstd-dev liblzma-dev
python3 ipa/methods/method4_hardcoded_aot.py   # sulla macchina di build
```
Il binario è linkato **staticamente** (niente `libbpf.so` richiesto a runtime) e vive in
`ipa/poc_aot/loader_aot`: è il file da copiare sul nodo, da solo, insieme al `.o`.

Note pratiche emerse costruendolo davvero:
- Il link statico di libbpf tira dentro dipendenze transitive che devono anch'esse essere
  statiche: `libelf`, `zlib`, e — su elfutils recente che comprime le sezioni ELF —
  anche `libzstd` e `liblzma`. Lo script prova prima la riga a 3 librerie, poi quella a 5
  (con `zstd`/`lzma`); su Ubuntu recente serve la seconda. Se fallisce stampa l'errore
  `ld` completo per capire quale `.a` manca.
- I file generati sotto `ipa/poc_aot/` (`nn_aot_arch.bpf.c`, `.o`, `loader_aot`) prendono
  il proprietario dell'utente che li crea: se un run precedente è stato fatto con `sudo`
  (root), un run successivo come utente normale fallisce con
  `PermissionError`. Rimedio: `sudo chown -R $USER:$USER ~/percorso/ipa_lab`.
- Su un nodo dove BCC è installato `libbpf.so.1` è presente (tirato dentro da BCC), quindi
  anche un loader linkato dinamicamente (`-lbpf`) funzionerebbe lì; il link statico resta
  comunque la scelta preferita perché non dipende da questo dettaglio dell'immagine.
- Il bench sull'host (`method4_hardcoded_aot.py` senza `--iface`) carica un programma BPF e
  quindi richiede root: eseguito come utente normale fallisce con `RLIMIT_MEMLOCK -EPERM`.
  Non è un problema del deploy — il caricamento reale avviene sul nodo, che gira
  come root.

Le pipeline avviano automaticamente il monitor `link_state` (thread di polling che tiene
`link_state[0..5]` allineato al carrier reale delle interfacce egress). Per un dry-run dei
carrier senza caricare eBPF:

```bash
# stampa lo stato up/down di eth0..eth5 che verrebbe scritto nella map
sudo python3 ipa/link_state_monitor.py --ifaces eth0 eth1 eth2 eth3 eth4 eth5
```

---

## 5. Invio pacchetti IPA di prova

La verifica di correttezza end-to-end è `test_fabric.py` (sezione 4): inietta,
cattura, e confronta sia la decisione (`cls_stats`) sia la porta d'uscita. Questi
script servono per traffico manuale su un fabric già attivo:

```bash
sudo python3 ipa/recv_ipa.py --timeout 30 --port 9999
sudo python3 ipa/send_ipa.py --dst <host> --count 100
sudo python3 ipa/test/test_ipa.py --dest <host> --count 100 --model-id 0

# traffico multi-modello (round-robin), per esercitare il dispatch di P2/P3
sudo python3 ipa/test/test_ipa.py --dest <host> --count 90 --model-ids 42 43 44
```

---

## 6. Costo reale di aggiunta modello (`bench_model_add.py`)

Misura, con `BPF(text=…)` + `load_func()` reali (non stimati), quanto costa registrare un
nuovo `model_id` a runtime in ciascuna pipeline — sfrutta il multi-model concorrente di P2/P3
(più `model_id` nella stessa run, blocchi di pesi non sovrapposti in `arch_weights`/`layer_weights`).

```bash
sudo python3 ipa/test/bench_model_add.py --n-models 3
sudo python3 ipa/test/bench_model_add.py --n-models 3
```

Limiti: `MAX_WEIGHT_ENTRIES=1024` in P2 (max 3 modelli con questa architettura),
`MAX_LAYER_WEIGHT_ENTRIES=2048` in P3 (max 6). Risultati e lettura nel dettaglio
in `docs/pipeline_design_space.html` (sezione Risultati Sperimentali).

---

## 7. Trade-off larghezza vs profondità in P1 hardcoded (`bench_depth_vs_width.py`)

P1 hardcoded ora supporta un numero **variabile** di hidden layer (`hidden_dims` di
qualunque lunghezza: `(4,4)` storico, `(8,)`, `(4,4,4,4)`, `()` lineare puro — non più
fisso a 2). Domanda del relatore: a parità di budget-pesi, conviene allargare un layer o
aggiungerne uno nuovo? Script dedicato:

```bash
sudo python3 ipa/test/bench_depth_vs_width.py                      # tutti e 4 i descrittori
sudo python3 ipa/test/bench_depth_vs_width.py --descriptor no_onehot
sudo python3 ipa/test/bench_depth_vs_width.py --repeat 5000        # più stabile, più lento
```

**Metodologia** (vedi il file per il codice completo):
- 3 tier a **budget-pesi abbinato** (A ~300, B ~1200, C ~4700 pesi): per ciascuno, una forma
  larga (1 layer) e due profonde (4 e 8 layer); lo scarto di pesi è stampato esplicitamente,
  mai assunto "circa uguale".
- **4 descrittori di feature** (`default` 2 one-hot, `no_onehot` 0, `small_onehot` 1 piccola,
  `big_onehot` 1 grande = `node`, size 52) per isolare l'effetto del descrittore da un
  effetto generale larghezza/profondità — il descrittore di default ha una one-hot
  (`node`) molto costosa che da sola avrebbe potuto falsare la conclusione.
- **Minimo su 7 trial indipendenti**, non un solo campione: un run con `repeat` singolo
  oscillava fino a 20× senza correlazione con le istruzioni — rumore di sistema **a senso
  unico** (interrupt/scheduling possono solo rallentare, mai accelerare un trial), quindi
  il minimo stima il costo al netto delle interferenze (stesso principio di hyperfine /
  Google Benchmark).
- **Ogni cella (descrittore × forma) in un subprocess isolato**: oltre un certo budget lo
  stack eBPF (512 byte) va in overflow e il backend LLVM di BCC termina con un abort
  **fatale, non catturabile** come eccezione Python. Isolare ogni cella in un subprocess fa
  sì che un crash marchi solo quella cella (`CRASHED`) senza fermare lo sweep.

**Metodologia, la correzione che conta.** Le forme erano **fisse** fra i quattro
descrittori (1×16, 4×11, 8×9…), ma `n_in` va da 65 a 11: con 65 ingressi il primo
layer domina il budget e gli strati in più lo muovono poco, con 11 no. Lo scarto di
pesi dentro un tier arrivava così al **160%** sui descrittori a ingresso piccolo — la
forma «profonda 8» aveva 2,6× i parametri della «larga» ed era più lenta anche solo
per quello. E cadeva proprio sui due descrittori **senza** one-hot grande, cioè
quelli che servono da controllo. Ora la larghezza è **risolta per descrittore**
(`solve_width`) perché il budget sia centrato davvero; lo scarto resta stampato.

**Risultato — tier B (~1 200 pesi), il meglio abbinato (scarti 3,9-10,1%):**

| descrittore | n_in | larga | 2 layer | 4 layer | 8 layer |
|---|---:|---:|---:|---:|---:|
| `default` (2 one-hot) | 65 | **122 ns** | 183 (+50%) | 279 (+129%) | 293 (**+140%**) |
| `big_onehot` (1 grande) | 59 | **110 ns** | 161 (+46%) | 215 (+95%) | 268 (**+144%**) |
| `no_onehot` (0) | 11 | *crash* | *crash* | 501 ns | 457 ns |
| `small_onehot` (1 piccola) | 13 | *crash* | *crash* | *rifiutata* | 465 ns |

**Tier A (~300 pesi):**

| descrittore | larga | 2 layer | 4 layer | 8 layer |
|---|---:|---:|---:|---:|
| `default` | **54 ns** | 56 | 58 | 70 (+30%) |
| `big_onehot` | 41 ns | **38** | 59 | 57 (+39%) |
| `no_onehot` | 107 ns | 110 | 107 | **102 (−5%)** |
| `small_onehot` | 93 ns | **92** | 105 | 112 (+20%) |

**Tier C (~4 700 pesi): crash su tutti e quattro i descrittori e tutte e quattro le
profondità.** Oltre ~1 300 pesi il modello non ci sta comunque.

### Che cosa dicono davvero

**1. Con un ingresso grande e dominato da one-hot, allargare batte approfondire** —
ed è il caso di IPA. +30-39% a 300 pesi, **+140-144%** a 1 200: il divario cresce col
budget, perché ogni strato in più ha una spesa fissa di transizione.

**2. Con un ingresso piccolo e denso il vantaggio sparisce.** Su `no_onehot`
(n_in=11) a 300 pesi la versione a 8 strati è marginalmente **più veloce** (102
contro 107 ns) e **più piccola** (1 280 contro 1 583 istruzioni). Il motivo è
strutturale: una one-hot larga costa poco per pacchetto perché il datapath ne legge
**una colonna sola**, mentre un ingresso denso fa moltiplicare le letture di mappa
per la larghezza del primo strato. La risposta dipende da **com'è fatto il vettore
d'ingresso**, non solo dal budget.

**3. Il limite mangia prima le forme larghe.** A parità di budget, la larga sfonda lo
stack da 512 byte prima della profonda, perché è il primo strato a consumarlo. Su
`no_onehot` a 1 200 pesi, in ordine di stack stimato:

| forma | stack stimato | esito |
|---|---:|---|
| larga 1×63 | 584 | **crash** |
| 2×26 | 288 | **crash** |
| profonda 4×17 | 216 | carica |
| profonda 8×11 | 168 | carica |

Con un ingresso piccolo e un budget medio, **la rete profonda è l'unica che sta in
piedi**. Da notare: `first_layer_stack_estimate` è documentata come diagnostica e non
come predittore, ma qui l'ordine che stima è esattamente l'ordine dei crash.

**4. Due limiti distinti, osservati nello stesso tier.** `small_onehot` a 1 200 pesi:
`1×57` e `2×25` muoiono nello **stack** (abort di clang, `Looks like the BPF stack
limit is exceeded`); `4×16` compila e viene rifiutata dal **verificatore**
(`Program too large (5637 insns)`). Compilazione ed esecuzione sono soglie diverse e
si toccano in punti diversi.

> ⚠️ Il tier A ha scarti fino al 21,8%: a 300 pesi le larghezze intere fanno passi
> grossi, e differenze di 2-3 ns dentro quel tier non sono risolvibili. Il tier B è
> quello su cui appoggiarsi.

**La frase per la tesi** non è «le reti larghe sono preferibili a quelle profonde»,
ma: *con un ingresso dominato da feature one-hot — il caso di IPA — allargare batte
approfondire, e sempre di più al crescere del budget; con un ingresso piccolo e denso
il vantaggio sparisce, e oltre una certa taglia è la forma larga a non compilare più.*

---

## 8. Isolare il costo del tail-call (`bench_tailcall_overhead.py`)

Le tre metriche esistenti (baseline, hardcoded, map-lookup) non isolavano MAI
il costo del solo hop `bpf_tail_call`: `hardcoded_latency - baseline_latency`
(sez. "Baseline vs hardcoded") impacchetta insieme tail-call + secondo parse
del pacchetto + MLP. La letteratura sul design tail-call-based (vedi fonti
in sez. 7-8 sotto) elenca il tail-call come una delle tre componenti di costo
separabili — mancava una misura dedicata.

```bash
sudo python3 ipa/test/bench_tailcall_overhead.py
sudo python3 ipa/test/bench_tailcall_overhead.py --repeat 5000 --trials 15
```

Confronta due varianti minime, **stesso parse, stessa azione di redirect**,
l'unica differenza è un hop `PROG_ARRAY` in mezzo: `xdp_baseline` (0 tail
call, già esistente) vs `xdp_baseline_dispatch → xdp_baseline_action` (1 tail
call, nuovo, in `verify_prog_run.EBPF_BASELINE_TAILCALL`). Stessa metodologia
minimo-su-N-trial di `bench_depth_vs_width.py`. Il delta stampato è il costo
**puro** del salto, isolato da qualunque aritmetica MLP o doppio parsing.

---

## 9. Architetture alternative dentro `test_suite.py --only kernel`

Prima, `test_suite --only kernel` verificava **una sola architettura** (65-4-4-7) su
tutte e 3 le pipeline — un vuoto reale rispetto alla tesi "P1/P2/P3 gestiscono profondità/
larghezza arbitrarie". Ora `suite_kernel()` chiama anche `verify_alt_architectures()`:

- **P1 hardcoded**: due programmi compilati **separatamente** con profondità diverse
  (`(8,)` un hidden layer, `(4,4,4)` tre hidden layer — esercita la generalizzazione a
  profondità variabile del Task 7), stesso descrittore di default, pesi sintetici,
  verificati contro `ref_infer_sparse` generalizzato (qualunque lunghezza di `hidden_dims`).
- **P2 template / P3 modular**: richiama i controlli già esistenti in
  `verify_multi_model.py` (65-6-5-7 per P2, 65-5-6-4-7 per P3, registrati **insieme** al
  modello reale nello stesso oggetto compilato — la vera prova "multi-model concorrente").

Nessun comando nuovo — è già dentro:
```bash
sudo python3 ipa/test/test_suite.py --only kernel
```

---

## 10. Analisi parametrica (`bench_scaling.py`)

Le sezioni precedenti misurano **un** modello su **una** topologia. Questa misura
come cambia il costo al variare della dimensione — e soprattutto se le pipeline
hanno **pendenze diverse**, che è l'argomento per cui ne esiste più di una.

**Quattro pipeline, non tre.** Lo sweep confronta una scala di specializzazione, cioè
di quanto si sa quando il programma viene compilato:

| | cosa è compilato dentro | un binario per |
|---|---|---|
| `p1_static` | pesi **e** indice di questo nodo | **nodo** |
| `hardcoded` (P1.5) | pesi; il nodo si legge da mappa | modello |
| `template` (P2) | solo i soffitti | tutto |
| `modular` (P3) | anche la profondità è a runtime | tutto |

`hardcoded` è la pipeline che il resto del documento chiama P1. Di fronte a
`p1_static` è in realtà una **P1.5**: la *disposizione* delle feature è compilata, ma
l'indice del nodo no. Rinominarla nei CSV romperebbe ogni misura già presa, quindi la
distinzione vive nelle etichette delle figure.

```bash
sudo python3 ipa/test/bench_scaling.py --out result/    # misura (Linux + BCC + root)
python3 ipa/test/bench_scaling.py --plot result/        # grafici (basta matplotlib)
python3 ipa/test/bench_scaling.py --axis width --out result/   # un asse solo
```

**Cinque assi, una variabile ciascuno.** Tutto il resto è bloccato, così una curva si
attribuisce alla variabile sull'asse x e a nient'altro.

| asse | valori | fermo a |
|---|---|---|
| `nodes` | 10, 25, 52, 75, 100 nodi | `MAX_N_IN` = 128 in P2/P3 (`n_in = 13 + n_nodi`) |
| `depth` | 1…6 hidden layer | — |
| `isoparam` | 1…5 hidden layer, **a parametri fermi** | famiglia a imbuto dentro i soffitti |
| `width` | 2, 4, 6, 8 neuroni | soffitto compilato 8 in P2 e P3 |
| `descriptor` | 4 composizioni di IV | 0/1/2 one-hot, piccola (6) o grande (52) |
| `sparsity` | 0, 25, 50, 75, 90% di pesi zero | — |

**Metodologia, tre scelte che contano.**

- *Ogni cella in un subprocess isolato.* P1 può far abortire clang (overflow dello
  stack a 512 byte) con un abort **fatale, non catturabile**; e un rifiuto del
  verificatore è un **dato**, non un guasto, quindi la tabella lo stampa come
  `RIFIUTATO` e non come `CRASH`.
- *Pesi da un pool fisso, presi come prefisso.* Un modello più grande **estende**
  quello più piccolo invece di sostituirne tutti i pesi. Serve perché in P1 il
  conteggio istruzioni dipende dai **valori** (vedi sotto): estraendo un vettore
  nuovo per ogni forma, parte della curva di P1 era rumore dei pesi travestito
  da asse x.
- *Allarme di contaminazione.* Se una pipeline mostra lo **stesso programma**
  (stesse istruzioni **e** stesse tail call) con latenza che varia oltre 2× lungo
  l'asse, lo scarto è la macchina e lo script lo dice. Il raggruppamento include le
  tail call apposta: P3 ha il binario identico a ogni profondità ma esegue un hop in
  più per layer, e senza quella chiave il controllo bollava come rumore il suo
  risultato migliore.

### Le nove figure, e cosa deducono

Lo sweep può disegnare decine di combinazioni metrica × asse. Nove portano un
risultato; le altre no (la memoria delle mappe non dipende da nessun asse, `build_ms` è sempre
la stessa compilazione). Il comando disegna **solo quelle**; `--all-plots` dà la
matrice intera, per guardare, non per pubblicare.

| # | figura | deduzione |
|---|---|---|
| 0 | `scaling_nodes_insns_log` | **La taglia della rete entra nel programma solo in P1.5** (746 → 1 692 istruzioni fra 10 e 100 nodi). Congelando l'indice del nodo la dipendenza **sparisce**: `p1_static` resta fra 611 e 640 a ogni taglia. Scala logaritmica, altrimenti le due curve P1 restano schiacciate contro le 14 628 di P2 e il confronto fra loro — che è il punto della figura — non si vede. |
| 1 | `scaling_depth_insns` | **P2 cresce di ~780 istruzioni per layer, P3 di zero.** P3 srotola *un* layer denso generico e ci rientra per tail call, quindi la profondità non entra nel programma. P2 deve srotolarli tutti: la sua genericità è sulle larghezze, non sulla profondità. |
| 2 | `scaling_depth_latenza` | **E P3 lo paga in tempo: ~70 ns per layer**, contro i ~36 di P2. Sono le sue tail call (da 2 a 7 hop). La stessa scelta di progetto spiega entrambe le figure: P3 è più piccolo *perché* riusa un pezzo, ed è più lento *perché* riusarlo costa un salto e delle letture ogni volta. |
| 3 | `scaling_depth_update` | **Due ordini di grandezza sull'aggiornamento del modello**: P1 ~1 400 ms (rigenera C e chiama clang), P2 e P3 ~7 ms (scritture in mappa). Asse logaritmico, altrimenti le due curve basse si schiacciano sullo zero. È la metrica che decide se una pipeline è usabile in una rete che cambia. |
| 4 | `scaling_nodes_insns` | **La taglia della rete entra nel programma solo in P1** (da 746 a 1 692 istruzioni fra 10 e 100 nodi: è lo `switch` sulla one-hot che si srotola). P2 e P3 restano alla cifra esatta a ogni punto — il loro sorgente non nomina mai la forma del modello. |
| 5 | `scaling_nodes_latenza` | **E non costa nulla a runtime, a nessuna delle tre.** Piatte tutte e cinque le colonne. Il motivo è strutturale: una one-hot legge **una sola colonna di pesi** qualunque sia la sua larghezza. |
| 6 | `scaling_width_latenza` | **Allargare i layer nascosti invece si paga**, su tutte e tre. Letto insieme alla figura 5: *la rete può crescere quanto vuole, il modello no.* |
| 7 | `scaling_sparsity_insns_log` | **Con pesi più sparsi P1 crolla** (1 071 → 224 istruzioni al 90% di zeri), P2 e P3 non si muovono di un'istruzione. I pesi di P1 sono letterali nel C, quindi clang cancella i prodotti per zero; per P2/P3 uno zero è un byte in mappa come un altro. Scala logaritmica: su scala lineare P1 sta a ~10³ e P2/P3 a ~10⁴, e il crollo sparisce schiacciato sullo zero. |
| 8a | `scaling_isoparam_insns` + `scaling_isoparam_latenza` | **A parità di parametri** (592 ± 2%), 1→5 hidden layer. Le due P1 non distinguono larga da profonda a questo budget; P2 cresce del 22% in istruzioni e dell'**84% in latenza**; P3 ha istruzioni **identiche** a tutti e cinque i punti e cresce del **58% in latenza**. Due meccanismi diversi per lo stesso sintomo: P2 srotola ogni layer, P3 ne paga uno in tail call. |
| 8b | `scaling_isoparam_mpps` | Lo stesso in throughput teorico, l'unità in cui la domanda si pone di solito. È `1/latenza` sotto `BPF_PROG_TEST_RUN`: un **picco**, non un throughput retto. |
| 9 | `scaling_descriptor_insns` | **Cambiare la composizione del vettore d'ingresso ricompila P1** (da 575 a 1 071 istruzioni fra le quattro IV), mentre P2 e P3 leggono il descrittore da `model_desc` e non cambiano. Ed è anche il **controllo** dell'esperimento sulla specializzazione: dove il descrittore non dichiara la feature `node`, le due P1 sono **identiche alla cifra** (599 e 599, 575 e 575); dove la dichiara, divergono (614 contro 1 071). Il divario è tutto lì e nient'altro. Barre e non curve: una linea fra `no_onehot` e `big_onehot` disegnerebbe una pendenza fra due nomi. |

### Testa a testa: P1 specializzata contro P1.5

Figura dedicata: `duel_p1_vs_p15.pdf`, quattro pannelli con le sole due P1 — in
tutte le altre figure P2 e P3 stanno un ordine di grandezza sopra e schiacciano
questo confronto sul fondo del grafico.

**Su Germany50** (52 nodi, 65-4-4-7, il punto di riferimento di tutto il progetto):

| | P1 specializzata | P1.5 hardcoded | |
|---|---:|---:|---|
| istruzioni eBPF | **614** | 1 071 | −43% |
| codice nativo (byte) | **2 740** | 5 218 | −47% |
| latenza (ns/pkt) | 54 | 57 | −5%, dentro il rumore |
| memoria mappe (byte) | 2 356 | 2 356 | identica |
| aggiornare il modello | ~1 550 ms | ~1 460 ms | identico |
| lettura di `node_id` per pacchetto | **0** | 1 | una in meno |
| binari da compilare e installare | **uno per nodo** | uno per modello | ⚠️ |

**A 100 nodi** il divario si allarga, perché una delle due cresce e l'altra no:

| | P1 specializzata | P1.5 hardcoded | |
|---|---:|---:|---|
| istruzioni eBPF | **640** | 1 692 | −62% |
| codice nativo (byte) | **2 837** | 8 432 | −66% |
| latenza (ns/pkt) | 55 | 61 | −10% |

Due righe da leggere con attenzione perché smentiscono un'aspettativa ragionevole:

- **La memoria delle mappe è identica.** Il programma specializzato non *legge* più
  `node_id`, ma la mappa resta **dichiarata** nell'header condiviso. Sono pochi byte
  e non cambia nulla nelle misure, ma è codice morto: un header specializzato potrebbe
  non dichiararla affatto.
- **Il costo di aggiornamento è identico.** Il sorgente è più piccolo, ma il tempo è
  dominato dal costo fisso di far partire clang, non dalla lunghezza del file. La
  specializzazione non rende la compilazione più veloce — e visto che ne servono N
  invece di una, il costo totale di deployment **peggiora** di un fattore N.

### Congelare il nodo conviene? Sì, ma non per la ragione che sembra

L'indice del nodo è una **costante di deployment**: non cambia per tutta la vita del
nodo. Congelarlo a tempo di generazione fa sparire lo `switch` a `n_nodi` casi e la
lettura della mappa `node_id`; restano `n_h1` costanti che clang piega
nell'accumulatore. Vale la pena? I numeri dicono sì, e dicono anche che il motivo non
è quello che verrebbe da indovinare.

**Equivalenza prima di tutto.** Congelare il nodo significa scegliere *una colonna*
della matrice del primo layer a tempo di compilazione. Sceglierne una sbagliata dà un
programma più piccolo, più veloce, e che calcola **un altro modello** — e nessuna
misura di costo se ne accorgerebbe.

```bash
sudo python3 ipa/test/bench_scaling.py --verify     # 80/80 casi identici
```

80 casi (ttl 2-11 × 8 pattern di link): la specializzata decide **la stessa classe**
della P1.5 con lo stesso indice installato. Solo dopo questo i numeri sotto
significano qualcosa.

**Quello che si guadagna: dimensione, e la sua pendenza.**

| nodi della rete | 10 | 25 | 52 | 75 | 100 |
|---|---:|---:|---:|---:|---:|
| P1 specializzata | 617 | 625 | 614 | 611 | **640** |
| P1.5 hardcoded | 746 | 863 | 1 071 | 1 539 | **1 692** |

A 100 nodi è **2,6× più piccola**. Ma il numero che conta non è il rapporto: è che la
riga della specializzata è **piatta**. Il costo in dimensione della feature più grossa
del modello — 52 dei 65 ingressi, 208 dei 319 pesi — smette di dipendere dalla taglia
della rete.

**Quello che NON si guadagna: velocità.**

| nodi della rete | 10 | 25 | 52 | 75 | 100 |
|---|---:|---:|---:|---:|---:|
| P1 specializzata | 58 | 68 | 54 | 55 | 55 ns |
| P1.5 hardcoded | 61 | 60 | 57 | 59 | 61 ns |

Praticamente identiche, dentro il rumore. Sull'asse larghezza il vantaggio è un po'
più visibile e costante (35 contro 47 ns a 2 neuroni, 92 contro 107 a 8: circa 10-15
ns, il 12-15%), perché lo switch assegna `n_h1` pesi e quindi cresce con la larghezza.
Ma resta un miglioramento modesto.

> **Il motivo per cui la dimensione crolla e il tempo no è lo stesso.** Lo switch ha
> `n_nodi` casi ma ne **esegue uno**: a runtime è un salto indicizzato, che costa
> poco. Quelle 208 assegnazioni sono compilate per eseguirne 4. Toglierle libera
> molto **spazio** e quasi nessun **tempo** — che è, in miniatura, la stessa lezione
> della tabella principale: le istruzioni misurano quanto è grande il programma, non
> quanto lavora.

**I due vantaggi non si sommano.** Sull'asse sparsità le due P1 **convergono**:

| pesi a zero | 0% | 25% | 50% | 75% | 90% |
|---|---:|---:|---:|---:|---:|
| P1 specializzata | 614 | 566 | 417 | 294 | **216** |
| P1.5 hardcoded | 1 071 | 939 | 686 | 363 | **224** |

Al 90% di zeri il divario è sparito (216 contro 224). Sparsità e nodo congelato sono
**due strade alla stessa riduzione**: se i pesi sono già quasi tutti zero, clang
cancella lo switch da solo e non c'è più niente da congelare.

**Quello che si paga: un binario per nodo.** Una rete da 52 nodi vuole 52
compilazioni e 52 installazioni, ognuna da ~1,4 s. Il costo di aggiornamento si
moltiplica per la taglia della rete — esattamente la grandezza da cui la
specializzazione ha appena liberato la *dimensione*.

**Il verdetto.** Non è un'ottimizzazione di velocità: è ciò che rende P1 **praticabile
su una rete grande**. Lo switch di P1.5 cresce con il numero di nodi moltiplicato per
la larghezza del primo layer; su una topologia da 500 nodi con 8 neuroni sarebbero
4 000 assegnazioni srotolate, e c'è una taglia oltre la quale P1.5 semplicemente non
si carica più. La specializzata non ci arriva mai. Su Germany50, dove 52 nodi
costano 1 071 istruzioni contro 614, è una scelta legittima in entrambe le direzioni;
su una rete dieci volte più grande non lo è più.

---

### Il risultato che non cercavamo: in P1 i pesi decidono se il programma si carica

Nello sweep una cella si è fatta rifiutare dal verificatore: `65-4-4-4-4-7`, 359 pesi.
Le forme intorno caricavano tutte, compresa `(4,4,4,3)` e la **più grande**
`(4,4,4,4,4)`. Nessuna proprietà della profondità può produrre questo.

Tenendo fissa la forma e cambiando **solo il seme** dei pesi:

| seme | esito |
|---|---|
| 42 | **rifiutato** |
| 1 | carica, 1 119 istruzioni |
| 2 | carica, 1 175 |
| 7 | carica, 1 118 |
| 999 | carica, 1 075 |

Il seme 1 carica a 1 119, il 42 viene rifiutato a 1 120. **Una istruzione di
differenza.**

> **In P1, riaddestrare un modello senza toccare l'architettura può renderlo non
> caricabile.** Stessa rete, stessi iperparametri, pesi nuovi, e il nodo lo rifiuta.
> P2 e P3 non hanno questo rischio: per loro i pesi sono byte in una mappa e la
> caricabilità dipende solo dalla forma.
>
> È il rovescio esatto del vantaggio della figura 7. La stessa strength reduction che
> porta P1 a 224 istruzioni è quella che lo rende imprevedibile.

Il meccanismo preciso — quale limite del kernel — **non è stato confermato**, e non
va inventato: `E2BIG` ha più cause nel percorso di caricamento BPF e BCC ci stampa
sopra `Program too large (1120 insns), at most 4096 insns`, dove il 4096 è una
costante morta nella stringa di BCC (nello stesso sweep P2 carica a 18 057). È la
stessa trappola documentata per P3. Per chiuderlo serve il log del verificatore
(`BPF(text=src, debug=0x10)`).

### Limiti di questo run, dichiarati

- **Non affiancare latenze prese da assi diversi.** A programma identico P2 misura
  ~250 ns sugli assi `nodes` e `width` e ~310 su `descriptor` e `sparsity`: la
  macchina si è caricata nella seconda metà dell'esecuzione. Dentro un asse i
  confronti reggono, fra assi no. Le istruzioni sono deterministiche e confrontabili
  ovunque.
- **La figura 6 va presa per la direzione, non per la pendenza.** I punti a 6 e 8
  neuroni hanno anche `build_ms` più alto del resto, che è il segno della stessa
  macchina carica. Che allargare i layer costi è strutturale; *quanto*, su questo
  run, non è misurato bene.
- **Oltre ~115 nodi non si va** senza alzare `MAX_N_IN` (128) in P2 e P3. Per dire
  qualcosa su una rete da 500 nodi bisogna alzarlo e **rimisurare**.
- La sparsità richiesta e quella ottenuta differiscono di qualche punto (i pesi sono
  un prefisso di un pool mescolato, quindi un campione). La colonna `sparsity_real`
  nel CSV riporta quella vera.

---

## Risultati (kernel, `test_suite.py --only kernel`, 4 vCPU, modello 65→4→4→7, scale=24)

Rimisurati dopo tre correzioni che invalidavano la tabella precedente:

1. **bias dell'ultimo strato nel riferimento** (`ref_infer` moltiplicava per `scale⁰`
   invece che per `scale²`): ogni confronto float/int8 misurava la cosa sbagliata;
2. **mappa `ingress_port`**: la feature `ingress_iface` passava da contribuire **zero**
   su hardware vero a contribuire davvero — il modello girava di fatto su 3 input su 4;
3. **`cls_stats`** ora scritto anche su DROP e UNUSED, non solo sul FORWARD riuscito.

> ⚠️ **La tabella precedente mescolava run di versioni diverse del codice.** Le righe
> erano etichettate A/B/C come se fossero esecuzioni ripetute dello stesso build, ma
> P2 vi compariva con 9 916 istruzioni mentre le note dello stesso documento
> registravano già `~2 618→16 988` per un cambiamento successivo. Non erano numeri da
> correggere: era la tabella da rifare. Qui c'è **un solo stato del codice**.

Metodologia: minimo su 7 trial indipendenti, con p50/max e spread relativo.
**Un solo run, un solo stato del codice**: nido di cicli invertito in
`layer_first` (P3) e `fc1` (P2), `IPA_MAX_QUEUES = 8` in entrambe.

| Metrica | baseline | P1 hardcoded | P2 template | P3 modular |
|---|---:|---:|---:|---:|
| Istruzioni eBPF (xlated) | 155 | 1 026 | 14 628 | 12 031 |
| Codice jited (byte) | 709 | 4 985 | 63 975 | 55 015 |
| Tail call / pacchetto | 0 | 1 | 1 | **3** |
| Map lookup / pacchetto (reali) | 3.0 | 6.0 | 11.0 | **29.0** |
| Memoria mappe (byte) | 280 | 2 356 | 10 416 | 19 508 |
| **Latenza min (ns/pkt)** | **29.0** | **73.0** | **262.0** | **421.0** |
| ...p50 | 30.0 | 88.0 | 278.0 | 453.0 |
| ...max | 32.0 | 99.0 | 327.0 | 476.0 |
| ...spread (max−min)/min | 10% | 36% | 25% | 13% |
| Throughput teorico (Mpps, da min) | 34.483 | 13.699 | 3.817 | 2.375 |

Suddivisione per programma:

| | dispatcher | leaf |
|---|---|---|
| baseline | — | `xdp_baseline` 155 |
| P1 hardcoded | `ipa_switch_hardcoded` 29 | `model_0` 997 |
| P2 template | `ipa_switch_template` 41 | `arch_generic_2layer` 14 587 |
| P3 modular | `modular_dispatcher` 136 | `layer_first` 10 207 + `layer_hidden` 1 688 |

Correttezza, stesso run:

| | |
|---|---|
| Dispatch (TTL 2-6) | 5/5 PASS su tutte e tre |
| Gestione TTL (decremento + checksum + scadenza) | 2/2 PASS su tutte e tre |
| `link_state` reroute | PASS, **15/30** casi di link-down cambiano uscita |
| Architetture alternative (65-8-7, 65-4-4-4-7) | 5/5 PASS |
| Multi-modello concorrente (P2 65-6-5-7, P3 65-5-6-4-7) | PASS |
| Aggiornamento modello P1 (ricompila + ricarica) | 1 242 ms |
| Datapath reale (`test_fabric.py`, XDP native, veth) | **18/18**, 6 classi su 7 |

### Il risultato principale: la dimensione non predice la velocità

**P3 ha il 18% di istruzioni in meno di P2 ed è il 61% più lento** (12 031 contro
14 628 istruzioni; 421 contro 262 ns). Le due righe che lo spiegano sono al centro
della tabella:

- **3 tail call** contro 1;
- **29 lookup di mappa** per pacchetto contro 11.

Il conteggio `xlated` misura quanto è grande il programma caricato, non quanto lavoro
fa per pacchetto. In questo regime dominano **lookup e salti**, non l'aritmetica.

### Perché P2 è più grande di P3, che pure è più lento

Le due cose hanno la stessa causa: **P3 non tiene la rete intera in un programma.**

```
P2:  arch_generic_2layer = 14 587      una sola immagine
     fc1 (65->8) + fc2 (8x8) + out (32x8), tutti srotolati insieme

P3:  layer_first  = 10 207             IV sparsa dal descrittore, 8 uscite
     layer_hidden =  1 688             UN layer denso generico 8x8
     dispatcher   =    136
                    12 031             layer_hidden e' UNA copia, eseguita DUE volte
```

P3 srotola **un** layer denso generico e ci rientra per tail call a ogni hop, quindi
la profondità del modello non costa dimensione: un modello a 4 strati gira sullo
stesso binario (provato sopra, `65-5-6-4-7`). P2 deve srotolarli tutti e tre, perché
è un programma solo — e più strati significa un altro binario.

Quel riuso è esattamente ciò che P3 paga in latenza: ogni rientro è una tail call più
le letture di mappa che ricostruiscono il contesto (`scratch_meta`, `scratch_acts`,
`layer_shapes`, i pesi). 29 lookup contro 11.

> ⚠️ **Il confronto sulla DIMENSIONE è in parte un confronto fra soffitti, non fra
> pipeline.** Entrambe portano capacità inutilizzata, e non la stessa:
>
> | | soffitto | bisogno reale del modello depositato |
> |---|---:|---:|
> | P2, strato d'uscita | `MAX_N_OUT` 32 × `T2_MAX_H2` 8 = 256 MAC | 7 × 4 = 28 |
> | P3, vettore code | `IPA_MAX_QUEUES` 8 | 0 (nessuna feature coda dichiarata) |
>
> Con `IPA_MAX_QUEUES=1` P3 misura 8 674 istruzioni invece di 12 031, cioè il 41% in
> meno di P2 invece del 18%, **a parità di latenza** (419 contro 421 ns). Il numero
> di istruzioni si sposta del 39% senza che cambi nulla di ciò che gira. È il motivo
> per cui la riga delle istruzioni non va letta come una misura di costo.

> ⚠️ **Le istruzioni sono un conteggio STATICO, non il percorso eseguito.** Dividere
> 1 026 istruzioni per 73 ns darebbe ~4.2 istruzioni per ciclo a 3 GHz, sopra il
> massimo pratico su x86 (3-4). In P1 lo switch della one-hot `node` ha 52 casi ma ne
> esegue **uno solo**; inoltre, con i pesi come letterali, clang applica strength
> reduction (i pesi a zero spariscono, quelli potenza di due diventano shift). Il
> percorso dinamico è una frazione delle 1 026 — ed è il vantaggio strutturale della
> hardcoded sulle altre due.

### I lookup si contano di nuovo, su tutte e quattro

La riga "Map lookup / pacchetto" riportava `n.d.` per P2 **e** P3: contarli richiede di
ricompilare il programma con un contatore su ogni sito di lookup, e le due build
strumentate sforavano il verificatore. Ora caricano entrambe:

```
[count_lookups] template: 21 lookup sites (arch_generic_2layer=19  ipa_switch_template=1  <header>=1)
[count_lookups] modular : 34 lookup sites (layer_first=11  layer_hidden=6  ml_argmax_forward=12
                                           modular_dispatcher=3  <header>=2)
```

Non è stato reinserito niente a mano: è il margine di verifica liberato dal nido di
cicli invertito che ha reso caricabili le build strumentate. Una misura prima
impossibile è adesso una riga di tabella.

P1 passa da 5.0 a 6.0 lookup: è la mappa `node_id`, il prezzo di far dire alla one-hot
del nodo *quale nodo è questo* invece di *quale modello porta il pacchetto*.

### Il nido di cicli invertito: cosa ha cambiato e cosa no

In `layer_first` (P3) e `fc1` (P2) il ciclo sulle feature era **dentro** quello sui
neuroni. Ma `code`, `size` e `col_off` di una voce del descrittore non dipendono dal
neurone, quindi la catena a cinque rami su `code` veniva rivalutata `8 × 4 = 32` volte
per pacchetto e il gate `i < size` su un vettore denso 64 volte, per ricavare ogni
volta la stessa risposta. Invertito: 4 dispatch, 8 gate, e cicli interni di sola
moltiplica-accumula senza un ramo.

**L'aritmetica non cambia, termine per termine.** Cambia solo l'ordine della somma, e
l'addizione int64 in complemento a due è associativa e commutativa (anche in overflow,
che avvolge uguale nei due ordini): ogni accumulatore finisce bit-identico.
L'accumulatore diventa `out[]`/`h1[]`, che erano già vivi attraverso il ciclo, quindi
non si aggiunge stato tracciato.

| | prima | dopo |
|---|---:|---:|
| P2 `arch_generic_2layer` | 16 144 | **14 587** |
| P3 `layer_first` (a parità di soffitti) | 6 417 | **6 850** |
| P3 build strumentata (conteggio lookup) | non caricava | **carica** |
| P3 `IPA_MAX_QUEUES` massimo caricabile | 1 | **8** |

P3 è **cresciuto** di 433 istruzioni ed è diventato molto più economico da verificare.
Non è una contraddizione: **il verificatore paga i cammini, non la dimensione**, e sono
valute diverse. Prima della riscrittura, a `IPA_MAX_QUEUES=8` non caricava niente.

### Il soffitto delle code è tornato a 8, e non costa tempo

Misurato, non dedotto — due run consecutivi dello stesso codice con il solo `#define`
cambiato:

| | `IPA_MAX_QUEUES` 1 | `IPA_MAX_QUEUES` 8 |
|---|---:|---:|
| `layer_first` | 6 850 | 10 207 |
| modular, totale | 8 674 | 12 031 |
| **latenza min** | **419.0 ns** | **421.0 ns** |
| lookup / pacchetto | 29.0 | 29.0 |
| memoria mappe | 19 480 B | 19 508 B |

**+3 357 istruzioni, +2 ns** — dentro uno spread del 13% — e i lookup identici. Con un
descrittore che non dichiara la feature coda, il ramo `FEAT_QUEUE_OCC` non viene mai
preso: cresce la dimensione statica, non il percorso eseguito. Le uniche voci che si
muovono davvero sono i 28 byte di `queue_state` (8 slot invece di 1).

È la dimostrazione più pulita, in questo documento, che dimensione statica e costo per
pacchetto sono cose diverse.

### Attendibilita' dei numeri di latenza

**Due esecuzioni dello stesso binario, a minuti di distanza:**

| | baseline | P1 | P2 | P3 |
|---|---:|---:|---:|---:|
| run 1 | 35.0 | 62.0 | 243.0 | 478.0 |
| run 2 | 28.0 | 67.0 | 247.0 | 422.0 |
| scarto | −20% | +8% | +2% | −12% |

Le **istruzioni sono identiche** nei due run: sono deterministiche. Le latenze no.

Quindi: su questa VM a 4 vCPU una differenza di latenza sotto il ~20% fra due misure
prese in momenti diversi **non significa nulla**. Vale il confronto *dentro* un run, dove
tutte le righe vedono la stessa macchina nello stesso secondo. Ogni cifra assoluta qui va
letta come "ordine di grandezza su questa VM", mai come prestazione del sistema.

Va aggiunto un limite di metodo più profondo: `BPF_PROG_TEST_RUN` esegue il programma in
un ciclo sullo stesso buffer. Niente NIC, niente driver, niente allocazione di `sk_buff`,
nessuna pressione di cache da traffico vero. Il `Mpps` in tabella è `1/latenza`, cioè un
**picco teorico**, non throughput retto. Per quello serve traffico vero.

---

### Nota storica: perché la sezione è stata rifatta

**La versione precedente sosteneva che le latenze assolute riproducessero bene**, e su
quella base costruiva un modello di costo in cicli. Conservata qui perché la conclusione
opposta — misurata sopra su due run dello stesso binario — è essa stessa il risultato.
Il testo di allora diceva: su tre esecuzioni indipendenti
P1 misura 47 / 48 / 51 ns e P3 misura 387 / 392 / 391 ns: variazione sotto il 10% su P1 e
sotto l'1.5% su P3. Anche l'ordine di grandezza e' quello atteso in letteratura per XDP
sotto `BPF_PROG_TEST_RUN` (un programma minimale sta sui 10-20 ns, un redirect sui 25-50):
il baseline a 25-28 ns e' esattamente li'.

Il modello di costo torna. A circa 3 GHz, 25 ns sono ~75 cicli (parse + redirect), 51 ns
~153 cicli (P1: piu' una tail call, un secondo parsing e l'intera rete), 391 ns ~1 170
cicli per P3 — di cui la maggior parte spiegabile con le sole 26 letture di mappa e le 3
tail call. E' esattamente la tesi che il capitolo sostiene: in questo regime dominano
lookup e salti, non l'aritmetica.

### Perche' la riga "latenza normalizzata sul baseline" e' stata rimossa

Una versione precedente riportava una riga *latenza normalizzata (× baseline)*,
giustificata cosi': il baseline e' lo stesso identico programma ovunque, quindi
dividere per esso rende confrontabili misure prese su macchine diverse. Il caso di
controllo era P1, invariato, con rapporto 1.67 e poi 1.68.

I tre run mostrano che il metodo e' **fragile quanto la stima del baseline**:

| run | trial | P1/base | P2/base | P3/base |
|---|---:|---:|---:|---:|
| A | 7 | 1.68 | 8.00 | 13.82 |
| B | 7 | 3.43 | 11.79 | 28.00 |
| C | 15 | 2.04 | 9.36 | 15.64 |

A e C concordano entro il ~20%; B e' anomalo, ma va notato che lo e' su **due** colonne
insieme (baseline 14 ns *e* template 165 ns), quindi era la macchina in uno stato diverso,
non un difetto della metrica. Con 15 trial il baseline torna a 25 ns, vicino ai 28 del
run A: il valore di 14 ns era un outlier da troppi pochi campioni.

La causa strutturale resta pero' valida e si legge direttamente nella riga *spread*: il
baseline ha uno spread relativo del **112%** contro il 31-38% delle tre pipeline. Essendo
il programma piu' economico (129 istruzioni), l'overhead per iterazione di
`BPF_PROG_TEST_RUN` e' dello stesso ordine di grandezza di cio' che si vuole misurare,
quindi il suo minimo ha bisogno di **piu'** trial di quelli delle pipeline per assestarsi.

**Conseguenza pratica:** la normalizzazione non e' priva di senso, ma non e' abbastanza
stabile da essere riportata come numero in tesi — con 7 trial oscilla di un fattore 2, con
15 resta entro il ~20%. Riporta quindi le latenze **assolute** insieme alle specifiche
della macchina, e usa il baseline come *pavimento qualitativo* ("l'inferenza costa molto
piu' del solo framework XDP"). Cio' che riproduce sempre e' l'**ordinamento** —
baseline < P1 < P2 < P3 — insieme a istruzioni, lookup e memoria mappe, deterministici.

### La colonna CPU (%) e' stata rimossa

Era calcolata come `(utime + stime del processo) / wall time` del ciclo di misura. Ma
tutto il lavoro avviene dentro una `bpf_prog_test_run()` **bloccante**, quindi quel
rapporto non misura quanta CPU costi il programma eBPF: misura quanto lo scheduler ha
lasciato il thread sulla CPU, cioe' l'interferenza di sistema. I dati lo confermano —
risultava **non monotona** (template al 47%, sotto sia baseline 53% sia hardcoded 57%,
pur costando 4× la latenza) e **non riproducibile** (59% e poi 47% per la stessa
pipeline fra due run). Il costo per pipeline e' gia' descritto dalle colonne latenza e
istruzioni. Il codice porta un commento che spiega perche' non va reintrodotta.

### Blocco pesi a valore strutturato (P2/P3) — cosa è cambiato

`arch_weights` e `layer_weights` erano `BPF_ARRAY` con valore da 1 byte: **una
`lookup` + un NULL-check per ogni peso**. Contati sul sorgente generato, ~139 delle
147 lookup di P2 erano esattamente questo. Ora ciascuna mappa è **una sola entry a
valore strutturato** che contiene l'intero blocco: una `lookup`, poi accessi diretti
su puntatore. L'indice runtime resta verifier-safe con la maschera `& (SIZE-1)`
(SIZE potenza di due), che elimina anche i ~139 bound-check espliciti. Stesso
trattamento per `scratch_acts` di P3, che veniva riletta per **ogni coppia**
(neurone di uscita, ingresso) invece di una volta per hop.

| | P2 prima | P2 dopo | P3 prima | P3 dopo |
|---|---:|---:|---:|---:|
| Map lookup / pacchetto | 147.0 | **8.0** | 160.0 | **26.0** |
| Istruzioni xlated | 16 988 | 9 962 | 15 767 | 8 209 |
| Jited (byte) | 84 587 | 48 640 | 76 376 | 40 635 |
| Memoria mappe (byte) | 8 052 | 3 960 | 16 884 | 8 188 |
| Latenza min (ns/pkt, stessa sessione) | 349.7 | **224.0** | 590.0 | **387.0** |

(Prima/dopo misurati nella stessa sessione sulla stessa macchina, quindi qui le
latenze assolute sono direttamente confrontabili senza normalizzare.)

Inferenza **invariata**: stessa classe scelta su tutta la suite contro il riferimento
Python, multi-model e alt-arch inclusi. Lato control plane, registrare un modello è
ora **una** `bpf_map_update_elem` sull'intero blocco invece di 319 (P2) / 2048 (P3).

Lettura onesta del risultato: ~1/3 del costo per pacchetto di P2 e P3 **non era il
prezzo della flessibilità**, era il prezzo di una codifica del contenitore dei pesi.
L'ordinamento del design space non cambia, ma il divario ha due componenti da
separare: una *strutturale* (tail call + indirezione dei pesi a runtime) e una
*implementativa*, che va misurata e sottratta prima di attribuirla al design space.

### Baseline vs hardcoded (la domanda "perché l'hardcoded è così veloce?")

Il **baseline** riceve il pacchetto in XDP, fa lo stesso parse del dispatcher e un
`bpf_redirect` — **niente tail-call, niente MLP**. È il *pavimento* del framework:
**28 ns** nel run A, **14 ns** nel run B. L'hardcoded costa 47-48 ns in entrambi,
cioè aggiunge ~20-34 ns per tail-call + double-parse + la rete.

La lettura qualitativa regge in entrambi i run: l'hardcoded **non** è sospettosamente
veloce, sta nello stesso ordine di grandezza del do-nothing, e il throughput elevato
è in larga parte il pavimento XDP+parse+redirect — la rete int8 65-4-4-7 srotolata
costa poco in confronto. Il *fattore* preciso però non riproduce (1.68× vs 3.43×),
perché è il baseline a oscillare: vedi la nota sulla normalizzazione sopra. Per
quantificare davvero il costo del solo salto usa `bench_tailcall_overhead.py` (sez. 8),
che confronta due programmi che differiscono **solo** per un hop `PROG_ARRAY` e non
dipende da questo rapporto.

### AOT-literal deploy (P1, `poc_aot/loader_aot.c`)

Run del 17/09, **stessa sessione** del suite kernel qui sopra — che è la condizione
senza la quale il confronto per-pacchetto non vale niente.

| | BCC hardcoded | AOT literal |
|---|---:|---:|
| aggiornamento modello | **1 242 ms** (clang sul nodo) | **37.2 ms** (`open` 0.73 + `load` 36.5) |
| istruzioni | 1 026 (disp 29 + model 997) | 979 (disp 28 + model 951) |
| latenza | 73.0 ns | **74.0 ns** |
| throughput teorico | 13.699 Mpps | 13.51 Mpps |

**74.0 contro 73.0 ns: la stessa cifra**, dentro uno spread del 36% misurato nello
stesso run. Il guadagno dell'AOT non è per-pacchetto e non è mai stato quello: è che
la strength reduction sui pesi letterali **resta dentro l'oggetto**, quindi il costo
per pacchetto non peggiora, e il compilatore sparisce dal nodo datapath.

I due binari non sono identici (979 contro 1 026 istruzioni): passano per versioni di
clang diverse e per dialetti di accesso alle mappe diversi (rewriter di BCC contro
`bpf_map_lookup_elem` di libbpf). Affermazioni tipo "byte-identical" non sono
supportate; quello che è supportato è che stanno nella stessa classe di costo,
lontanissime da P2/P3.

> ⚠️ **La cifra di deploy varia molto fra run.** Per lo stesso oggetto sono stati
> osservati 4.66, 6.15, 20.7 e 37.2 ms, quasi tutto in `load` (verify+JIT). Regge
> l'**ordine di grandezza** rispetto a 1.2-1.3 s di clang, cioè un fattore fra 30 e
> 300, non il valore preciso. Una riga che citi "5 ms" o "37 ms" come proprietà
> dell'AOT sta sovra-interpretando un campione.

Il `1 242 ms` non è misurato da `loader_aot`, che non esegue mai il percorso BCC: è la
riga `[M1 update timing]` di `--only kernel` nello stesso run.

#### L'indice del nodo cambia la decisione, e si vede qui

Un oggetto AOT è costruito su una macchina di build, quindi non può portarsi dentro
l'indice del nodo: arriva al caricamento, da `--node-id` o `$IPA_NODE_ID`, come fa il
control plane Python. Due esecuzioni dello **stesso identico binario**:

```
$ sudo ./loader_aot nn_aot_arch.o
node_id left empty (no --node-id and no $IPA_NODE_ID) ...      retval=1   (XDP_DROP)

$ sudo ./loader_aot nn_aot_arch.o --node-id 7
seeded node_id: this node is index 7                          retval=2   (XDP_PASS)
```

Cambia solo la mappa `node_id`, e cambia la classe scelta. È la prova più diretta in
tutto il repository che quella feature — 208 pesi su 319 — **contribuisce davvero**,
e non un test che verifica sé stesso.

Senza `--node-id` la one-hot resta **spenta**, non messa a zero: il default è "non lo
so", non "sono il nodo 0". È lo stesso motivo per cui la mappa è un `HASH` e non un
`ARRAY`.

### Costo di aggiunta modello (`bench_model_add.py`, 3 modelli)

| pipeline | add **min** (ms) | media | come |
|---|---:|---:|---|
| hardcoded | 1146.4 | 1299.2 | ricompilazione completa (clang = 99.7%) |
| template | **0.346** | 4.86 | una `bpf_map_update_elem` sul blocco pesi |
| modular | **0.385** | 0.73 | una `bpf_map_update_elem` sul blocco pesi |

Hardcoded ~3313× più lento di template, ~2977× di modular. L'AOT stima ~3 ms di load →
**~432× più economico** del BCC, **senza perdita di perf**.

La statistica riportata è il **minimo**, non la media — coerente con la sezione 2:
il rumore è a senso unico e con soli 3 modelli la media è dominata dal primo add,
che paga il primo accesso alle pagine di una mappa appena creata (template: min
0.346 ms ma max 13.85, stdev 6.36 — la media descrive l'outlier, non l'operazione).
Il crollo rispetto alle misure precedenti viene da **due** cause da non confondere:
il passaggio media→minimo, e il fatto che registrare un modello sia ora **una**
`bpf_map_update_elem` invece di 319 (P2) / 2048 (P3).

### Multi-model (`verify_multi_model.py`) — regge shape custom

`model_desc` popolato correttamente anche per shape non-default: P2 `model_id=1` = 65-**6-5**-7,
P3 `model_id=1` = 65-**5-6-4**-7 (4 layer). Tutti PASS.

## 11. Throughput end-to-end misurato (`bench_throughput.py`)

Tutte le cifre di throughput nelle sezioni precedenti sono `1 / latenza` sotto
`BPF_PROG_TEST_RUN`: un ciclo sullo stesso buffer, senza driver e senza un pacchetto che
arrivi davvero. Sono **picchi teorici**. Questa sezione riporta l'altra cosa: pktgen (TG,
in-kernel) genera traffico vero, la pipeline XDP (DUT) lo elabora e lo redirige, e un
contatore XDP sull'interfaccia d'uscita conta quanti ne sono arrivati.

### 11.1 Il banco, e perché ne servono due

TG, DUT e contatore stanno sulla **stessa** macchina, collegati da una coppia veth con XDP
in modalità nativa. Quel vincolo genera un dilemma che non si risolve su questa VM:

| | NAPI in thread (core separati) | softirq (`--no-threaded-napi`) |
|---|---|---|
| dove gira la RX | kernel thread su una CPU dedicata | sulla CPU che ha trasmesso |
| perdita osservata | 8-70%, **a qualunque rate** | **0.00%** |
| collo di bottiglia | la coda del veth | il generatore |
| serve per | throughput massimo, confronto | rate a perdita nulla, costo per pacchetto |

**Perché la prima colonna perde a qualunque rate.** Attaccando XDP a un veth il kernel
alloca un `ptr_ring` sul lato ricevente, che `veth.c` fissa a `VETH_RING_SIZE` (256
descrittori) e che su questo kernel `ethtool -g` non espone — verificato, non è
configurabile. 256 descrittori a 1,5 Mpps sono **170 µs** di traffico: il thread NAPI deve
essere schedulato entro 170 µs ogni volta, e un guest VirtualBox su host a core ibridi non
lo garantisce. Il conto torna con le misure: a 74 kpps il ring copre 3,5 ms e la perdita è
0,10%; a 1,5 Mpps copre 0,17 ms e sta fra il 9 e il 18%. È un pavimento del banco, non
della pipeline — in tutte le righe `TX == HIT == RX`, cioè **il datapath non ha mai perso
un pacchetto che gli sia stato consegnato**.

In softirq la RX gira sulla CPU che ha trasmesso, il ring si drena in pratica
sincronamente e la perdita sparisce. Il prezzo è che generatore e pipeline condividono il
core, quindi il rate misurato è `1/(t_gen + t_pipeline)` e il tetto è sempre il generatore.

### 11.2 Rate a perdita nulla (softirq, perdita 0.00%)

Run del 2026-09-18, commit `131b7a6b`, `--threads 1 --duration 2.0 --repeat 5
--no-threaded-napi`. Sono **limiti inferiori** dell'NDR nel senso di RFC 2544: a massima
spinta non si è perso niente, quindi la pipeline non era satura e il vero NDR sta più in
alto.

| pipeline | 64 B | 512 B | 1514 B |
|---|---|---|---|
| baseline (nessuna inferenza) | ≥ 879 581 | ≥ 886 897 | ≥ 688 287 |
| p1_static (P1) | ≥ 784 711 | ≥ 774 151 | ≥ 652 699 |
| hardcoded (P1.5) | ≥ 847 622 | ≥ 838 514 | ≥ 614 433 |
| template (P2) | ≥ 643 508 | ≥ 637 925 | ≥ 542 678 |
| modular (P3) | ≥ 549 003 | ≥ 548 085 | ≥ 480 756 |

**Variazione fra run.** Un secondo run identico sette minuti dopo (`f3821c1e`) ha dato
baseline 913 530 / 889 125 / 713 687 e p1_static 839 712 / 819 103 / 674 403: le cifre
assolute si spostano del 4-14% da un run all'altro, sempre verso l'alto o verso il basso
insieme. È il motivo per cui la sezione seguente sottrae la baseline invece di citare i pps.

### 11.3 Costo dell'inferenza per pacchetto

È la cifra che il regime senza perdite rende pulita. Senza code di mezzo `1/RX pps` è il
tempo del percorso completo; la baseline fa lo stesso percorso **meno l'inferenza**, quindi
la differenza è il costo dell'inferenza. Il termine `t_gen` è comune a tutte le righe della
stessa taglia e sottraendo la baseline si cancella.

**Quattro run indipendenti** a `--repeat 5`, stessi parametri, nell'arco di mezz'ora
(`131b7a6b`, `f3821c1e`, `f4daa6d9`, `ee973cde`). `spread` è `(max − min) / media`.

**Costo dell'inferenza, ns/pacchetto sopra la baseline**

| pipeline | 512 B: A / B / C / E | media | spread | 1514 B media | spread |
|---|---|---|---|---|---|
| p1_static (P1) | 164 / 96 / 37 / 32 | 82 | 160% | 81 | 104% |
| hardcoded (P1.5) | 65 / 186 / 120 / 93 | 116 | 104% | 135 | 154% |
| template (P2) | 440 / — / 465 / 385 | **430** | 19% | 424 | 25% |
| modular (P3) | 697 / 704 / 691 / 601 | **673** | 15% | 692 | 25% |

**Cosa si può affermare, e con quale precisione.**

- **L'ordine P1 ≈ P1.5 < P2 < P3 regge in tutti e quattro i run**, a tutte le taglie. È
  l'affermazione solida di questa sezione.
- **P3 costa ~670 ns per pacchetto, P2 ~430 ns**, con uno spread del 15-19% fra run. Sono
  misure a una cifra significativa: "circa 0,7 µs" e "circa 0,4 µs", non 697 e 440.
- **P1 e P1.5 stanno entrambi sotto i ~200 ns e non sono separabili**, né fra loro né
  individualmente con precisione: i loro spread superano il 100%, cioè la variazione fra
  run è maggiore del valore stesso. Fra i run il loro ordine reciproco si inverte.
- **512 byte resta la taglia di riferimento** (spread 15-19% contro 25% a 1514).

**Nota metodologica, e vale più dei numeri.** Una stesura precedente di questa sezione
riportava P3 a "697/704/691 ns, spread 2%" sulla base dei primi tre run, e ne concludeva
che fosse "la cifra più solida". Il quarto run ha dato 601 ns e ha portato lo spread al
15%. Tre misure concordi su una macchina rumorosa non sono una misura precisa: sono tre
estrazioni che è capitato cadessero vicine. Lo spread va ricalcolato a ogni run aggiunto,
mai congelato al primo numero che fa una bella impressione.

### 11.4 Come si leggono le due colonne di perdita

Il banco riporta `perd.pegg` (la peggiore delle ripetizioni) e `perd.med` (la mediana), e
**decide** sulla seconda. È una deviazione dichiarata da RFC 2544, che definisce il
throughput come il rate a cui non si perde nemmeno un frame: la norma presuppone un DUT
quieto e dedicato, mentre qui capita che l'host sospenda il vCPU per l'intera finestra e
quella ripetizione descriva l'host, non il rate. Misurato: baseline a 512 byte, quattro
ripetizioni d'accordo e la quinta a 94,70% di perdita. Per la stessa ragione la dispersione
si valuta sull'intervallo interquartile e le ripetizioni anomale vengono **contate e
riportate** invece che scartate in silenzio.

La perdita è anche spezzata per colpevole, perché tre cause diverse chiedono tre rimedi
diversi: `respinti (veth)` — mai entrati nel DUT, backpressure; `persi in coda` — accettati
e mai arrivati al programma; `persi dopo` — elaborati e non usciti. In tutti i run di questa
sezione gli ultimi due sono **zero**.

### 11.5 Latenza end-to-end (`--latency`)

Run del 2026-09-18, commit `2b85d1f0`, `--frames 512 --rounds 3 --repeat 5 --threads 1`.
Il dispatcher marca `bpf_ktime_get_ns()` in una cella per-CPU e il programma d'uscita rilegge
e sottrae: si misura arrivo → ripartenza, non la durata del solo programma. È una **build
strumentata**, quindi la cifra è leggermente superiore a quella di produzione.

**Attenzione a non confrontarla con 11.2 e 11.3**: questo percorso gira con NAPI in thread
(core separati), non in softirq. I pps che riporta (1,4 Mpps contro gli 875 k della 11.2)
sono di un altro esperimento.

**Latenza minima a scarico (50 kpps, nessuna coda davanti), ns sopra la baseline**

Due run, a 3 e a 5 giri (`2b85d1f0` e `b0447b3e`). Mediana fra i giri.

| pipeline | 3 giri | 5 giri | media |
|---|---|---|---|
| baseline (assoluto) | 368 ns | 342 ns | 355 ns |
| p1_static (P1) | +76 | +107 | ~92 |
| hardcoded (P1.5) | +102 | +91 | ~97 |
| template (P2) | +269 | +288 | ~279 |
| modular (P3) | +440 | +473 | ~457 |

P2 e P3 concordano fra i due run entro il 7-8%. **P1 e P1.5 restano indistinguibili** — 92
contro 97 ns, e fra i due run il loro ordine si inverte — esattamente come nella 11.3.

**Solo la colonna `min` è utilizzabile, e va detto perché.** Il minimo viene da un
accumulatore ed è esatto. I percentili vengono da un istogramma `bpf_log2l`, quindi i
bucket sono potenze di due e il valore riportato è il **bordo superiore** di quello che
contiene il quantile: la risoluzione è un fattore 2. Nei run tutte e cinque le pipeline
cadono negli stessi due bucket — `p50` fra 4 e 8 µs, `p99` fra 16 e 32 µs — quindi p50 e
p99 **non separano niente** e non vanno riportati come misure. La tabella del banco li
stampa come `<8192n` per rendere la lettura obbligata.

**Un difetto del banco trovato proprio qui, e la ragione per cui la mediana è la statistica
giusta.** Il percorso `--latency` non passa da `_measure_once` e per questo non aveva
nessuna delle protezioni sulle finestre aggiunte per la modalità `saturate`. Al giro 5 la
fase `scarico` di `hardcoded` ha consegnato **171 pacchetti invece di ~100 000**, ed è
entrata in tabella con `min 5627 ns` contro i ~430 degli altri quattro giri. Effetto:

| | spread di `hardcoded` |
|---|---|
| con la finestra rotta | 1227% → `[FAIL]` |
| senza | **4%** → passa |

La **mediana non si è spostata di un nanosecondo** — 433 ns con e senza. A cadere è stato
solo il controllo di riproducibilità, che usa max/min. È la conferma pratica della scelta
fatta in 11.4: riportare il caso peggiore, decidere sulla statistica robusta. Le protezioni
(scarto delle finestre troncate, drenaggio prima e dopo) sono ora anche in
`_one_fair_point`.

**Il confronto fra le due stime del costo è esso stesso un risultato.** Per P1 e P1.5 la
latenza minima e il costo dedotto dal throughput coincidono (76 contro 82, 102 contro 116).
Per P2 e P3 divergono, e la divergenza cresce con la complessità: +269 contro 430 per P2,
+440 contro 673 per P3, cioè il 53% in più. La lettura: il minimo è il cammino più
fortunato — tutto in cache, nessuna contesa — mentre il costo dedotto dal throughput è
quello medio sotto carico continuo. Le pipeline che usano tail call e lookup di mappa (P2,
P3) pagano sotto carico quello che nel caso migliore non si vede. **Per dimensionare un
nodo va usata la cifra da throughput, non la latenza minima.**

### 11.6 Cosa questo banco NON può dare su questa macchina

L'NDR vero. Con i core separati il pavimento del ring distrugge la misura a perdita nulla;
con i core condivisi il generatore è sempre il collo di bottiglia, perché la sua CPU fa
anche la RX — e aggiungere core al generatore ne aggiunge anche al DUT, quindi il rapporto
fra i due non cambia mai. Servirebbero due macchine, o una NIC che supporti XDP nativo
(l'unica fisica qui è `e1000`, emulata, che non lo supporta).

Quello che resta valido, ed è su cui si basano 11.2 e 11.3: il **confronto** fra pipeline a
parità di condizioni, e il costo per pacchetto in regime senza perdite.

## Note oneste

- **Ordine design-space confermato**: costo (istruzioni, jited, tail call, lookup, memoria)
  cresce monotono baseline→P1→P2→P3; le prestazioni calano nello stesso ordine.
- **Costo della flessibilità IV runtime (Task 3)**: rendere P2/P3 descrittore-driven ha
  aumentato il loro conteggio istruzioni (P2 template ~2 618→16 988): il loop generico
  per-feature unrolled (`MAX_FEAT` × neuroni × dense) pesa. Parte di quel costo è però
  rientrata col blocco pesi strutturato (16 988→9 962): vedi la sezione dedicata sopra —
  non tutto ciò che sembrava prezzo della flessibilità lo era davvero.
- **P1 = meno memoria mappe** (308 B): nessun `model_cache`, solo contatori + `link_state`.
- **Inferenza identica** nelle 3 pipeline (stesso MLP/pesi/argmax): verificata dal match di
  classe kernel vs riferimento Python (10/10 e 5/5 PASS).
- **Azione uniforme (`mac_table`)**: `argmax → mac_table[classe] → bpf_redirect`.
- **Nessun `ctx_in` custom**: sotto `BPF_PROG_TEST_RUN` l'`ingress_ifindex` di sandbox vale 1.
  P1 lo traduce attraverso la propria `ifindex_table` (default `[2..7]`), che **non** mappa 1
  → `_iface=0`. P2/P3 invece usano l'ifindex **grezzo** come indice one-hot e `1` cade dentro
  il clamp `[1,sz]` → contribuiscono la colonna 0. **Le due semantiche divergono**, e non solo
  in sandbox: su un nodo reale `eth0` ha ifindex 2, quindi P1 sceglie la colonna 0 e P2/P3 la
  colonna 1 per lo stesso pacchetto. Non è ancora stato uniformato — su questo modello sposta
  solo argmax quasi pari (la classe 0 domina), ma va allineato prima di trarre conclusioni
  sull'equivalenza delle tre pipeline. Vedi il commento in `verify_prog_run.py` (`ref_ifindex`).
- **P2/P3 non caricano in un container minimale**: il nodo applica il cap storico di 4096 istruzioni per
  programma, e `arch_generic_2layer` ne conta 9 318 compilato nel container (`bpf: Program too
  large`). Le misure di questa tabella vengono da `BPF_PROG_TEST_RUN` **sull'host**, dove il
  cap non si applica. È un limite preesistente e non una regressione — prima del blocco pesi
  strutturato lo stesso programma era circa il doppio. Riguarda l'immagine container minimale, non il
  kernel dell'host: vedi la voce seguente.
- **P1, P2 e P3 girano end-to-end su un datapath reale** (`ipa/test/test_fabric.py`, 18/18):
  XDP in modalità **native** su `veth`, `bpf_redirect` vero, pacchetto catturato sulla porta
  d'uscita, DROP verificato dal contatore `cls_stats` e non dal silenzio. Questa riga diceva
  il contrario fino a poco fa — era vera quando l'unico banco era un emulatore.

### P3 era al limite del verificatore: com'è stato chiuso

Per un giorno intero questa sezione ha detto che su Pipeline 3 la one-hot del nodo
**non si poteva** fare: `layer_first` caricava a 9 994 istruzioni con l'indice preso dal
`model_id` del pacchetto, e ogni tentativo di leggerlo da una mappa veniva rifiutato.
Adesso l'indice arriva dalla mappa e `layer_first` carica a **6 417 istruzioni**, più
piccolo di prima. Vale la pena raccontare perché, perché la conclusione sbagliata era
ragionevole e la diagnosi ha richiesto dodici configurazioni.

**Il meccanismo.** Il costo per il verificatore non è la somma degli scalari che il ciclo
srotolato tiene vivi: è il loro **prodotto**. La versione che caricava era quella in cui
`_node = model_id`, cioè *lo stesso registro* che il verificatore stava già seguendo —
uno scalare, non due. Qualunque `_node` indipendente ne aggiunge un secondo, e il numero
di stati si moltiplica.

Escluse una per una, ciascuna con la sua prova: il tipo di mappa, la dichiarazione della
mappa, il valore in sé, il cast a `__u8`, il numero di chiamate helper, il numero di
valori nati da una fusione (ternari), la larghezza in bit dell'intervallo, `barrier_var`
con maschera esplicita. Tutte rifiutate, fra 9 069 e 9 402 istruzioni.

**Quello che ha liberato spazio non tocca il nodo**: `IPA_MAX_QUEUES` in
`ipa/ebpf_modular.py`, da 8 a 1. Il descrittore depositato **non dichiara** nessuna
feature `queue_occupancy` (i suoi codici sono 1, 2, 3, 4; queue è 5), quindi otto slot
restavano vivi lungo tutto il corpo srotolato per una feature che non c'è.

| | istruzioni | esito |
|---|---:|---|
| indice da `model_id`, `IPA_MAX_QUEUES` 8 | 9 994 | carica (ma il nodo non è il nodo) |
| indice da mappa, `IPA_MAX_QUEUES` 8 — 12 varianti | 9 069 – 9 402 | tutte rifiutate |
| **indice da mappa, `IPA_MAX_QUEUES` 1** | **6 417** | **carica** |
| indice da mappa, queues 1 **e** `IPA_MAX_IFACES` 6 | — | rifiutato |

**Questi limiti sono scogliere, non pendenze.** L'ultima riga è la lezione: ridurre *anche*
`IPA_MAX_IFACES` da 8 a 6 — cioè chiedere *meno* — fa fallire di nuovo. Un soffitto qui si
cambia e **si rimisura**, non si ragiona.

Il control plane protegge il soffitto invece di subirlo: `load_modular_weights`
**rifiuta** un descrittore che chieda più slot di coda di quanti il datapath ne compili,
invece di troncarlo silenziosamente al primo. Un modello che serve davvero quella feature
fa alzare la costante e ripetere la misura.

#### Epilogo: il soffitto è tornato a 8

Tagliare `IPA_MAX_QUEUES` a 1 era una perdita reale, non una pulizia: a 1, un modello che
dichiari `queue_occupancy` più larga di uno slot viene **rifiutato**. Il nido di cicli
invertito (sezione Risultati) ha restituito il margine, e la misura è
`diag_p3_bisect.py --ceilings`:

| `IPA_MAX_QUEUES` | `layer_first` | esito |
|---:|---:|---|
| 1 | 6 850 | carica |
| 2 | 7 320 | carica |
| 4 | 8 365 | carica |
| **8** | **10 207** | **carica** |

Prima della riscrittura, a 8 non caricava niente. Il soffitto è di nuovo 8, uguale a
Pipeline 2, e l'asimmetria fra le due è chiusa.

La lettura da portarsi via è che **istruzioni e complessità di verifica sono valute
diverse**: la riscrittura ha fatto *crescere* `layer_first` di 433 istruzioni e gli ha
fatto accettare un corpo da 10 207. Il verificatore paga i cammini.

Conseguenza per le tre pipeline: l'indice del nodo ora viene dalla mappa `node_id` in
**tutte e tre**, letto a runtime, senza tabelle compilate. È la chiusura dell'ultimo
ingresso su cui non concordavano.

> **Due trappole nel leggere il fallimento**, entrambe costate ore.
>
> BCC riporta il rifiuto come `Program too large (N insns), at most 4096 insns`. Il 4096 è
> una **costante vecchia nella stringa d'errore di BCC**: nello stesso run P2 carica a
> oltre 14 000 istruzioni. Va letto come "il verificatore ha rinunciato", non "il programma è
> troppo lungo".
>
> E il numero `layer_first=9994` è il conteggio **xlated**, cioè di un programma già
> caricato, mentre quello nel messaggio d'errore è il conteggio **grezzo** prima del
> caricamento. Confrontarli direttamente porta alla conclusione "ogni versione rifiutata è
> più piccola di quella che carica", che è un artefatto di due unità di misura diverse. Quella
> frase è stata in questo documento per un giorno.

Lo strumento che ha chiuso la questione è `ipa/test/diag_p3_bisect.py`: con `--variants`
costruisce modifiche testuali del sorgente corrente e riporta quali caricano; senza flag
ripercorre la storia git. Le ipotesi sono state escluse da lì, non ragionando.

### Il soffitto compilato ha un costo di verifica, e ha un limite

`T2_MAX_H1`, `T2_MAX_H2` e `MAX_N_IN` sono **soffitti a compile-time**: i cicli interni sono
`#pragma unroll`ati a quelli, non alle larghezze reali del modello, così un programma compilato
serve qualunque modello che stia sotto. È il livello L1 del modello a tre livelli, ed è la
ragione per cui P2 non ricompila quando cambia modello.

Il conto però lo paga il **verificatore**, che percorre ogni cammino del corpo srotolato. Con i
soffitti larghi (`8 × 4 × 128`) il kernel si arrende:

```
processed 1000001 insns (limit 1000000) ... total_states 13864 peak_states 1010
```

Due limiti distinti, da non confondere: il programma è ~14 900 istruzioni, ampiamente **dentro**
il cap sulla dimensione. Quello che finisce è la **complessità di verifica**, e cresce col
prodotto dei soffitti.

È la misura concreta di quanto un programma "generico" possa essere generico: la genericità di
P2 non è gratis, si paga in stati del verificatore, e il tetto è raggiungibile con numeri
ragionevoli (8 neuroni, 128 feature). Il modello depositato usa 4-4-65, cioè circa metà di ogni
soffitto — abbassarli a quelle misure riduce il corpo srotolato di circa 4×.

Emerso provando a caricare lo stesso datapath con `libbpf` invece di BCC. Quel percorso non è
stato portato avanti — BCC resta il backend di deploy per P2/P3 — ma il limite che ha messo in
luce non dipende dal backend: è il verificatore del kernel, lo stesso per entrambi.
- Latenza/throughput hanno varianza run-to-run non trascurabile sotto `BPF_PROG_TEST_RUN`
  (fino a 20× su un singolo campione, rumore a senso unico — vedi sez. 7): tutti gli script
  di benchmark aggiunti in questa sessione (7, 8) usano minimo su N trial indipendenti, mai
  un campione singolo.

- **Limiti dell'ambiente (onestà, cfr. Heiser "Benchmarking Crimes", arXiv:1801.02381)**:
  nessun CPU pinning/isolamento core, nessuna frequenza CPU fissata, nessun C-state
  disabilitato, VM — i numeri assoluti (ns/pacchetto, Mpps) non sono comparabili con
  paper su bare-metal. Il confronto **relativo** fra le pipeline sullo stesso nodo, stesse
  condizioni, è l'unica misura difendibile con questo setup — è quello su cui si basano
  tutte le conclusioni di questo documento (ordine P1/P2/P3, larghezza-vs-profondità).
