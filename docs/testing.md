# Guida ai test — IPA/eBPF design space

Tre pipeline (P1 hardcoded, P2 template, P3 modular) verificate su due piani:

- **userspace** (numerico, PyTorch/NumPy) — accuratezza, quantizzazione, robustezza, struttura;
- **kernel** (`BPF_PROG_TEST_RUN` sui programmi XDP reali) — istruzioni eBPF, latenza, throughput, CPU, memoria mappe + dispatch reale.

Tutto è raccolto in un unico script: `shared/test/test_suite.py`. Tutti gli script di test
(compreso `bench_model_add.py`, vedi §6) vivono ora sotto `shared/test/`.

---

## 1. Test locali (userspace) — nessun root, nessun kernel eBPF

Richiede solo `torch` + `numpy`. Girano ovunque (anche fuori da Kathara).

```bash
# Tutte le suite (la suite kernel viene saltata se non c'è BCC/root)
python3 shared/test/test_suite.py

# Una singola suite
python3 shared/test/test_suite.py --only core       # struttura design-space + update latency
python3 shared/test/test_suite.py --only quant       # accuratezza argmax vs scale_factor
python3 shared/test/test_suite.py --only pktstats    # HIT/FAKE/MISS per pipeline
python3 shared/test/test_suite.py --only extract     # coerenza pesi / weights.json / dequant
python3 shared/test/test_suite.py --only robust      # input anomali, nessun crash

# Opzioni
python3 shared/test/test_suite.py --only quant --samples 500
python3 shared/test/test_suite.py --model shared/frr_germany50_5_model_4x2.pt --verbose
```

---

## 2. Test nel kernel (`--only kernel`) — richiede Linux + BCC + root

Carica i programmi XDP reali ed esegue `BPF_PROG_TEST_RUN`. Misura le metriche del design
space direttamente dal kernel e verifica il dispatch (redirect) per ogni TTL. La tabella
include ora una colonna **baseline** (parse + redirect, nessuna inferenza) come pavimento di
riferimento — utile per capire quanto costa davvero l'inferenza rispetto al solo framework XDP.

```bash
# Su host Linux con BCC installato
sudo python3 shared/test/test_suite.py --only kernel

# Dentro Kathara (nodo frankfurt)
kathara exec frankfurt -- python3 /shared/test/test_suite.py --only kernel

# Solo metriche, senza il gate di dispatch
sudo python3 shared/test/test_suite.py --only kernel --no-verify

# Più ripetizioni per una latenza più stabile (per-trial repeat)
sudo python3 shared/test/test_suite.py --only kernel --kernel-repeat 200000

# Più trial indipendenti (default 7) se il risultato è ancora volatile
sudo python3 shared/test/test_suite.py --only kernel --kernel-trials 15
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
throughput/CPU) + `5 PASS / 0 FAIL` per ciascuna pipeline + il probe `link_state reroute`
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
> - Su un nodo Kathara vero gli ifindex sono 201/209/217/223: non stanno né in `[2..7]`
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
kathara exec frankfurt -- python3 /shared/test/verify_prog_run.py --method hardcoded
kathara exec frankfurt -- python3 /shared/test/verify_prog_run.py --method template
kathara exec frankfurt -- python3 /shared/test/verify_prog_run.py --method modular
kathara exec frankfurt -- python3 /shared/test/verify_prog_run.py --method modular --model-id 3
```

---

## 3. Avvio del lab Kathara

```bash
# dalla root del repo
kathara lstart                 # avvia tutti i nodi (germany50)
kathara linfo                  # stato dei nodi
kathara lclean                 # ferma e pulisce il lab
```

Ogni nodo esegue `shared/fix_bpf.sh` al boot (monta debugfs, abilita ip_forward, FRR/OSPF).

---

## 4. Attaccare una pipeline a un'interfaccia (XDP reale sul fabric)

Attacca sull'interfaccia dove **entra** il traffico (XDP conta solo l'ingresso). In questo
lab il traffico per `frankfurt` (IP loopback `10.255.255.17`) entra su **eth1** — verifica con
`kathara exec frankfurt -- tcpdump -i any -n udp port 9999`.

```bash
# sul nodo che fa da switch (es. frankfurt), su eth1
kathara exec frankfurt -- python3 /shared/execute_pipeline.py --method template  --iface eth1 --model-id 0
kathara exec frankfurt -- python3 /shared/execute_pipeline.py --method modular   --iface eth1 --model-id 0

# hardcoded: AOT-literal è l'UNICO backend di deploy (BCC live-attach rimosso su
# richiesta esplicita del relatore). Serve un .o prebuilt (build offline su host
# con clang) + loader_aot linkato staticamente contro libbpf (nessuna dipendenza
# runtime su libbpf.so sul nodo Kathara). BCC resta solo internamente ai test
# (verify_prog_run.py ecc.), mai per il deploy.
kathara exec frankfurt -- python3 /shared/execute_pipeline.py --method hardcoded --iface eth1

# solo verifica del caricamento, senza restare in ascolto
kathara exec frankfurt -- python3 /shared/execute_pipeline.py --method hardcoded --verify-only

# se un XDP resta appeso da un run precedente ("File exists"): staccalo
kathara exec frankfurt -- ip link set dev eth1 xdp off
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
sudo python3 shared/methods/method4_hardcoded_aot.py
# deploy LIVE su Kathara (via execute_pipeline, backend AOT di default):
kathara exec frankfurt -- ip link set dev eth1 xdp off
kathara exec frankfurt -- python3 /shared/execute_pipeline.py --method hardcoded --iface eth1
```

**Verificato end-to-end** su nodo Kathara `frankfurt` (che NON ha clang, cc né `libbpf.so`
usabile per il link): il loader fully-static carica il `.o` prebuilt e attacca il programma
XDP; `ip link show dev eth1` mostra `prog/xdp id ... name xdp_dispatch ... jited`, cioè il
dispatcher AOT agganciato e JIT-compilato. Il comando di deploy resta resident (loop
`pause()`) finché non lo si interrompe con Ctrl-C, che stacca l'XDP. La correttezza
dell'inferenza è coperta separatamente da `test_suite --only kernel` (5/5 PASS per TTL).

Il modello AOT è **build offline** (macchina con clang) → deploy del `.o` prebuilt sul nodo
(nessun clang). Su un nodo senza clang, se `nn_aot_arch.o` è già presente viene riusato.

**`loader_aot` va costruito allo stesso modo, una volta sola, fuori da Kathara**: anche
`cc`/gcc manca nei nodi Kathara (oltre a clang), quindi non si può compilare il loader
dentro `kathara exec`. Costruiscilo **sull'host** (come utente normale, non `sudo` — il
build non richiede root; solo l'attach XDP finale lo richiede):
```bash
# dev-lib per il link statico (una volta):
sudo apt-get install -y libbpf-dev libelf-dev zlib1g-dev libzstd-dev liblzma-dev
python3 shared/methods/method4_hardcoded_aot.py   # sull'host, non via kathara exec
```
Il binario è linkato **staticamente** (niente `libbpf.so` richiesto a runtime) e vive in
`shared/poc_aot/loader_aot` — poiché `shared/` è montato via bind mount in ogni nodo
Kathara, una volta costruito sull'host è **immediatamente visibile** su tutti i nodi,
nessuna copia manuale.

Note pratiche emerse costruendolo davvero:
- Il link statico di libbpf tira dentro dipendenze transitive che devono anch'esse essere
  statiche: `libelf`, `zlib`, e — su elfutils recente che comprime le sezioni ELF —
  anche `libzstd` e `liblzma`. Lo script prova prima la riga a 3 librerie, poi quella a 5
  (con `zstd`/`lzma`); su Ubuntu recente serve la seconda. Se fallisce stampa l'errore
  `ld` completo per capire quale `.a` manca.
- I file generati sotto `shared/poc_aot/` (`nn_aot_arch.bpf.c`, `.o`, `loader_aot`) prendono
  il proprietario dell'utente che li crea: se un run precedente è stato fatto con `sudo`/
  `kathara exec` (root), un run successivo come utente normale fallisce con
  `PermissionError`. Rimedio: `sudo chown -R $USER:$USER ~/percorso/ipa_lab`.
- Sui nodi Kathara di questo lab `libbpf.so.1` **è presente** (tirato dentro da BCC), quindi
  anche un loader linkato dinamicamente (`-lbpf`) funzionerebbe lì; il link statico resta
  comunque la scelta preferita perché non dipende da questo dettaglio dell'immagine.
- Il bench sull'host (`method4_hardcoded_aot.py` senza `--iface`) carica un programma BPF e
  quindi richiede root: eseguito come utente normale fallisce con `RLIMIT_MEMLOCK -EPERM`.
  Non è un problema del deploy — il caricamento reale avviene sul nodo Kathara, che gira
  come root.

Le pipeline avviano automaticamente il monitor `link_state` (thread di polling che tiene
`link_state[0..5]` allineato al carrier reale delle interfacce egress). Per un dry-run dei
carrier senza caricare eBPF:

```bash
# stampa lo stato up/down di eth0..eth5 che verrebbe scritto nella map
kathara exec frankfurt -- python3 /shared/link_state_monitor.py --ifaces eth0 eth1 eth2 eth3 eth4 eth5
```

---

## 5. Invio pacchetti IPA di prova

Il fabric Kathara non consegna UDP:9999 end-to-end, quindi la verifica di correttezza
si fa con `BPF_PROG_TEST_RUN` (sopra). Per un test di invio live:

```bash
# listener su frankfurt
kathara exec frankfurt -- python3 /shared/recv_ipa.py --timeout 30 --port 9999

# sender da darmstadt
kathara exec darmstadt -- python3 /shared/send_ipa.py
kathara exec darmstadt -- python3 /shared/test/test_ipa.py --dest frankfurt --count 100 --model-id 0

# traffico multi-modello (round-robin), per esercitare il dispatch multi-model_id di P2/P3
kathara exec darmstadt -- python3 /shared/test/test_ipa.py --dest frankfurt --count 90 --model-ids 42 43 44
```

---

## 6. Costo reale di aggiunta modello (`bench_model_add.py`)

Misura, con `BPF(text=…)` + `load_func()` reali (non stimati), quanto costa registrare un
nuovo `model_id` a runtime in ciascuna pipeline — sfrutta il multi-model concorrente di P2/P3
(più `model_id` nella stessa run, blocchi di pesi non sovrapposti in `arch_weights`/`layer_weights`).

```bash
sudo python3 shared/test/bench_model_add.py --n-models 3
kathara exec frankfurt -- python3 /shared/test/bench_model_add.py --n-models 3
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
sudo python3 shared/test/bench_depth_vs_width.py                      # tutti e 4 i descrittori
sudo python3 shared/test/bench_depth_vs_width.py --descriptor no_onehot
sudo python3 shared/test/bench_depth_vs_width.py --repeat 5000        # più stabile, più lento
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

**Risultato** (minimo su 7 trial, range osservato sui 4 descrittori):

| Tier | Forma | Pesi | ns/pkt (min) |
|---|---|---:|---:|
| A (~100-320 pesi) | baseline / wide 1 layer | ~90-320 | 44 - 56 ns |
| A | deep 8×3 | ~150-310 | 57 - 76 ns (overhead profondità: +13/+32 ns) |
| B (~300-1300 pesi) | wide 1×16 | ~310-1175 | **103 - 111 ns (sempre il più veloce)** |
| B | deep 4×11 | ~610-1210 | 203 - 236 ns (~2× più lento) |
| B | deep 8×9 | ~810-1295 | 269 - 301 ns (~2.5-3× più lento) |
| C (~1200-4700 pesi) | tutte (wide / deep 4 / deep 8) | — | **CRASH sempre**, ogni descrittore, ogni forma |

**Cosa significa**: a parità di budget-pesi, **allargare batte approfondire** — risultato
coerente sui 4 descrittori indipendenti (non un artefatto delle feature one-hot del
descrittore di default). Ogni hidden layer in più costa un overhead fisso (~15-40 ns/layer,
transizione + ReLU) indipendente dalla composizione delle feature. Oltre ~1200-1300 pesi lo
stack eBPF va in overflow **sempre**, larga o profonda che sia la rete: non è una scelta di
design larghezza/profondità, è un limite strutturale dell'architettura "tutto srotolato in
un'unica funzione C, pesi come literal" — per modelli più grandi serve spostare gli array
grandi in una `BPF per-cpu array map` (suggerimento diretto del compilatore nel messaggio di
errore), non redistribuire gli stessi pesi su più layer.

---

## 8. Isolare il costo del tail-call (`bench_tailcall_overhead.py`)

Le tre metriche esistenti (baseline, hardcoded, map-lookup) non isolavano MAI
il costo del solo hop `bpf_tail_call`: `hardcoded_latency - baseline_latency`
(sez. "Baseline vs hardcoded") impacchetta insieme tail-call + secondo parse
del pacchetto + MLP. La letteratura sul design tail-call-based (vedi fonti
in sez. 7-8 sotto) elenca il tail-call come una delle tre componenti di costo
separabili — mancava una misura dedicata.

```bash
sudo python3 shared/test/bench_tailcall_overhead.py
sudo python3 shared/test/bench_tailcall_overhead.py --repeat 5000 --trials 15
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
sudo python3 shared/test/test_suite.py --only kernel
```

---

## Risultati (kernel, `test_suite.py --only kernel`, 4 CPU, modello 65→4→4→7, scale=24)

Aggiornati dopo: IV **descrittore-driven** in P2/P3 (registry `model_desc`), AOT-literal
universale in P1, riga **baseline** (parse + redirect, **nessuna inferenza**) come pavimento.

Metodologia: minimo su 7 trial indipendenti (sez. 2) — p50/max riportati per trasparenza,
non solo il minimo. Numeri dal run più recente (box Linux, 4 CPU).

Due run indipendenti sono riportati affiancati, perché il confronto fra i due dice
qualcosa che nessuno dei due da solo direbbe (vedi la nota sulla normalizzazione).

| Metrica                    | baseline | P1 hardcoded | P2 template | P3 modular |
|----------------------------|---------:|-------------:|------------:|-----------:|
| Istruzioni eBPF (xlated) — run A |  129 |          997 |       9 962 |      8 209 |
| Istruzioni eBPF (xlated) — run B |  129 |          997 |       9 916 |      8 201 |
| Codice jited (byte) — run A |     600 |        4 751 |      48 640 |     40 635 |
| Codice jited (byte) — run B |     600 |        4 751 |      50 306 |     40 544 |
| Tail calls / pacchetto     |        0 |            1 |           1 |          3 |
| Map lookup / pacchetto (reali) |    0 |          4.0 |         8.0 |       26.0 |
| Memoria mappe (byte)       |      280 |          308 |       3 960 |      8 188 |
| Latenza min (ns/pkt) — run A |   28.0 |         47.0 |       224.0 |      387.0 |
| Latenza min (ns/pkt) — run B |   14.0 |         48.0 |       165.0 |      392.0 |
| ...p50 — run B             |     21.0 |         73.0 |       251.0 |      450.0 |
| ...max — run B             |     23.0 |         94.0 |       468.0 |      499.0 |
| Throughput (Mpps, da min) — run B | 71.429 |   20.833 |       6.061 |      2.551 |
| CPU (%) — run B            |       27 |           34 |          59 |         62 |

| Dispatch (correttezza)     |        — |      5/5 PASS |   5/5 PASS |   5/5 PASS |
| link_state reroute         |          | PASS (5/30 casi cambiano uscita) |||

> **La latenza normalizzata sul baseline NON è una statistica stabile — non usarla.**
> Una versione precedente di questa tabella riportava una riga "latenza normalizzata
> (× baseline)" e la giustificava così: il baseline è lo stesso identico programma su
> ogni macchina, quindi dividere per esso rende i numeri comparabili fra box diversi.
> Il caso di controllo citato era P1, invariato, con rapporto 1.67 e poi 1.68.
>
> Il run B falsifica questa affermazione. Le latenze **assolute** delle tre pipeline
> riproducono bene (P1 47→48 ns, P3 387→392 ns); è il **baseline** a essere passato da
> 28 a 14 ns. Di conseguenza il rapporto di P1 salta da 1.68× a 3.43×, quello di P3 da
> 13.8× a 28×. Il numeratore è stabile, il denominatore no.
>
> La causa è che il baseline è troppo economico (129 istruzioni) perché il minimo-su-N
> sia stabile: nel run B `min=14, p50=21, max=23`, uno spread del 50% su un valore che
> dividerebbe l'intera colonna. Con così poche istruzioni l'overhead per iterazione di
> `BPF_PROG_TEST_RUN` è dello stesso ordine del programma misurato.
>
> **Conseguenza pratica:** riporta le latenze assolute insieme alle specifiche della
> macchina, e usa il baseline come *pavimento qualitativo* ("l'inferenza costa molto
> più del solo framework XDP"), non come divisore quantitativo. Quello che riproduce
> fra i run è l'**ordinamento** — baseline < P1 < P2 < P3 — insieme a istruzioni,
> lookup e memoria mappe, che sono deterministici.

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

### AOT-literal deploy (P1, `method4_hardcoded_aot.py`)

| | run A | run B |
|---|---:|---:|
| open_file | 0.27 ms | 0.16 ms |
| load (verify+JIT) | 4.40 ms | 6.00 ms |
| **deploy totale** | **4.66 ms** | **6.15 ms** |
| build offline (clang → .o) | — | 147 ms |
| perf: insn totali | 1 010 (disp 28 + model 982) | 1 026 (disp 28 + model 998) |
| perf: latenza / throughput | 90 ns / 11.1 Mpps | 57 ns / 17.5 Mpps |

Confronto con BCC hardcoded **nella stessa sessione del run B**: BCC 997 istruzioni
(29 + 968) a 48 ns, AOT 1 026 (28 + 998) a 57 ns. Cioè AOT è nello stesso ordine di
grandezza ma **non identico**: i due passano per versioni di clang diverse e dialetti
di accesso alle mappe diversi (BCC rewriter vs `bpf_map_lookup_elem` di libbpf), quindi
il codice generato differisce di qualche punto percentuale. Affermazioni tipo
"byte-identical" o "prestazioni identiche" non sono supportate dai dati; quello che è
supportato è che **la strength reduction sui pesi letterali è preservata** e il costo
per pacchetto resta nella classe della hardcoded, lontanissimo da P2/P3.

Il guadagno vero non è la latenza per pacchetto ma il **costo di deploy sul nodo**:
~5-6 ms di `open+load` contro ~1.3 s di `clang` a runtime, cioè oltre due ordini di
grandezza, e senza bisogno di clang sul nodo datapath.

> Il numero "~1.3 s" citato qui è il costo di ricompilazione BCC misurato dalla riga
> `[M1 update timing]` di `--only kernel` (1 258.9 ms nel run B; 1.26-1.66 s osservati
> su box diversi). Non è misurato da `method4_hardcoded_aot.py`, che non esegue mai il
> percorso BCC: quello script lo stampa come valore di riferimento, non come misura.

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
- **P2/P3 non caricano dentro Kathara**: il nodo applica il cap storico di 4096 istruzioni per
  programma, e `arch_generic_2layer` ne conta 9 318 compilato nel container (`bpf: Program too
  large`). Le misure di questa tabella vengono da `BPF_PROG_TEST_RUN` **sull'host**, dove il
  cap non si applica. È un limite preesistente e non una regressione — prima del blocco pesi
  strutturato lo stesso programma era circa il doppio — ma va detto: **P2 e P3 non hanno mai
  girato end-to-end sul fabric**, solo P1. Servirebbe un altro ~2.3× di riduzione istruzioni.
- Latenza/throughput hanno varianza run-to-run non trascurabile sotto `BPF_PROG_TEST_RUN`
  (fino a 20× su un singolo campione, rumore a senso unico — vedi sez. 7): tutti gli script
  di benchmark aggiunti in questa sessione (7, 8) usano minimo su N trial indipendenti, mai
  un campione singolo.
- **Limiti dell'ambiente (onestà, cfr. Heiser "Benchmarking Crimes", arXiv:1801.02381)**:
  nessun CPU pinning/isolamento core, nessuna frequenza CPU fissata, nessun C-state
  disabilitato, VM/Kathara — i numeri assoluti (ns/pacchetto, Mpps) non sono comparabili con
  paper su bare-metal. Il confronto **relativo** fra le pipeline sullo stesso nodo, stesse
  condizioni, è l'unica misura difendibile con questo setup — è quello su cui si basano
  tutte le conclusioni di questo documento (ordine P1/P2/P3, larghezza-vs-profondità).
