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

Metodologia: minimo su 7 trial indipendenti, con p50/max e spread relativo. Sono
riportate **due esecuzioni consecutive dello stesso identico binario**, perché la
distanza fra loro è il dato metodologico più importante della sezione.

| Metrica | run | baseline | P1 hardcoded | P2 template | P3 modular |
|---|---|---:|---:|---:|---:|
| Istruzioni eBPF (xlated) | 1 e 2 | 155 | 971 | 16 185 | 11 826 |
| Codice jited (byte) | 1 e 2 | 709 | 4 764 | 79 051 | 57 831 |
| Tail call / pacchetto | — | 0 | 1 | 1 | 3 |
| Map lookup / pacchetto (reali) | — | 3.0 | 5.0 | n.d. | 28.0 |
| Memoria mappe (byte) | — | 280 | 2 356 | 10 416 | 19 508 |
| **Latenza min (ns/pkt)** | **1** | **35.0** | **62.0** | **243.0** | **478.0** |
| **Latenza min (ns/pkt)** | **2** | **28.0** | **67.0** | **247.0** | **422.0** |
| ...p50 | 2 | 30.0 | 73.0 | 261.0 | 445.0 |
| ...max | 2 | 38.0 | 80.0 | 278.0 | 455.0 |
| ...spread (max−min)/min | 2 | 36% | 19% | 13% | 8% |
| Throughput teorico (Mpps, da min) | 2 | 35.714 | 14.925 | 4.049 | 2.370 |

Suddivisione per programma (identica nei due run):

| | dispatcher | leaf |
|---|---|---|
| baseline | — | `xdp_baseline` 155 |
| P1 hardcoded | `ipa_switch_hardcoded` 29 | `model_0` 942 |
| P2 template | `ipa_switch_template` 41 | `arch_generic_2layer` 16 144 |
| P3 modular | `modular_dispatcher` 116 | `layer_first` 9 994 + `layer_hidden` 1 716 |

Correttezza, run 2:

| | |
|---|---|
| Dispatch (TTL 2-6) | 5/5 PASS su tutte e tre |
| Gestione TTL (decremento + checksum + scadenza) | 2/2 PASS su tutte e tre |
| `link_state` reroute | PASS, **11/30** casi di link-down cambiano uscita |
| Architetture alternative (65-8-7, 65-4-4-4-7) | 5/5 PASS |
| Multi-modello concorrente (P2 65-6-5-7, P3 65-5-6-4-7) | PASS |
| Aggiornamento modello P1 (ricompila + ricarica) | 1 476 ms |

### Il risultato principale: la dimensione non predice la velocità

**P3 ha il 27% di istruzioni in meno di P2 ed è quasi il doppio più lento** (11 826 contro
16 185 istruzioni; 422 contro 247 ns). Il motivo è nelle due righe centrali: 3 tail call
contro 1, e 28 letture di mappa per pacchetto.

Il conteggio `xlated` misura quanto è grande il programma caricato, non quanto lavoro
fa per pacchetto. A dominare in questo regime sono **lookup e salti**, non l'aritmetica —
ed è visibile solo perché le quattro righe vengono dallo stesso run, sulla stessa
macchina, nello stesso minuto.

`n.d.` sui lookup di P2: contarli richiede di strumentare il programma, e la versione
strumentata sfora il tetto (`Program too large (16497 insns), at most 4096`). È lo stesso
limite del verificatore discusso nelle note oneste, raggiunto da un'altra direzione.

> ⚠️ **Le istruzioni sono un conteggio STATICO, non il percorso eseguito.** Dividere
> 971 istruzioni per 67 ns darebbe ~4.8 istruzioni per ciclo a 3 GHz, sopra il massimo
> pratico su x86 (3-4). Non è una contraddizione: `xlated` misura la dimensione del
> programma caricato, non quante istruzioni girano per pacchetto. In P1 lo switch della
> one-hot `node` ha 52 casi ma ne esegue **uno solo**; inoltre, con i pesi come letterali,
> clang applica strength reduction (i pesi a zero spariscono, quelli potenza di due
> diventano shift). Il percorso dinamico è quindi una frazione delle 971 — ed è
> precisamente il vantaggio strutturale che la hardcoded ha sulle altre due. Vale la pena
> saperlo perché è la prima obiezione naturale davanti a questa tabella.
>
> (La versione precedente di questa nota citava anche uno switch a 6 casi per
> `ingress_iface`. Non c'è più: quella traduzione è una lettura della mappa
> `ingress_port`, perché una tabella compilata di ifindex non corrisponde a nulla su una
> macchina reale.)

### Un lookup in più per pacchetto, misurato

P1 passa da 4.0 a 5.0 letture di mappa per pacchetto e P3 da 26.0 a 28.0: è la mappa
`ingress_port`, che traduce l'ifindex del kernel in porta logica. È il prezzo di rendere
viva una feature che prima non contribuiva nulla, ed è esattamente un lookup.

Nello stesso cambiamento P1 perde 26 istruzioni (997→971): la mappa ha sostituito uno
`switch` a 6 casi letterali, e il lookup costa meno del salto.

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

### P3 non ha più margine di verifica: misurato

`layer_first`, il programma più grande di Pipeline 3, **carica a 9 994 istruzioni**.
Provando a farlo leggere l'indice del nodo da una mappa — invece che dal `model_id` del
pacchetto, come fanno ora P1 e P2 — il verificatore lo ha **rifiutato quattro volte**:

| forma tentata | istruzioni | esito |
|---|---:|---|
| (prima, indice da `model_id`) | 9 994 | carica |
| lookup di mappa dentro `layer_first` | 9 402 | rifiutato |
| valore limitato a un byte | 9 205 | rifiutato |
| risolto nel dispatcher, passato via `scratch_meta` | 9 205 | rifiutato |
| uscita anticipata invece di ternario | 9 176 | rifiutato |

**Ogni versione rifiutata è più piccola di quella che carica.** Non è la dimensione del
programma: è la complessità di verifica, e `layer_first` non ha margine per **un solo
valore tracciato in più**, qualunque forma gli si dia.

Conseguenza, lasciata aperta e non mascherata: su P3 la one-hot del nodo resta guidata dal
`model_id` del pacchetto, quindi con un solo modello registrato ogni nodo accende lo stesso
slot e 52 dei 65 ingressi non portano informazione. È l'**ultimo ingresso su cui le tre
pipeline non concordano**, e il riferimento lo modella esplicitamente invece di ignorarlo.

Chiuderlo richiede di ridurre il corpo srotolato di P3, non di limare la feature.

> Nota sul messaggio d'errore: BCC riporta questo rifiuto come
> `Program too large (N insns), at most 4096 insns`. Il 4096 è una costante vecchia nella
> stringa d'errore di BCC — nello stesso run P2 ha caricato a 15 383 istruzioni. Va letto
> come "il verificatore ha rinunciato", non "il programma è troppo lungo".

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
