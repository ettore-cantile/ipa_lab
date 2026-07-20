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
  (`cls_stats[ref_cls] > 0`). Nessun `ctx_in` custom: sotto `BPF_PROG_TEST_RUN` l'`ingress_ifindex`
  di sandbox cade fuori sia dalla `ifindex_table` di P1 sia dal clamp `[1,6]` di P2/P3, quindi tutte
  e tre risolvono a "nessuna iface di ingresso" (`_iface=0`) — il riferimento Python usa `ifindex=0`
  per combaciare, senza bisogno di forzare il contesto.
- **Reroute su guasto**: per ogni TTL e interfaccia `k`, esegue P1 con tutti i link up e poi con
  `link_state[k]=0`, e conferma che l'argmax cambia uscita in almeno un caso.

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

# hardcoded: due backend. Su Kathara (niente clang) usa BCC.
kathara exec frankfurt -- python3 /shared/execute_pipeline.py --method hardcoded --iface eth1 --hardcoded-backend bcc
#   --hardcoded-backend aot (default) = .o prebuilt, richiede clang+libbpf (host/build box, non i nodi Kathara)

# solo verifica del caricamento, senza restare in ascolto
kathara exec frankfurt -- python3 /shared/execute_pipeline.py --method hardcoded --verify-only

# se un XDP resta appeso da un run precedente ("File exists"): staccalo
kathara exec frankfurt -- ip link set dev eth1 xdp off
```

Tutte e tre stampano `HIT | MISS | DROP` dal vivo. Popolano `mac_table` (classe → ifindex +
MAC) e `link_state` da sole all'avvio; non serve un setup separato.

### AOT-literal deploy / bench (P1, host con clang o build box)

```bash
# bench (deploy-cost + perf, via BPF_PROG_TEST_RUN)
sudo python3 shared/methods/method4_hardcoded_aot.py
# deploy LIVE: builda il .o e lo attacca all'interfaccia (resta resident)
sudo python3 shared/methods/method4_hardcoded_aot.py --iface enp0s3
```

Il modello AOT è **build offline** (macchina con clang) → deploy del `.o` prebuilt sul nodo
(nessun clang). Su un nodo senza clang, se `nn_aot_arch.o` è già presente viene riusato.

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

## 9. Traffico reale end-to-end (`bench_live_throughput.py`)

Tutte le metriche di throughput finora (baseline/P1/P2/P3 in tabella, i tier
di `bench_depth_vs_width.py`) sono **derivate** da `BPF_PROG_TEST_RUN`: il
programma gira isolato, senza interrupt di NIC reale, senza driver, senza
contesa di cache con altro traffico. È esattamente il tipo di scarto che la
letteratura sul benchmarking ("Benchmarking Crimes", Heiser, arXiv:1801.02381;
talk USENIX LISA21 di Verizon) segnala: un timer sintetico in-kernel può
divergere silenziosamente da cosa succede quando i pacchetti arrivano
davvero dal cavo. Nuovo script che genera traffico **reale**:

```bash
# sul nodo mittente (es. darmstadt)
python3 shared/test/bench_live_throughput.py --dest-ip 10.0.0.234 --duration 10
python3 shared/test/bench_live_throughput.py --dest-ip 10.0.0.234 --duration 10 --workers 4

# sul nodo ricevente (es. frankfurt), in un'altra shell
# (bpftool NON è installato nelle immagini Kathara di questo lab -- confermato
#  "executable file not found" -- usa bpf_introspect.py, stessa sintassi bpf() raw)
kathara exec frankfurt -- python3 /shared/bpf_introspect.py pkt_stats 3
```

**Onestà sui limiti**: è un sender Python, aspettati decine di migliaia di
pkt/s al massimo, non i milioni di pkt/s che `BPF_PROG_TEST_RUN` deriva. Il
confronto che conta è **relativo** (l'ordine P1/P2/P3 regge sotto consegna
reale?), non il numero assoluto di pkt/s. Usa un socket UDP connesso in un
loop stretto (non `scapy.send()` per pacchetto come `test_ipa.py`, che nella
sessione ha misurato ~28-200 pkt/s — troppo lento per un vero test di
throughput). **Importante**: `--dest-ip` deve essere l'IP reale
dell'interfaccia direttamente connessa del ricevente (il vicino su quel
link), non il suo hostname/loopback — il fabric Kathara non instrada
UDP:9999 fino al loopback (sez. 5).

### Profiling con contatori hardware — provato, non disponibile in questo lab

La letteratura (talk USENIX LISA21) raccomanda `bpftool prog profile` per cicli/cache-miss/
branch-miss. **Provato e non disponibile**: `bpftool` non è installato nelle immagini
Kathara di questo lab (`exec: "bpftool": executable file not found in $PATH`, confermato
in sessione — non solo il subcomando `prog profile`, il binario stesso manca). Non è un
limite di PMU/virtualizzazione, è proprio assente dal filesystem del container. Per
usarlo servirebbe una immagine Kathara custom con `bpftool` installato (fuori scope) —
altrimenti questa via resta chiusa in questo ambiente.

---

## 10. Architetture alternative dentro `test_suite.py --only kernel`

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

## 11. Reroute su guasto REALE (`test_frr_linkstate.py`)

Il probe "link_state reroute" esistente (sez. 2) scrive **direttamente nella mappa**
`link_state[k]=0` — non tocca mai un'interfaccia reale, il rilevamento di carrier, o il
thread `link_state_monitor` che dovrebbe tenerli allineati. Nuovo script che orchestra
**da fuori Kathara** (host, via `kathara exec`) un guasto vero mentre la pipeline è
attaccata dal vivo e c'è traffico reale (`bench_live_throughput.py`, sez. 9):

```bash
python3 shared/test/test_frr_linkstate.py \
    --switch frankfurt --ingress-iface eth1 --fail-iface eth2 \
    --sender darmstadt --method template --model-id 0

# vedi la sequenza esatta di comandi senza eseguirla:
python3 shared/test/test_frr_linkstate.py --switch frankfurt --ingress-iface eth1 \
    --fail-iface eth2 --sender darmstadt --dry-run
```

Sequenza: attacca la pipeline dal vivo → avvia il flood reale → snapshot `cls_stats` →
abbatte **davvero** `--fail-iface` (`ip link set down`) → aspetta il polling
(`link_state_monitor`) → nuovo snapshot → confronta i delta per classe (la classe
dell'interfaccia guasta deve fermarsi, le altre devono crescere) → ripristina tutto.

Legge `cls_stats*` via `shared/bpf_introspect.py` (syscall `bpf()` raw, niente `bpftool`
— assente da questa immagine Kathara, vedi sez. 9). `--n-classes` deve combaciare con
`n_out` del modello registrato (default 7).

**Onestà**: non misura un tempo di failover in stile SLA, solo se il reroute avviene
entro un intervallo di polling. Se il verdetto sembra sbagliato, `--dry-run` stampa ogni
comando singolarmente per rifarlo a mano e ispezionare `bpf_introspect.py` manualmente.

---

## Risultati (kernel, `test_suite.py --only kernel`, 4 CPU, modello 65→4→4→7, scale=24)

Aggiornati dopo: IV **descrittore-driven** in P2/P3 (registry `model_desc`), AOT-literal
universale in P1, riga **baseline** (parse + redirect, **nessuna inferenza**) come pavimento.

⚠️ **Numeri sotto = metodologia a singolo campione (obsoleta)**: catturati prima del fix
min-su-N-trial (sez. 2). Latenza/throughput qui possono differire 2-5× da un run reale con
la metodologia corretta — rilancia `sudo python3 shared/test/test_suite.py --only kernel`
(default ora min-su-7-trial) e sostituisci questa tabella con i nuovi numeri prima di
usarla in tesi. Istruzioni/jited/tail-call/memoria non dipendono da `BPF_PROG_TEST_RUN`
quindi restano validi.

| Metrica                    | baseline | P1 hardcoded | P2 template | P3 modular |
|----------------------------|---------:|-------------:|------------:|-----------:|
| Istruzioni eBPF (xlated)   |      113 |          980 |      16 988 |     15 767 |
| Codice jited (byte)        |      542 |        4 684 |      84 587 |     76 376 |
| Tail calls / pacchetto     |        0 |            1 |           1 |          3 |
| Map lookup / pacchetto (reali) |    0 |          4.0 |       147.0 |      160.0 |
| Memoria mappe (byte)       |      280 |          308 |       8 052 |     16 884 |
| Latenza (ns/pacchetto)     |     29.0 |         77.0 |       523.0 |    1 030.0 |
| Throughput (Mpps)          |   34.483 |       12.987 |       1.912 |      0.971 |
| CPU (%)                    |       39 |           59 |          80 |         82 |
| Dispatch (correttezza)     |        — |     10/10 PASS |   5/5 PASS |   5/5 PASS |
| link_state reroute         |          | PASS (5/30 casi cambiano uscita) |||

### Baseline vs hardcoded (la domanda "perché l'hardcoded è così veloce?")

Il **baseline** riceve il pacchetto in XDP, fa lo stesso parse del dispatcher e un
`bpf_redirect` — **niente tail-call, niente MLP**. È il *pavimento* del framework:
**29 ns / 34.5 Mpps**. L'hardcoded (**77 ns**) aggiunge ~48 ns per tail-call + double-parse +
la rete. Quindi l'hardcoded **non** è sospettosamente veloce: è **2.6× più lento** del
do-nothing. Il throughput alto è il pavimento XDP+parse+redirect; la rete int8 65-4-4-7
unrolled costa poco in confronto.

### AOT-literal deploy (P1, `method4_hardcoded_aot.py`)

| | valore |
|---|---:|
| open_file | 0.27 ms |
| load (verify+JIT) | 4.40 ms |
| **deploy totale** | **4.66 ms** |
| BCC ricompila lo stesso modello | ~1660 ms |
| perf: insn (disp 28 + model 982) | 1010 |
| perf: latenza / throughput | 90 ns / 11.1 Mpps |

Perf ≈ BCC hardcoded (varianza run-to-run): l'AOT preserva il massimo literal, ma sposta
`clang` **offline** → deploy sul nodo ~4.7 ms invece di ~1660 ms.

### Costo di aggiunta modello (`bench_model_add.py`, 3 modelli)

| pipeline | add medio (ms) | come |
|---|---:|---|
| hardcoded | 1435.8 | ricompilazione completa (clang = 99.7%) |
| template | 4.9 | solo `bpf_map_update_elem` |
| modular | 8.4 | solo `bpf_map_update_elem` |

Hardcoded ~294× più lento di template, ~172× di modular. L'AOT stima ~4 ms di load →
**~341× più economico** del BCC, **senza perdita di perf**.

### Multi-model (`verify_multi_model.py`) — regge shape custom

`model_desc` popolato correttamente anche per shape non-default: P2 `model_id=1` = 65-**6-5**-7,
P3 `model_id=1` = 65-**5-6-4**-7 (4 layer). Tutti PASS.

## Note oneste

- **Ordine design-space confermato**: costo (istruzioni, jited, tail call, lookup, memoria)
  cresce monotono baseline→P1→P2→P3; le prestazioni calano nello stesso ordine.
- **Costo della flessibilità IV runtime (Task 3)**: rendere P2/P3 descrittore-driven ha
  aumentato il loro conteggio istruzioni (P2 template ~2 618→16 988, latenza 125→523 ns): il
  loop generico per-feature unrolled (`MAX_FEAT` × neuroni × dense) pesa. È il prezzo della
  flessibilità a runtime, coerente con la posizione di P2/P3 (flessibilità > velocità).
- **P1 = meno memoria mappe** (308 B): nessun `model_cache`, solo contatori + `link_state`.
- **Inferenza identica** nelle 3 pipeline (stesso MLP/pesi/argmax): verificata dal match di
  classe kernel vs riferimento Python (10/10 e 5/5 PASS).
- **Azione uniforme (`mac_table`)**: `argmax → mac_table[classe] → bpf_redirect`.
- **Nessun `ctx_in` custom**: sotto `BPF_PROG_TEST_RUN` l'`ingress_ifindex` di sandbox cade
  fuori dalla `ifindex_table` di P1 e dal clamp `[1,6]` di P2/P3 → tutte risolvono `_iface=0`.
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
