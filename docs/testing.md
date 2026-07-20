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

# Più ripetizioni per una latenza più stabile
sudo python3 shared/test/test_suite.py --only kernel --kernel-repeat 200000
```

Output atteso: tabella metriche (istruzioni/jited/tail-call/memoria/latenza/throughput/CPU)
+ `5 PASS / 0 FAIL` per ciascuna pipeline + il probe `link_state reroute` (un link giù cambia
l'uscita) + `kernel suite: PASS`.

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

## Risultati (kernel, `test_suite.py --only kernel`, 4 CPU, modello 65→4→4→7, scale=24)

Aggiornati dopo: IV **descrittore-driven** in P2/P3 (registry `model_desc`), AOT-literal
universale in P1, riga **baseline** (parse + redirect, **nessuna inferenza**) come pavimento.

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
- Latenza/throughput hanno varianza run-to-run non trascurabile sotto `BPF_PROG_TEST_RUN`.
