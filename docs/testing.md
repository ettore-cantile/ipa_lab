# Guida ai test — IPA/eBPF design space

Tre pipeline (P1 hardcoded, P2 template, P3 modular) verificate su due piani:

- **userspace** (numerico, PyTorch/NumPy) — accuratezza, quantizzazione, robustezza, struttura;
- **kernel** (`BPF_PROG_TEST_RUN` sui programmi XDP reali) — istruzioni eBPF, latenza, throughput, CPU, memoria mappe + dispatch reale.

Tutto è raccolto in un unico script: `shared/test_suite.py`.

---

## 1. Test locali (userspace) — nessun root, nessun kernel eBPF

Richiede solo `torch` + `numpy`. Girano ovunque (anche fuori da Kathara).

```bash
cd shared

# Tutte le suite (la suite kernel viene saltata se non c'è BCC/root)
python3 test_suite.py

# Una singola suite
python3 test_suite.py --only core       # struttura design-space + update latency
python3 test_suite.py --only quant       # accuratezza argmax vs scale_factor
python3 test_suite.py --only pktstats    # HIT/FAKE/MISS per pipeline
python3 test_suite.py --only extract     # coerenza pesi / weights.json / dequant
python3 test_suite.py --only robust      # input anomali, nessun crash

# Opzioni
python3 test_suite.py --only quant --samples 500
python3 test_suite.py --model shared/frr_germany50_5_model_4x2.pt --verbose
```

---

## 2. Test nel kernel (`--only kernel`) — richiede Linux + BCC + root

Carica i tre programmi XDP reali ed esegue `BPF_PROG_TEST_RUN`. Misura le metriche
del design space direttamente dal kernel e verifica il dispatch (redirect) per ogni TTL.

```bash
# Su host Linux con BCC installato
sudo python3 shared/test_suite.py --only kernel

# Dentro Kathara (nodo frankfurt)
kathara exec frankfurt -- python3 /shared/test_suite.py --only kernel

# Solo metriche, senza il gate di dispatch
sudo python3 shared/test_suite.py --only kernel --no-verify

# Più ripetizioni per una latenza più stabile
sudo python3 shared/test_suite.py --only kernel --kernel-repeat 200000
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
kathara exec frankfurt -- python3 /shared/verify_prog_run.py --method hardcoded
kathara exec frankfurt -- python3 /shared/verify_prog_run.py --method template
kathara exec frankfurt -- python3 /shared/verify_prog_run.py --method modular
kathara exec frankfurt -- python3 /shared/verify_prog_run.py --method modular --model-id 3
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

```bash
# sul nodo che fa da switch (es. frankfurt)
kathara exec frankfurt -- python3 /shared/execute_pipeline.py --method hardcoded --iface eth1 --model-id 0
kathara exec frankfurt -- python3 /shared/execute_pipeline.py --method template  --iface eth1 --model-id 0
kathara exec frankfurt -- python3 /shared/execute_pipeline.py --method modular   --iface eth1 --model-id 0

# solo verifica del caricamento, senza restare in ascolto
kathara exec frankfurt -- python3 /shared/execute_pipeline.py --method hardcoded --verify-only
```

Le pipeline popolano `mac_table` (class → ifindex + MAC) da sole all'avvio; non serve uno
step separato di setup della tabella di forwarding.

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
kathara exec darmstadt -- python3 /shared/test_ipa.py --dest frankfurt --count 100 --model-id 0
```

---

## Risultati (kernel, TTL 1–5, modello 65→4→4→7, scale=24)

| Metrica                    | P1 hardcoded | P2 template | P3 modular |
|----------------------------|-------------:|------------:|-----------:|
| Istruzioni eBPF (xlated)   |          996 |       2 668 |     13 645 |
| Codice jited (byte)        |        4 658 |      12 575 |     58 146 |
| Tail calls / pacchetto     |     0 (leaf) |           1 |          3 |
| Map lookup / pacchetto (stima) | 8 (0 pesi) |         322 |        384 |
| Memoria mappe (byte)       |          264 |      15 796 |     28 468 |
| Latenza (ns/pacchetto)     |         72.0 |       287.0 |     1274.0 |
| Throughput (Mpps)          |       13.889 |       3.484 |      0.785 |
| CPU (%)                    |           58 |          61 |         80 |
| Dispatch (TTL 1–5)         |    5/5 PASS  |   5/5 PASS  |  5/5 PASS  |
| link_state reroute         |         PASS (5/30 casi cambiano uscita) |||

Misurate con `test_suite.py --only kernel` (4 CPU, scale 24) dopo l'aggiunta di `link_state` reale
e la rimozione di `model_cache`.

Note oneste:
- **P1 hardcoded è il più veloce** (72 ns, 13.9 Mpps), il più compatto (264 B, 996 istr) e senza tail call né lookup pesi: massime prestazioni, minima flessibilità. **P3 modular** all'opposto (1274 ns, 3 tail call, ~28 KB). **P2 template** nel mezzo (287 ns). Ordine coerente con la tassonomia.
- Ogni metrica di costo (istruzioni, jited, tail call, map lookup, memoria) cresce monotona P1→P2→P3; le prestazioni di picco calano nello stesso ordine.
- **P1 = meno memoria mappe** (264 B): nessun `model_cache` (prima 83 KB, il 99%), restano solo i contatori + `link_state` a 6 slot.
- **Confronto pulito**: P1 è sceso da 1109 a 72 ns dopo aver rimosso 3 `bpf_trace_printk` per pacchetto dal path HIT (helper costoso, assente in P2/P3) che falsavano il baseline.
- **Inferenza identica** nelle 3 pipeline (stesso MLP, stessi pesi, stesso argmax): verificata dal check di corrispondenza di classe (classe kernel = classe riferimento Python). Differiscono solo per *come* calcolano l'inferenza.
- **Azione uniforme (mac_table)**: tutte fanno `argmax → mac_table[classe] → bpf_redirect`. La NN decide la porta; `mac_table` è un dizionario `classe → {ifindex, MAC}` (in P1 hardcoded in uno `switch`, 0 lookup). Rimossa la vecchia `fwd_table` indicizzata dal valore + validazione per-TTL (`valid_keys`).
- **P2/P3 da rimisurare**: istruzioni e soprattutto memoria mappe calano (hash 256 slot → 8 slot). Rieseguire `--only kernel`.
- `link_state[0..5]` = stato up/down delle 6 interfacce egress (segnale fast-reroute), letto dalla map condivisa; aggiornato dal monitor carrier. Il probe conferma che un link giù cambia l'uscita (5/30 casi).
- Latenza/throughput hanno varianza run-to-run non trascurabile sotto `BPF_PROG_TEST_RUN`.
