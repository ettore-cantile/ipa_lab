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
+ `5 PASS / 0 FAIL` per ciascuna pipeline + `kernel suite: PASS`.

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

Popolamento tabella di forwarding (se richiesto dalla pipeline):

```bash
kathara exec frankfurt -- python3 /shared/setup_fwd_table.py --model-id 0 --method hardcoded
```

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
| Istruzioni eBPF (xlated)   |        1 095 |       2 897 |     13 645 |
| Codice jited (byte)        |        5 132 |      12 575 |     58 146 |
| Tail calls / pacchetto     |     0 (leaf) |           1 |          3 |
| Map lookup / pacchetto (stima) | 8 (0 pesi) |         322 |        384 |
| Memoria mappe (byte)       |          264 |      15 796 |     28 468 |
| Latenza (ns/pacchetto)     |       1109.0 |       339.0 |     1291.0 |
| Throughput (Mpps)          |        0.902 |       2.950 |      0.775 |
| CPU (%)                    |           60 |          48 |         79 |
| Dispatch (TTL 1–5)         |    5/5 PASS  |   5/5 PASS  |  5/5 PASS  |

Misurate con `test_suite.py --only kernel` (4 CPU, scale 24) dopo l'aggiunta di `link_state` reale
e la rimozione di `model_cache`.

Note oneste:
- **P2 è il più veloce** (339 ns): l'inferenza via lookup sparsi su `BPF_ARRAY` costa meno del grande `switch` a 52+6 rami del P1 hardcoded.
- **P1 hardcoded puro = meno memoria mappe** (264 B): nessun `model_cache` (prima erano 83 KB, il 99% del totale), restano solo i contatori + la map `link_state` a 6 slot.
- Costo del popolamento `link_state`: P1 +38 istruzioni, P2 +~930 (loop a 6 lookup srotolato sui 4 neuroni fc1), P3 +157.
- Tail-call P1 = 0 perché sotto TEST_RUN si esegue direttamente il leaf `ipa_switch` (il dispatcher aggiungerebbe 1 salto).
- Istruzioni, jited e tail-call crescono con la flessibilità: è il costo strutturale del design modulare (P3 ≈ 12× le istruzioni di P1).
- `link_state[0..5]` = stato up/down delle 6 interfacce egress (segnale fast-reroute), letto dalla map condivisa. Aggiornato dal monitor carrier userspace.
- Latenza/throughput hanno varianza run-to-run non trascurabile sotto `BPF_PROG_TEST_RUN`.
