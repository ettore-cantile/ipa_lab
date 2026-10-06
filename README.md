# IPA Lab — una rete neurale dentro il kernel Linux, con eBPF/XDP

Questo repository esegue una piccola rete neurale **dentro il kernel Linux**, nel
primo punto in cui un pacchetto arriva (XDP), per decidere da quale porta farlo
uscire. È l'implementazione di laboratorio degli **Intelligent PAckets (IPA)**:
il pacchetto porta con sé quale modello usare, e ogni nodo esegue l'inferenza sul
proprio stato locale, senza un piano di controllo che riconfiguri le rotte.

La stessa rete è scritta in **quattro versioni**, da completamente compilata a
completamente configurabile, e il repository misura quanto costa ogni scelta:
per pacchetto, in istruzioni, su traffico vero, e su core di tipo diverso.

> Il lavoro estende il proof-of-concept di Polverini, Cianfrani e Listanti
> (Sapienza Università di Roma / Università del Molise). Il codice della fase
> preliminare è sul branch `ipa-poc-preliminar`.

---

## Indice

1. [I risultati in una tabella](#i-risultati-in-una-tabella)
2. [Le quattro versioni](#le-quattro-versioni)
3. [Com'è fatto il repository](#comè-fatto-il-repository)
4. [Installazione](#installazione)
5. [Primi passi: i test in dieci minuti](#primi-passi-i-test-in-dieci-minuti)
6. [Misurare](#misurare)
7. [Tutti i test](#tutti-i-test)
8. [Usare una pipeline su un'interfaccia](#usare-una-pipeline-su-uninterfaccia)
9. [Come funziona il datapath](#come-funziona-il-datapath)
10. [Altri modelli, altre reti](#altri-modelli-altre-reti)
11. [Documentazione](#documentazione)
12. [Limiti](#limiti)
13. [Riferimenti](#riferimenti)

---

## I risultati in una tabella

Modello 65-4-4-7 (319 pesi), pacchetti da 64 byte, generatore `xdp_gen`, un core
del nodo a 3,5 GHz. Campagna del 6 ottobre 2026, tutti i dati in
[`results/campagna_2026-10-06/`](results/campagna_2026-10-06/) (sintesi in `sintesi.md`).

| | baseline | P1 statica | P1.5 | P2 | P3 |
|---|---:|---:|---:|---:|---:|
| **milioni di pacchetti/s, P-core** | 15,27 | 8,56 | 8,04 | 3,45 | 2,36 |
| ns di CPU per pacchetto | 66 | 117 | 124 | 290 | 425 |
| costo della rete neurale (sopra la baseline) | — | +51 ns | +58 ns | +224 ns | +359 ns |
| istruzioni eseguite per pacchetto | 606 | 1 220 | 1 426 | 4 556 | 6 573 |
| istruzioni per ciclo (IPC), P-core | 2,7 | 3,0 | 3,3 | 4,5 | 4,4 |
| **milioni di pacchetti/s, E-core** | 9,39 | 6,35 | 5,84 | 2,83 | 1,94 |
| E-core rispetto al P-core | 0,61 | 0,74 | 0,73 | 0,82 | 0,82 |
| programma da solo (`BPF_PROG_TEST_RUN`) | 14 ns | 46 ns | 52 ns | 194 ns | 318 ns |

In quattro righe:

- **La configurabilità si paga per pacchetto**: circa 50–60 ns di rete con i pesi
  compilati, 225–360 ns con i pesi letti da tabella.
- **Il collo di bottiglia è il programma**: oltre la capacità i pacchetti si
  perdono all'ingresso, mai dopo il programma; due core reggono il doppio.
- **Su un core lento il codice è lo stesso, l'IPC no**: l'E-core esegue le stesse
  istruzioni ma rallenta soprattutto la parte fissa del nodo, poco la rete neurale.
- **Cambiare modello costa millisecondi a tutte le pipeline**: P1 si compila
  fuori dal nodo e si carica in ~1 ms; P2 e P3 scrivono una tabella in ~10 ms.

---

## Le quattro versioni

Tutte calcolano la stessa rete intera (pesi a 8 bit) e prendono la stessa
decisione sullo stesso pacchetto. Cambia che cosa è scritto nel programma quando
lo si compila e che cosa il programma legge da tabelle (mappe eBPF) mentre gira.

| | **P1 statica** (`p1_static`) | **P1.5** (`hardcoded`) | **P2** (`template`) | **P3** (`modular`) |
|---|---|---|---|---|
| pesi | nel codice | nel codice | in tabella | in tabella |
| identità del nodo | nel codice | in tabella | in tabella | in tabella |
| forma della rete | nel codice | nel codice | in tabella, entro tetti compilati | in tabella |
| numero di strati | nel codice | nel codice | nel codice | in tabella |
| un binario per | nodo | modello | famiglia di architetture | tutto |
| salti fra programmi per pacchetto | 1 | 1 | 1 | 1 + strati |
| cambiare modello | ricompilare (fuori dal nodo) | ricompilare (fuori dal nodo) | scrivere una tabella | scrivere una tabella |

P1 e P1.5 si distribuiscono come **oggetto precompilato (AOT)**: il C con i pesi
dentro si compila con clang su una macchina qualunque, e il nodo carica il file
pronto con un piccolo caricatore statico, senza compilatore. P2 e P3 si compilano
una volta con BCC all'avvio del nodo e poi non si toccano più.

Due programmi di riferimento completano i confronti: **baseline** (legge
l'intestazione, decrementa il TTL e inoltra, senza rete neurale) e **rxonly**
(riceve e butta: il costo della sola ricezione).

---

## Com'è fatto il repository

Tre strati, e la dipendenza punta sempre verso l'alto: il motore non sa niente
della rete su cui si misura.

```
ipa_lab/
├── ipa/                          MOTORE: pipeline, inferenza, piano di controllo
│   ├── execute_pipeline.py       punto d'ingresso: attacca una pipeline a un'interfaccia
│   ├── ebpf_program.py           P1/P1.5: genera il C con i pesi come letterali
│   ├── ebpf_template_arch.py     P2: sorgente eBPF e caricamento dei pesi in tabella
│   ├── ebpf_modular.py           P3: sorgente eBPF, uno strato per programma
│   ├── p1_aot.py                 P1 come oggetto precompilato (build + caricatore)
│   ├── poc_aot/                  generatore del C (gen_full_c.py), loader_aot.c, Makefile
│   ├── methods/                  ingresso per pipeline (usati da execute_pipeline)
│   ├── class_semantics.py        classe → azione → porta logica, dichiarata dal modello
│   ├── node_config.py            porta logica → interfaccia, ifindex e MAC (per nodo)
│   ├── model_meta.py / .json     la scheda del modello: feature, scale, classi, rete
│   ├── model_source.py           carica qualunque modello (checkpoint, sintetico, cartella)
│   ├── pipeline_limits.py        quali forme regge ogni pipeline
│   ├── link_state_monitor.py     stato reale dei collegamenti → mappa link_state
│   ├── queue_state_monitor.py    occupazione delle code → mappa queue_state
│   ├── common.py, stats_maps.py, pinned_maps.py   mappe, attach XDP, contatori per-CPU
│   ├── FRR_model.py, extract_weights.py, label_mapping.py   lato addestramento: .pt → pesi
│   ├── frr_germany50_5_model_4x2.pt, weights.json          il modello addestrato
│   ├── synth/                    generatore di modelli sintetici (scenari generati: non in git)
│   └── test/                     test, banchi di misura, script di campagna (sotto)
│
├── topologies/                   SCENARI: una cartella per rete
│   ├── germany50/                SNDlib Germany50 (la rete del modello addestrato)
│   └── germany50_ttl16/, synth_*/   le reti dei modelli sintetici
│
├── results/                      MISURE: una cartella per campagna
│   └── campagna_2026-10-06/      CSV, condizioni della macchina, sintesi.md
│
└── docs/                         DOCUMENTI (in italiano)
    ├── testing.md                la guida ai test, con tutti i risultati
    ├── claims.md                 ogni affermazione, la sua prova e come rifarla
    ├── september_notebook.tex/.pdf   il quaderno: come funziona e quanto costa
    ├── *.pptx + "- spiegazione.pdf"  le presentazioni, e una spiegazione slide per slide
    ├── slides_src/               build.py e i testi delle spiegazioni
    └── figures/                  i grafici del quaderno
```

`ipa/test/` contiene tre famiglie di file:

| famiglia | file | a che cosa serve |
|---|---|---|
| test senza root | `test_suite.py`, `test_class_semantics.py`, `test_synth.py`, `test_model_source.py`, `test_host_conditions.py`, `test_bitrate_math.py`, `test_steady_window.py`, `p1_c_eval.py` | aritmetica, semantica, modelli sintetici, logica dei banchi |
| test nel kernel | `verify_prog_run.py`, `verify_multi_model.py`, `verify_per_model_semantics.py`, `verify_synth_kernel.py`, `test_fabric.py`, `test_host_kernel.py`, `diag_verifier.py` | i programmi veri caricati nel kernel, il fabric `veth`, la macchina |
| banchi di misura | `bench_throughput.py`, `bench_bitrate.py`, `bench_scaling.py`, `bench_depth_vs_width.py`, `bench_tailcall_overhead.py` | capacità, curve al crescere del traffico, analisi parametrica |
| infrastruttura | `host_conditions.py`, `hw_counters.py`, `xdp_gen.py`, `netns_fabric.py`, `pipeline_setup.py`, `model_under_test.py`, `traffic_models.py`, `campaign_report.py`, `plot_bitrate.py` | condizioni della macchina, contatori hardware, generatore, fabric, modelli |
| campagne | `remeasure_campagna.sh`, `remeasure_all.sh` | rifanno ogni numero dei documenti |

---

## Installazione

Serve **Linux su una macchina vera** (non una macchina virtuale: vedi
[Limiti](#limiti)), con BCC. Su Ubuntu 24.04:

```bash
sudo apt install bpfcc-tools python3-bpfcc linux-headers-$(uname -r) \
                 clang libbpf-dev libelf-dev zlib1g-dev libzstd-dev liblzma-dev \
                 python3-numpy python3-matplotlib python3-networkx
# facoltativo: PyTorch, solo per i test sul checkpoint addestrato (estrazione dei pesi)
pip install --user --break-system-packages torch
```

Niente da scaricare o compilare a parte: il motore compila i programmi eBPF da sé,
contro gli header del kernel che gira. I documenti si rigenerano con
`pdflatex` (quaderno) e con LibreOffice, `pdftoppm` e Chrome (spiegazioni delle
slide; `pip install python-pptx` per modificare le presentazioni).

---

## Primi passi: i test in dieci minuti

Tutti i comandi si lanciano dalla radice del repository.

**1. Senza root** (un minuto): il C di P1 calcola il modello, la semantica delle
classi regge, i modelli sintetici sono coerenti.

```bash
python3 ipa/test/test_synth.py               # 60 controlli, anche il C di P1 valutato dal testo
python3 ipa/test/test_class_semantics.py     # 69 controlli
python3 ipa/test/test_model_source.py        # 62 controlli: modelli, reti, compatibilità
python3 ipa/test/test_suite.py               # estrazione dei pesi e quantizzazione (serve torch)
```

**2. La macchina** (niente root per il primo comando):

```bash
python3 ipa/test/host_conditions.py --show   # tipi di core, piano dei ruoli, condizioni attuali
sudo python3 ipa/test/test_host_kernel.py    # le condizioni si mettono, si misurano e si tolgono
```

**3. Il kernel** (qualche minuto):

```bash
sudo python3 ipa/test/test_suite.py --only kernel   # metriche e decisioni delle quattro pipeline
sudo python3 ipa/test/test_fabric.py                # il pacchetto attraversa davvero un fabric veth
sudo python3 ipa/test/verify_synth_kernel.py --all --n 300   # 8 modelli sintetici, 2 400 decisioni
```

Se questi passano, il repository funziona su quella macchina.

---

## Misurare

### Le condizioni della macchina

Un portatile lasciato a sé stesso cambia frequenza, addormenta i core e mette i
processi dove capita. `host_conditions.py` mette la macchina in condizioni note
per la durata di un banco e le **ripristina** alla fine (anche dopo un errore o
un Ctrl-C):

- nodo, generatore e nodo successivo su **core fisici distinti**, un thread per
  core; il gemello SMT di ognuno, e gli altri tre core del modulo di un E-core,
  restano a riposo;
- **frequenza fissa e misurata** (3,5 GHz di default, verificata con APERF/MPERF);
- stati di sonno profondi spenti, desktop, IRQ e thread del kernel spostati sulle
  altre CPU, un monitor di temperatura e throttling sempre acceso.

I banchi di traffico la applicano da soli; per qualunque altro comando:
`sudo python3 ipa/test/host_conditions.py --run -- <comando>`. Dopo un run ucciso:
`sudo python3 ipa/test/host_conditions.py --restore`.

### Una campagna intera

```bash
bash ipa/test/remeasure_campagna.sh                 # tutto, circa un'ora
bash ipa/test/remeasure_campagna.sh pcore ecore     # solo alcune sezioni
python3 ipa/test/campaign_report.py results/campagna_<data>   # le tabelle di sintesi
```

| sezione | che cosa misura | durata |
|---|---|---:|
| `pcore` | nodo su un P-core: capacità a 1 e 2 core, per classe, per taglia, tre marcature, curve del bit rate | ~12 min |
| `ecore` | lo stesso nodo su un E-core (stessa frequenza) | ~7 min |
| `lpe` | nodo su un LP E-core (2,5 GHz) | ~4 min |
| `assi` | larghezza, profondità, pari pesi, sparsità sotto traffico, su P-core ed E-core | ~22 min |
| `kernel` | tutto quello che non usa traffico vero (`remeasure_all.sh`) | ~15 min |

Tutto finisce in `results/campagna_<data>/`: un CSV per misura, le condizioni
della macchina (`env.csv`, `host_monitor.csv`), i log e `sintesi.md`.

### Una misura sola

```bash
# capacità a massima spinta: nodo sul P-core 6 (oppure --dut-cpus 12 per un E-core)
sudo python3 ipa/test/bench_throughput.py --mode compare --generator xdp --rounds 3 \
    --gen-cpus 10 --dut-cpus 6 --egress-cpu 8 --out results/prova

# il traffico che cresce: dove si perde, e il ritardo
sudo python3 ipa/test/bench_bitrate.py --generator xdp --gen-cpus 10 --dut-cpus 6 \
    --egress-cpu 8 --out results/prova_bitrate

# il programma da solo, al variare della forma della rete
sudo python3 ipa/test/host_conditions.py --run -- \
    python3 ipa/test/bench_scaling.py --axis all --out results/prova_assi
```

### Che cosa si legge

- **Tempo di CPU per pacchetto** (`ns_cpu`): occupazione del core del nodo × 1 /
  pacchetti elaborati, nella stessa finestra stazionaria da 300 ms.
- **Istruzioni, cicli, IPC per pacchetto** (`instr_pkt`, `cycles_pkt`, `ipc`):
  dai contatori hardware del core del nodo (`hw_counters.py`), nella stessa
  lettura. Dicono *perché* un pacchetto costa quello che costa.
- **Dove si perde**: inviati, ricevuti dal programma, inoltrati; se mancano prima
  del programma il collo di bottiglia è il programma, se mancano dopo è la
  trasmissione.

Il generatore è **`xdp_gen`**: consegna al nodo frame XDP grezzi, come una scheda
di rete con XDP nativo, senza la copia che pktgen impone. Un thread per coda del
nodo: più scrittori nella stessa coda si intralciano.

---

## Tutti i test

| comando | root | che cosa verifica | esito atteso |
|---|:---:|---|---|
| `test_suite.py` | no | estrazione dei pesi, quantizzazione | PASS (serve torch) |
| `test_class_semantics.py` | no | classe → azione su cinque schemi di classi | 69/69 |
| `test_synth.py` | no | modelli sintetici; il C di P1 contro il riferimento | 60/60 |
| `test_model_source.py` | no | modelli, reti, compatibilità, limiti delle pipeline | 62/62 |
| `test_host_conditions.py` | no | ruoli, moduli E-core, applicazione e ripristino su un /sys finto | 95/95 |
| `test_bitrate_math.py` | no | formule e attribuzione delle perdite | 100/100 |
| `test_steady_window.py` | no | la finestra stazionaria, con un generatore simulato | 18 (uno sensibile ai tempi) |
| `test_suite.py --only kernel` | sì | metriche, dispatch per TTL, TTL e checksum, reroute | PASS |
| `verify_prog_run.py --method <p>` | sì | verificatore e decisioni di una pipeline | 9/9 |
| `verify_multi_model.py` | sì | più modelli registrati insieme | PASS |
| `verify_per_model_semantics.py` | sì | semantica diversa per modello in P2 e P3 | 53/53 |
| `verify_synth_kernel.py --all` | sì | riferimento intero ed eBPF identici su 8 modelli | 8/8 |
| `test_model_source.py --kernel` | sì | ogni rete × modello × pipeline | 110/110 |
| `test_fabric.py` (`--method aot`, `--sweep`) | sì | consegna su veth, P1 come si distribuisce, cinque topologie | 29/29, 11/11, 34/34 |
| `test_host_kernel.py --bench` | sì | le condizioni sul kernel vero | 25/25 |
| `diag_verifier.py` | sì | statistiche del verificatore, ReLU con e senza salto | — |

Il criterio di correttezza è lo stesso per tutte le pipeline: si eseguono i
programmi veri nel kernel, si richiede un redirect (o uno scarto, se il modello lo
decide) **e** l'incremento del contatore della classe giusta, confrontata con un
riferimento Python intero indipendente che replica la stessa aritmetica.

---

## Usare una pipeline su un'interfaccia

```bash
# una rete di veth su cui attaccare (Ctrl-C la smonta)
sudo python3 ipa/test/netns_fabric.py --n-ports 5 --hold

# una pipeline sull'interfaccia d'ingresso
sudo IPA_IFACE_PATTERN='ipa{i}' python3 ipa/execute_pipeline.py --method template --iface ipain
sudo python3 ipa/execute_pipeline.py --method hardcoded --iface ipain   # P1: l'oggetto AOT
```

`--method` è `hardcoded`, `template` o `modular`; il nodo stampa dal vivo HIT,
MISS e DROP. Quale interfaccia realizza quale porta logica è un fatto del nodo:
`IPA_PORT_MAP="0=ipa0,1=ipa1,4=enp0s3"` (esplicito) o `IPA_IFACE_PATTERN="ipa{i}"`
(per nome). L'attacco è **native** di default, e la modalità davvero in uso si
rilegge dal kernel: un attacco native che fallisce è un errore, non un ripiego
silenzioso su generic. Per togliere un programma rimasto: `sudo ip link set dev
ipain xdp off`.

---

## Come funziona il datapath

```
Ethernet → IP → UDP:9999 → intestazione IPA (model_id)
   │
   ├── vettore d'ingresso, costruito SUL NODO dal descrittore del modello:
   │     link_state (stato dei collegamenti) · ingress_iface (porta d'ingresso)
   │     ttl (normalizzato) · node (identità del nodo) · queue_occupancy
   │
   ├── rete neurale intera (pesi a 8 bit, ReLU senza salti), argmax
   │
   └── classe → azione (FORWARD su una porta logica / DROP / UNUSED)
                → porta logica → interfaccia (mac_table) → bpf_redirect
```

- **Il vettore d'ingresso non viaggia nel pacchetto**: lo costruisce il nodo dal
  proprio stato. Le larghezze vengono dalla rete (`topology_config.json`), il tipo
  e l'ordine delle feature dal modello (`model_meta.json`).
- **La classe non è la porta**: che cosa significa ogni classe lo dichiara il
  modello, quale interfaccia realizza ogni porta lo dichiara il nodo. In P2 e P3
  la tabella classe → azione ha chiave `(model_id, classe)`: modelli con
  significati diversi convivono nello stesso programma.
- **Il TTL entra normalizzato**, come in addestramento (`ttl / 30`): la divisione
  si applica al prodotto con il peso, per non perdere risoluzione. La scala è un
  dato del modello.
- **Il nodo si comporta da router**: decrementa il TTL dopo l'inferenza e
  aggiorna il checksum; un pacchetto che scadrebbe passa allo stack (ICMP Time
  Exceeded).
- **La ReLU non ha salti** (`x & ~(x >> 63)` dietro una barriera per il
  compilatore): con un salto per neurone il verificatore del kernel rifiuterebbe
  P2 oltre due strati.
- **L'intestazione IPA** (21 byte, porta UDP 9999) seleziona il modello con
  `model_id`; i pesi sono caricati dal piano di controllo, non letti dal
  pacchetto.

Il modello depositato è addestrato su **Germany50** (SNDlib): 50 router più due
host, quindi 52 nodi, e grado massimo 6 (Karlsruhe con il suo host). Da lì la
forma: 6 + 6 + 1 + 52 = **65 ingressi**, 7 uscite. Questi numeri stanno in
`topologies/germany50/topology_config.json` e nella scheda del modello, mai nel
motore.

---

## Altri modelli, altre reti

Ogni test e ogni banco accettano `--model` e `--topology`:

```bash
python3 ipa/test/traffic_models.py                    # i modelli degli assi, in ipa/synth/traffic/
sudo python3 ipa/test/test_suite.py --only kernel --model synth:deep
sudo python3 ipa/test/test_fabric.py --model synth:small --topology synth_small
sudo python3 ipa/test/bench_throughput.py --mode compare --generator xdp \
    --model ipa/synth/traffic/depth_3 --out results/depth_3
```

`--model` accetta `checkpoint`, `synth:<preset>` (ipa_like, deep, sparse,
ipa_ttl16, small, mixed, large, ones), una cartella o un altro `.pt`. Il modello
deve stare sulla rete: ogni feature larga quanto la dimensione da cui dipende, la
scala del TTL uguale al TTL iniziale. Altrimenti il test si ferma prima di
compilare e dice perché; una pipeline che non regge la forma è "non applicabile",
non un errore.

---

## Documentazione

| documento | per chi |
|---|---|
| [`docs/testing.md`](docs/testing.md) | la guida completa ai test e ai banchi, con tutte le cifre |
| [`docs/claims.md`](docs/claims.md) | ogni affermazione della tesi: ipotesi, misura, numero, comando per rifarla |
| [`docs/september_notebook.pdf`](docs/september_notebook.pdf) | il quaderno: come funziona e quanto costa, spiegato dall'inizio |
| `docs/Inferenza … eBPF XDP.pptx` + `- spiegazione.pdf` | le slide dei risultati, e la loro spiegazione una alla volta |
| `docs/Test reale su dual boot.pptx` + `- spiegazione.pdf` | il banco su traffico vero e la domanda sul bit rate |

Per rigenerare: `pdflatex docs/september_notebook.tex` (da `docs/`), e
`python3 docs/slides_src/build.py` per i PDF di spiegazione.

---

## Limiti

- **Tutto su una macchina.** Generatore, nodo e nodo successivo sono core dello
  stesso processore collegati da `veth`: niente scheda di rete, niente DMA. Le
  cifre assolute sono di questo percorso a 3,5 GHz; i confronti fra pipeline
  reggono. Una macchina virtuale non va bene: un core virtuale può fermarsi per
  millisecondi, più dei ~170 µs che la coda da 256 posti concede.
- **Il modello non decide sulla destinazione**: le feature non contengono
  l'indirizzo di destinazione. Il TTL limita i giri a vuoto, ma un instradamento
  per destinazione richiede un modello addestrato con quella feature.
- **I pesi non viaggiano nel pacchetto**: li carica il piano di controllo.
- **Reti fino a ~115 nodi** in P2 e P3 (`MAX_N_IN` = 128); oltre si alza il tetto
  e si rimisura.
- **Isolamento a sistema acceso**, non dal boot (`isolcpus`, `nohz_full` non usati).

---

## Riferimenti

- M. Polverini, A. Cianfrani, M. Listanti, *"Intelligent Packets: Embedding Machine
  Learning Models into Network Packets"*, IEEE INFOCOM Workshops ICCN 2026 (sottomesso).
- M. Polverini, *"IPA Prototype"*,
  [github.com/marcopolverini/ipa-prototype](https://github.com/marcopolverini/ipa-prototype), 2026.
- S. Miano, F. Risso, *"Extended Berkeley Packet Filter"*, CNIT Technical Report 06 —
  Network Programmability, 2020.
- S. Orlowski et al., *"SNDlib 1.0 — Survivable Network Design Library"*, Networks,
  vol. 55, no. 3, 2010.
