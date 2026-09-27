# Registro delle affermazioni sperimentali

Una riga della tesi che afferma qualcosa di misurabile deve poter essere
rintracciata fino all'esperimento che la sostiene. Questo documento è quella
mappa: per ogni affermazione, l'ipotesi, che cosa è stato mosso, che cosa è stato
tenuto fermo, che cosa è stato misurato, il numero ottenuto e il comando per
rifarlo.

**Tutte le cifre sono del 2026-09-27**, sulla macchina di laboratorio (Intel Core
Ultra 7 155H, Ubuntu 24.04, kernel 6.8.0-100, bare metal) nelle condizioni di
`host_conditions.py`: core del banco fissi a **3 500 MHz misurati**, isolati, senza
C6/C10 (`docs/testing.md` §0). Si rifanno tutte con

```bash
bash ipa/test/remeasure_all.sh       # BPF_PROG_TEST_RUN, correttezza, analisi parametrica
bash ipa/test/remeasure_traffic.sh    # traffico vero, semantica, soffitti, topologie
```

(log in `/tmp/ipa_logs/`, `$IPA_LOG_DIR` per cambiarlo). Dove una scheda cita un altro comando, è quello.

**Stato**:

| | |
|---|---|
| ✅ | misurato sul codice corrente, dati riportati |
| ⚠️ | l'affermazione è sostenuta solo in parte; il limite è dichiarato nella scheda |

**Regola che questo registro applica a sé stesso**: nessuna conclusione poggia su
una sola configurazione. Dove un'affermazione ha un solo punto sperimentale, la
scheda lo dice.

---

## A. Semantica e correttezza

### A1 — La semantica delle classi è dichiarata, mai dedotta ✅

| | |
|---|---|
| **Ipotesi** | Il datapath non deve ricavare che cosa significhi una classe da formule tipo `DROP = n_out - 1` o `n_out = n_interfacce + 1`: dedurle è vero per caso solo sul modello depositato. |
| **Variabile modificata** | Il descrittore del modello: `n_out` e `class_semantics` dichiarati contro assenti. |
| **Variabili fisse** | Pesi, topologia, pipeline. |
| **Metrica** | La classe scelta, e la porta logica su cui il pacchetto esce. |
| **Risultato** | Sul modello depositato `n_out=7`, `drop_class=5`, e la classe 6 è `UNUSED`. Le formule dedotte darebbero `drop=6`: installerebbero un next-hop per la classe DROP e tratterebbero come inoltro una classe non addestrata. `test_class_semantics`: 69/69 su cinque layout di classi. |
| **Conclusione** | La catena classe → azione → porta logica → interfaccia è letta da mappe riempite dal descrittore. |
| **Come rigirarlo** | `python3 ipa/test/test_class_semantics.py`; la sezione `class_action` di `--only kernel`; A7 per la semantica distinta per modello. |

### A2 — Il datapath consegna pacchetti veri, non solo aritmetica ✅

| | |
|---|---|
| **Ipotesi** | Un test che confronta logit con un riferimento non dimostra che il pacchetto esca dal nodo. |
| **Variabile modificata** | Il banco: un fabric `veth` con XDP **native** e `bpf_redirect` reale. |
| **Variabili fisse** | Modello, pesi, descrittore. |
| **Metrica** | Pacchetto catturato sull'interfaccia d'uscita; DROP letto dal contatore `cls_stats`, non dal silenzio. |
| **Risultato** | `test_fabric`: **29/29**, tutte e tre le pipeline, 6 classi su 7 (la settima è `UNUSED`). La P1 **come si deploya** (oggetto AOT, `loader_aot`, mappe pinnate riempite dal piano di controllo prima dell'attach): `--method aot` **11/11** — `mac_table` riletto dopo il deploy con gli ifindex del fabric, le 5 classi FORWARD escono dalla porta attesa, la DROP è contata e nulla esce, loader staccato con rc=0 e pin rimossi. |
| **Conclusione** | Consegna, non solo inferenza, anche per il binario che va sui nodi. |
| **Come rigirarlo** | `sudo python3 ipa/test/test_fabric.py`; `--method aot` |

### A3 — Il motore non dipende dalla topologia ✅ ⚠️

| | |
|---|---|
| **Ipotesi** | Il codice funziona su Germany50 perché Germany50 è l'unica topologia mai provata. |
| **Variabile modificata** | La topologia: scenari sintetici (3/8, 4/16, 5/24, 2/6, 6/52 porte/nodi). |
| **Variabili fisse** | Le tre pipeline, il meccanismo di inferenza. |
| **Metrica** | Generazione, caricamento e consegna su ciascuna. |
| **Risultato** | **34/34** controlli sulle cinque topologie più lo scenario principale. |
| **Conclusione** | Nessuna dimensione di scenario è cablata nel motore. |
| **Limite dichiarato** | ⚠️ Lo sweep varia solo il TTL con tutti i link attivi, quindi esercita **una classe per topologia**. La copertura su tutte le classi c'è nello scenario singolo (A2). |
| **Come rigirarlo** | `sudo python3 ipa/test/test_fabric.py --sweep` |

### A4 — Congelare l'indice del nodo non cambia la decisione ✅

| | |
|---|---|
| **Ipotesi** | La P1 specializzata sceglie una colonna della matrice del primo layer a tempo di compilazione; se fosse la colonna sbagliata, il programma sarebbe più piccolo, più veloce e calcolerebbe **un altro modello**, e nessuna misura di costo se ne accorgerebbe. |
| **Variabile modificata** | Da dove arriva l'indice del nodo: costante compilata contro mappa `node_id`. |
| **Variabili fisse** | Pesi, descrittore, topologia, indice del nodo (7 in entrambe). |
| **Metrica** | La classe scelta e il valore di ritorno XDP. |
| **Risultato** | **80/80** casi identici (TTL 2-11 × 8 configurazioni di link). |
| **Conclusione** | Congelare il nodo cambia il codice, non la decisione: è il prerequisito di ogni numero della colonna `p1_static`. |
| **Come rigirarlo** | `sudo python3 ipa/test/bench_scaling.py --verify` |

### A5 — L'equivalenza numerica vale anche sui modelli sintetici ✅ ⚠️

| | |
|---|---|
| **Ipotesi** | Le pipeline calcolano esattamente il riferimento intero anche su modelli che non sono quello depositato. |
| **Variabile modificata** | Il modello: scenari sintetici (`deep`, `ipa_like`, `ipa_ttl16`, `large`, `mixed`, `ones`, `small`, `sparse`), pesi casuali, forme da 11-2-3 a 117-8-8-9, scala del TTL dichiarata dal modello. |
| **Variabili fisse** | Il descrittore di ciascuno scenario, 300 ingressi per scenario con seme fisso. |
| **Metrica** | Accordo fra argmax del riferimento intero (`synth.reference`, scala dichiarata dal modello) e dell'eBPF nel kernel. |
| **Risultato** | **P1: 8/8** scenari a 300/300. **P3: 7/7** a 300/300 (`large` non applicabile: 9 uscite, limite 8). **P2: 6/7** a 300/300; `large` non applicabile (1 097 pesi, blocco da 1 024) e **`deep` rifiutato dal verificatore** (`E2BIG`, vedi C9). La scala dichiarata diversa da 30 sposta davvero le decisioni su `ipa_ttl16` (41/300) e `small` (89/300). Controllo negativo: riscritto il solo byte `feat_ent.scale` al default, l'eBPF segue il riferimento al default su 300/300 e si stacca da quello dichiarato **esattamente** sui 41 casi previsti, quindi il kernel legge quel byte. |
| **Conclusione** | L'aritmetica del datapath è esatta su ogni scenario che la pipeline carica. |
| **Limite dichiarato** | ⚠️ `ones` e `large` non muovono la scala: il loro 100% non dice niente su di lei. |
| **Come rigirarlo** | `sudo python3 ipa/test/verify_synth_kernel.py --all --n 300` (`--pipeline p2` / `p3`); `--dry-run` senza kernel confronta anche il C di P1 valutato dal sorgente; `python3 ipa/test/test_synth.py` |

### A6 — Non generare le colonne delle porte assenti non cambia la decisione ✅

| | |
|---|---|
| **Ipotesi** | Un nodo di grado 3 ha `link_state[3..5]` permanentemente a zero: quelle interfacce **non esistono**. Togliere quelle colonne dal primo layer di P1 deve essere esatto, non approssimato. |
| **Variabile modificata** | `static_ports`: quali colonne di `link_state` P1 genera. Il nodo è congelato in **entrambe** le build. |
| **Variabili fisse** | Pesi, descrittore, topologia, `n_in`, offset dei pesi, indice del nodo. |
| **Metrica** | La classe scelta e il valore di ritorno XDP, su tutti i pattern di link realizzabili × TTL 2-11. |
| **Condizione dichiarata** | Vale finché gli slot senza interfaccia valgono 0, e lo garantisce `link_state_monitor` (`carrier_state()` ritorna 0 per un'interfaccia inesistente). Non vale sotto `verify_prog_run._seed_link_state`, che semina 1 ovunque: il test azzera gli slot assenti nel riferimento. |
| **Controllo negativo** | Accendendo uno slot assente le due build **devono** divergere; altrimenti «concordano» sarebbe vero anche per una specializzazione sbagliata. Il test cerca fra più semi del pool e fallisce se nessuno morde. |
| **Risultato** | **80/80** casi identici (porte {0,1,4}); accendendo uno slot assente le build divergono in **29** casi (seme 123). |
| **Conclusione** | Cambia il codice, non la decisione: prerequisito di ogni numero dell'asse `degree` (C7). |
| **Come rigirarlo** | `sudo python3 ipa/test/bench_scaling.py --verify-ports` |

### A7 — Ogni modello ha la sua semantica, senza un programma per modello ✅ ⚠️

| | |
|---|---|
| **Ipotesi** | In P2 e P3 modelli con significati diversi per la stessa classe possono convivere nello **stesso** programma caricato, senza contaminarsi e senza costo misurabile per pacchetto. |
| **Variabile modificata** | La chiave della tabella classe → azione: classe sola (albero `16f1a024^`) contro `(model_id, banco, classe)`, in un `BPF_ARRAY` di 256 × 2 × 32 righe. Il banco attivo sta nell'entry del registry: ricaricare un modello scrive il banco inattivo e un solo update installa insieme `n_out` e banco. |
| **Variabili fisse** | Inferenza, pesi, descrittori, un programma per architettura, 21 trial. |
| **Metrica** | Azione prodotta per ogni classe di ogni modello; istruzioni, JIT, lookup, tail call, memoria, latenza. |
| **Risultato** | **53/53** su P2 e P3: un modello; due con la stessa semantica; due con semantiche diverse su ogni classe a pacchetti alternati; A → B → A anche dopo aver ricaricato B; `model_id` inesistente o rimosso non elaborato; `n_out` 4 e 7 insieme; stesso `model_id` ricaricato con altra semantica e altro `n_out`. **Costo**: istruzioni P2 −9, P3 +41; lookup (11, 29) e tail call invariati; latenza minima P2 192 → 191 ns, P3 325 → 319 ns; da 1 a 8 modelli P2 188–194 ns, P3 316–319 fino a 4 modelli e 340 con 8; **memoria +131 072 byte per pipeline**, fissi. |
| **Controllo negativo** | Con una tabella condivisa simulata A e B passano e C, D, F, R falliscono. |
| **Perché non dentro il registry** | Indicizzare il valore dell'entry con `best_cls` obbliga il verificatore a tracciare `best_cls` con precisione attraverso l'argmax: `layer_hidden` di P3 non carica (`E2BIG`). Una chiave sullo stack no. |
| **Limite dichiarato** | ⚠️ I 128 KiB sono riservati per 256 modelli anche con un modello solo; l'alternativa a pochi KB (slot allocato dal piano di controllo) non è implementata. Il +6% di P3 con 8 modelli è un solo punto e non è spiegato. |
| **Come rigirarlo** | `sudo python3 ipa/test/verify_per_model_semantics.py`; `bench_semantics_models.py --baseline-dir <worktree di 16f1a024^>/ipa --trials 21` (lo prepara `remeasure_traffic.sh`) |

---

## B. Il costo della flessibilità

La scala ha **quattro** gradini: sotto la P1 del progetto (qui P1.5, pesi compilati,
nodo da mappa) c'è una P1 pienamente specializzata (pesi **e** nodo compilati).

### B1 — Rendere le feature configurabili a runtime costa latenza ✅

| | |
|---|---|
| **Ipotesi** | Più cose si decidono a runtime invece che a compile time, più costa per pacchetto. |
| **Variabile modificata** | Quanto è noto alla compilazione: P1 specializzata → P1.5 → P2 (soffitti) → P3 (anche la profondità). |
| **Variabili fisse** | Modello 65-4-4-7, topologia Germany50, descrittore, stesso run. |
| **Metrica** | Latenza minima su 7 trial, istruzioni eBPF, tail call, letture di mappa. |
| **Risultato** | `test_suite`: baseline **22**, P1.5 **47**, P2 **199**, P3 **323 ns**; istruzioni 155 / 989 / 14 969 / 12 318; letture 3 / 6 / 11 / 29; salti 0 / 1 / 1 / 3; spread 2–5%. Analisi parametrica (pesi sintetici): P1 specializzata **36**, P1.5 43, P2 184, P3 308 ns. |
| **Conclusione** | **La flessibilità costa circa 9× in latenza** fra i due estremi, e il costo non è aritmetico: è in letture di mappa e salti fra programmi. |
| **Come rigirarlo** | `sudo python3 ipa/test/test_suite.py --only kernel`; `bench_scaling.py --out results/` |

### B2 — Aggiornare il modello: con l'oggetto precompilato il divario sparisce ✅

| | |
|---|---|
| **Ipotesi** | Compilare i pesi dentro il codice sposta il costo dal pacchetto al deployment. |
| **Variabile modificata** | La pipeline, su tutti gli assi dello sweep. |
| **Metrica** | `update_ms` (installare un modello nuovo su un nodo in servizio) e `build_ms` (compilazione). |
| **Risultato** | `update_ms`: P1 e P1.5 **0,9–2,3 ms** (caricamento dell'oggetto AOT), P2 e P3 **10–12 ms** (scritture in mappa). `build_ms`: P1 66–113 ms (clang, sulla macchina di build), P2 ~1,6 s e P3 ~1,3 s (BCC, una volta all'avvio del nodo). Ricompilare P1 con BCC sul nodo costa invece 76 ms per modello contro 0,4–0,5 ms di una `bpf_map_update_elem` (`bench_model_add`). |
| **Conclusione** | Il costo di P1 è della **compilazione**, non dei pesi letterali: con l'oggetto precompilato aggiornare P1 non costa più di aggiornare P2/P3. Resta la differenza qualitativa: P1 richiede un compilatore (fuori dal nodo) per ogni modello nuovo, P2 e P3 no. |
| **Nota metodologica** | `build_ms` e `update_ms` non vanno confusi: per P2/P3 il primo è pagato una volta all'avvio del nodo, il secondo per modello. |
| **Come rigirarlo** | `bench_scaling.py --out results/` (figura `scaling_depth_update`); `bench_model_add.py --n-models 3` |

### B3 — L'AOT toglie il compilatore dal nodo senza costo per pacchetto ✅

| | |
|---|---|
| **Ipotesi** | Compilare l'oggetto fuori dal nodo elimina clang dal nodo, e la strength reduction sui pesi letterali sopravvive dentro l'oggetto. |
| **Variabile modificata** | Dove avviene la compilazione: macchina di build (clang, 76,5 ms) contro nodo. |
| **Metrica** | Costo di messa in servizio; latenza per pacchetto. |
| **Risultato** | Deploy dell'oggetto sul nodo **1,16 ms** (`open` 0,08 + verifica e JIT 1,08); latenza **47 ns** sul percorso d'inoltro (retval 4), la stessa di `test_suite`; 989 istruzioni (dispatch 29 + modello 960). Throughput reale P1.5: C1, E1. |
| **Conclusione** | Il nodo non ha bisogno di un compilatore, e il binario che ci va costa per pacchetto come quello misurato ovunque in questo registro (tutte le cifre di P1 e P1.5 sono dell'oggetto AOT). |
| **Come rigirarlo** | `sudo python3 ipa/methods/method4_hardcoded_aot.py` |

---

## C. Che cosa costa, e che cosa no

### C1 — La dimensione del programma non predice la velocità ✅

| | |
|---|---|
| **Ipotesi** | Le istruzioni eBPF sono un proxy del costo per pacchetto. **Falsa.** |
| **Variabile modificata** | La pipeline (P2 contro P3); il soffitto `IPA_MAX_QUEUES` di P3. |
| **Metrica** | Istruzioni contro latenza, con tail call e letture di mappa come variabili esplicative. |
| **Risultato** | P3 ha il **18% di istruzioni in meno** di P2 ed è il **62% più lento** (12 318 contro 14 969; 323 contro 199 ns). Le righe che lo spiegano: 3 salti contro 1, 29 letture contro 11. Sul traffico vero lo stesso ordine: 1,48 contro 1,89 Mpps. **Prova di rinforzo**: `IPA_MAX_QUEUES` da 1 a 8 porta `layer_first` da 7 009 a 10 503 istruzioni (+50%) senza cambiare nulla di ciò che gira, perché il descrittore non dichiara la feature coda. |
| **Conclusione** | `xlated` misura quanto è **grande** il programma caricato, non quanto **lavora**. In questo regime dominano letture di mappa e salti. |
| **Come rigirarlo** | `test_suite.py --only kernel`; `diag_p3_bisect.py --ceilings` |

### C2 — La larghezza dell'ingresso è gratis a runtime; quella nascosta no ✅

| | |
|---|---|
| **Ipotesi** | Una rete più grande costa di più per pacchetto. **Falsa per la one-hot.** |
| **Variabile modificata** | Numero di nodi (10 → 100) e neuroni per hidden layer (2 → 8). |
| **Metrica** | Latenza minima su 7 trial. |
| **Risultato** | Nodi: P1 specializzata 34–36, P1.5 41–43, P2 182–185, P3 306–318 ns, **piatte**, mentre le istruzioni di P1.5 vanno da 758 a 1 699. Neuroni: P1 26 → 68, P1.5 33 → 79, P2 173 → 208, P3 279 → 372 ns, in salita su tutte. |
| **Conclusione** | Una one-hot ha un solo uno, quindi il datapath legge una colonna di pesi qualunque sia la sua larghezza. Un layer denso più largo legge più pesi. **La rete può crescere quanto vuole, il modello no.** |
| **Come rigirarlo** | `bench_scaling.py --axis nodes` e `--axis width` |

### C3 — In P1 il conteggio istruzioni e il tempo dipendono dai valori dei pesi ✅

| | |
|---|---|
| **Ipotesi** | Con i pesi letterali nel C il compilatore cancella i prodotti per zero: la dimensione dipende dai **valori**, non solo dalla forma. |
| **Variabile modificata** | La frazione di pesi zero: 0, 25, 50, 75, 90%. |
| **Variabili fisse** | Forma 65-4-4-7; pesi prefisso di un pool fisso. |
| **Risultato** | P1.5: 1 114 → 236 istruzioni e 43 → 24 ns. P1 specializzata: 631 → 216 e 36 → 18 ns. P2: 14 969 istruzioni e 182–185 ns a tutte le sparsità; P3: 12 318 e 308–311 ns. |
| **Conclusione** | Al 90% di zeri P1 dimezza la latenza; per P2 e P3 uno zero è un byte in tabella come un altro. È l'asse su cui scendono insieme dimensione e tempo. |
| **Come rigirarlo** | `bench_scaling.py --axis sparsity` |

### C5 — La genericità compilata si paga in complessità di verifica ✅

| | |
|---|---|
| **Ipotesi** | Il verificatore percorre ogni cammino del corpo srotolato, e il costo cresce col **prodotto** dei soffitti: un programma generico non è gratis. |
| **Variabile modificata** | I soffitti compilati (`IPA_MAX_QUEUES` in P3; `T2_MAX_H1/H2`, `MAX_N_IN` in P2). |
| **Metrica** | Il programma si carica, e a quante istruzioni. |
| **Risultato** | P3 carica con `IPA_MAX_QUEUES` 1, 2, 4, 8 (`layer_first` 7 009 / 7 611 / 8 707 / 10 503). P2 con soffitti larghi (`8 × 4 × 128`) si ferma a `processed 1000001 insns (limit 1000000)` con ~14 900 istruzioni: dentro il limite di dimensione, oltre quello di complessità. |
| **Conclusione** | Due limiti distinti da non confondere: il verificatore **paga i cammini, non la dimensione**. È lo stesso limite di C9 e D1. |
| **Limite dichiarato** | ⚠️ Questi limiti sono scogliere, non pendenze: un soffitto si cambia e si rimisura. |
| **Come rigirarlo** | `sudo python3 ipa/test/diag_p3_bisect.py --ceilings` |

### C6 — Congelare il nodo toglie la dipendenza dalla taglia della rete ✅

| | |
|---|---|
| **Ipotesi** | L'indice del nodo è una costante di deployment; congelarlo fa sparire lo `switch` a N casi. |
| **Variabile modificata** | Da dove arriva l'indice: costante compilata contro mappa. |
| **Metrica** | Istruzioni, byte nativi, latenza al variare del numero di nodi. |
| **Risultato** | Istruzioni: specializzata 630–637 (**piatta**), P1.5 758 → 1 699. Codice nativo: 2 874–2 904 contro 3 525 → 8 499 byte. Latenza: 34–36 contro 41–43 ns (**−16%**, 7 ns). |
| **Controllo** | Sull'asse descrittore, dove il vettore d'ingresso non contiene `node`, le due P1 sono identiche alla cifra (602/602, 597/597); dove lo contiene divergono (631 contro 1 114). |
| **Conclusione** | La dimensione crolla e il tempo cala poco, per la stessa ragione: lo switch ha N casi ma ne esegue uno. È ciò che rende P1 praticabile su una rete grande. |
| **Contro-risultato** | Con pesi sparsi il vantaggio si annulla (216 contro 236 istruzioni al 90% di zeri): sparsità e nodo congelato sono due strade alla stessa riduzione. I binari da installare passano da uno a N (~70 ms di clang ciascuno). |
| **Come rigirarlo** | `bench_scaling.py --axis nodes`; figura `duel_p1_vs_p15.pdf` |

### C7 — Non generare le colonne delle porte assenti toglie lavoro vero ✅

| | |
|---|---|
| **Ipotesi** | `link_state` è un vettore **denso**: il datapath esegue una moltiplicazione-accumulo per ogni coppia (interfaccia, neurone). Non generare le colonne assenti toglie lavoro eseguito, non solo codice morto. |
| **Variabile modificata** | Il numero di porte presenti, 2–6, via `static_ports`. |
| **Variabili fisse** | Modello 65-4-4-7, 52 nodi, **gli stessi pesi** in ogni punto. |
| **Controllo** | `hardcoded`, `template` e `modular` non specializzano e devono restare piatte. |
| **Risultato** | Istruzioni 565 / 583 / 600 / 617 / 631 per grado 2–6: **16,5 per porta**, lineare; grado 2 contro 6 **−10,5%**. Latenza **32 / 33 / 33 / 35 / 36 ns**, monotona: −4 ns fra grado 6 e grado 2 (16 moltiplicazioni-accumulo). Controllo riuscito: 1 114 / 14 969 / 12 318 istruzioni e latenze piatte (43, 184–186, 306–311 ns) su tutti i punti. |
| **Conclusione** | Diversamente dal nodo congelato (C6), qui le moltiplicazioni tolte sono davvero eseguite, e la misura le vede: ~1 ns per porta. |
| **Come rigirarlo** | `bench_scaling.py --axis degree` |

### C8 — Il costo per MAC **eseguita** è una costante della pipeline ✅

| | |
|---|---|
| **Ipotesi** | La latenza si predice dalle MAC contate sulla forma del modello (n_in × h1, …). |
| **Variabile modificata** | Quattro assi: colonne dense (n_in 5 → 17), colonne one-hot (16 → 65), larghezza (4 → 32), profondità (1 → 4 strati). |
| **Metrica** | Pendenza e r² della retta sui quattro assi insieme, con MAC nominali e con MAC eseguite. |
| **Risultato** | Eseguite: **0,255 / 0,264 / 0,277 / 1,074 ns/MAC** (P1 statica, P1.5, P2, P3), r² **0,96 / 0,91 / 0,48 / 0,91**. Nominali: r² 0,14 / 0,29 / 0,02 / 0,07. |
| **Conclusione** | Con le MAC nominali il modello non spiega niente; con quelle eseguite i quattro assi collassano sulla stessa retta. Una one-hot occupa `size` colonne ma ne attiva una. **P3 costa 4,2× P1 per MAC eseguita**: il prezzo della genericità espresso in una costante. |
| **Controprova** | Sull'asse one-hot n_in ×4 e pesi ×2,4, latenza piatta su tutte (p1_static 64–66, P1.5 64–66, P2 169–173, P3 359–365 ns) mentre le istruzioni di P1 vanno da 1 238 a 2 162. |
| **Limite dichiarato** | ⚠️ P2 ha r² basso: pochi punti (oltre due strati non carica, C9) e un costo fisso alto rispetto alla pendenza. |
| **Come rigirarlo** | `bench_scaling.py --axis campaign --out results/`, poi `--plot results/` |

### C9 — P2 carica solo foglie con al più due strati nascosti ✅ ⚠️

| | |
|---|---|
| **Ipotesi** | P2 serve qualunque profondità sotto i suoi soffitti. **Falsa su questo kernel.** |
| **Variabile modificata** | Il numero di strati nascosti della foglia `arch_generic_2layer`. |
| **Metrica** | Il programma si carica. |
| **Risultato** | 1 e 2 strati caricano (14 676 e 14 969 istruzioni); con 3 o più `Failed to load BPF program b'arch_generic_2layer': Argument list too long` (`E2BIG`) su **ogni** asse che li prova: `depth` 3–6, `isoparam` 3–5, `depth_camp` 3–4, scenario sintetico `deep`. P3 carica fino a 6 strati (§ D3). |
| **Conclusione** | La profondità è la dimensione in cui P3 è generica e P2 no, anche nel senso più elementare: P2 oltre due strati non si carica. |
| **Limite dichiarato** | ⚠️ La causa precisa (quale limite del verificatore) non è letta: serve il log del verificatore (`BPF(text=src, debug=0x10)`). |
| **Come rigirarlo** | `bench_scaling.py --axis depth --out results/` |

---

## D. Larga contro profonda

### D1 — «Allargare batte approfondire» vale solo per certi ingressi, e solo sotto un limite ✅

| | |
|---|---|
| **Ipotesi** | Dato un numero di parametri, spenderli in un layer largo costa meno che in molti stretti. **Vera solo per certi vettori d'ingresso.** |
| **Variabile modificata** | La profondità: 1, 2, 4, 8 hidden layer, in P1 (oggetto AOT). |
| **Variabili fisse** | Il budget-pesi, con la larghezza risolta per descrittore e lo scarto stampato. Tre tier: ~300, ~1 200, ~4 700 pesi. Quattro descrittori. |
| **Metrica** | Latenza (min di 7 trial), istruzioni, e se il programma si carica. |
| **Risultato, tier A (~300 pesi)** | `default` (2 one-hot, n_in 65): larga **39** ns, 2 strati 39, 4 strati 41, 8 strati 50 (**+28%**). `no_onehot` (n_in 11): 96 / 96 / 84 / **76 ns (−21%)**, e 8 strati più piccola (1 323 contro 1 630 istruzioni). |
| **Risultato, tier B (~1 200 pesi)** | Su `default` carica solo la forma a 8 strati (230 ns); larga, 2 e 4 strati rifiutate dal verificatore: `processed 1000001 insns (limit 1000000)`, `E2BIG` su `xdp_model`. Negli altri descrittori nessuna forma carica (abort di clang per lo stack, o lo stesso limite). **Tier C**: nessuna forma carica. |
| **Conclusione** | Con un ingresso grande e dominato da una one-hot (il caso di IPA) allargare batte approfondire; con un ingresso piccolo e denso è il contrario, perché un ingresso denso moltiplica le letture per la larghezza del primo strato mentre una one-hot ne legge una colonna. E oltre ~300 pesi il limite di complessità del verificatore arriva prima per la forma larga. |
| **Limite dichiarato** | ⚠️ Il tier A ha scarti di pesi fino al 21,8%: differenze di 2-3 ns dentro quel tier non sono risolvibili. |
| **Come rigirarlo** | `sudo python3 ipa/test/bench_depth_vs_width.py` |

> **La frase per la tesi.** *Con un ingresso dominato da feature one-hot — il caso di
> IPA — allargare batte approfondire; con un ingresso piccolo e denso vince la rete
> profonda; e oltre qualche centinaio di pesi, in P1, è la forma larga a smettere per
> prima di passare il verificatore.*

### D2 — A parametri fermi, la risposta cambia con la pipeline ✅

| | |
|---|---|
| **Ipotesi** | La conclusione di D1 vale anche fuori da P1. **Parzialmente falsa.** |
| **Variabile modificata** | Come lo stesso budget è disposto: 1–5 hidden layer. |
| **Variabili fisse** | **I parametri: 592 ± 2%** (591, 599, 595, 604, 589). Famiglia a imbuto dentro i soffitti. |
| **Risultato, latenza (ns)** | P1 specializzata 50 / 52 / 49 / 63 / 59; P1.5 56 / 61 / 57 / 70 / 66; P2 167 / 183 e poi non carica (C9); P3 279 / 323 / 357 / 453 / **471 (+69%)**. |
| **Risultato, istruzioni** | P1 specializzata 888–1 056, P1.5 1 696–1 858, P3 **12 318 a tutti i punti**. |
| **Conclusione** | Le due P1 crescono poco e non in modo monotono (+18% fra gli estremi); P3 paga un tail call per strato a codice identico. Chi sceglie l'architettura deve sapere su quale pipeline girerà. |
| **Come rigirarlo** | `bench_scaling.py --axis isoparam` |

### D3 — Perché la profondità costa, quando costa ✅

| | |
|---|---|
| **Ipotesi** | Il costo di un layer in più non è aritmetico: è un costo fisso di transizione. |
| **Variabile modificata** | Il numero di layer (`depth` a parametri crescenti, `depth_camp` a larghezza 8, `isoparam`). |
| **Metrica** | Latenza per layer aggiunto; tail call; il costo del solo salto. |
| **Risultato** | P3 su `depth` (1 → 6 strati da 4): **257 → 537 ns**, ~56 ns per strato, istruzioni ferme a 12 318; su `depth_camp` (1 → 4 da 8) 278 → 549 ns. P1 specializzata 33 → 50 ns (~3–4 per strato). Il salto `PROG_ARRAY` da solo costa **+1 ns** (`bench_tailcall_overhead`: 10 → 11 ns). |
| **Conclusione** | In P3 **dimensione costante, tempo crescente** è la firma di un costo di transizione. Ma il salto in sé è quasi gratuito: i ~56 ns per strato sono le letture di mappa che ricostruiscono il contesto a ogni hop (`scratch_meta`, `scratch_acts`, `layer_shapes`, i pesi). |
| **Come rigirarlo** | `bench_scaling.py --axis depth`; `bench_tailcall_overhead.py` |

---

## E. Traffico vero

Fino alla sezione D ogni cifra in ns viene da `BPF_PROG_TEST_RUN`. Qui ci sono pacchetti
veri: pktgen o frame XDP grezzi, un fabric `veth`, contatori all'ingresso e all'uscita,
generatore, DUT e nodo successivo su P-core fisici distinti.

### E1 — Sotto capacità il nodo non perde niente; oltre, perde all'ingresso ✅

| | |
|---|---|
| **Ipotesi** | Le perdite su un banco `veth` possono essere della pipeline, del trasporto o della ricezione; vanno separate. |
| **Variabile modificata** | Il carico offerto; il punto di conteggio (inviati, respinti da `veth_xmit`, ricevuti da XDP, decisioni, inoltrati). |
| **Metrica** | Perdita prima di XDP, dopo XDP, e del solo contatore (`rxonly`) allo stesso rate. |
| **Risultato** | `bench_throughput --mode compare`, a 1,338 Mpps offerti a tutte: **nessun respinto** su nessuna delle sei. Saturazione: rxonly 4,39, baseline 3,26, P1 2,90, P1.5 2,78, P2 1,89, P3 1,48 Mpps, variazione fra i giri 0,1–1,7%. `bench_bitrate`, 390 finestre: sotto capacità `rxonly` perde lo 0,01–0,03%; oltre, per tutte e sei la perdita è **prima di XDP** e dopo XDP al massimo lo 0,02%. |
| **Conclusione** | Il collo di bottiglia è il programma eBPF, all'ingresso. Un nodo sotto la sua capacità consegna tutto. |
| **Come rigirarlo** | `bench_throughput.py --mode compare --rounds 3`; `bench_bitrate.py --out results/bitrate_3500` |

### E2 — I due banchi misurano la stessa grandezza ✅

| | |
|---|---|
| **Ipotesi** | `test_suite` e l'analisi parametrica, che usano entrambi `BPF_PROG_TEST_RUN`, danno lo stesso numero; e così `bench_throughput` e `bench_bitrate` sul traffico vero. |
| **Risultato** | Stesso modello 65-4-4-7: campagna 18 / 43 / 184 / 311 ns contro `test_suite` 22 / 47 / 199 / 323 (entro −4…−18%, pesi sintetici contro pesi del modello: 1 114 contro 989 istruzioni per P1.5). Traffico: `bench_bitrate` 4,39 / 3,18 / 2,84 / 2,72 / 1,86 / 1,45 Mpps contro `bench_throughput` 4,39 / 3,26 / 2,90 / 2,78 / 1,89 / 1,48 — entro il 3%, con `bench_bitrate` sempre più basso (ha il contatore davanti, +2–3 ns, e l'uscita su un core separato). |
| **Metodo che lo rende vero** | Il frame si rinfresca ogni 200 esecuzioni da TTL 255: `BPF_PROG_TEST_RUN` non ripristina il buffer e il datapath decrementa il TTL, e un frame riusato arriverebbe a TTL 1 e prenderebbe il ramo che salta la coda di inoltro. |
| **Come rigirarlo** | Tutti e quattro nella stessa sessione. |

### E3 — Il costo della pipeline si separa da quello del trasporto ✅

| | |
|---|---|
| **Ipotesi** | La latenza da arrivo a partenza tiene insieme due costi che si possono separare, e il secondo non dipende dalla pipeline. |
| **Variabile modificata** | Dove si prende il tempo: tre marcature (T1 ingresso del dispatcher, T2 prima di `bpf_redirect`, T3 ingresso del contatore all'altro capo). |
| **Risultato** | T2−T1: **35 / 64 / 74 / 226 / 349 ns** (baseline, P1, P1.5, P2, P3), piatto sul rate da 0,5 a 3 Mpps. T3−T2: **199–259 ns per tutte e cinque**. Sopra la baseline la sola pipeline: +29 / +39 / +191 / +314 ns. |
| **Conclusione** | Il trasporto è un costo comune di ~200–260 ns che non dipende dal lavoro della pipeline. |
| **Limite dichiarato** | ⚠️ Build **strumentata**: due letture dell'orologio e due scritture per pacchetto che il datapath di produzione non fa. |
| **Come rigirarlo** | `bench_throughput.py --mode rates --frames 64 --rounds 3 --rates 0.5,1,1.5,2,2.5,3` |

### E4 — Il costo del nodo per pacchetto, e da che cosa non dipende ✅ ⚠️

| | |
|---|---|
| **Ipotesi** | Il costo del nodo dipende dalla pipeline, non dalla taglia del pacchetto né dalla classe decisa. |
| **Variabile modificata** | Il generatore (frame XDP grezzi, niente skb né copia di headroom), la taglia (64 / 512 / 1514 B), la classe (stato dei link e TTL cercati per ciascuna delle 6 classi raggiungibili). |
| **Metrica** | ns/pacchetto = 1e9 / pacchetti elaborati, uscita su un core suo. |
| **Risultato** | P2 **285–287** e P3 **420–426 ns** a ogni taglia (entro l'1%). Per classe: sulle 5 FORWARD P2 244–272, P3 420–433 ns; **la classe DROP costa di più**: P1 256 contro ~155, P1.5 262 contro ~159, P2 325, P3 474 ns (con il DROP la pagina si restituisce sulla CPU del DUT; con l'inoltro sulla CPU d'uscita). |
| **Conclusione** | Il nodo tocca solo le intestazioni: il costo è per pacchetto. La porta d'uscita non conta, la decisione DROP sì. |
| **Limite dichiarato** | ⚠️ Con i frame XDP baseline, P1 e P1.5 non saturano il nodo: il core d'uscita consegna 4,4–4,8 Mpps e il generatore XDP a 3 thread si ferma a ~6,8. Le loro cifre (142 / 157 / 160 ns) sono limiti superiori del costo; il controllo di validità lo segnala. |
| **Come rigirarlo** | `bench_throughput.py --mode compare --generator xdp --egress-cpu auto` (`--frames 64,512,1514`; `--per-class`) |

### E5 — Latenza end-to-end e bit rate ✅

| | |
|---|---|
| **Ipotesi** | Al crescere del bit rate la coda d'ingresso si riempie, il ritardo cresce e poi si perde; il punto in cui comincia dipende dalla pipeline. |
| **Variabile modificata** | Il bit rate offerto, 13 punti calibrati sul tetto di ricezione (0,11–2,82 Gbit/s a 64 B). |
| **Metrica** | Latenza end-to-end (timbro di pktgen → contatore del nodo successivo, corretta per l'attesa di pktgen), perdita prima e dopo XDP. |
| **Risultato** | Pulite fino a: baseline 1,35, P1 e P1.5 1,13, P2 0,90, P3 0,68 Gbit/s; perdono dal punto successivo, all'ingresso. Latenza p50 8–9 µs a basso carico per tutte, 54–192 µs al primo punto in perdita. Latenza minima arrivo → ripartenza a scarico (`--latency`, 512 B): 261 / 277 / 293 / 457 / 593 ns. |
| **Come rigirarlo** | `bench_bitrate.py --out results/bitrate_3500`; `bench_throughput.py --latency --frames 512 --rounds 3 --repeat 5` |

---

## G. La macchina

### G1 — Con la macchina condizionata le misure si ripetono entro pochi punti ✅

| | |
|---|---|
| **Ipotesi** | La variabilità delle misure è della macchina (frequenza, idle, scheduling, temperatura), e si può togliere. |
| **Variabile modificata** | Le condizioni: frequenza fissa e misurata, C-state profondi spenti, core fisici distinti, isolamento a runtime (`host_conditions.py`). |
| **Metrica** | Dispersione fra trial e fra giri; eventi di throttling; frequenza reale del DUT. |
| **Risultato** | `test_suite`: spread 2–5%. `bench_bitrate`: variazione del massimo fra 5 giri 0,4–2,0%. `bench_throughput`: 0,1–1,7%. DUT a 3 484–3 499 MHz in ogni comando; nessun evento di throttling sui core in nessuna misura di questo registro; eventi di pacchetto 0–4 per comando. |
| **Conclusione** | Le cifre sono ripetibili sulla stessa macchina alla stessa frequenza. |
| **Come rigirarlo** | `sudo python3 ipa/test/test_host_kernel.py --bench` (25/25) |

### G2 — La frequenza conta quasi in proporzione, i rapporti fra pipeline no ✅ ⚠️

| | |
|---|---|
| **Ipotesi** | Il costo per pacchetto è lavoro di CPU e scala con la frequenza del core. |
| **Variabile modificata** | La frequenza fissa del banco: 2,0 / 3,0 / 3,5 / 4,0 / 4,5 GHz misurati. |
| **Risultato** | Baseline 2,00 / 2,89 / 3,22 / 3,55 / 3,54 Mpps; template 1,14 / 1,66 / 1,86 / 2,09 / 2,04. Da 3 a 4 GHz +23% invece di +33%; i cicli per pacchetto crescono dell'8–13% fra 2 e 4 GHz. Template/baseline 0,57–0,59 a ogni frequenza pulita. A 4,5 GHz 28/39 finestre in throttling; a 4,0 GHz un run da 5 minuti porta il pacchetto a 98 °C e il DUT in throttling. |
| **Conclusione** | Le cifre assolute vanno citate con la loro frequenza; i rapporti fra pipeline no. La frequenza di default del banco, 3,5 GHz, è la più alta che il portatile regge per un run intero. |
| **Limite dichiarato** | ⚠️ Con 1 400 MHz scritti nel sysfs il core gira a ~2 000 MHz misurati: la frequenza vera si misura (APERF/MPERF), non si legge. |
| **Come rigirarlo** | `bench_bitrate.py --freq <MHz> --method rxonly,baseline,template --rounds 1` |

---

## F. Che cosa nessun test di questo progetto dimostra

Dichiarato per non far sembrare coperto ciò che non lo è.

- **Throughput su hardware di rete.** Generatore, DUT e nodo successivo sono core dello
  stesso processore collegati da `veth`: niente NIC, niente DMA, e con pktgen una copia di
  headroom per pacchetto. Le cifre in Mpps sono di questo percorso a 3,5 GHz; per un valore
  su una scheda di rete servono una seconda macchina e una NIC con XDP nativo.
- **Il costo del nodo di baseline e P1 con frame XDP** (E4): il banco non li satura.
- **Accuratezza del modello.** Il modello non è stato addestrato in questo lavoro. I test
  verificano che il datapath calcoli **la stessa cosa** del riferimento, non che quella
  cosa sia una buona politica di routing.
- **Reti oltre ~115 nodi.** `MAX_N_IN` è 128 in P2 e P3: per una topologia da 500 nodi
  bisogna alzare quel soffitto e rimisurare.
- **Che i pesi, a forma fissa, decidano se P1 si carica.** È una conseguenza attesa di C3
  (il codice generato dipende dai valori) e il limite di complessità di D1 la rende
  plausibile, ma su questa macchina non è stato misurato variando il solo seme dei pesi.
- **Isolamento dal boot.** `isolcpus`, `nohz_full` e `rcu_nocbs` non sono usati: le CPU del
  banco restano soggette al tick e ai callback RCU.
