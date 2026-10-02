# Registro delle affermazioni sperimentali

Una riga della tesi che afferma qualcosa di misurabile deve poter essere
rintracciata fino all'esperimento che la sostiene. Questo documento è quella
mappa: per ogni affermazione, l'ipotesi, che cosa è stato mosso, che cosa è stato
tenuto fermo, che cosa è stato misurato, il numero ottenuto e il comando per
rifarlo.

**Le cifre sono del 2026-09-28** (tranne G2, del 27, A8, B1, B3, C1, del 29, e il traffico vero con `xdp_gen` di E1–E7, del 2026-10-02), sulla macchina di laboratorio
(Intel Core Ultra 7 155H, Ubuntu 24.04, kernel 6.8.0-142, bare metal) nelle condizioni di
`host_conditions.py`: core del banco fissi a **3 500 MHz misurati**, isolati, senza
C6/C10 (`docs/testing.md` §0). Si rifanno tutte con

```bash
bash ipa/test/remeasure_all.sh       # BPF_PROG_TEST_RUN, correttezza, analisi parametrica
bash ipa/test/remeasure_traffic.sh    # traffico vero, semantica, soffitti, topologie
bash ipa/test/remeasure_xdp.sh        # traffico vero con xdp_gen: capacità a 1 e 2 core, curve
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
| **Risultato** | **P1: 8/8** scenari a 300/300. **P3: 7/7** a 300/300 (`large` non applicabile: 9 uscite, limite 8). **P2: 7/7** a 300/300, `deep` compreso (4 strati, vedi C9); `large` non applicabile (1 097 pesi, blocco da 1 024). La scala dichiarata diversa da 30 sposta davvero le decisioni su `ipa_ttl16` (41/300) e `small` (89/300). Controllo negativo: riscritto il solo byte `feat_ent.scale` al default, l'eBPF segue il riferimento al default su 300/300 e si stacca da quello dichiarato **esattamente** sui 41 casi previsti, quindi il kernel legge quel byte. |
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
| **Variabile modificata** | Semantiche diverse per modelli registrati nello stesso programma. La chiave della tabella classe → azione è `(model_id, banco, classe)`, in un `BPF_ARRAY` di 256 × 2 × 32 righe. Il banco attivo sta nell'entry del registry: ricaricare un modello scrive il banco inattivo e un solo update installa insieme `n_out` e banco. |
| **Variabili fisse** | Inferenza, pesi, descrittori, un programma per architettura. |
| **Metrica** | Azione prodotta per ogni classe di ogni modello; lookup, memoria. |
| **Risultato** | **53/53** su P2 e P3: un modello; due con la stessa semantica; due con semantiche diverse su ogni classe a pacchetti alternati; A → B → A anche dopo aver ricaricato B; `model_id` inesistente o rimosso non elaborato; `n_out` 4 e 7 insieme; stesso `model_id` ricaricato con altra semantica e altro `n_out`. **Costo**: una lettura di tabella per pacchetto (lookup totali 11 in P2, 29 in P3), latenza che non cambia da 1 a 8 modelli registrati; **memoria 131 072 byte per pipeline**, fissi. |
| **Controllo negativo** | Con una tabella condivisa simulata A e B passano e C, D, F, R falliscono. |
| **Perché non dentro il registry** | Indicizzare il valore dell'entry con `best_cls` obbliga il verificatore a tracciare `best_cls` con precisione attraverso l'argmax: `layer_hidden` di P3 non carica (`E2BIG`). Una chiave sullo stack no. |
| **Limite dichiarato** | ⚠️ I 128 KiB sono riservati per 256 modelli anche con un modello solo; l'alternativa a pochi KB (slot allocato dal piano di controllo) non è implementata. |
| **Come rigirarlo** | `sudo python3 ipa/test/verify_per_model_semantics.py` |

### A8 — Ogni test del kernel e del traffico vero gira su qualsiasi modello compatibile ✅ ⚠️

| | |
|---|---|
| **Ipotesi** | Suite kernel, verifica per TTL, consegna sul fabric e banchi di traffico non devono presupporre il checkpoint né Germany50: caricano un modello qualsiasi, su una rete le cui dimensioni esso rispetta. |
| **Variabile modificata** | Il modello (`--model`: checkpoint e 8 preset sintetici, da 11-2-3 a 117-8-8-9) e la rete (`--topology`: 6 scenari in `topologies/`). |
| **Variabili fisse** | Le pipeline, i costruttori comuni (`pipeline_setup.py`), il riferimento generico. |
| **Metrica** | Classe e azione decise nel kernel contro il riferimento; pacchetto consegnato sulla porta attesa. |
| **Compatibilità** | Ogni feature larga quanto la dimensione della rete da cui dipende, scala del TTL uguale al TTL iniziale; limiti compilati di P2/P3 da `pipeline_limits.py`. Un'incompatibilità ferma il test prima di compilare, con il motivo. |
| **Risultato** | `test_model_source --kernel` **110/110** (scenario × modello × pipeline, 40 ingressi, model_id 0 e 190; `large` su P2/P3 non applicabile); suite kernel PASS e fabric senza errori su 9 modelli; `verify_synth_kernel` invariato dopo il passaggio ai costruttori comuni. Col checkpoint la strada nuova dà pesi, scala, semantica e riferimento identici (3 000/3 000), e sorgenti di P1 e della foglia di P2 identici byte per byte. |
| **Controllo negativo** | Un modello incompatibile (one-hot a 52 su 30 nodi, TTL 16 su una rete a 30, 9 interfacce oltre il tetto) è rifiutato con il motivo: `test_model_source`, 62/62. |
| **Limite dichiarato** | ⚠️ Le classi consegnate dal fabric sono quelle che il modello decide davvero: per `sparse` 2 su 7, per `ones` 1 su 3 (campionamento di 200 000 ingressi). `--mode rates` e `--latency` restano solo col checkpoint. |
| **Come rigirarlo** | `sudo python3 ipa/test/test_model_source.py --kernel`; `test_suite.py --only kernel --model synth:deep`; `test_fabric.py --model synth:small` |

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
| **Risultato** | `test_suite` (29-09, contatori per-CPU): baseline **14**, P1 **48**, P1.5 **53**, P2 **200**, P3 **314 ns**; istruzioni 135 / 606 / 1 019 / 15 089 / 12 288; letture 3 / 5 / 6 / 11 / 29; salti 0 / 1 / 1 / 1 / 3; spread 0–7%. Analisi parametrica (pesi sintetici, 28-09): P1 specializzata **41**, P1.5 46, P2 188, P3 307 ns. |
| **Conclusione** | **La flessibilità costa circa 6,5× in latenza** fra i due estremi (48 contro 314 ns; 7,5× con i pesi sintetici), e il costo non è aritmetico: è in letture di mappa e salti fra programmi. |
| **Come rigirarlo** | `sudo python3 ipa/test/test_suite.py --only kernel`; `bench_scaling.py --out results/` |

### B2 — Aggiornare il modello: con l'oggetto precompilato il divario sparisce ✅

| | |
|---|---|
| **Ipotesi** | Compilare i pesi dentro il codice sposta il costo dal pacchetto al deployment. |
| **Variabile modificata** | La pipeline, su tutti gli assi dello sweep. |
| **Metrica** | `update_ms` (installare un modello nuovo su un nodo in servizio) e `build_ms` (compilazione). |
| **Risultato** | `update_ms`: P1 e P1.5 **0,7–2,1 ms** (caricamento dell'oggetto AOT), P2 e P3 **10–12 ms** (scritture in mappa). `build_ms`: P1 66–120 ms (clang, sulla macchina di build), P2 ~1,5 s e P3 ~1,2 s (BCC, una volta all'avvio del nodo). |
| **Conclusione** | Il costo di P1 è della **compilazione**, non dei pesi letterali: con l'oggetto precompilato aggiornare P1 non costa più di aggiornare P2/P3. Resta la differenza qualitativa: P1 richiede un compilatore (fuori dal nodo) per ogni modello nuovo, P2 e P3 no. |
| **Nota metodologica** | `build_ms` e `update_ms` non vanno confusi: per P2/P3 il primo è pagato una volta all'avvio del nodo, il secondo per modello. |
| **Come rigirarlo** | `bench_scaling.py --out results/` (figura `scaling_depth_update`) |

### B3 — L'AOT toglie il compilatore dal nodo senza costo per pacchetto ✅

| | |
|---|---|
| **Ipotesi** | Compilare l'oggetto fuori dal nodo elimina clang dal nodo, e la strength reduction sui pesi letterali sopravvive dentro l'oggetto. |
| **Variabile modificata** | Dove avviene la compilazione: macchina di build (clang, 75,8 ms) contro nodo. |
| **Metrica** | Costo di messa in servizio; latenza per pacchetto. |
| **Risultato** | Deploy dell'oggetto sul nodo **1,12 ms** (`open` 0,09 + verifica e JIT 1,03); latenza **51 ns** sul percorso d'inoltro (retval 4), come `test_suite` (52–53); 1 019 istruzioni (dispatch 29 + modello 990; 1 064 prima dei contatori per-CPU). Throughput reale P1.5: C1, E1. |
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
| **Risultato** | P3 ha il **19% di istruzioni in meno** di P2 ed è il **57% più lento** (12 288 contro 15 089; 314 contro 200 ns). Le righe che lo spiegano: 3 salti contro 1, 29 letture contro 11. Sul traffico vero lo stesso ordine: 1,50 contro 1,89 Mpps. **Prova di rinforzo**: `IPA_MAX_QUEUES` da 1 a 8 porta `layer_first` da 7 003 a 10 528 istruzioni (+50%) senza cambiare nulla di ciò che gira, perché il descrittore non dichiara la feature coda. |
| **Conclusione** | `xlated` misura quanto è **grande** il programma caricato, non quanto **lavora**. In questo regime dominano letture di mappa e salti. |
| **Come rigirarlo** | `test_suite.py --only kernel`; per i tetti, ricompilare `layer_first` con un altro `IPA_MAX_QUEUES` (`ebpf_modular.py`) |

### C2 — La larghezza dell'ingresso è gratis a runtime; quella nascosta no ✅

| | |
|---|---|
| **Ipotesi** | Una rete più grande costa di più per pacchetto. **Falsa per la one-hot.** |
| **Variabile modificata** | Numero di nodi (10 → 100) e neuroni per hidden layer (2 → 8). |
| **Metrica** | Latenza minima su 7 trial. |
| **Risultato** | Nodi: P1 specializzata 38–41, P1.5 45–48, P2 186–188, P3 307–311 ns, **piatte**, mentre le istruzioni di P1.5 vanno da 776 a 1 718. Neuroni: P1 27 → 67, P1.5 34 → 75, P2 174 → 212, P3 279 → 383 ns, in salita su tutte. |
| **Conclusione** | Una one-hot ha un solo uno, quindi il datapath legge una colonna di pesi qualunque sia la sua larghezza. Un layer denso più largo legge più pesi. **La rete può crescere quanto vuole, il modello no.** |
| **Come rigirarlo** | `bench_scaling.py --axis nodes` e `--axis width` |

### C3 — In P1 il conteggio istruzioni e il tempo dipendono dai valori dei pesi ✅

| | |
|---|---|
| **Ipotesi** | Con i pesi letterali nel C il compilatore cancella i prodotti per zero: la dimensione dipende dai **valori**, non solo dalla forma. |
| **Variabile modificata** | La frazione di pesi zero: 0, 25, 50, 75, 90%. |
| **Variabili fisse** | Forma 65-4-4-7; pesi prefisso di un pool fisso. |
| **Risultato** | P1.5: 1 090 → 357 istruzioni e 47 → 26 ns. P1 specializzata: 663 → 263 e 41 → 19 ns. P2: 15 142 istruzioni e 186–189 ns a tutte le sparsità; P3: 12 394 e 307–311 ns. |
| **Conclusione** | Al 90% di zeri P1 più che dimezza la latenza; per P2 e P3 uno zero è un byte in tabella come un altro. È l'asse su cui scendono insieme dimensione e tempo. |
| **Come rigirarlo** | `bench_scaling.py --axis sparsity` |

### C5 — La genericità compilata si paga in complessità di verifica ✅

| | |
|---|---|
| **Ipotesi** | Il verificatore percorre ogni cammino del corpo srotolato, e il costo cresce col **prodotto** dei soffitti: un programma generico non è gratis. |
| **Variabile modificata** | I soffitti compilati (`IPA_MAX_QUEUES` in P3; `T2_MAX_H1/H2`, `MAX_N_IN` in P2). |
| **Metrica** | Il programma si carica, e a quante istruzioni. |
| **Risultato** | P3 carica con `IPA_MAX_QUEUES` 1, 2, 4, 8 (`layer_first` 7 003 / 7 628 / 8 729 / 10 528). P2 con soffitti larghi (`8 × 4 × 128`) si ferma a `processed 1000001 insns (limit 1000000)` con ~14 900 istruzioni: dentro il limite di dimensione, oltre quello di complessità. |
| **Conclusione** | Due limiti distinti da non confondere: il verificatore **paga i cammini, non la dimensione**. C9 mostra quanto pesa un singolo salto condizionale ripetuto. |
| **Limite dichiarato** | ⚠️ Questi limiti sono scogliere, non pendenze: un soffitto si cambia e si rimisura. |
| **Come rigirarlo** | Ricompilare `layer_first` con un altro `IPA_MAX_QUEUES` (`ebpf_modular.py`); `diag_verifier.py` per le statistiche del verificatore |

### C6 — Congelare il nodo toglie la dipendenza dalla taglia della rete ✅

| | |
|---|---|
| **Ipotesi** | L'indice del nodo è una costante di deployment; congelarlo fa sparire lo `switch` a N casi. |
| **Variabile modificata** | Da dove arriva l'indice: costante compilata contro mappa. |
| **Metrica** | Istruzioni, byte nativi, latenza al variare del numero di nodi. |
| **Risultato** | Istruzioni: specializzata 647–663 (**piatta**), P1.5 776 → 1 718. Codice nativo: 2 867–2 929 contro 3 507 → 8 507 byte. Latenza: 38–41 contro 45–48 ns (**−13%**, 5–7 ns). |
| **Controllo** | Sull'asse descrittore, dove il vettore d'ingresso non contiene `node`, le due P1 sono identiche alla cifra (656/656, 649/649); dove lo contiene divergono (663 contro 1 090). |
| **Conclusione** | La dimensione crolla e il tempo cala poco, per la stessa ragione: lo switch ha N casi ma ne esegue uno. È ciò che rende P1 praticabile su una rete grande. |
| **Contro-risultato** | Con pesi sparsi il vantaggio quasi si annulla (263 contro 357 istruzioni al 90% di zeri): sparsità e nodo congelato sono due strade alla stessa riduzione. I binari da installare passano da uno a N (~70 ms di clang ciascuno). |
| **Come rigirarlo** | `bench_scaling.py --axis nodes`; figura `duel_p1_vs_p15.pdf` |

### C7 — Non generare le colonne delle porte assenti toglie lavoro vero ✅

| | |
|---|---|
| **Ipotesi** | `link_state` è un vettore **denso**: il datapath esegue una moltiplicazione-accumulo per ogni coppia (interfaccia, neurone). Non generare le colonne assenti toglie lavoro eseguito, non solo codice morto. |
| **Variabile modificata** | Il numero di porte presenti, 2–6, via `static_ports`. |
| **Variabili fisse** | Modello 65-4-4-7, 52 nodi, **gli stessi pesi** in ogni punto. |
| **Controllo** | `hardcoded`, `template` e `modular` non specializzano e devono restare piatte. |
| **Risultato** | Istruzioni 579 / 599 / 615 / 639 / 663 per grado 2–6: **21 per porta**, lineare; grado 2 contro 6 **−12,7%**. Latenza **37 / 38 / 39 / 39 / 41 ns**, monotona: −4 ns fra grado 6 e grado 2 (16 moltiplicazioni-accumulo). Controllo riuscito: 1 090 / 15 142 / 12 394 istruzioni e latenze piatte (46–47, 187–189, 306–309 ns) su tutti i punti. |
| **Conclusione** | Diversamente dal nodo congelato (C6), qui le moltiplicazioni tolte sono davvero eseguite, e la misura le vede: ~1 ns per porta. |
| **Come rigirarlo** | `bench_scaling.py --axis degree` |

### C8 — Il costo per MAC **eseguita** è una costante della pipeline ✅

| | |
|---|---|
| **Ipotesi** | La latenza si predice dalle MAC contate sulla forma del modello (n_in × h1, …). |
| **Variabile modificata** | Quattro assi: colonne dense (n_in 5 → 17), colonne one-hot (16 → 65), larghezza (4 → 32), profondità (1 → 4 strati). |
| **Metrica** | Pendenza e r² della retta sui quattro assi insieme, con MAC nominali e con MAC eseguite. |
| **Risultato** | Eseguite: **0,287 / 0,290 / 0,548 / 1,175 ns/MAC** (P1 statica, P1.5, P2, P3), r² **0,99 / 0,98 / 0,71 / 0,91**. Nominali: r² 0,62 / 0,70 / 0,22 / 0,08. |
| **Conclusione** | Con le MAC nominali il modello spiega poco; con quelle eseguite i quattro assi collassano sulla stessa retta. Una one-hot occupa `size` colonne ma ne attiva una. **P3 costa 4,1× P1 per MAC eseguita**: il prezzo della genericità espresso in una costante. |
| **Controprova** | Sull'asse one-hot n_in ×4 e pesi ×2,4, latenza piatta su tutte (p1_static 64–65, P1.5 64–65, P2 169–170, P3 363–367 ns) mentre le istruzioni di P1 vanno da 1 144 a 1 632. |
| **Limite dichiarato** | ⚠️ P2 ha r² più basso: un costo fisso alto rispetto alla pendenza, e il residuo più grande su `width_camp`, dove i neuroni oltre la larghezza del modello si calcolano comunque fino al soffitto. |
| **Come rigirarlo** | `bench_scaling.py --axis campaign --out results/`, poi `--plot results/` |

### C9 — Un salto condizionale per neurone bastava a esaurire il verificatore ✅

| | |
|---|---|
| **Ipotesi** | I limiti di caricamento di P2 (oltre due strati nascosti) e di P1 (oltre ~300 pesi) dipendono dal kernel. **Falsa: dipendevano dal codice.** |
| **Variabile modificata** | Come è scritta la ReLU: `x > 0 ? x : 0` (un salto per neurone) contro `ipa_relu`, `x & ~(x >> 63)` dietro una barriera `asm volatile("")`, stesso risultato bit per bit e nessun salto. |
| **Variabili fisse** | Kernel 6.8.0-142, forme, pesi, descrittore default; tutto il resto del sorgente. |
| **Metrica** | Istruzioni percorse dal verificatore (`log_level = 4`, limite 1 000 000), stati salvati; se il programma carica. |
| **Risultato** | P2, da 1 a 6 strati: con il salto 799 563 / 417 292 / rifiutato / … ; con `ipa_relu` 120 452 / 120 557 / 127 906 / 127 738 / 134 413 / 136 642, e 201 528 a 20 strati. P1 tier B (~1 200 pesi, `default`): con il salto larga, 2 e 4 strati rifiutate (1 000 001), 8 strati 229 039; con `ipa_relu` 5 698–8 516, tutte caricano. P3 `layer_hidden`: 186 489 → 27 979. |
| **Conclusione** | Il verificatore paga i cammini: un bivio per neurone li moltiplica. P2 ora carica fino a **20 strati**; il limite successivo è la distanza di salto eBPF (offset a 16 bit: a 37 strati `LLVM ERROR: Branch target out of insn range`), poi la tabella dei pesi (1 024: 37 strati a larghezza 4, 7 a larghezza 8). Anche la barriera `asm` è necessaria: senza, clang riconosce `smax(x, 0)` e rimette il salto. |
| **Costo** | Sotto `BPF_PROG_TEST_RUN` P1 sale da 47 a 52 ns (la baseline scende da 22 a 18 nello stesso confronto): lì il salto era sempre predetto. Sul traffico vero nessuna differenza: sopra la baseline P1 38 → 38 ns, P2 224 → 226, P3 368 → 364 (con pktgen, E9). |
| **Limite dichiarato** | ⚠️ Fra 20 e 37 strati il punto esatto in cui clang si ferma non è misurato. |
| **Come rigirarlo** | `sudo python3 ipa/test/diag_verifier.py` (varianti `attuale` e `salto`); `--only p2 --depths 6,10,20,37` |

---

## D. Larga contro profonda

### D1 — «Allargare batte approfondire» vale solo per certi ingressi, e solo sotto un limite ✅

| | |
|---|---|
| **Ipotesi** | Dato un numero di parametri, spenderli in un layer largo costa meno che in molti stretti. **Vera solo per certi vettori d'ingresso.** |
| **Variabile modificata** | La profondità: 1, 2, 4, 8 hidden layer, in P1 (oggetto AOT). |
| **Variabili fisse** | Il budget-pesi, con la larghezza risolta per descrittore e lo scarto stampato. Tre tier: ~300, ~1 200, ~4 700 pesi. Quattro descrittori. |
| **Metrica** | Latenza (min di 7 trial), istruzioni, e se il programma si carica. |
| **Risultato, tier A (~300 pesi)** | `default` (2 one-hot, n_in 65): larga **39** ns, 2 strati 46, 4 strati 49, 8 strati 64 (**+64%**). `no_onehot` (n_in 11): 93 / 88 / 83 / **81 ns (−13%)**, e 8 strati più piccola (1 368 contro 1 535 istruzioni). |
| **Risultato, tier B (~1 200 pesi)** | `default`: larga **110** ns, 2 strati 150, 4 strati 176, 8 strati 219 (**+99%**). `no_onehot`: larga e 2 strati non compilano (stack eBPF oltre 512 byte), 4 strati 320, 8 strati **291 ns (−9%)**. **Tier C**: nessuna forma compila (stack). |
| **Conclusione** | Con un ingresso grande e dominato da una one-hot (il caso di IPA) allargare batte approfondire; con un ingresso piccolo e denso è il contrario, perché un ingresso denso moltiplica le letture per la larghezza del primo strato mentre una one-hot ne legge una colonna. Oltre ~1 200 pesi il limite di P1 è lo stack, e ci arriva prima la forma larga. |
| **Limite dichiarato** | ⚠️ Il tier A ha scarti di pesi fino al 21,8%: differenze di 2-3 ns dentro quel tier non sono risolvibili. |
| **Come rigirarlo** | `sudo python3 ipa/test/bench_depth_vs_width.py` |

> **La frase per la tesi.** *Con un ingresso dominato da feature one-hot — il caso di
> IPA — allargare batte approfondire; con un ingresso piccolo e denso vince la rete
> profonda; e oltre un migliaio di pesi, in P1, è la forma larga a esaurire per prima
> lo stack.*

### D2 — A parametri fermi, la risposta cambia con la pipeline ✅

| | |
|---|---|
| **Ipotesi** | La conclusione di D1 vale anche fuori da P1. **Parzialmente falsa.** |
| **Variabile modificata** | Come lo stesso budget è disposto: 1–5 hidden layer. |
| **Variabili fisse** | **I parametri: 592 ± 2%** (591, 599, 595, 604, 589). Famiglia a imbuto dentro i soffitti. |
| **Risultato, latenza (ns)** | P1 specializzata 52 / 54 / 55 / 67 / 66; P1.5 60 / 65 / 62 / 75 / 71; P2 169 / 189 / 206 / 261 / **268 (+59%)**; P3 274 / 321 / 355 / 443 / **471 (+72%)**. |
| **Risultato, istruzioni** | P1 specializzata 889–1 096, P1.5 1 776–1 861, P2 14 657 → 17 992, P3 **12 394 a tutti i punti**. |
| **Conclusione** | Le due P1 crescono poco e non in modo monotono (circa +25% fra gli estremi); P2 paga lo strato in codice, P3 un tail call per strato a codice identico. Chi sceglie l'architettura deve sapere su quale pipeline girerà. |
| **Come rigirarlo** | `bench_scaling.py --axis isoparam` |

### D3 — Perché la profondità costa, quando costa ✅

| | |
|---|---|
| **Ipotesi** | Il costo di un layer in più non è aritmetico: è un costo fisso di transizione. |
| **Variabile modificata** | Il numero di layer (`depth` a parametri crescenti, `depth_camp` a larghezza 8, `isoparam`). |
| **Metrica** | Latenza per layer aggiunto; tail call; il costo del solo salto. |
| **Risultato** | P3 su `depth` (1 → 6 strati da 4): **249 → 513 ns**, ~53 ns per strato, istruzioni ferme a 12 394; su `depth_camp` (1 → 4 da 8) 271 → 571 ns. P2 su `depth`: 166 → 289 ns, ~25 ns e ~870 istruzioni per strato. P1 specializzata 33 → 60 ns (~5 per strato). Il salto `PROG_ARRAY` da solo costa **+1 ns** (`bench_tailcall_overhead`: 10 → 11 ns). |
| **Conclusione** | In P3 **dimensione costante, tempo crescente** è la firma di un costo di transizione. Ma il salto in sé è quasi gratuito: i ~53 ns per strato sono le letture di mappa che ricostruiscono il contesto a ogni hop (`scratch_meta`, `scratch_acts`, `layer_shapes`, i pesi). |
| **Come rigirarlo** | `bench_scaling.py --axis depth`; `bench_tailcall_overhead.py` |

---

## E. Traffico vero

Fino alla sezione D ogni cifra in ns viene da `BPF_PROG_TEST_RUN`. Qui ci sono pacchetti
veri: frame XDP grezzi da `xdp_gen`, consegnati al nodo come da una NIC con XDP nativo, un
fabric `veth`, contatori all'ingresso e all'uscita, generatore, DUT e nodo successivo su
P-core fisici distinti. Le cifre sono del 2026-10-02, tutte nella stessa sessione
(`remeasure_xdp.sh`). L'alternativa, pktgen, compare come confronto in E3 e in E9.

### E1 — Sotto capacità il nodo non perde niente; oltre, perde all'ingresso ✅

| | |
|---|---|
| **Ipotesi** | Le perdite su un banco `veth` possono essere della pipeline, del trasporto o della ricezione; vanno separate. |
| **Variabile modificata** | Il carico offerto; il punto di conteggio (inviati, ricevuti da XDP, decisioni, inoltrati). |
| **Metrica** | Perdita prima di XDP, dopo XDP, e del solo contatore (`rxonly`) allo stesso rate. |
| **Risultato** | Saturazione (`bench_throughput --mode compare --generator xdp`, 1 core): baseline 15,13, P1 8,69, P1.5 8,07, P2 3,41, P3 2,41 Mpps, variazione fra i giri 1,2–3,2%, nodo al 100%; rxonly 19,11 senza saturare. `bench_bitrate`, 480 finestre da 0,5 a 12 Mpps: sotto capacità nessuna perdita (≤ 0,05%); oltre, per P1, P1.5, P2 e P3 la perdita è **prima di XDP**, con il nodo al 99,6–99,9%, e dopo XDP al massimo lo 0,04% (rumore di lettura, negativo in 159 finestre su 400). `rxonly` non perde fino a 11 Mpps (0,3% a 12, dove cede il generatore): la perdita delle pipeline è del programma. |
| **Conclusione** | Il collo di bottiglia è il programma eBPF, all'ingresso. Un nodo sotto la sua capacità consegna tutto. |
| **Come rigirarlo** | `bash ipa/test/remeasure_xdp.sh` |

### E2 — I due banchi misurano la stessa grandezza ✅

| | |
|---|---|
| **Ipotesi** | `test_suite` e l'analisi parametrica, che usano entrambi `BPF_PROG_TEST_RUN`, danno lo stesso numero; e così `bench_throughput` e `bench_bitrate` sul traffico vero. |
| **Risultato** | Stesso modello 65-4-4-7: campagna 18 / 46 / 190 / 305 ns contro `test_suite` 18 / 52 / 195 / 315 (entro 0…−12%, pesi sintetici contro pesi del modello: 1 090 contro 1 064 istruzioni per P1.5). Traffico: la curva di `bench_bitrate` si ferma a P1 8,64, P1.5 8,06, P2 3,48, P3 2,33 Mpps contro 8,69 / 8,07 / 3,41 / 2,41 a massima spinta di `bench_throughput`, entro il 3% (sessioni diverse) (con il contatore davanti, da −1,4 a +2,4 ns). |
| **Metodo che lo rende vero** | Il frame si rinfresca ogni 200 esecuzioni da TTL 255: `BPF_PROG_TEST_RUN` non ripristina il buffer e il datapath decrementa il TTL, e un frame riusato arriverebbe a TTL 1 e prenderebbe il ramo che salta la coda di inoltro. |
| **Come rigirarlo** | Tutti e quattro nella stessa sessione. |

### E3 — Il costo della pipeline si separa da quello del trasporto ✅

| | |
|---|---|
| **Ipotesi** | La latenza da arrivo a partenza tiene insieme due costi che si possono separare, e il secondo non dipende dalla pipeline. |
| **Variabile modificata** | Dove si prende il tempo: tre marcature (T1 ingresso del dispatcher, T2 prima di `bpf_redirect`, T3 ingresso del contatore all'altro capo). |
| **Risultato** | Con `xdp_gen` (2026-10-02): T2−T1 **26 / 60 / 68 / 218 / 327 ns** (baseline, P1, P1.5, P2, P3), piatto sul rate da 0,5 a 3 Mpps. T3−T2: **183–236 ns per tutte e cinque**. Sopra la baseline la sola pipeline: +34 / +43 / +192 / +301 ns. Latenza minima arrivo → ripartenza (T3−T1 a 50 kpps): 223 / 261 / 267 / 441 / 592 ns. Con pktgen (28-09) le stesse differenze, +34 / +43 / +194 / +306. |
| **Conclusione** | Il trasporto è un costo comune di ~185–235 ns che non dipende dal lavoro della pipeline. La copia di headroom di pktgen avviene prima di T1 e non entra in nessuno dei tre intervalli. |
| **Limite dichiarato** | ⚠️ Build **strumentata**: due letture dell'orologio e due scritture per pacchetto che il datapath di produzione non fa. Il throughput di questa modalità non è una capacità: con la build strumentata e l'uscita sulla CPU del DUT la coda respinge già da ~2,5 Mpps per la baseline e ~1,3 per P3, con tutti e due i generatori. Un giro di tre round. |
| **Come rigirarlo** | `bash ipa/test/remeasure_xdp.sh nuove`; oppure `bench_throughput.py --mode rates --gen-cpus 10 --dut-cpus 6 --frames 64 --rounds 3 --rates 0.05,0.5,1,1.5,2,2.5,3` |

### E4 — Il costo del nodo per pacchetto, e da che cosa non dipende ✅ ⚠️

| | |
|---|---|
| **Ipotesi** | Il costo del nodo dipende dalla pipeline, non dalla taglia del pacchetto né dalla classe decisa. |
| **Variabile modificata** | La taglia (64 / 512 / 1514 B), la classe (stato dei link e TTL cercati per ciascuna delle 6 classi raggiungibili). |
| **Metrica** | **Tempo di CPU per pacchetto**: occupazione del core del nodo nella finestra × 1 / elaborati; uno scrittore per coda (1 thread di generatore, 1 core del nodo, uscita su un core suo), una chiamata `test_run` per finestra. |
| **Risultato** | Il nodo lavora al **100%** e 1 / elaborati coincide con il tempo di CPU. Baseline **66**, P1 **115**, P1.5 **124**, P2 **293**, P3 **416 ns**; sopra la baseline +49 / +58 / +227 / +350. A 64 / 512 / 1514 B ogni pipeline costa uguale entro il 2,5%. Per classe: FORWARD P1 114–119, P1.5 122–126, P2 256–286, P3 423–432; **DROP ~+50 ns**: 168 / 180 / 309 / 473 (con il DROP la pagina si restituisce sul core del nodo, con l'inoltro sul core d'uscita), come il 30-09. |
| **Conclusione** | Il nodo tocca solo le intestazioni: il costo è per pacchetto. La porta d'uscita non conta, la decisione DROP sì. |
| **Limite dichiarato** | ⚠️ rxonly non satura (il nodo è al 77% con 19 Mpps offerti): i suoi 40 ns di CPU sono indicativi. La baseline satura appena (il generatore offre 15,1 Mpps, quanti il nodo ne regge). Fino al 2026-10-01 ogni chiamata `test_run` lasciava il generatore fermo ~12 ms: il nodo dormiva il ~13% della finestra anche a coda piena (i tempi di CPU di allora erano giusti, i Mpps bassi del ~13%). Lo hanno mostrato le statistiche di scheduling del thread NAPI del DUT (`results/diag_xdp/` contro `results/diag_xdp_lunga/`). P3 varia fra sessioni: 416–460 ns. Durante la misura per classe il pacchetto ha registrato 3 eventi di throttling e la CPU del generatore è scesa a 3,4 GHz (quella del DUT no): run marcato dal banco. |
| **Come rigirarlo** | `bash ipa/test/remeasure_xdp.sh`; oppure `bench_throughput.py --mode compare --generator xdp --egress-cpu auto --gen-cpus 10 --dut-cpus 6` (`--per-class`; `--frames 64,512,1514`) |

### E5 — Latenza end-to-end e bit rate ✅ ⚠️

| | |
|---|---|
| **Ipotesi** | Al crescere del bit rate la coda d'ingresso si riempie, il ritardo cresce e poi si perde; il punto in cui comincia dipende dalla pipeline. |
| **Variabile modificata** | Il rate chiesto: 16 punti da 0,5 a 12 Mpps (0,26–6,1 Gbit/s a 64 B), 5 giri; cadenza e timbro nel programma generatore di `xdp_gen` (un frame all'istante previsto, intestazione pktgen scritta all'invio). |
| **Metrica** | Inviati, ricevuti dal programma, inoltrati; ritardo end-to-end (timbro all'invio → contatore del nodo successivo, nessuna correzione); in più lo scheduling del thread NAPI del DUT e la diagnostica della cadenza. |
| **Risultato** | Cadenza esatta fino a 11 Mpps (98% a 12). Pulite fino a: P1 4,04 Gbit/s (si ferma a 8,64 Mpps; 1 / 115 ns = 8,69), P1.5 3,55 (8,06; 8,07), P2 1,54 (3,48; 3,41), P3 1,02 (2,33; 2,41). Perdita prima di XDP. Ritardo a coda piena P1 33–34 µs, P1.5 35–36, P2 80–84, P3 120–132 (256 ÷ capacità: 30, 32, 74, 110, più il tratto fino al nodo successivo). A basso carico 17–19 µs con il lotto da 256, **3–6 µs** con `--xdp-batch 32` (il frame non aspetta la fine del lotto nel generatore). |
| **Conclusione** | Il collo di bottiglia è il programma, il ritardo è la coda piena, e le capacità della curva coincidono con 1 / tempo di CPU per tutte e quattro le pipeline. |
| **Limite dichiarato** | ⚠️ La baseline sulla curva non arriva al suo limite (15,1 Mpps): da 9 Mpps perde ~1% con il nodo al 60%, perché con l'inoltro il generatore non va oltre ~9 Mpps; il banco la classifica `banco: nodo non saturo`. rxonly non arriva al suo (~19). Con il lotto da 32 la cadenza regge solo fino a ~2,5 Mpps. Il primo tentativo spediva l'80–87% del richiesto con il nodo all'~80%: erano le pause di ~12 ms di ogni chiamata `test_run`, trovate con le colonne `napi_*` e `gen_*` (E4). |
| **Come rigirarlo** | `bash ipa/test/remeasure_xdp.sh`; oppure `bench_bitrate.py --generator xdp --gen-cpus 10 --dut-cpus 6 --rates 0.5,1,1.5,2,2.5,3,3.5,4,5,6,7,8` (`--xdp-batch 32` per il basso carico) |

### E6 — La capacità cresce con i core ✅ ⚠️

| | |
|---|---|
| **Ipotesi** | Con i contatori per-CPU i core del nodo non si contendono niente di scritto a ogni pacchetto, quindi due code su due core danno circa il doppio, e il costo per pacchetto per core resta quello di un core. |
| **Variabile modificata** | Il numero di core e di code del DUT (1 o 2); con due core, il numero di code d'uscita (1 o una per core) e i core d'uscita (1 o 2). |
| **Metrica** | Pacchetti elaborati al secondo a saturazione e tempo di CPU per pacchetto per core, 3 giri. |
| **Risultato** | Un thread `xdp_gen` per coda, una coda e un core d'uscita per core (stessa sessione di E4): baseline 29,20, P1 16,84, P1.5 15,72, P2 6,74, P3 4,58 Mpps contro 15,13 / 8,69 / 8,07 / 3,41 / 2,41 su un core: **95–99% del doppio**; tempo di CPU per core 67 / 119 / 127 / 297 / 436 ns contro 66 / 115 / 124 / 293 / 416; persi dopo XDP ≤ 0,04%. Con pktgen (01-10, 4 thread, due per coda) il rapporto è 1,93–1,99. |
| **Conclusione** | Il costo misurato su un core è quello da moltiplicare per il numero di code di una scheda con RSS. Il banco lo mostra solo con uno scrittore per coda anche in uscita: con una coda d'uscita condivisa dai due core un core d'uscita solo si fermava a ~10 Mpps (baseline 13,15 elaborati, 49% perso dopo XDP). |
| **Limite dichiarato** | ⚠️ Solo 1 e 2 core: oltre, questa macchina non ha P-core liberi per generatore e DUT insieme. La baseline satura appena (respinti 1,8%, il generatore offre 29,8 Mpps). Il secondo core d'uscita (cpu5) è il fratello SMT della CPU 0, che tiene timer e IRQ non spostabili; `--egress-cpu auto` non lo sceglie e va indicato. |
| **Come rigirarlo** | `bench_throughput.py --mode compare --generator xdp --gen-cpus 10,1 --dut-cpus 6,8 --egress-cpu 3,5`; il confronto 1 coda / 3 code con `--egress-queues 1` (`results/generator_contention/xdp_2core_2thread_uscita_*`) |

### E7 — Sul traffico vero il costo segue la forma del modello ✅ ⚠️

| | |
|---|---|
| **Ipotesi** | I modelli sintetici caricati sul fabric si comportano come nel kernel: P2 e P3 costano per la forma, P1 per i valori dei pesi, e uno strato in più ha un costo fisso per pipeline. |
| **Variabile modificata** | Il modello: checkpoint, `deep` (65-4-4-4-7), `small` (15-4-4), `mixed` (18-6-5), `large` (117-8-8-9), ciascuno sulla sua rete. |
| **Variabili fisse** | Banco di E4 (1 core, un thread `xdp_gen`, uscita su un core suo, 3 giri), pacchetto a TTL 32, uno stato dei link che il modello **inoltra** (cercato e stampato dal banco). |
| **Metrica** | Mpps a saturazione, ns di CPU sopra la baseline. |
| **Risultato** | Sopra la baseline, P1 / P1.5 / P2 / P3: checkpoint +52 / +59 / +225 / +393, deep +53 / +63 / +258 / +423, small +34 / +42 / +164 / +265, mixed +42 / +47 / +175 / +283, large +80 / +89 / N/A / N/A. Uno strato in più: +33 ns a P2 e +30 a P3 (nel kernel +24 e +44). Bit rate su deep (scala fino a 8 Mpps): pulite fino a ~4,06 (baseline, P1, oltre la scala) / 3,55 / 1,54 / 0,77 Gbit/s, perdita sempre all'ingresso. Con pktgen (29-09) le stesse differenze entro ~15 ns. |
| **Conclusione** | Il confronto fra pipeline tiene su modelli diversi; la forma pesa su P2 e P3, i valori dei pesi su P1. |
| **Limite dichiarato** | ⚠️ Un giro di misure per modello; il P3 del checkpoint qui dà 460 ns contro 416 di E4, la sua variazione fra sessioni, e lo strato in più di P3 ne resta dentro. Le latenze kernel dei sintetici (`results/models/kernel_battery.csv`) sono state prese a batteria: indicative. |
| **Come rigirarlo** | `bash ipa/test/remeasure_xdp.sh modelli` |

### E8 — Uno scrittore per coda: più thread di generatore peggiorano la misura ✅ ⚠️

| | |
|---|---|
| **Ipotesi** | Con i frame XDP il limite di ~7 Mpps di rxonly, baseline, P1 e P1.5 a 3 thread è il tetto del generatore. |
| **Variabile modificata** | Thread del generatore (1, 2, 3), core e code del nodo (1 o 2), uscita separata o sul nodo; generatore `xdp_gen` (con pktgen l'effetto è ~17 ns per pacchetto su tutte). |
| **Metrica** | Pacchetti elaborati, occupazione del core del nodo nella finestra, tempo di CPU per pacchetto. |
| **Risultato** | **Ipotesi falsa.** Su un core, con 1 / 2 / 3 thread la baseline elabora 12,4 / 7,3 / 7,2 Mpps, rxonly 14,9 / 9,8 / 7,4: più thread, meno elaborati. Su due core (alimentatore, una coda d'uscita condivisa come allora): 2 thread, uno per coda, contro 3 thread, due sulla stessa coda: baseline 13,0 contro 7,6 (+72%), P1 +46%, P1.5 +45%, P2 +6%, P3 +1%; le cifre assolute contengono anche la contesa in uscita (E6), il confronto fra le due righe no. Le cifre `xdp_gen` di questa scheda sono del 30-09, con il generatore fermo ~12 ms a ogni chiamata `test_run` (E4): basse in assoluto, il confronto fra righe regge. |
| **Conclusione** | Il limite era la coda d'ingresso condivisa da più scrittori, che rallenta anche il core del nodo. Regola: un solo scrittore per coda, in ingresso e in uscita (in uscita: una coda per core del nodo, E6). Con una scheda di rete vera la coda la riempie la scheda: un solo scrittore per costruzione. |
| **Controllo** | `rxonly_fwd` (rxonly che inoltra): a 3 thread 7,53 contro 7,21 Mpps di rxonly; la baseline (7,21) **non** supera rxonly. |
| **Limite dichiarato** | ⚠️ La serie 1 / 2 / 3 thread su un core è stata presa a batteria (differenze fino al doppio, concordi con le misure con l'alimentatore). La coda di `xdp_gen` è scelta dalla CPU che trasmette (CPU modulo code): è ciò che le misure mostrano, non verificato nel sorgente del kernel. |
| **Come rigirarlo** | `bench_throughput.py --mode compare --generator xdp --gen-cpus 10,1 --dut-cpus 6,8` contro `--gen-cpus 10,1,3`; `results/generator_contention/summary.csv` |

### E9 — Con pktgen la risposta è la stessa ✅

| | |
|---|---|
| **Ipotesi** | La risposta di E1 ed E5 è del nodo, non del generatore. |
| **Variabile modificata** | Il generatore: pktgen (`--generator pktgen`), skb copiate prima di XDP per l'headroom; 13 punti calibrati sul tetto di ricezione (0,12–2,98 Gbit/s). |
| **Risultato** | 28-09 (`results/bitrate_3500/`, `results/throughput_3500/`): capacità 3,31 / 2,94 / 2,81 / 1,89 / 1,50 Mpps (baseline, P1, P1.5, P2, P3), sopra la baseline +38 / +53 / +226 / +364 ns, come con `xdp_gen` entro la variazione fra sessioni; la copia e il percorso della skb costano 225–250 ns in più a tutte. Perdita sempre prima di XDP; la sola ricezione regge ~4,6 Mpps, e al traffico più alto rxonly perde il 21%. |
| **Conclusione** | Stesso collo di bottiglia e stesse differenze fra pipeline; capacità più basse per la copia, che su una NIC con XDP nativo non c'è. |
| **Come rigirarlo** | `bash ipa/test/remeasure_traffic.sh` |

## G. La macchina

### G1 — Con la macchina condizionata le misure si ripetono entro pochi punti ✅

| | |
|---|---|
| **Ipotesi** | La variabilità delle misure è della macchina (frequenza, idle, scheduling, temperatura), e si può togliere. |
| **Variabile modificata** | Le condizioni: frequenza fissa e misurata, C-state profondi spenti, core fisici distinti, isolamento a runtime (`host_conditions.py`). |
| **Metrica** | Dispersione fra trial e fra giri; eventi di throttling; frequenza reale del DUT. |
| **Risultato** | `test_suite`: spread 2–6%. `bench_bitrate`: variazione del massimo fra 5 giri 1,5–2,5%. `bench_throughput`: 0,2–0,9% (pktgen), 0,1–1,9% (frame grezzi). DUT a 3 494–3 495 MHz in ogni comando; nessun evento di throttling sui core in nessuna misura di questo registro; eventi di pacchetto 0–8 per comando (durante le compilazioni di `bench_scaling`, sugli altri core). |
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
  stesso processore collegati da `veth`: niente NIC, niente DMA. Le cifre in Mpps sono di questo percorso a 3,5 GHz; per un valore
  su una scheda di rete servono una seconda macchina e una NIC con XDP nativo.
- **Il costo del nodo di rxonly con frame XDP** (E4): con uno scrittore per coda il generatore non lo satura; il suo tempo di CPU è indicativo.
- **Le curve del bit rate per baseline e rxonly fino al loro limite** (E5): con l'inoltro un thread `xdp_gen` non va oltre ~9 Mpps, senza ~12,7, sotto i loro limiti su un core (15,1 e ~19).
- **Accuratezza del modello.** Il modello non è stato addestrato in questo lavoro. I test
  verificano che il datapath calcoli **la stessa cosa** del riferimento, non che quella
  cosa sia una buona politica di routing.
- **Reti oltre ~115 nodi.** `MAX_N_IN` è 128 in P2 e P3: per una topologia da 500 nodi
  bisogna alzare quel soffitto e rimisurare.
- **Che i pesi, a forma fissa, decidano se P1 si carica.** È possibile per C3 (il codice
  generato dipende dai valori), ma non è stato misurato variando il solo seme dei pesi.
- **Tre marcature e latenza minima su modelli diversi dal checkpoint.** `--mode rates` e
  `--latency` usano build strumentate generate dal sorgente del checkpoint.
- **Isolamento dal boot.** `isolcpus`, `nohz_full` e `rcu_nocbs` non sono usati: le CPU del
  banco restano soggette al tick e ai callback RCU.
