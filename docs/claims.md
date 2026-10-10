# Registro delle affermazioni sperimentali

Una riga della tesi che afferma qualcosa di misurabile deve poter essere
rintracciata fino all'esperimento che la sostiene. Questo documento è quella
mappa: per ogni affermazione, l'ipotesi, che cosa è stato mosso, che cosa è stato
tenuto fermo, che cosa è stato misurato, il numero ottenuto e il comando per
rifarlo.

**Le cifre vengono dalla campagna del 2026-10-06** (`results/campagna_2026-10-06/`,
sintesi in `sintesi.md`, log in `log/`), sulla macchina di laboratorio (Intel Core Ultra 7
155H, Ubuntu 24.04, kernel 6.8.0-142, bare metal) nelle condizioni di `host_conditions.py`:
core del banco fissi a **3 500 MHz misurati** (2 500 sul LP E-core), isolati, senza C6/C10
(`docs/testing.md` §0). Si rifanno tutte con

```bash
bash ipa/test/remeasure_campagna.sh   # traffico vero (P-, E-, LP E-core), assi sotto traffico, e remeasure_all.sh
bash ipa/test/remeasure_all.sh        # solo BPF_PROG_TEST_RUN, correttezza, analisi parametrica
```

Dove una scheda cita un altro comando, è quello.

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
| **Ipotesi** | Il codice funziona su Germany50 perché Germany50 è l'unica topologia provata. |
| **Variabile modificata** | La topologia: scenari sintetici (3/8, 4/16, 5/24, 2/6, 6/52 porte/nodi). |
| **Variabili fisse** | Le tre pipeline, il meccanismo di inferenza. |
| **Metrica** | Generazione, caricamento e consegna su ciascuna. |
| **Risultato** | **34/34** controlli sulle cinque topologie più lo scenario principale. |
| **Conclusione** | Nessuna dimensione di scenario è cablata nel motore. |
| **Limite dichiarato** | ⚠️ Lo sweep varia solo il TTL con tutti i link attivi, quindi esercita **una classe per topologia**. La copertura su tutte le classi c'è nello scenario singolo (A2). |
| **Come rigirarlo** | `sudo python3 ipa/test/test_fabric.py --sweep` (dentro `remeasure_all.sh`) |

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
| **Risultato** | **P1: 8/8** scenari a 300/300 (2 400 decisioni su 2 400). **P2 e P3: 7/7** a 300/300; `large` non applicabile (1 097 pesi oltre il blocco da 1 024 di P2; 9 uscite oltre il limite 8 di P3). La scala dichiarata diversa da 30 sposta davvero le decisioni su `ipa_ttl16` (41/300) e `small` (89/300). Controllo negativo: riscritto il solo byte `feat_ent.scale` al default, l'eBPF segue il riferimento al default su 300/300 e si stacca da quello dichiarato **esattamente** sui 41 casi previsti, quindi il kernel legge quel byte. |
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
| **Variabile modificata** | Il modello (`--model`: checkpoint, 8 preset sintetici da 11-2-3 a 117-8-8-9, le 18 cartelle degli assi di `traffic_models.py`) e la rete (`--topology`: 6 scenari in `topologies/`). |
| **Variabili fisse** | Le pipeline, i costruttori comuni (`pipeline_setup.py`), il riferimento generico. |
| **Metrica** | Classe e azione decise nel kernel contro il riferimento; pacchetto consegnato sulla porta attesa. |
| **Compatibilità** | Ogni feature larga quanto la dimensione della rete da cui dipende, scala del TTL uguale al TTL iniziale; limiti compilati di P2/P3 da `pipeline_limits.py`. Un'incompatibilità ferma il test prima di compilare, con il motivo. |
| **Risultato** | `test_model_source --kernel` **110/110** (scenario × modello × pipeline, 40 ingressi, model_id 0 e 190; `large` su P2/P3 non applicabile); suite kernel PASS su 9 modelli; i banchi di traffico misurano 18 modelli sintetici sugli assi (E8), anche con la build strumentata a tre marcature (E9). Col checkpoint, `--model checkpoint` e nessun `--model` danno pesi, scala, semantica e riferimento identici (3 000/3 000), e sorgenti di P1 e della foglia di P2 identici byte per byte. |
| **Controllo negativo** | Un modello incompatibile (one-hot a 52 su 30 nodi, TTL 16 su una rete a 30, 9 interfacce oltre il tetto) è rifiutato con il motivo: `test_model_source`, 62/62. Un modello che per il pacchetto del generatore decide DROP in ogni stato dei link non viene misurato come inoltro: il banco salta la pipeline. |
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
| **Risultato** | `test_suite`: baseline **14**, P1 **46**, P1.5 **52**, P2 **194**, P3 **318 ns**; istruzioni 135 / 606 / 1 019 / 15 089 / 12 288; letture 3 / 5 / 6 / 11 / 29; salti 0 / 1 / 1 / 1 / 3; spread 0–7%. Analisi parametrica (pesi sintetici): P1 specializzata **41**, P1.5 46, P2 192, P3 312 ns. Sul traffico vero (E4) la stessa scala: 117 / 124 / 290 / 425 ns di CPU per pacchetto. |
| **Conclusione** | **La flessibilità costa circa 7× in latenza** fra i due estremi (46 contro 318 ns), e il costo non è aritmetico: è in letture di mappa e salti fra programmi. |
| **Come rigirarlo** | `sudo python3 ipa/test/test_suite.py --only kernel`; `bench_scaling.py --out results/` |

### B2 — Aggiornare il modello costa millisecondi a ogni pipeline ✅

| | |
|---|---|
| **Ipotesi** | Compilare i pesi dentro il codice sposta il costo dal pacchetto al deployment. |
| **Variabile modificata** | La pipeline, su tutti gli assi dello sweep. |
| **Metrica** | `update_ms` (installare un modello nuovo su un nodo in servizio) e `build_ms` (compilazione). |
| **Risultato** | `update_ms`: P1 e P1.5 **0,4–2,2 ms** (caricamento dell'oggetto AOT), P2 e P3 **10–12 ms** (scritture in mappa). `build_ms`: P1 57–121 ms (clang, sulla macchina di build), P2 ~1,5 s e P3 ~1,2 s (BCC, una volta all'avvio del nodo). |
| **Conclusione** | Il costo di P1 è della **compilazione**, non dei pesi letterali: con l'oggetto precompilato aggiornare P1 non costa più di aggiornare P2/P3. Resta la differenza qualitativa: P1 richiede un compilatore (fuori dal nodo) per ogni modello nuovo, P2 e P3 no. |
| **Nota metodologica** | `build_ms` e `update_ms` non vanno confusi: per P2/P3 il primo è pagato una volta all'avvio del nodo, il secondo per modello. |
| **Come rigirarlo** | `bench_scaling.py --out results/` (figura `scaling_depth_update`) |

### B3 — L'AOT toglie il compilatore dal nodo senza costo per pacchetto ✅

| | |
|---|---|
| **Ipotesi** | Compilare l'oggetto fuori dal nodo elimina clang dal nodo, e la strength reduction sui pesi letterali sopravvive dentro l'oggetto. |
| **Variabile modificata** | Dove avviene la compilazione: macchina di build (clang, 78 ms) contro nodo. |
| **Metrica** | Costo di messa in servizio; latenza per pacchetto. |
| **Risultato** | Deploy dell'oggetto sul nodo **1,06 ms** (`open` 0,08 + verifica e JIT 0,97); latenza **52 ns** sul percorso d'inoltro (retval 4), come `test_suite`; 1 019 istruzioni (dispatch 29 + modello 990). Throughput reale P1.5: E4. |
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
| **Risultato** | P3 ha il **19% di istruzioni in meno** di P2 ed è il **64% più lento** (12 288 contro 15 089; 318 contro 194 ns). Le righe che lo spiegano: 3 salti contro 1, 29 letture contro 11. Sul traffico vero lo stesso ordine: 2,36 contro 3,45 Mpps, e le istruzioni **eseguite** per pacchetto, dai contatori hardware, sono l'opposto di quelle caricate (6 573 contro 4 556, E7). **Prova di rinforzo**: `IPA_MAX_QUEUES` da 1 a 8 porta `layer_first` da 7 003 a 10 528 istruzioni (+50%) senza cambiare nulla di ciò che gira, perché il descrittore non dichiara la feature coda. |
| **Conclusione** | `xlated` misura quanto è **grande** il programma caricato, non quanto **lavora**. In questo regime dominano letture di mappa e salti. |
| **Come rigirarlo** | `test_suite.py --only kernel`; per i tetti, ricompilare `layer_first` con un altro `IPA_MAX_QUEUES` (`ebpf_modular.py`) |

### C2 — La larghezza dell'ingresso è gratis a runtime; quella nascosta no ✅

| | |
|---|---|
| **Ipotesi** | Una rete più grande costa di più per pacchetto. **Falsa per la one-hot.** |
| **Variabile modificata** | Numero di nodi (10 → 100) e neuroni per hidden layer (2 → 8). |
| **Metrica** | Latenza minima su 7 trial; sul traffico vero, tempo di CPU per pacchetto. |
| **Risultato** | Nodi: P1 specializzata 39–42, P1.5 45–47, P2 188–192, P3 310–317 ns, **piatte**, mentre le istruzioni di P1.5 vanno da 731 a 1 673. Neuroni: P1 26 → 68, P1.5 34 → 75, P2 178 → 216, P3 280 → 386 ns, in salita su tutte; sul traffico vero P1 104 → 145, P3 391 → 496 ns di CPU (E8). Sul traffico vero anche i nodi: da 10 a 100 il costo della rete neurale resta piatto su tutte (E8). |
| **Conclusione** | Una one-hot ha un solo uno, quindi il datapath legge una colonna di pesi qualunque sia la sua larghezza. Un layer denso più largo legge più pesi. **La rete può crescere quanto vuole, il modello no.** |
| **Come rigirarlo** | `bench_scaling.py --axis nodes` e `--axis width` |

### C3 — In P1 il conteggio istruzioni e il tempo dipendono dai valori dei pesi ✅

| | |
|---|---|
| **Ipotesi** | Con i pesi letterali nel C il compilatore cancella i prodotti per zero: la dimensione dipende dai **valori**, non solo dalla forma. |
| **Variabile modificata** | La frazione di pesi zero: 0, 25, 50, 75, 90%. |
| **Variabili fisse** | Forma 65-4-4-7; pesi prefisso di un pool fisso. |
| **Risultato** | P1.5: 1 045 → 337 istruzioni e 45 → 25 ns. P1 specializzata: 618 → 243 e 40 → 19 ns. P2: 15 089 istruzioni e 187–188 ns a tutte le sparsità; P3: 12 288 e 307–311 ns. Sul traffico vero, al 90% di zeri, P1 113 → 95 e P1.5 120 → 106 ns di CPU, P2 e P3 fermi; istruzioni eseguite di P1 1 210 → 939 (E8). |
| **Conclusione** | Al 90% di zeri P1 più che dimezza la latenza sotto `BPF_PROG_TEST_RUN`; per P2 e P3 uno zero è un byte in tabella come un altro. È l'asse su cui scendono insieme dimensione e tempo. |
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
| **Risultato** | Istruzioni: specializzata 602–618 (**piatta**), P1.5 731 → 1 673. Codice nativo: 2 692–2 754 contro 3 332 → 8 325 byte. Latenza: 39–42 contro 45–47 ns (**−11–15%**, 5–7 ns). |
| **Controllo** | Sull'asse descrittore, dove il vettore d'ingresso non contiene `node`, le due P1 sono identiche alla cifra (611/611, 604/604); dove lo contiene divergono (618 contro 1 045). |
| **Conclusione** | La dimensione crolla e il tempo cala poco, per la stessa ragione: lo switch ha N casi ma ne esegue uno. È ciò che rende P1 praticabile su una rete grande. |
| **Contro-risultato** | Con pesi sparsi il vantaggio quasi si annulla (243 contro 337 istruzioni al 90% di zeri): sparsità e nodo congelato sono due strade alla stessa riduzione. I binari da installare passano da uno a N (~70 ms di clang ciascuno). |
| **Come rigirarlo** | `bench_scaling.py --axis nodes`; figura `duel_p1_vs_p15.pdf` |

### C7 — Non generare le colonne delle porte assenti toglie lavoro vero ✅

| | |
|---|---|
| **Ipotesi** | `link_state` è un vettore **denso**: il datapath esegue una moltiplicazione-accumulo per ogni coppia (interfaccia, neurone). Non generare le colonne assenti toglie lavoro eseguito, non solo codice morto. |
| **Variabile modificata** | Il numero di porte presenti, 2–6, via `static_ports`. |
| **Variabili fisse** | Modello 65-4-4-7, 52 nodi, **gli stessi pesi** in ogni punto. |
| **Controllo** | `hardcoded`, `template` e `modular` non specializzano e devono restare piatte. |
| **Risultato** | Istruzioni 534 / 554 / 570 / 594 / 618 per grado 2–6: **~21 per porta**, lineare; grado 2 contro 6 **−14%**. Latenza **37 / 38 / 39 / 39 / 40 ns**, monotona: −3 ns fra grado 6 e grado 2 (16 moltiplicazioni-accumulo). Controllo riuscito: 1 045 / 15 089 / 12 288 istruzioni e latenze piatte (45–46, 188–193, 309–310 ns) su tutti i punti. |
| **Conclusione** | Diversamente dal nodo congelato (C6), qui le moltiplicazioni tolte sono davvero eseguite, e la misura le vede: ~1 ns per porta. |
| **Come rigirarlo** | `bench_scaling.py --axis degree` |

### C8 — Il costo per MAC **eseguita** è una costante della pipeline ✅

| | |
|---|---|
| **Ipotesi** | La latenza si predice dalle MAC contate sulla forma del modello (n_in × h1, …). |
| **Variabile modificata** | Quattro assi: colonne dense (n_in 5 → 17), colonne one-hot (16 → 65), larghezza (4 → 32), profondità (1 → 4 strati). |
| **Metrica** | Pendenza e r² della retta sui quattro assi insieme, con MAC nominali e con MAC eseguite. |
| **Risultato** | Eseguite: **0,287 / 0,292 / 0,574 / 1,195 ns/MAC** (P1 statica, P1.5, P2, P3), r² **0,99 / 0,98 / 0,71 / 0,92**. Nominali: r² 0,63 / 0,69 / 0,24 / 0,10. **Sotto traffico** (`xdp_gen`, tempo di CPU meno la baseline, ingressi densi, one-hot e larghezza, 11 punti per pipeline): **0,22 / 0,18 / — / 0,69 ns/MAC**, r² 0,89 / 0,71 / 0,09 / 0,94; dalla forma r² ≤ 0,22. P2 non sta su una retta sola: ~0,2 ns/MAC in ogni esperimento, con un costo di partenza che cambia con l'ingresso. La profondità resta fuori dalla retta (costo fisso per strato, D3). |
| **Conclusione** | Con le MAC nominali il modello spiega poco; con quelle eseguite i quattro assi collassano sulla stessa retta. Una one-hot occupa `size` colonne ma ne attiva una. **P3 costa 4,2× P1 per MAC eseguita**: il prezzo della genericità espresso in una costante. |
| **Controprova** | Sull'asse one-hot n_in ×4 e pesi ×2,4, latenza piatta su tutte (p1_static e P1.5 63–65, P2 168–170, P3 361–367 ns) mentre le istruzioni di P1 vanno da 1 099 a 1 587. |
| **Limite dichiarato** | ⚠️ P2 ha r² più basso: un costo fisso alto rispetto alla pendenza, e il residuo più grande su `width_camp`, dove i neuroni oltre la larghezza del modello si calcolano comunque fino al soffitto. |
| **Come rigirarlo** | `bench_scaling.py --axis campaign --out results/`, poi `--plot results/` |

### C9 — Un salto condizionale per neurone basta a esaurire il verificatore ✅ ⚠️

| | |
|---|---|
| **Ipotesi** | I limiti di caricamento di P2 e di P1 dipendono dal kernel. **Falsa: dipendono da come è scritta la ReLU.** |
| **Variabile modificata** | Come è scritta la ReLU: `x > 0 ? x : 0` (un salto per neurone, variante `salto`) contro `ipa_relu`, `x & ~(x >> 63)` dietro una barriera `asm volatile("")`, stesso risultato bit per bit e nessun salto (variante `attuale`, quella delle pipeline). |
| **Variabili fisse** | Kernel 6.8.0-142, forme, pesi, descrittore default; tutto il resto del sorgente. |
| **Metrica** | Istruzioni percorse dal verificatore (`log_level = 4`, limite 1 000 000), stati salvati; se il programma carica. |
| **Risultato** | P2, da 1 a 6 strati: con il salto 799 563 / 417 292 / rifiutato / … ; con `ipa_relu` 120 452 / 120 557 / 127 906 / 127 738 / 134 413 / 136 642, e 201 528 a 20 strati. P1 tier B (~1 200 pesi, `default`): con il salto larga, 2 e 4 strati rifiutate (1 000 001); con `ipa_relu` 5 698–8 516, tutte caricano. P3 `layer_hidden`: 186 489 → 27 979. |
| **Conclusione** | Il verificatore paga i cammini: un bivio per neurone li moltiplica. Con `ipa_relu` P2 carica fino a **20 strati**; il limite successivo è la distanza di salto eBPF (offset a 16 bit: a 37 strati `LLVM ERROR: Branch target out of insn range`), poi la tabella dei pesi (1 024: 37 strati a larghezza 4, 7 a larghezza 8). Anche la barriera `asm` è necessaria: senza, clang riconosce `smax(x, 0)` e rimette il salto. |
| **Limite dichiarato** | ⚠️ Fra 20 e 37 strati il punto esatto in cui clang si ferma non è misurato. |
| **Come rigirarlo** | `sudo python3 ipa/test/diag_verifier.py` (varianti `attuale` e `salto`, dentro `remeasure_all.sh`); `--only p2 --depths 6,10,20,37` |

---

## D. Larga contro profonda

### D1 — «Allargare batte approfondire» vale solo per certi ingressi, e solo sotto un limite ✅

| | |
|---|---|
| **Ipotesi** | Dato un numero di parametri, spenderli in un layer largo costa meno che in molti stretti. **Vera solo per certi vettori d'ingresso.** |
| **Variabile modificata** | La profondità: 1, 2, 4, 8 hidden layer, in P1 (oggetto AOT). |
| **Variabili fisse** | Il budget-pesi, con la larghezza risolta per descrittore e lo scarto stampato. Tre tier: ~300, ~1 200, ~4 700 pesi. Quattro descrittori. |
| **Metrica** | Latenza (min di 7 trial), istruzioni, e se il programma si carica. |
| **Risultato, tier A (~300 pesi)** | `default` (2 one-hot, n_in 65): larga **39** ns, 2 strati 44, 4 strati 48, 8 strati 62 (**+59%**). `no_onehot` (n_in 11): 93 / 90 / 85 / **83 ns (−11%)**, e 8 strati più piccola (1 323 contro 1 490 istruzioni). |
| **Risultato, tier B (~1 200 pesi)** | `default`: larga **105** ns, 2 strati 145, 4 strati 165, 8 strati 211 (**+101%**). `no_onehot`: larga e 2 strati non compilano (stack eBPF oltre 512 byte), 4 strati 330, 8 strati **295 ns (−11%)**. **Tier C**: nessuna forma compila (stack). |
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
| **Risultato, latenza (ns)** | P1 specializzata 56 / 54 / 57 / 67 / 68; P1.5 62 / 64 / 63 / 72 / 71; P2 175 / 190 / 207 / 254 / **268 (+53%)**; P3 284 / 328 / 358 / 445 / **490 (+73%)**. Sul traffico vero (E8): P2 276 → 373 (+35%), P3 380 → 607 (+60%), le P1 125–135 ns. |
| **Risultato, istruzioni** | P1 specializzata 844–1 051, P1.5 1 731–1 816, P2 14 604 → 17 939, P3 **12 288 a tutti i punti**. |
| **Conclusione** | Le due P1 crescono poco e non in modo monotono; P2 paga lo strato in codice, P3 un tail call per strato a codice identico. Chi sceglie l'architettura deve sapere su quale pipeline girerà. |
| **Come rigirarlo** | `bench_scaling.py --axis isoparam` |

### D3 — Perché la profondità costa, quando costa ✅

| | |
|---|---|
| **Ipotesi** | Il costo di un layer in più non è aritmetico: è un costo fisso di transizione. |
| **Variabile modificata** | Il numero di layer (`depth` a parametri crescenti, `depth_camp` a larghezza 8, `isoparam`). |
| **Metrica** | Latenza per layer aggiunto; tail call; il costo del solo salto; istruzioni eseguite per pacchetto. |
| **Risultato** | P3 su `depth` (1 → 6 strati da 4): **260 → 524 ns**, ~53 ns per strato, istruzioni caricate ferme a 12 288. P2: 171 → 300 ns, ~26 ns e ~870 istruzioni per strato. P1 specializzata 33 → 61 ns (~6 per strato). Il salto `PROG_ARRAY` da solo costa **+1 ns** (`bench_tailcall_overhead`: 9 → 10 ns). Sul traffico vero P3 paga ~60 ns per strato e i contatori hardware contano **+1 096 istruzioni eseguite per strato**, esatte, su P-core ed E-core (E8). |
| **Conclusione** | In P3 **dimensione costante, tempo crescente** è la firma di un costo di transizione. Ma il salto in sé è quasi gratuito: i ~53 ns per strato sono le letture di mappa che ricostruiscono il contesto a ogni hop (`scratch_meta`, `scratch_acts`, `layer_shapes`, i pesi), e le ~1 100 istruzioni che le fanno. |
| **Come rigirarlo** | `bench_scaling.py --axis depth`; `bench_tailcall_overhead.py` |

---

## E. Traffico vero

Fino alla sezione D ogni cifra in ns viene da `BPF_PROG_TEST_RUN`. Qui ci sono pacchetti
veri: frame XDP grezzi da `xdp_gen`, consegnati al nodo come da una NIC con XDP nativo, un
fabric `veth`, contatori all'ingresso e all'uscita, generatore, DUT e nodo successivo su
core fisici distinti, un thread di generatore per coda e una coda d'uscita per core del nodo
(`docs/testing.md` §10.1–§10.4). Tutte le misure di traffico vengono da
`remeasure_campagna.sh`; dove non è detto altro, il nodo è un P-core (cpu6) a 3,5 GHz.

### E1 — Sotto capacità il nodo non perde niente; oltre, perde all'ingresso ✅

| | |
|---|---|
| **Ipotesi** | Le perdite su un banco `veth` possono essere della pipeline, del trasporto o della ricezione; vanno separate. |
| **Variabile modificata** | Il carico offerto; il punto di conteggio (inviati, ricevuti da XDP, decisioni, inoltrati); il tipo di core del nodo. |
| **Metrica** | Perdita prima di XDP, dopo XDP, e del solo contatore (`rxonly`) allo stesso rate. |
| **Risultato** | Saturazione (`bench_throughput --mode compare --generator xdp`, 1 core): baseline 15,27, P1 8,56, P1.5 8,04, P2 3,45, P3 2,36 Mpps, nodo al 100%; rxonly 19,47 senza saturare. `bench_bitrate`, 16 punti da 0,5 a 12 Mpps, 5 giri: sotto capacità nessuna perdita (≤ 0,05%); oltre, per P1, P1.5, P2 e P3 la perdita è **prima di XDP**, con il nodo al 99,5–100%, e dopo XDP al massimo lo 0,04%. `rxonly` non perde fino a 11 Mpps (0,1% a 12, dove cede il generatore): la perdita delle pipeline è del programma. Lo stesso sull'E-core, con il ginocchio alla sua capacità. |
| **Conclusione** | Il collo di bottiglia è il programma eBPF, all'ingresso, su ogni tipo di core. Un nodo sotto la sua capacità consegna tutto. |
| **Come rigirarlo** | `bash ipa/test/remeasure_campagna.sh pcore ecore` |

### E2 — I banchi misurano la stessa grandezza ✅

| | |
|---|---|
| **Ipotesi** | `test_suite` e l'analisi parametrica, che usano entrambi `BPF_PROG_TEST_RUN`, danno lo stesso numero; e così `bench_throughput` e `bench_bitrate` sul traffico vero; e il tempo di CPU coincide con i cicli contati dall'hardware. |
| **Risultato** | Stesso modello 65-4-4-7: campagna 14 / 45 / 187 / 308 ns contro `test_suite` 14 / 52 / 194 / 318 (entro 0…−13%, pesi sintetici contro pesi del modello: 1 045 contro 1 019 istruzioni per P1.5). Traffico: la curva di `bench_bitrate` si ferma a P1 8,66, P1.5 8,17, P2 3,45, P3 2,37 Mpps contro 8,56 / 8,04 / 3,45 / 2,36 a massima spinta, entro il 2% (con il contatore davanti, da −3,3 a +2,1 ns). Cicli per pacchetto contro ns × 3,5 GHz: baseline 225 contro 231, P3 1 483 contro 1 487; la frequenza ricavata dai cicli (3,4–3,5 GHz) coincide con quella di APERF/MPERF. |
| **Metodo che lo rende vero** | Il frame si rinfresca ogni 200 esecuzioni da TTL 255: `BPF_PROG_TEST_RUN` non ripristina il buffer e il datapath decrementa il TTL, e un frame riusato arriverebbe a TTL 1 e prenderebbe il ramo che salta la coda di inoltro. |
| **Come rigirarlo** | Tutti nella stessa campagna. |

### E3 — Il costo della pipeline si separa da quello del trasporto ✅

| | |
|---|---|
| **Ipotesi** | La latenza da arrivo a partenza tiene insieme due costi che si possono separare, e il secondo non dipende dalla pipeline. |
| **Variabile modificata** | Dove si prende il tempo: tre marcature (T1 ingresso del dispatcher, T2 prima di `bpf_redirect`, T3 ingresso del contatore all'altro capo); il tipo di core del nodo. |
| **Risultato** | P-core: T2−T1 **26 / 60 / 69 / 216 / 331 ns** (baseline, P1, P1.5, P2, P3), piatto sul rate da 0,5 a 3 Mpps. T3−T2: **206–222 ns per tutte e cinque**. Sopra la baseline la sola pipeline: +34 / +43 / +190 / +305 ns. Latenza minima arrivo → ripartenza (T3−T1 a 50 kpps): 221 / 259 / 274 / 442 / 609 ns. E-core: T2−T1 28 / 72 / 84 / 266 / 434, T3−T2 240–256, T3−T1 minimo 282 / 329 / 346 / 555 / 727 ns. |
| **Conclusione** | Il trasporto è un costo comune (~210 ns sul P-core, ~245 sull'E-core) che non dipende dal lavoro della pipeline. |
| **Limite dichiarato** | ⚠️ Build **strumentata**: due letture dell'orologio e due scritture per pacchetto che il datapath di produzione non fa. Il throughput di questa modalità non è una capacità: l'uscita resta sulla CPU del DUT. Tre giri. |
| **Come rigirarlo** | `bench_throughput.py --mode rates --generator xdp --gen-cpus 10 --dut-cpus 6 --frames 64 --rounds 3 --rates 0.05,0.5,1,1.5,2,2.5,3` (`--dut-cpus 12` per l'E-core) |

### E4 — Il costo del nodo per pacchetto, e da che cosa non dipende ✅ ⚠️

| | |
|---|---|
| **Ipotesi** | Il costo del nodo dipende dalla pipeline, non dalla taglia del pacchetto né dalla porta d'uscita. |
| **Variabile modificata** | La taglia (64 / 512 / 1514 B), la classe (stato dei link e TTL cercati per ciascuna delle 6 classi raggiungibili). |
| **Metrica** | **Tempo di CPU per pacchetto**: occupazione del core del nodo nella finestra × 1 / elaborati; uno scrittore per coda (1 thread di generatore, 1 core del nodo, uscita su un core suo), una chiamata `test_run` per finestra. |
| **Risultato** | Il nodo lavora al **100%** e 1 / elaborati coincide con il tempo di CPU. Baseline **66**, P1 **117**, P1.5 **124**, P2 **290**, P3 **425 ns**; sopra la baseline +51 / +58 / +224 / +359. A 64 / 512 / 1514 B ogni pipeline costa uguale entro l'1%. Per classe: FORWARD P1 118–120, P1.5 124–127, P2 245–274, P3 416–426; **DROP ~+50 ns**: 166 / 176 / 304 / 467 (con il DROP la pagina si restituisce sul core del nodo, con l'inoltro sul core d'uscita). |
| **Conclusione** | Il nodo tocca solo le intestazioni: il costo è per pacchetto. La porta d'uscita non conta, la decisione DROP sì. |
| **Limite dichiarato** | ⚠️ rxonly non satura (il nodo è al 79% con 19,6 Mpps offerti): i suoi 41 ns di CPU sono indicativi. La baseline satura appena (il generatore offre 15,3 Mpps). P3 varia fra misure della stessa giornata: lo stesso 65-4-4-7 dà 416–445 ns. |
| **Come rigirarlo** | `bash ipa/test/remeasure_campagna.sh pcore`; oppure `bench_throughput.py --mode compare --generator xdp --gen-cpus 10 --dut-cpus 6 --egress-cpu 8` (`--per-class`; `--frames 64,512,1514`) |

### E5 — Latenza end-to-end e bit rate ✅ ⚠️

| | |
|---|---|
| **Ipotesi** | Al crescere del bit rate la coda d'ingresso si riempie, il ritardo cresce e poi si perde; il punto in cui comincia dipende dalla pipeline. |
| **Variabile modificata** | Il rate chiesto: 16 punti da 0,5 a 12 Mpps (0,26–6,1 Gbit/s a 64 B), 5 giri; cadenza e timbro nel programma generatore di `xdp_gen` (un frame all'istante previsto, intestazione pktgen scritta all'invio); il tipo di core del nodo. |
| **Metrica** | Inviati, ricevuti dal programma, inoltrati; ritardo end-to-end (timbro all'invio → contatore del nodo successivo, nessuna correzione); in più lo scheduling del thread NAPI del DUT e la diagnostica della cadenza. |
| **Risultato** | Cadenza esatta fino a 11 Mpps (98% a 12). P-core, pulite fino a: P1 e P1.5 8 Mpps (4,04–4,08 Gbit/s; si fermano a 8,66 e 8,17 Mpps), P2 3 Mpps (1,54 Gbit/s; 3,45), P3 2 Mpps (1,02 Gbit/s; 2,37). Perdita prima di XDP. Ritardo a coda piena P1 34–35 µs, P1.5 35–36, P2 78–86, P3 116–126 (256 ÷ capacità: 30, 32, 74, 108, più il tratto fino al nodo successivo); a basso carico 17–19 µs (attesa a fine lotto nel generatore). E-core: inoltro massimo 9,34 / 6,24 / 5,81 / 2,81 / 1,93 Mpps, ritardo a coda piena 29 / 45 / 49 / 103 / 148 µs. |
| **Conclusione** | Il collo di bottiglia è il programma, il ritardo è la coda piena, e le capacità della curva coincidono con 1 / tempo di CPU per tutte e quattro le pipeline. |
| **Limite dichiarato** | ⚠️ Sul P-core la baseline sulla curva non arriva al suo limite (15,3 Mpps): da 9 Mpps perde ~1,3% con il nodo al 60%, perché con l'inoltro il generatore non va oltre ~9 Mpps; il banco la classifica `banco: nodo non saturo`. rxonly non arriva al suo (~19). |
| **Come rigirarlo** | `bash ipa/test/remeasure_campagna.sh pcore ecore`; oppure `bench_bitrate.py --generator xdp --gen-cpus 10 --dut-cpus 6 --egress-cpu 8` |

### E6 — La capacità cresce con i core ✅ ⚠️

| | |
|---|---|
| **Ipotesi** | Con i contatori per-CPU i core del nodo non si contendono niente di scritto a ogni pacchetto, quindi due code su due core danno circa il doppio, e il costo per pacchetto per core resta quello di un core. |
| **Variabile modificata** | Il numero di core e di code del DUT (1 o 2); il tipo di core (P o E). |
| **Metrica** | Pacchetti elaborati al secondo a saturazione e tempo di CPU per pacchetto per core, 3 giri. |
| **Risultato** | Un thread `xdp_gen` per coda, una coda e un core d'uscita per core. 2 P-core: baseline 29,11, P1 17,46, P1.5 16,19, P2 6,63, P3 4,60 Mpps, **95–102% del doppio**, tempo di CPU per core 67 / 114 / 124 / 301 / 434 ns. 2 E-core (uno per modulo): 19,09 / 12,74 / 11,71 / 5,60 / 3,84 Mpps, **99–102% del doppio**, 105 / 157 / 171 / 357 / 521 ns. |
| **Conclusione** | Il costo misurato su un core è quello da moltiplicare per il numero di code di una scheda con RSS. Vale con uno scrittore per coda anche in uscita: una coda e un core d'uscita per core del nodo. |
| **Limite dichiarato** | ⚠️ Solo 1 e 2 core: oltre, questa macchina non ha P-core liberi per generatore, DUT e uscita insieme. La baseline su 2 P-core satura appena (respinti 2%). Il secondo core d'uscita del P-core (cpu5) è il fratello SMT della CPU 0, che tiene timer e IRQ non spostabili; `--egress-cpu auto` non lo sceglie e va indicato. rxonly su 2 E-core dà il 117% del doppio: solo il riferimento di sola ricezione, il più variabile fra i giri. |
| **Come rigirarlo** | `bench_throughput.py --mode compare --generator xdp --gen-cpus 10,1 --dut-cpus 6,8 --egress-cpu 3,5`; `--dut-cpus 12,16 --egress-cpu 6,8` |

### E7 — Su un core lento il nodo regge meno, e la differenza è di IPC ✅ ⚠️

| | |
|---|---|
| **Ipotesi** | Spostare il nodo da un P-core a un E-core (o a un LP E-core) riduce la capacità; a parità di frequenza la riduzione viene dal numero di istruzioni per ciclo, non dal codice, e pesa allo stesso modo su tutte le pipeline. |
| **Variabile modificata** | Il core del nodo: P-core (cpu6) ed E-core (cpu12, compagni di modulo 13-15 a riposo) a 3,5 GHz, LP E-core (cpu20) a 2,5 GHz, il suo massimo. |
| **Variabili fisse** | Generatore (cpu10) e uscita (cpu8) su P-core a 3,5 GHz, pipeline, modello, pacchetto, 3 giri, alimentatore. |
| **Metrica** | Mpps elaborati, tempo di CPU per pacchetto; istruzioni, cicli, mancate di cache per pacchetto dai contatori hardware del core del nodo (`hw_counters.py`, stessa finestra dei pacchetti). |
| **Risultato** | Mpps P / E / LP E: baseline 15,27 / 9,39 / 3,29*, P1 8,56 / 6,35 / 3,10, P1.5 8,04 / 5,84 / 2,91, P2 3,45 / 2,83 / 1,57, P3 2,36 / 1,94 / 1,10. E/P **0,61** (baseline), 0,74, 0,73, **0,82**, **0,82**. Istruzioni per pacchetto identiche entro il 2% sui tre core (606 / 1 220 / 1 426 / 4 556 / 6 573). IPC P / E: 2,7 / 1,7 (baseline), 3,0 / 2,3, 3,3 / 2,4, 4,5 / 3,7, 4,4 / 3,7; LP E 0,8–2,9, con 14–19 mancate dell'ultimo livello di cache per pacchetto (P ed E ~0). |
| **Conclusione** | **L'ipotesi vale per la prima metà, non per la seconda.** Il codice è lo stesso, la differenza è l'IPC; ma l'E-core penalizza soprattutto la parte fissa del nodo (ricezione, redirect, pagina: +60% di tempo) e poco l'aritmetica della rete (inferenza di P3 sopra la baseline +14%). Più la pipeline è pesante, più il rapporto si avvicina a 1. Il LP E-core, fuori dalla L3, paga anche la memoria: 36–47% del P-core sulle pipeline. |
| **Limite dichiarato** | ⚠️ \* rxonly e baseline sul LP E-core non saturano (nodo al 72% e al 93%): il generatore offre solo 4,1 e 3,3 Mpps, e le loro cifre sono un limite inferiore. Il perché il generatore rallenti verso il LP E-core non è misurato. Gli E-core a 3,8 GHz (il loro massimo) non sono misurati: ci si aspetta capacità più alte di circa l'8%. |
| **Come rigirarlo** | `bash ipa/test/remeasure_campagna.sh ecore lpe`; `bench_throughput.py --mode compare --generator xdp --gen-cpus 10 --dut-cpus 12 --egress-cpu 8` |

### E8 — Gli andamenti degli assi valgono sul nodo vero ✅ ⚠️

| | |
|---|---|
| **Ipotesi** | Quello che larghezza, profondità, pari pesi e sparsità fanno sotto `BPF_PROG_TEST_RUN` (C2, C3, D2, D3) lo fanno anche sul traffico vero, più il costo fisso del nodo. |
| **Variabile modificata** | Il modello: 30 cartelle sintetiche (`traffic_models.py`): 65-v-v-7 (v = 2…8), 65-4×d-7 (d = 1…6), le cinque forme a ~592 pesi, 65-4-4-7 al 0 / 50 / 90 % di zeri, con il descrittore del checkpoint; e con una rete propria per punto (`topology_config.json` nella cartella) (13+n)-4-4-7 per n = 10…100 nodi, ingressi densi n-8-8-7 (n = 5…17) e one-hot n-8-8-7 (n = 16…65); il core del nodo (P o E). |
| **Variabili fisse** | Il banco di E4, il seme dei pesi (tranne tre punti dove quel seme decide DROP per il pacchetto del generatore in ogni stato dei link: lì il seme successivo). |
| **Metrica** | Tempo di CPU per pacchetto; istruzioni eseguite per pacchetto. |
| **Risultato** | Baseline 64–67 ns (P-core) e 105–107 (E-core) in ogni punto. Profondità: P3 351 → 652 ns (~60 per strato), **+1 096 istruzioni eseguite per strato esatte** (5 488 → 10 952) su entrambi i core; P2 264 → 396; P1 113 → 132. Larghezza: P1 104 → 145, P3 391 → 496. Pari pesi: P2 +35%, P3 +60% da 1 a 5 strati, P1 125–135. Sparsità al 90%: P1 113 → 95, P1.5 120 → 106, P2 e P3 fermi (istruzioni di P1 1 210 → 939, di P2 e P3 invariate). E-core: ogni punto +20–35%. Nodi (10 → 100, CPU meno baseline, P-core): piatti su tutte (P1 45–52, P2 221–237, P3 351–366 ns), istruzioni eseguite di P3 6 573–6 577. Ingressi one-hot 16 → 65: piatti; ingressi densi 5 → 17: P1 +12, P2 +40, P3 +72 ns. |
| **Conclusione** | Le conclusioni del programma da solo reggono sul nodo vero; i contatori hardware mostrano che P3 esegue lo stesso lavoro per ogni strato. |
| **Limite dichiarato** | ⚠️ Due campagne (6 e 10 ottobre, 3 giri per punto), entrambe a batteria senza throttling dei core (frequenza misurata 3,38–3,50 GHz); fra le due il tempo di CPU dei 180 punti × pipeline differisce dello 0,7% in mediana, al massimo del 6%. Un caricamento di P3 (E-core, 25 nodi) ha dato una volta 699 ns di CPU con IPC 2,8; un nuovo caricamento 533 ns, in linea: i punti fuori curva si rifanno. |
| **Come rigirarlo** | `bash ipa/test/remeasure_campagna.sh assi` (`ASSI_CORES`, `ASSI_SOLO`) |

### E9 — Sotto traffico la sola rete neurale costa quanto da sola, più la cache fredda ✅ ⚠️

| | |
|---|---|
| **Ipotesi** | Il costo della rete neurale misurato con `BPF_PROG_TEST_RUN` (programma da solo, pacchetto sempre caldo) è quello che il nodo paga davvero sotto traffico. |
| **Variabile modificata** | Il modo di misurare: T2−T1 della build strumentata (§10.6) sotto `xdp_gen` a 0,3 e 0,6 Mpps, contro il programma da solo; i 18 modelli degli assi di E8; il core del nodo (P o E). |
| **Variabili fisse** | Il banco di E3, i modelli e i semi di E8; baseline sottratta in entrambe le misure. |
| **Metrica** | ns di rete neurale per pacchetto: minimo per finestra e media, mediana fra 3 giri e 2 rate. |
| **Risultato** | P-core: il **minimo** coincide con il programma da solo entro 30 ns per P2 e P3 ed entro 12 per P1 e P1.5 (profondità, P3: 246 → 510 da solo, 262 → 508 minimo). La **media** sta sopra di 10–40 ns per P1 e P1.5 e di 40–110 ns per P2 e P3 (P3 a 6 strati: 610 contro 510), con gli stessi andamenti su ogni asse. E-core: scarto circa doppio (P3 110–210, P2 75–130 ns). Sul checkpoint la media sopra la baseline (P1 44, P2 229, P3 364 ns) coincide con il tempo di CPU di E4 meno la baseline (51, 224, 359). |
| **Conclusione** | Le conclusioni del programma da solo valgono per l'inferenza sul nodo vero. `BPF_PROG_TEST_RUN` misura il caso migliore; il costo tipico sotto traffico è la media di T2−T1, e coincide con il tempo di CPU sopra la baseline. |
| **Limite dichiarato** | ⚠️ Una campagna (10 ottobre), a batteria. A 0,3–0,6 Mpps il core resta fermo fra un pacchetto e l'altro: la media descrive il nodo poco carico. La build strumentata legge l'orologio due volte in più; la sottrazione della baseline toglie quel costo. Un caricamento di P3 (1 strato, E-core) ha dato una volta 502 ns invece di 368, stabile su sei finestre: un punto fuori curva si rifà con un nuovo caricamento. |
| **Come rigirarlo** | `bash ipa/test/remeasure_campagna.sh assi` (T2−T1 in `<punto>/rates/`; `ASSI_RATES`, `ASSI_T2=0`); un modello a mano: `bench_throughput.py --mode rates --generator xdp --rates 0.3,0.6 --model <cartella>` |

## G. La macchina

### G1 — Con la macchina condizionata le misure si ripetono entro pochi punti ✅

| | |
|---|---|
| **Ipotesi** | La variabilità delle misure è della macchina (frequenza, idle, scheduling, temperatura), e si può togliere. |
| **Variabile modificata** | Le condizioni: frequenza fissa e misurata, C-state profondi spenti, core fisici distinti (e moduli E-core interi), isolamento a runtime (`host_conditions.py`). |
| **Metrica** | Dispersione fra trial e fra giri; eventi di throttling; frequenza reale del DUT. |
| **Risultato** | `test_suite`: spread 0–7%. `bench_throughput`: P-core ripetuto in quattro misure diverse della stessa sessione (confronto, classe 0, 512 B, 1514 B) entro il 2% per baseline e P1.5. Fra due sessioni a quattro giorni di distanza (assi sotto traffico, 6 e 10 ottobre, 180 punti × pipeline) il tempo di CPU differisce dello 0,7% in mediana, del 3% al 90° percentile, al massimo del 6%. DUT a 3 472–3 507 MHz (E-core 3 472–3 493, LP E-core 2 498–2 501) in ogni misura; nessun evento di throttling nelle misure della campagna. |
| **Conclusione** | Le cifre sono ripetibili sulla stessa macchina alla stessa frequenza. |
| **Come rigirarlo** | `sudo python3 ipa/test/test_host_kernel.py --bench` (25/25) |

### G2 — La frequenza conta quasi in proporzione, il tipo di core no ✅ ⚠️

| | |
|---|---|
| **Ipotesi** | Il costo per pacchetto è lavoro di CPU e scala con la frequenza del core. |
| **Variabile modificata** | La frequenza fissa del banco: 2,0 / 3,0 / 3,5 / 4,0 / 4,5 GHz misurati; il tipo di core a frequenza fissa (E7). |
| **Risultato** | Da 3 a 4 GHz il throughput sale del 23% invece del 33% (uncore, cache e memoria non accelerano con il core); il rapporto fra pipeline resta lo stesso a ogni frequenza pulita. A 4,5 GHz 28/39 finestre in throttling; a 4,0 GHz un run da 5 minuti porta il pacchetto a 98 °C e il DUT in throttling. A frequenza fissa, invece, il tipo di core cambia i rapporti fra pipeline (E7). |
| **Conclusione** | Le cifre assolute vanno citate con la loro frequenza e il loro tipo di core. La frequenza di default del banco, 3,5 GHz, è la più alta che il portatile regge per un run intero. |
| **Limite dichiarato** | ⚠️ Con 1 400 MHz scritti nel sysfs il core gira a ~2 000 MHz misurati: la frequenza vera si misura (APERF/MPERF, e i cicli dei contatori hardware), non si legge. |
| **Come rigirarlo** | `bench_bitrate.py --freq <MHz> --method rxonly,baseline,template --rounds 1` |

---

## F. Che cosa nessun test di questo progetto dimostra

Dichiarato per non far sembrare coperto ciò che non lo è.

- **Throughput su hardware di rete.** Generatore, DUT e nodo successivo sono core dello
  stesso processore collegati da `veth`: niente NIC, niente DMA. Le cifre in Mpps sono di
  questo percorso a 3,5 GHz; per un valore su una scheda di rete servono una seconda
  macchina e una NIC con XDP nativo.
- **Il costo del nodo di rxonly con frame XDP** (E4): con uno scrittore per coda il
  generatore non lo satura sul P-core; il suo tempo di CPU è indicativo.
- **Le curve del bit rate per baseline e rxonly fino al loro limite sul P-core** (E5): con
  l'inoltro un thread `xdp_gen` non va oltre ~9 Mpps, senza ~12,7, sotto i loro limiti su un
  core (15,3 e ~19).
- **La capacità di baseline e rxonly sul LP E-core** (E7): il generatore non li satura.
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
