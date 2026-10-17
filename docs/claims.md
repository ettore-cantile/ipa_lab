# Registro delle affermazioni sperimentali

Una riga della tesi che afferma qualcosa di misurabile deve poter essere
rintracciata fino all'esperimento che la sostiene. Questo documento è quella
mappa: per ogni affermazione, l'ipotesi, che cosa è stato mosso, che cosa è stato
tenuto fermo, che cosa è stato misurato, il risultato e il comando per rifarlo.

**Le cifre di costo vengono dalla campagna di popolazione**
(`results/popolazione_2026-10/`, sintesi in `sintesi.md`, log in `log/`): ogni misura su
**109 modelli sintetici** (`model_population.py`: 7 composizioni dell'ingresso da 5 a 117
ingressi, 1–6 strati, 2–8 neuroni, 3–7 uscite, repliche con altri semi, pesi a zero,
forme a pari pesi, strati a moltiplicazioni ferme), sulla macchina di laboratorio (Intel
Core Ultra 7 155H, Ubuntu 24.04, kernel 6.8.0-142, bare metal) nelle condizioni di
`host_conditions.py`: core del banco fissi a **3 500 MHz misurati** (2 500 sul LP E-core),
isolati, senza C6/C9 (`docs/testing.md` §0). Ogni cifra è una mediana sulla popolazione
con **[minimo–massimo]**, un conteggio («103/103»), o una legge stimata su tutti i modelli;
le misure in cui la macchina non è rimasta nelle condizioni dichiarate sono fuori (2 su
580). Si rifà con

```bash
bash ipa/test/run_population_campaign.sh                 # tutto (circa 4 h + 30 min)
python3 ipa/test/report_population.py results/popolazione_2026-10 > sintesi.md
```

Le schede marcate **🔧** sono verifiche del codice nel kernel (`BPF_PROG_TEST_RUN`, fabric
`veth`, verificatore) e non misure di costo: si rifanno con
`bash ipa/test/run_kernel_checks.sh`, e il loro esito è un sì o un no.

**Stato**:

| | |
|---|---|
| ✅ | misurato sul codice corrente, dati riportati |
| ⚠️ | l'affermazione è sostenuta solo in parte; il limite è dichiarato nella scheda |
| 🔧 | verifica del codice nel kernel (`run_kernel_checks.sh`) |

**Regola che questo registro applica a sé stesso**: nessuna conclusione di costo poggia su
una sola configurazione.

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

### A2 — Il datapath consegna pacchetti veri, non solo aritmetica ✅ 🔧

| | |
|---|---|
| **Ipotesi** | Un test che confronta logit con un riferimento non dimostra che il pacchetto esca dal nodo. |
| **Variabile modificata** | Il banco: un fabric `veth` con XDP **native** e `bpf_redirect` reale. |
| **Variabili fisse** | Modello, pesi, descrittore. |
| **Metrica** | Pacchetto catturato sull'interfaccia d'uscita; DROP letto dal contatore `cls_stats`, non dal silenzio. |
| **Risultato** | `test_forwarding`: **29/29**, tutte e tre le pipeline, 6 classi su 7 (la settima è `UNUSED`). P1 **come si deploya** (oggetto AOT, `loader_aot`, mappe pinnate riempite dal piano di controllo prima dell'attach): `--method aot` **11/11**: `mac_table` riletto dopo il deploy con gli ifindex del fabric, le 5 classi FORWARD escono dalla porta attesa, la DROP è contata e nulla esce, loader staccato con rc=0 e pin rimossi. |
| **Conclusione** | Consegna, non solo inferenza, anche per il binario che va sui nodi. |
| **Come rigirarlo** | `sudo python3 ipa/test/test_forwarding.py`; `--method aot` |

### A3 — Il motore non dipende dalla topologia ✅ ⚠️ 🔧

| | |
|---|---|
| **Ipotesi** | Il codice funziona su Germany50 perché Germany50 è l'unica topologia provata. |
| **Variabile modificata** | La topologia: scenari sintetici (3/8, 4/16, 5/24, 2/6, 6/52 porte/nodi). |
| **Variabili fisse** | Le tre pipeline, il meccanismo di inferenza. |
| **Metrica** | Generazione, caricamento e consegna su ciascuna. |
| **Risultato** | **34/34** controlli sulle cinque topologie più lo scenario principale. |
| **Conclusione** | Nessuna dimensione di scenario è cablata nel motore. |
| **Limite dichiarato** | ⚠️ Lo sweep varia solo il TTL con tutti i link attivi, quindi esercita **una classe per topologia**. La copertura su tutte le classi c'è nello scenario singolo (A2). |
| **Come rigirarlo** | `sudo python3 ipa/test/test_forwarding.py --sweep` |

### A4 — Congelare l'indice del nodo non cambia la decisione ✅ 🔧

| | |
|---|---|
| **Ipotesi** | P1 sceglie una colonna della matrice del primo layer a tempo di compilazione; se fosse la colonna sbagliata, il programma sarebbe più piccolo, più veloce e calcolerebbe **un altro modello**, e nessuna misura di costo se ne accorgerebbe. |
| **Variabile modificata** | Da dove arriva l'indice del nodo: costante compilata (P1) contro mappa `node_id` (P1.5). |
| **Variabili fisse** | Pesi, descrittore, topologia, indice del nodo (7 in entrambe). |
| **Metrica** | La classe scelta e il valore di ritorno XDP. |
| **Risultato** | **80/80** casi identici (TTL 2-11 × 8 configurazioni di link). Sulla popolazione, P1 e P1.5 caricano lo stesso oggetto generato con e senza nodo congelato e decidono come il riferimento su ogni modello (A5). |
| **Conclusione** | Congelare il nodo cambia il codice, non la decisione: è il prerequisito di ogni numero della colonna P1. |
| **Come rigirarlo** | `sudo python3 ipa/test/bench_scaling.py --verify` |

### A5 — L'equivalenza numerica vale su ogni modello della popolazione ✅

| | |
|---|---|
| **Ipotesi** | Le pipeline calcolano esattamente il riferimento intero su qualunque modello che sanno caricare, non solo su quello depositato. |
| **Variabile modificata** | Il modello: i 109 della popolazione (5–117 ingressi, 1–6 strati, 2–8 neuroni, 3–7 uscite, pesi uniformi, normali e sparsi, scala del TTL dichiarata dal modello). |
| **Variabili fisse** | Il descrittore di ciascun modello, 200 ingressi per modello con seme fisso. |
| **Metrica** | Accordo fra argmax del riferimento intero (`synth.reference`) e dell'eBPF nel kernel, pacchetto per pacchetto. |
| **Risultato** | **P1 109/109, P2 103/103, P3 109/109** modelli a 200/200. I 6 modelli fuori da P2 hanno più di 1 024 pesi (`MAX_WEIGHT_ENTRIES`): un limite della pipeline, dichiarato prima di compilare. Sugli scenari sintetici (`check_kernel_vs_reference --all`) c'è anche il controllo negativo sulla scala: riscritto il solo byte `feat_ent.scale` al default, l'eBPF si stacca dal riferimento dichiarato esattamente sui casi previsti. |
| **Conclusione** | L'aritmetica del datapath è esatta su ogni modello che la pipeline carica. |
| **Come rigirarlo** | `bash ipa/test/run_population_campaign.sh corretto`; un modello: `sudo python3 ipa/test/check_kernel_vs_reference.py --scenario <cartella> --pipeline p1 --n 200` |

### A6 — Non generare le colonne delle porte assenti non cambia la decisione ✅ 🔧

| | |
|---|---|
| **Ipotesi** | Un nodo di grado 3 ha `link_state[3..5]` permanentemente a zero: quelle interfacce **non esistono**. Togliere quelle colonne dal primo layer di P1 deve essere esatto, non approssimato. |
| **Variabile modificata** | `static_ports`: quali colonne di `link_state` P1 genera. Il nodo è congelato in **entrambe** le build. |
| **Variabili fisse** | Pesi, descrittore, topologia, `n_in`, offset dei pesi, indice del nodo. |
| **Metrica** | La classe scelta e il valore di ritorno XDP, su tutti i pattern di link realizzabili × TTL 2-11. |
| **Condizione dichiarata** | Vale finché gli slot senza interfaccia valgono 0, e lo garantisce `link_state_monitor` (`carrier_state()` ritorna 0 per un'interfaccia inesistente). Non vale sotto `check_pipelines._seed_link_state`, che semina 1 ovunque: il test azzera gli slot assenti nel riferimento. |
| **Controllo negativo** | Accendendo uno slot assente le due build **devono** divergere; altrimenti «concordano» sarebbe vero anche per una specializzazione sbagliata. Il test cerca fra più semi del pool e fallisce se nessuno morde. |
| **Risultato** | **80/80** casi identici (porte {0,1,4}); accendendo uno slot assente le build divergono. |
| **Conclusione** | Cambia il codice, non la decisione. |
| **Come rigirarlo** | `sudo python3 ipa/test/bench_scaling.py --verify-ports` |

### A7 — Ogni modello ha la sua semantica, senza un programma per modello ✅ ⚠️ 🔧

| | |
|---|---|
| **Ipotesi** | In P2 e P3 modelli con significati diversi per la stessa classe possono convivere nello **stesso** programma caricato, senza contaminarsi e senza costo aggiuntivo per pacchetto. |
| **Variabile modificata** | Semantiche diverse per modelli registrati nello stesso programma. La chiave della tabella classe → azione è `(model_id, banco, classe)`, in un `BPF_ARRAY` di 256 × 2 × 32 righe. Il banco attivo sta nell'entry del registry: ricaricare un modello scrive il banco inattivo e un solo update installa insieme `n_out` e banco. |
| **Variabili fisse** | Inferenza, pesi, descrittori, un programma per architettura. |
| **Metrica** | Azione prodotta per ogni classe di ogni modello; lookup, memoria. |
| **Risultato** | **53/53** su P2 e P3: un modello; due con la stessa semantica; due con semantiche diverse su ogni classe a pacchetti alternati; A → B → A anche dopo aver ricaricato B; `model_id` inesistente o rimosso non elaborato; `n_out` 4 e 7 insieme; stesso `model_id` ricaricato con altra semantica e altro `n_out`. **Costo**: una lettura di tabella per pacchetto, come la chiave per sola classe; **memoria 131 072 byte per pipeline**, fissi. |
| **Controllo negativo** | Con una tabella condivisa simulata A e B passano e C, D, F, R falliscono. |
| **Perché non dentro il registry** | Indicizzare il valore dell'entry con `best_cls` obbliga il verificatore a tracciare `best_cls` con precisione attraverso l'argmax: `layer_hidden` di P3 non carica (`E2BIG`). Una chiave sullo stack no. |
| **Limite dichiarato** | ⚠️ I 128 KiB sono riservati per 256 modelli anche con un modello solo; l'alternativa a pochi KB (slot allocato dal piano di controllo) non è implementata. |
| **Come rigirarlo** | `sudo python3 ipa/test/check_semantics_per_model.py` |

### A8 — Ogni test del kernel e del traffico vero gira su qualsiasi modello compatibile ✅

| | |
|---|---|
| **Ipotesi** | Suite kernel, verifica, consegna sul fabric e banchi di traffico non devono presupporre il checkpoint né Germany50: caricano un modello qualsiasi, su una rete le cui dimensioni esso rispetta. |
| **Variabile modificata** | Il modello (`--model`: una cartella della popolazione, un preset sintetico, il checkpoint) e la rete (`--topology`). |
| **Variabili fisse** | Le pipeline, i costruttori comuni (`pipeline_setup.py`), il riferimento generico. |
| **Metrica** | Il banco gira e misura; la classe decisa coincide con il riferimento. |
| **Risultato** | La campagna di popolazione fa girare **ogni banco su ogni modello**: correttezza, massima spinta su P-core ed E-core, tre marcature (`--mode rates`), LP E-core, traffico crescente, due core, classi, TTL misti, taglie, programma da solo: 580 misure su 109 modelli. Nessun banco ha rifiutato un modello che la pipeline sa caricare. `test_model_source --kernel` **110/110** sugli scenari sintetici. |
| **Controllo negativo** | Un modello incompatibile (one-hot a 52 su 30 nodi, TTL 16 su una rete a 30, 9 interfacce oltre il tetto) è rifiutato con il motivo: `test_model_source`, 62/62. Un modello che per il pacchetto del generatore decide DROP in ogni stato dei link non viene misurato come inoltro: il banco salta la pipeline (`_forwarding_inputs`); la popolazione sceglie i semi in modo che non succeda. |
| **Come rigirarlo** | `bash ipa/test/run_population_campaign.sh`; `sudo python3 ipa/test/test_model_source.py --kernel` |

---

## B. Il costo della flessibilità

La scala ha **quattro** gradini: sotto la P1.5 (pesi compilati, nodo da mappa) c'è una P1
pienamente specializzata (pesi **e** nodo compilati), poi P2 (soffitti compilati) e P3
(anche la profondità a runtime).

### B1 — Rendere le feature configurabili a runtime costa per pacchetto ✅

| | |
|---|---|
| **Ipotesi** | Più cose si decidono a runtime invece che a compile time, più costa per pacchetto. |
| **Variabile modificata** | Quanto è noto alla compilazione: P1 → P1.5 → P2 (soffitti) → P3 (anche la profondità); il modello (109). |
| **Variabili fisse** | Banco, pacchetto, core del nodo (P-core 3,5 GHz). |
| **Metrica** | Tempo di CPU per pacchetto a nodo saturo meno la baseline (sola rete); letture di tabella e salti per pacchetto (build strumentata, `bench_program_alone`). |
| **Risultato** | Sola rete, mediana [min–max]: P1 **53 [19–155]**, P1.5 **58 [19–156]**, P2 **226 [129–446]**, P3 **421 [240–852] ns**. **P1 ≤ P2 ≤ P3 su 103/103 modelli.** Modello per modello: P2/P1 4,4 [2,7–12,8], P3/P1 7,8 [4,9–24,6], P3/P2 1,9 [1,4–2,3], P1.5/P1 1,1 [0,9–1,7]. Letture di tabella per pacchetto 5 / 6 / 12 / 35,5 [23–54], salti fra programmi 1 / 1 / 1 / uno per strato. |
| **Conclusione** | La flessibilità costa da 4 a 8 volte P1 in mediana, e il costo non è aritmetico: è in letture di tabella e salti fra programmi (C9). |
| **Come rigirarlo** | `bash ipa/test/run_population_campaign.sh pop solo` |

### B2 — Cambiare modello costa millisecondi a ogni pipeline ✅ ⚠️

| | |
|---|---|
| **Ipotesi** | Compilare i pesi dentro il codice sposta il costo dal pacchetto al deployment. |
| **Variabile modificata** | La pipeline; il modello (108 modelli per l'installazione, 109 per la compilazione di P1). |
| **Metrica** | Installare un modello nuovo su un nodo in servizio (P1: caricare l'oggetto compilato, verifier e JIT; P2/P3: scrivere le tabelle); generare e compilare P1 (clang senza cache, fuori dal nodo); compilare il programma generico (P2/P3, una volta all'avvio). |
| **Risultato** | Installare: P1 **0,6 [0,3–1,5] ms**, P1.5 0,9 [0,3–5,6], P2 **0,3 [0,2–0,4]**, P3 **0,3 [0,2–0,5] ms**. Generare e compilare P1: **50 [34–114] ms** (P1.5 61 [34–181]); il C si genera in meno di 1 ms, il resto è clang e cresce con il modello. Compilare il programma generico: P2 1,6 [1,4–1,7] s, P3 1,2 s. |
| **Conclusione** | Sul nodo cambiare modello costa al più 6 ms a tutte, su ogni modello. Il costo di P1 è della **compilazione**, fuori dal nodo: P1 richiede un compilatore per ogni modello nuovo, P2 e P3 no. |
| **Nota metodologica** | Registrare lo stesso modello tre volte in un processo nuovo: la prima 0,62 ms (P2) e 1,11 ms (P3), le successive ~0,2 ms; la prima paga il piano di controllo che si prepara. `update_ms` di `bench_scaling` comprende anche la lettura dai file del modello del significato delle classi: non è il costo di installazione. |
| **Mentre il modello cambia** | Riscrivere le tabelle allo stesso `model_id` non è atomico: in P3, con 10 156 cambi mentre un altro core esegue il programma, 60 pacchetti su 183 148 hanno trovato tabelle che non stavano insieme e non sono stati elaborati. Con **make-before-break** (`install_model` sotto un id nuovo con il registro scritto per ultimo, poi i mittenti passano al nuovo id, poi `retire_model`): **0 pacchetti misti** in P2 e P3, su 1 119 231 pacchetti e 6 458 cambi (`check_model_swap.py`). |
| **Limite dichiarato** | ⚠️ Make-before-break richiede che il modello nuovo stia accanto al vecchio nel blocco dei pesi; un modello che non ci sta richiede un'interruzione. In P2 il modello nuovo deve avere la profondità del programma compilato. |
| **Come rigirarlo** | `bash ipa/test/run_population_campaign.sh solo` (`bench_program_alone.py`, e `bench_program_alone.py --compila` senza root); `sudo python3 ipa/test/check_model_swap.py` |

### B3 — L'AOT toglie il compilatore dal nodo senza costo per pacchetto ✅

| | |
|---|---|
| **Ipotesi** | Compilare l'oggetto fuori dal nodo elimina clang dal nodo, e la strength reduction sui pesi letterali sopravvive dentro l'oggetto. |
| **Variabile modificata** | Dove avviene la compilazione: macchina di build (clang) contro nodo. |
| **Metrica** | Costo di messa in servizio; costo per pacchetto. |
| **Risultato** | Tutte le cifre di P1 e P1.5 di questo registro sono dell'oggetto AOT caricato da `loader_aot`, linkato staticamente contro libbpf: compilazione fuori dal nodo 50 [34–114] ms, messa in servizio sul nodo 0,6 [0,3–1,5] ms (B2), costo per pacchetto il più basso della scala (B1). I pesi a zero accorciano l'oggetto (C3): la strength reduction resta dentro. |
| **Conclusione** | Il nodo non ha bisogno di un compilatore, e il binario che ci va è quello misurato. |
| **Come rigirarlo** | `sudo python3 ipa/methods/method4_hardcoded_aot.py`; `bash ipa/test/run_population_campaign.sh solo` |

---

## C. Che cosa costa, e che cosa no

### C1 — La dimensione del programma non predice la velocità ✅

| | |
|---|---|
| **Ipotesi** | Le istruzioni eBPF caricate sono un proxy del costo per pacchetto. **Falsa fra pipeline.** |
| **Variabile modificata** | La pipeline; il modello (103 modelli che P2 sa eseguire). |
| **Metrica** | Istruzioni caricate (kernel, `prog_census`) contro istruzioni eseguite per pacchetto (contatori hardware) e tempo di CPU. |
| **Risultato** | P2 carica più istruzioni di P3 (16 813 [14 604–18 937] contro 12 288, sempre uguale) ma ne **esegue meno** (4 578 contro 7 620 per pacchetto, mediane) ed è più veloce: **su 103 modelli su 103**. Dentro una pipeline la dimensione ordina i modelli come il lavoro per P1 (correlazione di rango 0,98), meno per P1.5 (0,90) e P2 (0,79). |
| **Conclusione** | `xlated` misura quanto è **grande** il programma caricato, non quanto **lavora**: dominano letture di tabella e salti (C9). |
| **Come rigirarlo** | `bash ipa/test/run_population_campaign.sh pop` |

### C2 — La larghezza della rete è gratis a runtime; quella del modello no ✅

| | |
|---|---|
| **Ipotesi** | Una rete più grande costa di più per pacchetto. **Falsa per la one-hot.** |
| **Variabile modificata** | Il numero di nodi della rete (la one-hot dell'identità del nodo: 10, 24, 52, 100) e i neuroni per strato (2–8), su tutta la popolazione. |
| **Metrica** | Tempo di CPU meno la baseline; lo scarto dalla legge di costo (C8) al variare dei nodi. |
| **Risultato** | Nodi, su 56 modelli con l'identità del nodo in ingresso: lo scarto dalla legge non cresce con i nodi, **al più 0,03 ns per nodo** su tutte e quattro le pipeline. Neuroni (famiglia base, mediane, P-core): P1 31 → 84, P3 347 → 516 ns da 2 a 8 neuroni; nella legge è il termine per MAC. |
| **Conclusione** | Una one-hot ha un solo uno, quindi il datapath legge una colonna di pesi qualunque sia la sua larghezza; un layer più largo legge più pesi. **La rete può crescere quanto vuole, il modello no.** |
| **Come rigirarlo** | `bash ipa/test/run_population_campaign.sh pop`; `python3 ipa/test/report_population_facts.py results/popolazione_2026-10` (chiavi `nodes`, `width`) |

### C3 — In P1 il conteggio istruzioni e il tempo dipendono dai valori dei pesi ✅

| | |
|---|---|
| **Ipotesi** | Con i pesi letterali nel C il compilatore cancella i prodotti per zero: la dimensione dipende dai **valori**, non solo dalla forma. |
| **Variabile modificata** | La frazione di pesi zero: 50 e 90 %, su quattro forme (famiglia `sparsita`), contro il modello denso con la stessa forma e contro la legge stimata sui modelli densi. |
| **Risultato** | Al 90 % di zeri: costo della rete **P1 0,44 [0,31–0,63]**, **P1.5 0,62 [0,27–0,83]** volte il previsto dalla legge densa; programma P1 0,40, P1.5 0,34 volte quello del gemello denso. Al 50 %: P1 0,79, P1.5 0,93; programmi 0,77–0,78. **P2 1,02 [0,91–1,14], P3 1,01 [0,91–1,03]**, con un programma identico al denso. |
| **Conclusione** | Potare il modello rende più veloci solo le versioni specializzate; per P2 e P3 uno zero è un byte in tabella come un altro. È l'asse su cui scendono insieme dimensione e tempo. |
| **Come rigirarlo** | `bash ipa/test/run_population_campaign.sh pop` (famiglia `sparsita`) |

### C4 — Congelare il nodo toglie lo `switch` sulla one-hot del nodo ✅

| | |
|---|---|
| **Ipotesi** | L'indice del nodo è una costante di deployment; congelarlo fa sparire lo `switch` a N casi che P1.5 genera per la one-hot del nodo. |
| **Variabile modificata** | Da dove arriva l'indice: costante compilata (P1) contro mappa (P1.5); il modello (109). |
| **Metrica** | Istruzioni caricate; costo della rete per pacchetto. |
| **Risultato** | Istruzioni caricate: P1 650 [239–2 315], P1.5 961 [282–4 313]. Costo della rete P1.5/P1 **1,11 [0,93–1,68]**: P1.5 costa di più su 89/109 modelli. |
| **Conclusione** | La dimensione cala molto e il tempo poco, per la stessa ragione: lo `switch` ha N casi ma ne esegue uno. Il prezzo è un binario per nodo invece che per modello, ciascuno con la sua compilazione (B2). |
| **Come rigirarlo** | `bash ipa/test/run_population_campaign.sh pop`; per l'asse dei nodi a pesi fissi, `bench_scaling.py --axis nodes` |

### C5 — La genericità compilata si paga in complessità di verifica 🔧

| | |
|---|---|
| **Ipotesi** | Il verificatore percorre ogni cammino del corpo srotolato, e il costo cresce col **prodotto** dei soffitti: un programma generico non è gratis. |
| **Variabile modificata** | I soffitti compilati (`IPA_MAX_QUEUES` in P3; `T2_MAX_H1/H2`, `MAX_N_IN` in P2). |
| **Metrica** | Il programma si carica, e a quante istruzioni. |
| **Risultato** | Con soffitti larghi (`8 × 4 × 128`) P2 si ferma a `processed 1000001 insns (limit 1000000)` restando dentro il limite di dimensione: oltre quello di complessità. In P3 `IPA_MAX_QUEUES` cambia le istruzioni di `layer_first` senza cambiare il percorso eseguito quando il descrittore non dichiara la coda, e il control plane rifiuta un descrittore che chieda più slot di quanti il datapath ne compili. |
| **Conclusione** | Due limiti distinti da non confondere: il verificatore **paga i cammini, non la dimensione**. C6 mostra quanto pesa un singolo salto condizionale ripetuto. |
| **Limite dichiarato** | ⚠️ Questi limiti sono scogliere, non pendenze: un soffitto si cambia e si rimisura. |
| **Come rigirarlo** | Ricompilare `layer_first` con un altro `IPA_MAX_QUEUES` (`ebpf_modular.py`); `check_verifier_stats.py` per le statistiche del verificatore |

### C6 — Un salto condizionale per neurone basta a esaurire il verificatore 🔧

| | |
|---|---|
| **Ipotesi** | I limiti di caricamento di P2 e di P1 dipendono dal kernel. **Falsa: dipendono da come è scritta la ReLU.** |
| **Variabile modificata** | Come è scritta la ReLU: `x > 0 ? x : 0` (un salto per neurone, variante `branch`) contro `ipa_relu`, `x & ~(x >> 63)` dietro una barriera `asm volatile("")`, stesso risultato bit per bit e nessun salto (variante `branchless`, quella delle pipeline). |
| **Variabili fisse** | Kernel, forme, pesi, descrittore default; tutto il resto del sorgente. |
| **Metrica** | Istruzioni percorse dal verificatore (`log_level = 4`, limite 1 000 000), stati salvati; se il programma carica. |
| **Risultato** | Con il salto la foglia di P2 è rifiutata da tre strati nascosti (`E2BIG`); con `ipa_relu` le istruzioni percorse crescono di qualche migliaio per strato e P2 carica fino a una ventina di strati. Anche `layer_hidden` di P3 percorre molti meno cammini con `ipa_relu`. |
| **Conclusione** | Il verificatore paga i cammini: un bivio per neurone li moltiplica. Con `ipa_relu` il limite successivo di P2 è la distanza di salto eBPF (offset a 16 bit: `LLVM ERROR: Branch target out of insn range`), poi la tabella dei pesi (1 024). Anche la barriera `asm` è necessaria: senza, clang riconosce `smax(x, 0)` e rimette il salto. |
| **Come rigirarlo** | `sudo python3 ipa/test/check_verifier_stats.py` (varianti `branchless` e `branch`); `--only p2 --depths 6,10,20,37` |

### C7 — Non generare le colonne delle porte assenti toglie lavoro vero 🔧

| | |
|---|---|
| **Ipotesi** | `link_state` è un vettore **denso**: il datapath esegue una moltiplicazione-accumulo per ogni coppia (interfaccia, neurone). Non generare le colonne assenti toglie lavoro eseguito, non solo codice morto. |
| **Variabile modificata** | Il numero di porte presenti, 2–6, via `static_ports`. |
| **Variabili fisse** | Modello 65-4-4-7, 52 nodi, **gli stessi pesi** in ogni punto. |
| **Controllo** | P1.5, P2 e P3 non specializzano e devono restare piatte. |
| **Risultato** | Le istruzioni di P1 scendono in modo lineare con le porte tolte, e la latenza con loro; le altre tre pipeline restano piatte. |
| **Conclusione** | Diversamente dal nodo congelato (C4), qui le moltiplicazioni tolte sono davvero eseguite. |
| **Come rigirarlo** | `bench_scaling.py --axis degree` |

### C8 — Il costo segue una legge: a + b × MAC eseguite + c × strati ✅

| | |
|---|---|
| **Ipotesi** | Il costo della rete si predice dalle moltiplicazioni (MAC) contate sulla forma del modello. **Vera solo contando le MAC eseguite.** |
| **Variabile modificata** | Il modello: 83 modelli densi (famiglie base, replica, imbuto; 77 per P2). |
| **Metrica** | Minimi quadrati di costo = a + b × MAC + c × strati, con MAC dalla forma e con MAC eseguite (una one-hot conta una colonna); errore relativo su un modello lasciato fuori dalla stima. |
| **Risultato** | P-core: **P1 22 + 0,26·MAC + 1·strati** (r² 0,98, errore 6 %), **P1.5 29 + 0,26 + 1** (0,95, 9 %), **P2 103 + 0,42 + 20** (0,93, 6 %), **P3 154 + 0,77 + 46** (0,99, 3 %). Con le MAC dalla forma r² 0,58–0,79. E-core, P3: 153 + 0,79 + 62. Le istruzioni seguono la stessa forma (P3 +901 per strato, r² 0,99). Sui 18 modelli della famiglia `strati`, esclusi dalla stima, l'errore sul tempo (P-core) è 5 % per P2 e P3, 6 % per P1, 13 % per P1.5. |
| **Conclusione** | Il costo di un modello si stima prima di misurarlo, con qualche punto percentuale di errore. **P3 costa ~3× P1 per MAC eseguita**: legge ogni peso da una tabella. |
| **Come rigirarlo** | `python3 ipa/test/report_population.py results/popolazione_2026-10` (sezione «A cost law, fitted on every model») |

### C9 — Con i pesi in tabella pesa la struttura, non l'aritmetica ✅ ⚠️

| | |
|---|---|
| **Ipotesi** | Il tempo di P2 e P3 va soprattutto nelle moltiplicazioni. **Falsa.** |
| **Variabile modificata** | La pipeline; il modello (83 densi). |
| **Metrica** | La quota di ciascun termine della legge (C8) sul costo previsto, modello per modello; letture di tabella e salti per pacchetto (build strumentata). |
| **Risultato** | Quote mediane fisso · MAC · strati: **P1 40 · 50 · 8 %**, P1.5 48 · 46 · 5 %, **P2 47 · 18 · 31 %**, **P3 37 · 18 · 39 %**. P3 fa 35,5 [23–54] letture di tabella per pacchetto, 6 in più per strato, e un salto per strato su 108/108 modelli. |
| **Conclusione** | Con i pesi nel codice circa metà del tempo è aritmetica; con i pesi in tabella circa l'82 % è struttura: il termine fisso (dispatcher, descrittore, ingressi da tabella) e quello per strato (salto allo strato generico e rilettura del contesto). Anche il termine per MAC contiene le tabelle: P3 legge ogni peso da una mappa. Nessun pezzo passa dallo user space: le mappe si leggono nel kernel. |
| **Limite dichiarato** | ⚠️ Quanto dei 46 ns per strato di P3 sia il salto e quanto le letture non è separato. |
| **Come rigirarlo** | `python3 ipa/test/report_population_facts.py results/popolazione_2026-10` (chiave `law_shares`); `bench_program_alone.py` per letture e salti |

---

## D. Larga contro profonda

### D1 — In P1 la risposta dipende dal vettore d'ingresso 🔧

| | |
|---|---|
| **Ipotesi** | Dato un numero di parametri, spenderli in un layer largo costa meno che in molti stretti. **Vera solo per certi vettori d'ingresso.** |
| **Variabile modificata** | La profondità: 1, 2, 4, 8 hidden layer, in P1 (oggetto AOT). |
| **Variabili fisse** | Il budget-pesi, con la larghezza risolta per descrittore e lo scarto stampato. Tre tier: ~300, ~1 200, ~4 700 pesi. Quattro descrittori. |
| **Metrica** | Latenza (min di 7 trial), istruzioni, e se il programma si carica. |
| **Che cosa si guarda** | Una one-hot costa poco perché il datapath ne legge una colonna; un ingresso denso moltiplica le letture per la larghezza del primo strato. Con un ingresso dominato da one-hot (il caso di IPA) conviene la forma larga, con un ingresso piccolo e denso quella profonda. Oltre un certo budget il limite di P1 è lo stack eBPF (512 byte), e ci arriva prima la forma larga. |
| **Come rigirarlo** | `sudo python3 ipa/test/bench_depth_vs_width.py` |

### D2 — A parametri fermi, la risposta cambia con la pipeline ✅ ⚠️

| | |
|---|---|
| **Ipotesi** | A parità di pesi, spenderli in più strati costa poco su ogni pipeline. **Falsa per P2 e P3.** |
| **Variabile modificata** | Come lo stesso budget è disposto: 1–5 hidden layer (famiglia `imbuto`). |
| **Variabili fisse** | **I parametri, dentro ogni composizione dell'ingresso**: ~600 con `ipa65`, 207–268 con `dense17` (10 modelli). Non le MAC eseguite: uguali entro il 3 % da 1 a 3 strati, **+16–43 % a 4 e 5 strati** (strati intermedi da 5 e 4 neuroni invece di 3). |
| **Risultato** | Sola rete, da 1 a 5 strati: **P2 +48 [44–53] %**, **P3 +63 [55–70] %**, circa 27 e 58 ns per strato; P1 +17 %, P1.5 +14 %, circa 4 ns per strato. Istruzioni caricate: P2 +887 per strato (legge), P3 **12 288 su ogni modello**. |
| **Conclusione** | Le due P1 crescono poco; P2 paga lo strato in codice, P3 un salto per strato a codice identico. Con le pipeline generiche, a parità di pesi, conviene una rete larga e poco profonda. |
| **Limite dichiarato** | ⚠️ Da 1 a 5 strati l'aumento comprende le MAC in più di 4 e 5 strati; la famiglia `strati` (D3) tiene ferme anche le MAC. |
| **Come rigirarlo** | `bash ipa/test/run_population_campaign.sh pop` (famiglia `imbuto`) |

### D3 — Perché la profondità costa, quando costa ✅

| | |
|---|---|
| **Ipotesi** | Il costo di un layer in più non è aritmetico: è un costo fisso di transizione. |
| **Variabile modificata** | Il numero di strati, su tutta la popolazione (la legge di C8 lo separa dalle MAC), e la famiglia `strati` (18 modelli, 1–6 strati nascosti, 102–113 MAC). |
| **Metrica** | Il termine per strato della legge, in ns e in istruzioni eseguite; istruzioni caricate; letture di tabella e salti per pacchetto. |
| **Risultato** | A MAC ferme uno strato costa **46 ns a P3**, 20 a P2, ~1 a P1 e P1.5; P3 esegue **+901 istruzioni per strato** (r² 0,99), identiche su P-core ed E-core, e carica sempre 12 288 istruzioni; P2 carica +887 istruzioni per strato. P3 salta una volta per strato (108/108) e fa 6 letture di tabella in più per strato. **A moltiplicazioni ferme** (famiglia `strati`, misure grezze): P3 +~900 istruzioni per strato in media (790–910 per composizione, come la legge: 901), P2 +~370 (legge: 370), P1 e P1.5 piatte; gradini singoli di P3 da +270 a +1 350. Con i termini del codice (fisso per strato, per neurone e per MAC dopo il primo strato, primo strato per composizione): **P3 687 per strato + 44 per neurone + 14 per MAC**, errore fuori stima 0,1 %; **P2 39 per strato + 122 per neurone**, MAC ~0, errore 1,0 %. |
| **Conclusione** | In P3 **dimensione costante, tempo crescente** è la firma di un costo di transizione: le letture di mappa che ricostruiscono il contesto a ogni hop (`scratch_meta`, `scratch_acts`, `layer_registry`, `layer_shapes`, i pesi) e i cicli srotolati a 8 (`MLH_MAX_H`), con cui ogni neurone controlla sempre 8 ingressi. Il "~900 per strato" è la media di ~690 fissi più i neuroni dello strato, sulle forme della popolazione. In P2 lo strato in sé costa poco (blocchi in fila, nessun salto): paga i neuroni, ognuno con 8 moltiplicazioni piene. |
| **Come rigirarlo** | `python3 ipa/test/report_population.py results/popolazione_2026-10`; `bench_tail_call.py` per il salto da solo; famiglia `strati`: `run_population_campaign.sh genera corretto pop solo` sulla stessa campagna |

---

## E. Traffico vero

Qui ci sono pacchetti veri: frame XDP grezzi da `xdp_gen`, consegnati al nodo come da una
NIC con XDP nativo, un fabric `veth`, contatori all'ingresso e all'uscita, generatore, DUT
e nodo successivo su core fisici distinti, un thread di generatore per coda e una coda
d'uscita per core del nodo (`docs/testing.md` §10.1–§10.4). Le misure vengono da
`run_population_campaign.sh`; dove non è detto altro, il nodo è un P-core (cpu6) a 3,5 GHz.

### E1 — Sotto capacità il nodo non perde niente; oltre, perde all'ingresso ✅ ⚠️

| | |
|---|---|
| **Ipotesi** | Le perdite su un banco `veth` possono essere della pipeline, del trasporto o della ricezione; vanno separate. |
| **Variabile modificata** | Il carico offerto (16 punti da 0,5 a 12 Mpps, 3 giri); il modello (6, dal più leggero al più pesante); il tipo di core (P, E). |
| **Metrica** | Massimo inoltrato contro la capacità a massima spinta dello stesso modello; quota della perdita avvenuta prima di XDP. |
| **Risultato** | Il massimo inoltrato sta a **0,98 [0,88–1,03]** della capacità sul P-core e **0,99 [0,94–1,03]** sull'E-core, 24 curve per core (i valori sopra 1 sono rumore fra sessioni, G1). Della perdita oltre la capacità, la quota persa **prima di XDP** è 1,000 in mediana. Divise per la capacità del loro modello, le curve si sovrappongono. |
| **Conclusione** | Il collo di bottiglia è il programma eBPF, all'ingresso, su ogni tipo di core. Un nodo sotto la sua capacità consegna tutto. |
| **Limite dichiarato** | ⚠️ P1 sui modelli più leggeri regge oltre 9 Mpps, e lì comincia a perdere anche l'uscita: la quota persa all'ingresso scende fino a 0,69, il massimo inoltrato fino a 0,88 della capacità. È il limite del cavo virtuale e del core d'uscita. |
| **Come rigirarlo** | `bash ipa/test/run_population_campaign.sh carico` |

### E2 — Due misure indipendenti danno lo stesso costo della rete, per P2 e P3 ✅ ⚠️

| | |
|---|---|
| **Ipotesi** | Il costo della rete misurato a nodo saturo (tempo di CPU meno la baseline) e a traffico leggero (media di T2−T1 meno la baseline) è la stessa grandezza. |
| **Variabile modificata** | Il modo di misurare; il modello (91, le famiglie misurate anche con le tre marcature); il core (P, E). |
| **Metrica** | Rapporto traffico leggero / nodo saturo, modello per modello. |
| **Risultato** | P-core: **P2 1,03 [0,94–1,09]**, **P3 1,02 [0,94–1,11]**; P1 0,77 [0,48–1,02], P1.5 0,83 [0,50–1,02]. E-core: P2 1,08, P3 1,07; P1 1,26, P1.5 1,22. I cicli per pacchetto dei contatori hardware, divisi per 3,5 GHz, ritrovano il tempo di CPU. |
| **Conclusione** | Per P2 e P3 i due metodi misurano la stessa cosa su ogni modello. |
| **Limite dichiarato** | ⚠️ Per P1 e P1.5 no: la loro rete costa poche decine di ns sopra una baseline di ~66, e la differenza fra due misure grandi è rumorosa. Il loro costo della rete si cita con il metodo che lo ha misurato; quello di riferimento è il tempo di CPU a nodo saturo. |
| **Come rigirarlo** | `bash ipa/test/run_population_campaign.sh pop` |

### E3 — Il costo della pipeline si separa da quello del trasporto ✅ ⚠️

| | |
|---|---|
| **Ipotesi** | La latenza da arrivo a partenza tiene insieme due costi che si possono separare, e il secondo non dipende dalla pipeline. |
| **Variabile modificata** | Dove si prende il tempo: tre marcature (T1 ingresso del dispatcher, T2 prima di `bpf_redirect`, T3 ingresso del contatore all'altro capo); il modello (91); il tipo di core. |
| **Risultato** | Trasporto T3−T2, minimo: **187–221 ns sul P-core, 226–274 sull'E-core** su ogni modello e pipeline; fra la pipeline più cara e la meno cara dello stesso modello differisce del 4 [1–17] %. Programma T2−T1, minimo, mediane P-core: 27 / 64 / 70 / 229 / 391 ns (baseline, P1, P1.5, P2, P3); P3 237–797 secondo il modello. |
| **Conclusione** | Il trasporto è un costo comune che non dipende né dalla pipeline né dal modello. |
| **Limite dichiarato** | ⚠️ Build **strumentata**: due letture dell'orologio in più per pacchetto. L'uscita resta sulla CPU del DUT, quindi la **media** di T3−T2 contiene l'attesa in coda e cresce col rate (circa 550 → 1 200 ns fra 0,25 e 0,5 Mpps): il trasporto è il minimo. |
| **Come rigirarlo** | `bash ipa/test/run_population_campaign.sh pop` (`POP_T2=1`, `POP_RATES`) |

### E4 — Il costo del nodo per pacchetto, e da che cosa non dipende ✅

| | |
|---|---|
| **Ipotesi** | Il costo del nodo dipende dalla pipeline e dal modello, non dalla taglia del pacchetto, dalla porta d'uscita o dal TTL. |
| **Variabile modificata** | Il modello (109); la taglia (64 / 512 / 1 514 B); la classe decisa (8 modelli); TTL diversi a ogni pacchetto (12 modelli). |
| **Metrica** | **Tempo di CPU per pacchetto** a nodo saturo (occupazione del core × 1 / elaborati). |
| **Risultato** | P-core, mediana [min–max]: baseline **66 [63–69]**, P1 **119 [85–221]**, P1.5 124 [86–222], P2 **292 [196–512]**, P3 **487 [307–918] ns**; capacità da 11,7 a 1,1 Mpps. Taglia: **1,2 [0,3–3,1] %** fra 64 e 1 514 B (30 coppie). Classi che inoltrano: 0 [0–9] % fra la più cara e la meno cara; **scartare +51 [17–63] ns** (la pagina si restituisce sul core del nodo). TTL misti: 0 [−6–4] %. |
| **Conclusione** | Il nodo tocca solo le intestazioni: un numero per pipeline e modello descrive il costo. La decisione DROP costa di più, per un effetto del banco. |
| **Come rigirarlo** | `bash ipa/test/run_population_campaign.sh pop taglie classi mix` |

### E5 — La capacità cresce con i core ✅ ⚠️

| | |
|---|---|
| **Ipotesi** | Con i contatori per-CPU i core del nodo non si contendono niente di scritto a ogni pacchetto, quindi due code su due core danno circa il doppio. |
| **Variabile modificata** | Il numero di core e di code del DUT (1 o 2); il tipo di core (P o E); il modello (8, dal più leggero al più pesante). |
| **Metrica** | Pacchetti elaborati al secondo a saturazione, 3 giri. |
| **Risultato** | Un thread `xdp_gen` per coda, una coda e un core d'uscita per core. Due P-core: **99 [94–103] %** del doppio, due E-core (uno per modulo) **99 [98–101] %**, su 40 coppie modello-pipeline per core. Un core e due core sono misure di sessioni diverse, ciascuna con il rumore di G1 (fino al 5 %): i valori sopra 100 % sono quel rumore, non un guadagno. |
| **Conclusione** | Il costo misurato su un core è quello da moltiplicare per il numero di code di una scheda con RSS, con qualunque modello. |
| **Limite dichiarato** | ⚠️ Solo 1 e 2 core: oltre, questa macchina non ha P-core liberi per generatore, DUT e uscita insieme. Il secondo core d'uscita del P-core (cpu5) va indicato a mano. |
| **Come rigirarlo** | `bash ipa/test/run_population_campaign.sh core2` |

### E6 — Su un core lento il nodo regge meno, e la differenza è di IPC ✅ ⚠️

| | |
|---|---|
| **Ipotesi** | Spostare il nodo da un P-core a un E-core (o a un LP E-core) riduce la capacità; a parità di frequenza la riduzione viene dalle istruzioni per ciclo, non dal codice. |
| **Variabile modificata** | Il core del nodo: P-core (cpu6) ed E-core (cpu12) a 3,5 GHz su 109 modelli, LP E-core (cpu20) a 2,5 GHz su 14. |
| **Variabili fisse** | Generatore (cpu10) e uscita (cpu8) su P-core a 3,5 GHz, pacchetto, 3 giri, alimentatore. |
| **Metrica** | Capacità; istruzioni, cicli, mancate di cache per pacchetto dai contatori hardware del core del nodo. |
| **Risultato** | Capacità E/P modello per modello: baseline **0,63 [0,61–0,66]**, P1 0,76 [0,69–0,91], P1.5 0,75, P2 **0,82 [0,77–0,87]**, P3 **0,83 [0,72–0,89]**. Istruzioni per pacchetto uguali entro lo 0,3 % (LP E-core 0,7 %). Cicli della parte fissa E/P **1,56 [1,50–1,61]**; cicli della sola rete E/P P1 0,95, P2 1,09, P3 1,13. IPC P / E: 2,6 / 1,7 la baseline, 4,5 / 3,7 P3. LP E-core: capacità **0,43 [0,32–0,53]** del P-core sulle pipeline, 13–21 mancate dell'ultimo livello di cache per pacchetto. |
| **Conclusione** | Il codice è lo stesso, la differenza è l'IPC; l'E-core penalizza soprattutto la parte fissa del nodo e poco l'aritmetica della rete, quindi il rapporto si avvicina a 1 con le pipeline pesanti (ρ fra quota di cicli della rete e capacità E/P = 0,76). Il LP E-core, fuori dalla L3, paga anche la memoria. |
| **Limite dichiarato** | ⚠️ Gli E-core a 3,8 GHz (il loro massimo) non sono misurati. |
| **Come rigirarlo** | `bash ipa/test/run_population_campaign.sh pop lpe` (`POP_CORES`) |

### E7 — Le leggi del costo valgono sul nodo vero, su tutta la popolazione ✅

| | |
|---|---|
| **Ipotesi** | Quello che larghezza, profondità, pari pesi e sparsità fanno al costo vale per ogni modello, non solo attorno al checkpoint. |
| **Variabile modificata** | Il modello: i 109 della popolazione; il core del nodo (P o E). |
| **Metrica** | Tempo di CPU per pacchetto a nodo saturo; istruzioni eseguite per pacchetto. |
| **Risultato** | La legge di C8 spiega il costo di tutte le pipeline (r² 0,93–0,99) con il 3–9 % di errore su modelli non visti; profondità (D3), pari pesi (D2), larghezza e taglia della rete (C2), pesi a zero (C3) ne sono casi particolari. Baseline 63–69 ns (P-core) e 105–108 (E-core) con ogni modello. Semi diversi a parità di forma: il costo della rete varia al più del 5–6 % (P3 2 %). |
| **Conclusione** | Le conclusioni sul costo non dipendono da un modello privilegiato. |
| **Come rigirarlo** | `bash ipa/test/run_population_campaign.sh pop` |

### E8 — Il programma da solo e il nodo vero ✅ ⚠️

| | |
|---|---|
| **Ipotesi** | Il costo della rete misurato con `BPF_PROG_TEST_RUN` (programma da solo) è quello che il nodo paga davvero sotto traffico. |
| **Variabile modificata** | Il modo di misurare: `bench_program_alone` (programma da solo, sul pacchetto e con gli ingressi del traffico, a chiamate singole e in ciclo caldo) contro il tempo di CPU a nodo saturo e T2−T1 a traffico leggero; il modello (108). |
| **Variabili fisse** | Pacchetto (TTL 32), nodo, porta, stato dei link che fa inoltrare il modello; baseline sottratta in entrambe le misure. Ogni misura ha inoltrato in tutte le esecuzioni. |
| **Metrica** | Sola rete sotto traffico / sola rete da sola, modello per modello. |
| **Risultato** | A chiamate singole, nodo saturo / da solo: **P2 0,94 [0,77–1,10]**, **P3 0,91 [0,84–0,97]**; P1 1,33 [0,95–3,55], P1.5 1,23 [1,02–3,19]. In ciclo caldo (blocchi di esecuzioni in cui il TTL che scende non cambia la classe): il pacchetto più veloce a traffico leggero coincide con il ciclo caldo (P1 0,99, P1.5 1,04, P2 0,95, P3 0,97); il nodo saturo costa 1,33 / 1,28 / 1,08 / 1,11 volte il ciclo caldo. |
| **Conclusione** | Il ciclo caldo descrive il pacchetto che trova cache e predittori pronti; sotto carico P2 e P3 pagano l'8–11 % in più, P1 e P1.5 circa un terzo, perché la loro rete è piccola rispetto a quello che il traffico sposta in cache. |
| **Limite dichiarato** | ⚠️ Il ciclo caldo vale solo sui modelli in cui il blocco è lungo almeno 10 esecuzioni. Per P1 e P1.5 vale il limite di E2. |
| **Come rigirarlo** | `bash ipa/test/run_population_campaign.sh solo` |

## G. La macchina

### G1 — Con la macchina condizionata le misure si ripetono entro pochi punti ✅

| | |
|---|---|
| **Ipotesi** | La variabilità delle misure è della macchina (frequenza, idle, scheduling, temperatura), e si può togliere. |
| **Variabile modificata** | Le condizioni: frequenza fissa e misurata, C-state profondi spenti, core fisici distinti (e moduli E-core interi), isolamento a runtime (`host_conditions.py`). |
| **Metrica** | Dispersione fra giri, fra sessioni e fra semi; eventi di throttling; misure escluse. |
| **Risultato** | La stessa misura (stesso modello e versione) rifatta in un'altra sessione cambia dell'1,8 % in mediana, del **5 % al 90° percentile**, del 7 % al massimo (30 coppie); i 3 giri di una misura dell'1,3 % in mediana; il nodo senza rete in 109 sessioni dell'1,1 % in mediana (al più 5 %). Una differenza sotto il 5 % fra misure di sessioni diverse non è una differenza. Sei forme con quattro semi: coefficiente di variazione del costo della rete ≤ 5–6 % (P3 ≤ 2 %). Su questo portatile un evento di throttling di pacchetto arriva circa una volta al minuto anche con l'alimentatore: le misure toccate tengono le sole finestre pulite (12 misure, 26 giri o finestre su 1 980 tolti), e 2 misure su 580 restano fuori. |
| **Conclusione** | Le cifre sono ripetibili sulla stessa macchina alla stessa frequenza, e una misura disturbata non entra nelle conclusioni. |
| **Come rigirarlo** | `sudo python3 ipa/test/test_host_conditions_kernel.py --bench` (25/25); `POP_RIFAI_DISTURBATE=1 bash ipa/test/run_population_campaign.sh` |

---

## F. Che cosa nessun test di questo progetto dimostra

Dichiarato per non far sembrare coperto ciò che non lo è.

- **Throughput su hardware di rete.** Generatore, DUT e nodo successivo sono core dello
  stesso processore collegati da `veth`: niente NIC, niente DMA. Le cifre in Mpps sono di
  questo percorso a 3,5 GHz; per un valore su una scheda di rete servono una seconda
  macchina e una NIC con XDP nativo.
- **La dipendenza dalla frequenza.** Tutte le cifre sono a 3,5 GHz (2,5 sul LP E-core);
  3,5 GHz è la frequenza più alta che il portatile regge per un run intero.
- **Il ritardo end-to-end sulla popolazione.** Le curve a traffico crescente lo registrano
  (`bitrate.csv`), ma `report_population.py` non lo riassume.
- **Un cambio di modello senza interruzione per i modelli più grandi** (B2): con
  make-before-break il modello nuovo deve stare accanto al vecchio nel blocco dei pesi.
- **Quanto del costo per strato di P3 sia il salto e quanto le letture** (C9): si contano
  entrambi, ma non si separano nel tempo.
- **La capacità di rxonly**: con uno scrittore per coda il generatore non la satura sul
  P-core; il suo tempo di CPU è indicativo.
- **Accuratezza del modello.** I modelli della popolazione sono sintetici e il modello
  depositato non è stato addestrato in questo lavoro. I test verificano che il datapath
  calcoli **la stessa cosa** del riferimento, non che quella cosa sia una buona politica
  di routing.
- **Reti oltre ~115 nodi.** `MAX_N_IN` è 128 in P2 e P3: per una topologia da 500 nodi
  bisogna alzare quel soffitto e rimisurare.
- **Modelli oltre i limiti di P2** (più di 1 024 pesi): restano nella popolazione, e per
  P2 le cifre sono su 103 modelli.
- **Isolamento dal boot.** `isolcpus`, `nohz_full` e `rcu_nocbs` non sono usati: le CPU del
  banco restano soggette al tick e ai callback RCU.
