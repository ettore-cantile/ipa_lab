# Registro delle affermazioni sperimentali

Una riga della tesi che afferma qualcosa di misurabile deve poter essere
rintracciata fino all'esperimento che la sostiene. Questo documento è quella
mappa: per ogni affermazione, l'ipotesi, che cosa è stato mosso, che cosa è stato
tenuto fermo, che cosa è stato misurato, il numero ottenuto e il comando per
rifarlo.

Lo schema di ogni scheda è quello richiesto dal relatore.

**Stato** dice a che punto è la prova, e va letto prima del resto:

| | |
|---|---|
| ✅ | misurato sul codice corrente, dati riportati |
| ⏳ | il test esiste e gira, ma i dati in tesi vengono da uno stato precedente: **da rigirare** |
| ⚠️ | l'affermazione è sostenuta solo in parte; il limite è dichiarato nella scheda |

**Regola che questo registro applica a sé stesso**: nessuna conclusione poggia su
una sola configurazione. Dove un'affermazione ha un solo punto sperimentale, la
scheda lo dice invece di nasconderlo.

---

## A. Semantica e correttezza

### A1 — La semantica delle classi è dichiarata, mai dedotta ✅

| | |
|---|---|
| **Ipotesi** | Il datapath non deve ricavare che cosa significhi una classe da formule tipo `DROP = n_out - 1` o `n_out = n_interfacce + 1`: dedurle è vero per caso solo sul modello depositato. |
| **Variabile modificata** | Il descrittore del modello: `n_out` e `class_semantics` dichiarati contro assenti. |
| **Variabili fisse** | Pesi, topologia, pipeline. |
| **Metrica** | La classe scelta, e la porta logica su cui il pacchetto esce. |
| **Risultato** | Sul modello depositato `n_out=7`, `drop_class=5`, e la classe 6 è `UNUSED`. Le formule dedotte davano `drop=6`: avrebbero installato un next-hop per la classe DROP e trattato come inoltro una classe non addestrata. |
| **Conclusione** | La catena classe → azione → porta logica → interfaccia è letta da mappe riempite dal descrittore. Nessuna aritmetica sugli indici decide che cosa significa una classe. |
| **Come rigirarlo** | `python3 ipa/test/test_class_semantics.py` e la sezione `class_action` di `--only kernel`; per la semantica distinta per modello, A7. |

### A2 — Il datapath consegna pacchetti veri, non solo aritmetica ✅

| | |
|---|---|
| **Ipotesi** | Un test che confronta logit con un riferimento non dimostra che il pacchetto esca dal nodo. |
| **Variabile modificata** | Il banco: `BPF_PROG_TEST_RUN` contro un fabric `veth` con XDP **native** e `bpf_redirect` reale. |
| **Variabili fisse** | Modello, pesi, descrittore. |
| **Metrica** | Pacchetto catturato sull'interfaccia d'uscita; DROP letto dal contatore `cls_stats`, non dal silenzio. |
| **Risultato** | **18/18** controlli, tutte e tre le pipeline, 6 classi su 7 raggiunte (la settima è `UNUSED`, irraggiungibile per costruzione). |
| **Conclusione** | Consegna, non solo inferenza. |
| **Limite trovato il 2026-09-22** | Per P1 i 18/18 provavano il build **BCC**, che non va mai su un nodo: l'unico deploy di P1 e' l'oggetto AOT attaccato da `loader_aot`, e quel percorso scriveva `mac_table` con **ifindex 1 (`lo`)** per ogni porta. La P1 deployata non consegnava sulla porta scelta, e nessun test la eseguiva. |
| **P1 come deployata (2026-09-23)** | Corretto (mappe pinnate riempite dal piano di controllo Python prima dell'attach) e messo sotto lo stesso banco: `test_fabric --method aot`, **11/11** -- `mac_table` letto dopo il deploy con gli ifindex del fabric e nessuno a 1; le 5 classi FORWARD escono dalla porta attesa, la DROP e' contata e nulla esce, la 7a (`UNUSED`) e' irraggiungibile; loader staccato con rc=0 e pin rimossi. |
| **Come rigirarlo** | `sudo python3 ipa/test/test_fabric.py` (ora comprende `aot`); solo la P1 deployata: `--method aot` |

### A3 — Il motore non dipende dalla topologia ✅

| | |
|---|---|
| **Ipotesi** | Il codice funziona su Germany50 perché Germany50 è l'unica topologia mai provata. |
| **Variabile modificata** | La topologia: 5 scenari sintetici (3/8, 4/16, 5/24, 2/6, 6/52 porte/nodi). |
| **Variabili fisse** | Le tre pipeline, il meccanismo di inferenza. |
| **Metrica** | Generazione, caricamento e consegna su ciascuna. |
| **Risultato** | **23/23** su cinque topologie più lo scenario principale. |
| **Conclusione** | Nessuna dimensione di scenario è cablata nel motore. |
| **Limite dichiarato** | ⚠️ Lo sweep varia solo il TTL con tutti i link attivi, quindi esercita **una classe per topologia**. La copertura su tutte le classi c'è nello scenario singolo, non nello sweep. |
| **Come rigirarlo** | `sudo python3 ipa/test/test_fabric.py --sweep` |

### A4 — Congelare l'indice del nodo non cambia la decisione ✅

| | |
|---|---|
| **Ipotesi** | La P1 specializzata sceglie una colonna della matrice del primo layer a tempo di compilazione; se fosse la colonna sbagliata, il programma sarebbe più piccolo, più veloce e calcolerebbe **un altro modello** — e nessuna misura di costo se ne accorgerebbe. |
| **Variabile modificata** | Da dove arriva l'indice del nodo: costante compilata contro mappa `node_id`. |
| **Variabili fisse** | Pesi, descrittore, topologia, indice del nodo (7 in entrambe). |
| **Metrica** | La classe scelta e il valore di ritorno XDP. |
| **Risultato** | **80/80** casi identici (TTL 2-11 × 8 configurazioni di link). |
| **Conclusione** | Congelare il nodo cambia il codice, non la decisione. È il prerequisito di ogni numero della colonna `p1_static`. |
| **Come rigirarlo** | `sudo python3 ipa/test/bench_scaling.py --verify` |

---

### A5 — L'equivalenza numerica vale anche sui modelli sintetici ✅

| | |
|---|---|
| **Ipotesi** | Che i pesi sintetici **compilino** e passino il verificatore dimostra che le pipeline sono corrette indipendentemente dal modello. |
| **Variabile modificata** | Il modello: 7 scenari sintetici (`deep`, `ipa_like`, `large`, `mixed`, `ones`, `small`, `sparse`), pesi casuali, forme da 11-2-3 a 117-8-8-9. |
| **Variabili fisse** | La pipeline (P1), il descrittore di ciascuno scenario, 300 ingressi per scenario con seme fisso. |
| **Metrica** | Accordo fra argmax su quattro vie: float (Python), int8 (`synth.reference`, scala **dichiarata dal modello**), int8 (`verify_prog_run.ref_infer_sparse`, scala **del catalogo**), int8 (eBPF nel kernel). |
| **Risultato** | **6/7 scenari: 300/300 decisioni identiche** fra riferimento intero ed eBPF. Il settimo (`small`) sta a 70,33%, ma la riga `int8 (riferim.) vs int8 (eBPF)` resta a **100%**: l'eBPF concorda esattamente con il riferimento che usa la sua stessa scala. |
| **Conclusione** | L'ipotesi era **troppo debole, e la sua verifica ha trovato due difetti diversi**. L'aritmetica del datapath e' esatta su tutti e 7 gli scenari. Su `small` e' esatta rispetto a una configurazione sbagliata: il modello dichiara `ttl/16`, i tre datapath compilano `ttl/30` e non leggono il descrittore per questo campo (`struct feat_ent` non ha un posto dove metterlo). Costo: 29,67 punti di accordo su quel modello. |
| **Difetto del banco trovato per primo** | Nel run iniziale cinque scenari su sette davano 71-85%. Era `verify_synth_kernel` che non comunicava al kernel la porta d'ingresso: `prog_test_run` accetta `ingress_ifindex` ma lo **ignora** (niente `ctx_in`), e il programma vede sempre `TEST_RUN_DEFAULT_INGRESS_IFINDEX = 1`. Confermato senza kernel: simulando "l'eBPF vede porta 0" si riproducono le percentuali osservate con scarto **0,00** su 6 scenari. |
| **Nota** | L'accordo float/int8 misurato qui (97,7-100%) **non e'** il `quant_agreement` di `expected.json` e non va confrontato con lui: li' gli ingressi sono campionati liberamente, qui solo fra quelli che il datapath sa esprimere. Ma la distanza che questa riga spiegava col campionamento (0,789 contro 97,7% su `ipa_like`) veniva quasi tutta da un'altra causa: `generate.py` chiamava `synth.reference.forward_int8` senza `scale`, e `expected.json` conteneva i logit di uno schema con il bias **non riscalato**, che nessuna pipeline esegue. Corretto il 2026-09-23: `scale` e' obbligatoria, `expected.json` dichiara `int8_scheme` e `load_scenario` rifiuta i file senza. Rigenerati: `ipa_like` 0,986 (era 0,789), `deep` 0,983 (0,706), `sparse` 0,995 (0,567), `small` 0,999 (0,349), `large` e `mixed` 0,997 (0,846), `ones` 1,000. |
| **Stato dopo le correzioni** | La scala per-feature nel descrittore (`feature_scale_of`, `struct feat_ent.scale`) e' entrata nello stesso commit che ha scritto questa scheda (`a217739b`, 2026-09-18): la frase su `struct feat_ent` descrive lo stato trovato, e il 70,33% di `small` e' il numero di **prima**. Rieseguito nel kernel il 2026-09-23 (`verify_synth_kernel.py --all --n 300`, scenari rigenerati dal seme): **7/7 scenari, 300/300 su tutte le righe int8**, `small` compreso (era 70,33%); float vs int8 fra 97,67% (`ipa_like`) e 100%. Senza kernel, dal 2026-09-23 `test_synth` [8] e `verify_synth_kernel --dry-run` confrontano `synth.reference` con il C generato da P1, valutato dal testo (`ipa/test/p1_c_eval.py`, regole intere del C): logit identici su tutti e 7 gli scenari, `small` compreso (2 940 casi in `test_synth`, 300 per scenario nel dry run). Clang, verificatore e JIT restano fuori da quel confronto. |
| **P2 e P3 (2026-09-23)** | Stesso confronto nel kernel con `--pipeline p2` / `p3`, 300 ingressi per scenario. **P2: 7/7** a 300/300 (`ipa_like`, `deep` con foglia a 3 strati nascosti, `sparse`, `ipa_ttl16`, e -- tolto il 2026-09-23 il vincolo n_out = 7 del piano di controllo, che il datapath non aveva -- `small`, `mixed`, `ones` con 4, 5 e 3 uscite); `large` non applicabile (1097 pesi, blocco da 1024). Nel primo run dello stesso giorno, prima della correzione, P2 era 4/4 con quei tre scenari rifiutati. **P3: 7/7** a 300/300; `large` non applicabile (9 uscite, limite 8). La scala diversa da 30 e' messa alla prova solo dove sposta davvero le decisioni: `ipa_ttl16` (41/300) e `small` (89/300), in P2 e in P3. Controllo negativo: riscritto il solo byte `feat_ent.scale` a 30, l'eBPF segue il riferimento a 30 su 300/300 e si stacca da quello dichiarato **esattamente** sui 41 / 89 casi previsti, quindi il kernel legge quel byte. `ones` e `large` hanno K = 0: il loro 100% non dice niente sulla scala. |
| **Come rigirarlo** | `sudo python3 ipa/test/verify_synth_kernel.py --all --n 300` — `--pipeline p2` / `p3` per le altre due pipeline; oppure `--dry-run` senza kernel, che confronta anche il C di P1 valutato dal sorgente; `python3 ipa/test/test_synth.py` per il riferimento contro il C, caso minimo compreso |

---

### A6 — Non generare le colonne delle porte assenti non cambia la decisione ✅

| | |
|---|---|
| **Ipotesi** | Un nodo di grado 3 ha `link_state[3..5]` permanentemente a zero: quelle interfacce **non esistono**, non sono link caduti. Togliere quelle colonne dal primo layer di P1 deve essere esatto, non approssimato — ma se una colonna tolta non fosse davvero nulla, il programma sarebbe più piccolo e calcolerebbe un altro modello, e nessuna misura di costo se ne accorgerebbe. |
| **Variabile modificata** | `static_ports`: quali colonne di `link_state` P1 genera. Il nodo è congelato in **entrambe** le build, quindi la differenza è attribuibile a questa sola modifica. |
| **Variabili fisse** | Pesi, descrittore, topologia, `n_in`, offset dei pesi, indice del nodo. |
| **Metrica** | La classe scelta e il valore di ritorno XDP, su tutti i pattern di link realizzabili × TTL 2-11. |
| **Condizione dichiarata** | L'equivalenza vale finché gli slot senza interfaccia valgono 0. È garantito da `link_state_monitor`: `carrier_state()` ritorna 0 per un'interfaccia inesistente, al seed e a ogni poll. **Non** vale sotto `verify_prog_run._seed_link_state`, che semina 1 ovunque — il test azzera esplicitamente gli slot assenti nel riferimento. |
| **Controllo negativo** | Accendendo uno slot assente le due build **devono** divergere. Un test che passa anche così non starebbe verificando la condizione: se quelle colonne non spostano mai l'argmax, «le due concordano» è vero anche per una specializzazione sbagliata. |
| **Risultato** | **80/80** casi identici (TTL 2-11 × 8 pattern realizzabili, porte {0,1,4}), e **controllo negativo che morde**: accendendo uno slot assente le due build divergono in **29** casi. |
| **Il primo run era inconcludente** | 80/80 ma controllo negativo **muto**: sul seme di default quelle colonne non spostavano mai l'argmax, quindi l'80/80 sarebbe stato vero anche per una specializzazione sbagliata. Una colonna di `link_state` contribuisce `1 × w` a un accumulatore che ne somma 65 — proprietà dei **pesi**, non del codice. Il controllo ora cerca fra più semi del pool e **fallisce** se nessuno morde: ha trovato il seme 123. |
| **Conclusione** | Non generare le colonne delle porte assenti cambia il codice, non la decisione. È il prerequisito di ogni numero dell'asse `degree`. |
| **Come rigirarlo** | `sudo python3 ipa/test/bench_scaling.py --verify-ports` (o `--ports 0,1,4`) |

---

### A7 — Ogni modello ha la sua semantica, senza un programma per modello ✅

| | |
|---|---|
| **Ipotesi** | In P2 e P3 modelli con significati diversi per la stessa classe possono convivere nello **stesso** programma caricato, senza contaminarsi e senza costo misurabile per pacchetto. Fino al 2026-09-23 non era possibile: `class_action_t2/_t3` era indicizzata dalla sola classe, condivisa da tutti i `model_id`, e il piano di controllo rifiutava un secondo modello con semantica diversa. |
| **Variabile modificata** | La chiave della tabella classe → azione: classe sola contro `(model_id, banco, classe)`, appiattita in un `BPF_ARRAY` di 256 × 2 × 32 righe. Il banco attivo sta nell'entry di `arch_registry` / `layer_registry`: ricaricare un modello scrive il banco inattivo e un solo update del registry installa insieme `n_out` e banco. |
| **Variabili fisse** | Inferenza, pesi, descrittori, un programma per architettura, pacchetti, VM (4 vCPU), metodologia di `test_suite` (minimo dei trial, p50/max). |
| **Metrica** | Azione prodotta dal kernel per ogni classe di ogni modello (MAC riscritto, `XDP_DROP`, `XDP_PASS` con o senza contatore); istruzioni, JIT, letture di tabella, tail call, memoria mappe, latenza min/p50/max. |
| **Risultato** | **53/53** su P2 e P3: un modello; due con la stessa semantica; due con semantiche diverse su ogni classe a pacchetti alternati (classe 0: FORWARD per A, DROP per B); A → B → A anche dopo aver ricaricato B; `model_id` inesistente o rimosso non elaborato; `n_out` 4 e 7 insieme; stesso `model_id` ricaricato con altra semantica e altro `n_out` (banco 0 → 1, altri modelli intatti). **Costo**: istruzioni P2 −9, P3 +25; letture 11 e 29 invariate; tail call invariate; latenza entro il rumore (p50, mediana su 1/2/4/8 modelli: P2 289 → 298 ns, P3 477 → 489 ns); nessuna pendenza da 1 a 8 modelli; **memoria +131 072 byte per pipeline**, fissi. |
| **Controllo negativo** | Con una tabella condivisa simulata (tutti i modelli sulle stesse righe) A e B passano e C, D, F, R falliscono: il test distingue le due cose. |
| **Perché non dentro il registry** | Il datapath ha già l'entry del modello, ma indicizzarne il valore con `best_cls` obbliga il verificatore a tracciare `best_cls` con precisione attraverso l'argmax: `layer_hidden` di P3 non carica più (`E2BIG`). Una chiave sullo stack no. |
| **Limite dichiarato** | ⚠️ I 128 KiB sono riservati per 256 modelli anche con un modello solo. Un'alternativa a pochi KB (slot allocato dal piano di controllo, come `weight_offset`) non è stata implementata. Nel primo run del bench il **minimo** di 4 configurazioni su 28 era sotto il pavimento del programma (artefatto non spiegato): il costo si legge sulle mediane. In P3 `layer_first` è al limite dello stack BPF nelle build strumentate: la chiave viaggia dentro `last_key` (al posto di `is_last`), altrimenti la build T1/T2 di `bench_throughput` non compila. |
| **Come rigirarlo** | `sudo python3 ipa/test/verify_per_model_semantics.py`; `sudo python3 -u ipa/test/bench_semantics_models.py --baseline-dir <albero precedente>/ipa --trials 21` |

---

## B. Il costo della flessibilità

> **Rimisura del 2026-09-23** (sezioni B, C, D). `bench_scaling` e `test_suite` sono stati rifatti con P1 e P1.5 come **oggetto AOT** (quello dei nodi). In quella sessione la macchina era circa il **35–40% più veloce** della precedente su **tutte** le pipeline, anche P2 e P3 che non sono cambiate: è lo stato dell'host (CPU ibrida), non dei programmi. I **rapporti** fra pipeline e le istruzioni restano invariati; le cifre assolute di sessioni diverse non si confrontano. Le schede riportano la rimisura in una riga propria.
>
> **Dal 2026-09-24** (semantica per modello, A7) P2 e P3 contano **14 976** e **12 374** istruzioni invece di 14 985 e 12 349, con letture di tabella, tail call e latenza invariate entro il rumore, e **+131 072 byte** di mappe per pipeline. Le cifre delle schede B, C e D sono state misurate prima: i rapporti e le conclusioni valgono, le istruzioni di P2/P3 e la memoria vanno lette con questa correzione.

Questa è la sezione che risponde all'esempio del relatore. La scala ha **quattro**
gradini, non tre: si è aggiunta una P1 pienamente specializzata sotto quella che
il progetto chiamava P1.

### B1 — Rendere le feature configurabili a runtime costa latenza ✅

| | |
|---|---|
| **Ipotesi** | Più cose si decidono a runtime invece che a compile time, più costa per pacchetto. |
| **Variabile modificata** | Quanto è noto alla compilazione: P1 specializzata (pesi + nodo) → P1.5 (pesi) → P2 (soffitti) → P3 (anche la profondità). |
| **Variabili fisse** | Modello 65-4-4-7, topologia Germany50, descrittore, stessa macchina, stesso run. |
| **Metrica** | Latenza minima su 7 trial, istruzioni eBPF, tail call, letture di mappa. |
| **Risultato** | 58 → 69 → 268 → 436 ns. Istruzioni 614 → 1 071 → 14 985 → 12 349. Salti fra programmi 1, 1, 1, 3. Letture di tabella 6 (P1.5), 11 (P2), 29 (P3). |
| **Conclusione** | **La flessibilità costa circa 8× in latenza** fra i due estremi, e il costo non è aritmetico: è in letture di mappa e salti fra programmi. |
| **Rimisurato (2026-09-23)** | `test_suite`, P1.5 AOT: baseline **17**, P1.5 **50**, P2 **180**, P3 **278 ns**; istruzioni 155 / 1 011 / 14 985 / 12 349; letture 3 / 6 / 11 / 29; salti 0 / 1 / 1 / 3. Campagna (65-4-4-7, pesi sintetici): 17 / **36** (P1 statica) / 42 / 173 / 258 ns. Fra gli estremi ancora circa **7×**; P3 il 54% più lento di P2 con il 18% di istruzioni in meno. Conclusione invariata. |
| **Come rigirarlo** | `sudo python3 ipa/test/test_suite.py --only kernel` e `sudo python3 ipa/test/bench_scaling.py --out results/` |

### B2 — Il costo di aggiornare il modello differisce di due ordini di grandezza ⚠️ *(superato dalla rimisura AOT)*

| | |
|---|---|
| **Ipotesi** | Compilare i pesi dentro il codice sposta il costo dal pacchetto al deployment. |
| **Variabile modificata** | La pipeline. |
| **Variabili fisse** | Modello e topologia; misurato su **tutti e sei** gli assi dello sweep. |
| **Metrica** | `update_ms`: tempo per installare un modello nuovo su un nodo già in servizio. |
| **Risultato** | P1 e P1.5 fra 1 162 e 1 690 ms (rigenerano C e chiamano clang); P2 e P3 fra 5 e 14 ms (scritture in mappa). |
| **Conclusione** | Circa 200×. È la metrica che decide se una pipeline è usabile in una rete che cambia. |
| **Nota metodologica** | `build_ms` e `update_ms` **non vanno confusi**: per P2/P3 il primo è una compilazione pagata una volta all'avvio del nodo, il secondo è il costo per modello. Metterli sullo stesso asse farebbe sembrare P2/P3 più costose di P1, cioè il rovescio della verità. |
| **Rimisurato (2026-09-23) — la conclusione cambia** ⚠️ | Con P1 come oggetto AOT, `update_ms` e' il solo caricamento sul nodo: **P1 e P1.5 5–8 ms** (un picco a 31 ms), **P2 e P3 4–10 ms**. Anche contando generazione del C, clang e caricamento (`build_ms`), P1 sta a **70–140 ms**. Il divario di circa 200× **non esiste piu'**: il ~1,5 s era il costo di **BCC** (che analizza gli header del kernel a ogni compilazione), non del compilatore. P2 e P3 pagano BCC una volta, all'avvio del nodo (1,3–1,8 s). Resta vera solo la differenza qualitativa: P1 richiede un compilatore per ogni modello nuovo (fuori dal nodo), P2 e P3 no. |
| **Come rigirarlo** | `sudo python3 ipa/test/bench_scaling.py --out results/`; figura `scaling_depth_update.pdf` |

### B3 — L'AOT toglie il compilatore dal nodo senza costo per pacchetto ✅

| | |
|---|---|
| **Ipotesi** | Compilare l'oggetto fuori dal nodo elimina il costo di clang dal datapath, e la riduzione sui pesi letterali sopravvive dentro l'oggetto. |
| **Variabile modificata** | Dove avviene la compilazione: sul nodo (BCC) contro su una macchina di build (AOT). |
| **Variabili fisse** | Stesso modello, stessa topologia, **stessa sessione di misura**. |
| **Metrica** | Costo di messa in servizio; latenza per pacchetto. |
| **Risultato** | Aggiornamento 1 242 ms → 37 ms. Latenza 73 → 74 ns, cioè la stessa cifra (**cifra AOT non valida, vedi sotto: misurava un altro percorso**). |
| **Conclusione** | Due ordini di grandezza sull'aggiornamento, nessun costo per pacchetto. |
| **Limite dichiarato** | ⚠️ La cifra di deploy varia molto fra esecuzioni (4,7 / 6,2 / 20,7 / 37,2 ms per lo stesso oggetto). Regge l'**ordine di grandezza** rispetto a 1,3 s, non il valore preciso. |
| **Difetto della misura (C2, trovato il 2026-09-22)** | Il 74 ns non misurava l'inoltro: il loader eseguiva **una** chiamata `BPF_PROG_TEST_RUN` con repeat=1e6 sullo **stesso** frame (TTL 64), che il kernel non ripristina fra le ripetizioni. Dopo poche decine di esecuzioni il TTL scadeva (o, senza `--node-id`, la classe scivolava su DROP): il numero descriveva quel percorso corto, confrontato con 73 ns BCC misurati sull'inoltro. |
| **Rimisurato (2026-09-23)** | Stesso schema per entrambi (blocchi da 200 su frame TTL 255 sempre nuovo, minimo delle medie), stessa sessione, percorso d'inoltro (retval 4), nodo non impostato in entrambi. `test_suite --only kernel`: **AOT 1 011 istruzioni (28 + 983), 46 ns** contro **BCC 1 026 (29 + 997), 44 ns**; il bench del loader corretto da' 45 ns. Differenza di 2 ns sul minimo, dentro il rumore di questo host (spread 52-76%, CPU ibrida). Aggiornamento: AOT 9,1-9,9 ms di open+load contro 741 ms di compilazione+caricamento BCC nella stessa sessione. **Conclusione che regge**: l'oggetto deployato e il build BCC costano uguale per pacchetto entro il rumore; e' la base per usare il build BCC come sostituto dichiarato nelle misure di P1 che non hanno ancora una versione AOT. |
| **Throughput (2026-09-23)** | `bench_throughput --mode compare`, frame 64 B, due esecuzioni separate (prima `hardcoded`, poi `aot`, stesse manopole): consegnati a massima spinta **2 035 308 pps BCC** contro **2 038 253 pps AOT**; al rate comune (~1,83 Mpps offerti) mediana su 3 giri **1 240 424 pps BCC** (1 238 514-1 240 533) contro **1 222 111 pps AOT** (1 181 270-1 250 703). Nessuna differenza fuori dalla dispersione dell'AOT. Limite: sessioni diverse, e le colonne 'perdita' (17-30%) sono respinti del veth, vedi C3. |
| **Come rigirarlo** | `sudo python3 ipa/test/test_suite.py --only kernel` (righe `hardcoded` e `aot`); `sudo ./ipa/poc_aot/loader_aot ipa/poc_aot/nn_aot_arch.o` |

---

## C. Che cosa costa, e che cosa no

### C1 — La dimensione del programma non predice la velocità ✅

| | |
|---|---|
| **Ipotesi** | Le istruzioni eBPF sono un proxy del costo per pacchetto. **Falsa.** |
| **Variabile modificata** | La pipeline (P2 contro P3). |
| **Variabili fisse** | Modello, topologia, run. |
| **Metrica** | Istruzioni contro latenza, con tail call e letture di mappa come variabili esplicative. |
| **Risultato** | P3 ha il **18% di istruzioni in meno** di P2 ed è il **65% più lento** (12 349 contro 14 985; 448 contro 271 ns). Le righe che lo spiegano: 3 salti fra programmi contro 1, 29 letture di tabella contro 11. |
| **Prova di rinforzo** | Lo stesso codice, cambiando un solo `#define` (`IPA_MAX_QUEUES` 1→8), misura 8 674 **o** 12 031 istruzioni — il 39% di differenza — **a parità di latenza** (419 contro 421 ns). Una metrica che si sposta del 39% senza che cambi nulla di ciò che gira non è una misura di costo. ⚠️ Questi quattro numeri vengono da quella bisezione, eseguita su uno stato del codice **precedente** alla scala per-feature a runtime (che ha aggiunto +318 istruzioni a P3): per questo dicono 12 031 dove il banco oggi dice 12 349. Il confronto interno regge — è la stessa build in entrambe le colonne — e la conclusione non dipende dai valori assoluti. |
| **Conclusione** | `xlated` misura quanto è **grande** il programma caricato, non quanto **lavora**. In questo regime dominano letture di mappa e salti. |
| **Come rigirarlo** | `sudo python3 ipa/test/test_suite.py --only kernel` |

### C2 — La larghezza dell'ingresso è gratis a runtime; quella nascosta no ✅

| | |
|---|---|
| **Ipotesi** | Una rete più grande costa di più per pacchetto. **Falsa per la one-hot.** |
| **Variabile modificata** | Due assi separati: numero di nodi (10→100, cioè l'ingresso da 23 a 113) e neuroni per hidden layer (2→8). |
| **Variabili fisse** | Su ciascun asse, tutto il resto. |
| **Metrica** | Latenza minima su 7 trial. |
| **Risultato** | Nodi (ingresso da 23 a 113): P2 269→266 ns, P3 448→422 ns, **piatte**; p1_static 57→59, hardcoded 64→67 mentre le sue istruzioni vanno da 746 a 1 692. Neuroni (2→8): P2 250→314 ns, P3 401→530 ns, in salita su tutte e quattro. |
| **Conclusione** | Una one-hot ha un solo uno, quindi il datapath legge **una colonna di pesi** qualunque sia la sua larghezza. Un layer denso più largo legge più pesi per pacchetto. **La rete può crescere quanto vuole, il modello no.** |
| **Come rigirarlo** | `sudo python3 ipa/test/bench_scaling.py --axis nodes --out results/` e `--axis width` |

### C3 — In P1 il conteggio istruzioni dipende dai valori dei pesi ✅

| | |
|---|---|
| **Ipotesi** | Se i pesi sono letterali nel C, il compilatore può cancellare i prodotti per zero: la dimensione del programma dipende dai **valori**, non solo dalla forma. |
| **Variabile modificata** | La frazione di pesi esattamente zero: 0, 25, 50, 75, 90%. |
| **Variabili fisse** | Forma 65-4-4-7, descrittore, topologia. I pesi sono un prefisso di un pool fisso, quindi una configurazione più grande **estende** la più piccola. |
| **Metrica** | Istruzioni eBPF, byte di codice nativo e latenza. |
| **Risultato** | P1.5: 1 071 → 224 istruzioni (4,8×) e 68 → 40 ns. P1 specializzata: 614 → 216 e 60 → 31 ns. P2: 14 985 istruzioni e 274→268 ns a **tutte** le sparsità. P3: 12 349 e 432→427 a tutte. |
| **Conclusione** | Al 90% di zeri P1 si avvicina al baseline senza scendervi sotto: 216 istruzioni contro 155. Per P2 e P3 uno zero è un byte in tabella come un altro, e non si muovono. È inoltre **l'unico asse su cui scendono insieme dimensione e tempo**: sull'asse delle porte le istruzioni calavano e la latenza no. |
| **Come rigirarlo** | `sudo python3 ipa/test/bench_scaling.py --axis sparsity --out results/` |

### C4 — In P1 i pesi decidono se il programma si carica ✅

| | |
|---|---|
| **Ipotesi** | Corollario di C3, e non previsto: se il codice generato dipende dai valori, allora anche il **verdetto del verificatore** ne dipende. |
| **Variabile modificata** | **Solo** il seme del generatore di pesi. |
| **Variabili fisse** | Forma 65-4-4-4-4-7, 359 pesi, descrittore, topologia. |
| **Metrica** | Il programma si carica o no. |
| **Risultato** | Seme 42: **rifiutato**. Semi 1, 2, 3, 7, 123, 999: caricano, fra 1 075 e 1 175 istruzioni. Il seme 1 carica a 1 119, il 42 è rifiutato a 1 120. Le forme vicine — comprese `(4,4,4,3)` e la **più grande** `(4,4,4,4,4)` — caricano tutte. |
| **Conclusione** | **Riaddestrare un modello senza toccare l'architettura può renderlo non caricabile.** P2 e P3 non hanno questo rischio: per loro la caricabilità dipende solo dalla forma. |
| **Limite dichiarato** | ⚠️ *Quale* limite del kernel venga toccato non è confermato. `E2BIG` ha più cause e BCC ci stampa sopra un messaggio che ne nomina una sbagliata (il «at most 4096 insns» è una costante morta nella sua stringa: nello stesso sweep P2 carica a 18 057). Serve il log del verificatore. |
| **Come rigirarlo** | Lo script nella sezione C4 di `docs/testing.md`. |

### C5 — La genericità compilata si paga in complessità di verifica ✅

| | |
|---|---|
| **Ipotesi** | Un programma «generico» non è gratis: il verificatore percorre ogni cammino del corpo srotolato, e il costo cresce col **prodotto** dei soffitti. |
| **Variabile modificata** | I soffitti compilati (`T2_MAX_H1/H2`, `MAX_N_IN` in P2; `IPA_MAX_QUEUES`, `IPA_MAX_IFACES` in P3). |
| **Variabili fisse** | Modello e descrittore. |
| **Metrica** | Il programma si carica; e a quante istruzioni. |
| **Risultato** | P2 con soffitti larghi: `processed 1000001 insns (limit 1000000)` a ~14 900 istruzioni, cioè **dentro** il limite di dimensione ma oltre quello di complessità. P3: con il nodo da mappa, dodici configurazioni rifiutate fra 9 069 e 9 402; dopo l'inversione del nido di cicli, carica a 10 207 con otto slot di coda. |
| **Conclusione** | Due limiti distinti da non confondere. E il verificatore **paga i cammini, non la dimensione**: la riscrittura ha fatto *crescere* P3 di 433 istruzioni rendendolo molto più economico da verificare. |
| **Limite dichiarato** | ⚠️ Questi limiti sono **scogliere, non pendenze**: ridurre *anche* un secondo soffitto — chiedere meno — ha fatto fallire di nuovo il caricamento. Un soffitto si cambia e **si rimisura**. |
| **Come rigirarlo** | `sudo python3 ipa/test/diag_p3_bisect.py --ceilings` |

### C6 — Congelare il nodo toglie la dipendenza dalla taglia della rete ✅

| | |
|---|---|
| **Ipotesi** | L'indice del nodo è una costante di deployment; congelarlo fa sparire lo switch a N casi e rende la one-hot più grande del modello gratuita in dimensione. |
| **Variabile modificata** | Da dove arriva l'indice: costante compilata contro mappa. |
| **Variabili fisse** | Modello 4-4, descrittore, pesi (pool a prefisso). |
| **Metrica** | Istruzioni, byte nativi, latenza, al variare del numero di nodi. |
| **Risultato** | Istruzioni: specializzata 617→640 (**piatta**), P1.5 746→1 692. Codice nativo: 2 759→2 837 contro 3 394→8 432. Latenza: 54-58 contro 57-61 ns, cioè uguali. |
| **Controllo** | Sull'asse descrittore, dove il vettore d'ingresso **non contiene** la feature `node`, le due P1 sono **identiche alla cifra** (599/599, 575/575); dove la contiene, divergono. Il divario è tutto lì. |
| **Conclusione** | La dimensione crolla, il tempo no, **per la stessa ragione**: lo switch ha N casi ma ne esegue uno, quindi a runtime è un salto indicizzato. Non è un'ottimizzazione di velocità: è ciò che rende la hardcoded praticabile su una rete grande. |
| **Contro-risultato** | Con pesi sparsi il vantaggio **si annulla** (216 contro 224 al 90% di zeri): sparsità e nodo congelato sono due strade alla stessa riduzione e non si sommano. E il costo di aggiornamento **non cala** (stesso avvio di clang), mentre i binari da installare passano da uno a N. |
| **Come rigirarlo** | `sudo python3 ipa/test/bench_scaling.py --axis nodes --out results/`; figura `duel_p1_vs_p15.pdf` |

---

### C7 — Quanto costa generare colonne che il nodo non può mai usare ✅

| | |
|---|---|
| **Ipotesi** | Il one-hot del nodo ha N casi ma ne esegue **uno**: congelarlo riduce la dimensione, non il tempo (vedi C6). `link_state` è un vettore **denso**: il datapath esegue una moltiplicazione-accumulo per ogni coppia (interfaccia, neurone), a ogni pacchetto. Non generare le colonne assenti dovrebbe quindi togliere lavoro vero, non solo codice morto. |
| **Variabile modificata** | Il numero di porte realmente presenti, 2–6, via `static_ports`. |
| **Variabili fisse** | Modello 65-4-4-7, 52 nodi, descrittore default, e **gli stessi identici pesi** — `n_in` non cambia, quindi la cella prende lo stesso prefisso del pool. |
| **Metrica** | Istruzioni xlated, byte JIT, latenza, memoria delle mappe. |
| **Controllo** | `hardcoded`, `template` e `modular` non specializzano: sull'asse devono restare **piatte**. Una pendenza lì vorrebbe dire che l'asse stesso costa qualcosa, e invaliderebbe la lettura della colonna `p1_static`. |
| **Quantità attesa a livello di sorgente** | Su 65-4-4-7 (nₕ₁ = 4) ogni porta assente toglie **4** moltiplicazioni-accumulo più una lettura e una dichiarazione. Grado 3 su 6: 12 MAC su 24. Verificato contando i termini nel C generato, **non** in kernel. |
| **Interazione con la sparsità** | Da misurare insieme all'asse `sparsity`: con pesi molto sparsi clang cancella già parte di quel lavoro da solo, e i due effetti potrebbero non sommarsi — è quanto successo in C6 fra nodo congelato e sparsità. |
| **Risultato, istruzioni** | Lineare e netto: 546 / 564 / 582 / 598 / 614 per grado 2–6, cioè **17 istruzioni per porta** (delta +18, +18, +16, +16). Un nodo di grado 2 porta l'**11,1 %** di istruzioni in meno di uno di grado 6. |
| **Risultato, latenza** | **Nessuna tendenza.** 54 / 47 / 58 / 49 / 53 ns: non monotona, escursione del 23 % su un valore di ~50 ns. L'effetto atteso — 16 moltiplicazioni-accumulo fra grado 6 e grado 2, ~5 ns a 3,2 GHz — sta **sotto il rumore di questo banco** e non è risolvibile qui. |
| **Controllo, riuscito** | `hardcoded` 1 071, `template` 14 985, `modular` 12 349 **su tutti e cinque i punti**, e 319 pesi ovunque. L'asse di per sé non costa nulla: ogni pendenza nella colonna `p1_static` viene da `static_ports`. |
| **Conclusione** | Stesso esito di C6, per una ragione diversa. Lì lo switch a N casi ne eseguiva uno solo; qui le moltiplicazioni sono davvero eseguite, ma sono **16 su ~979 istruzioni** e il banco non le distingue dal rumore. La specializzazione delle porte è una riduzione di dimensione dimostrata e un guadagno di tempo **non dimostrato**. |
| **Previsione smentita** | Era stato previsto che, essendo `link_state` un vettore denso e non una one-hot, togliere colonne avrebbe spostato la latenza. La misura dice di no, a questa risoluzione. |
| **Come rigirarlo** | `sudo python3 ipa/test/bench_scaling.py --axis degree --out results/` (i byte JIT sono nel CSV, non nella tabella a schermo) |

---

### C8 — Il costo per MAC **eseguita** e' una costante della pipeline ✅

| | |
|---|---|
| **Ipotesi** | La latenza si predice dalle MAC contate sulla forma del modello (n_in × h1, ecc.). |
| **Variabile modificata** | Quattro assi indipendenti: colonne d'ingresso dense (n_in 5→17), colonne d'ingresso one-hot (n_in 16→65), larghezza (4→32), profondita' (1→4 strati). |
| **Variabili fisse** | Su ciascun asse, tutto il resto. Stessa metodologia di `test_suite`: `BPF_PROG_TEST_RUN`, minimo su N prove. |
| **Metrica** | Pendenza e r² della retta ai minimi quadrati sui quattro assi **insieme**, con MAC nominali e con MAC eseguite. |
| **Risultato** | Nominali: 0,081 / 0,100 / 0,153 / 0,123 ns/MAC con r² **0,65 / 0,79 / 0,34 / 0,09**. Eseguite: 0,324 / 0,349 / 0,812 / 1,462 ns/MAC con r² **0,99 / 0,92 / 0,71 / 0,91**. |
| **Conclusione** | L'ipotesi e' falsa con le MAC nominali: per P3 il modello spiega l'11% della varianza. Una feature one-hot occupa `size` colonne nella matrice dei pesi ma nel datapath ne attiva **una** — l'arm `FEAT_INGRESS_IF` fa h1 addizioni e non guarda `size`. Contando le MAC **eseguite**, quattro assi costruiti in modi diversi collassano sulla stessa retta, una per pipeline. Il costo per MAC eseguita e' **~0,32 ns con i pesi compilati e ~1,46 ns con i pesi letti da tabella**: un fattore **4,5**, ed e' il prezzo della genericita' espresso in una costante. |
| **Controprova** | Sull'asse one-hot n_in va da 16 a 65 e i pesi da 271 a 663, ma la latenza resta 88/89/88 ns su p1_static e 507/487/509 su P3. Le istruzioni di P1 intanto vanno da 1146 a 1702: la taglia statica cresce, il percorso eseguito no. ⚠️ `hardcoded` (+22%) e `template` (+28%) si muovono al punto piu' largo: su `hardcoded` e' plausibile la pressione sulla cache istruzioni, su `template` e' compatibile col rumore. Le righe piatte da citare sono p1_static e modular. |
| **Limite dichiarato** | ⚠️ Il residuo di P3 e' piu' alto sugli assi larghezza (34 ns) e profondita' (29 ns): ogni strato in piu' e' anche una tail call, e una tail call non e' una MAC. Sull'asse delle istruzioni P3 non ha nemmeno una pendenza — 12 349 su ogni cella, latenza da 386 a 759 ns: il suo costo non sta nella taglia del codice. |
| **Rimisurato (2026-09-23)** | P1 come oggetto AOT. Eseguite: **0,174 / 0,231 / 0,451 / 0,909 ns/MAC**, r² **0,87 / 0,95 / 0,69 / 0,92**. Nominali: 0,017 / 0,061 / 0,066 / 0,086, r² **0,11 / 0,70 / 0,19 / 0,11**. Conclusione invariata (P3: r² da 0,11 a 0,92); rapporto P3/P1 5,2× (era 4,5×). Asse one-hot: latenza piatta su **tutte e quattro** (59/58/59, 58/58/59, 152/151/150, 292/296/284 ns); le salite di P1.5 e P2 al punto piu' largo nella misura precedente erano rumore. Pavimento baseline 16–24 ns; residuo P3 larghezza 24 ns, profondita' 14 ns; P3 238–455 ns a 12 349 istruzioni. **Nuovo**: a larghezza 16 `p1_static` AOT **non compila** (4 errori di clang; con BCC si misurava a 199 ns), `hardcoded` si' (141 ns); causa da leggere. |
| **Come rigirarlo** | `sudo python3 ipa/test/bench_scaling.py --axis campaign --out results/`, poi `--plot results/` |

---

## D. Larga contro profonda

La risposta **non è la stessa per tutte le pipeline**, e per la hardcoded dipende
dal budget. Le due schede qui sotto vanno lette insieme: D2 varia la profondità a
parametri fermi su tutte e quattro le pipeline, D1 spinge il budget più in alto ma
solo su P1.

### D1 — «Allargare batte approfondire» vale, ma non sempre ✅

| | |
|---|---|
| **Ipotesi** | Dato un numero di parametri, spenderli in un layer largo costa meno che in molti stretti. **Vera solo per certi vettori d'ingresso.** |
| **Variabile modificata** | La profondità: 1, 2, 4, 8 hidden layer. |
| **Variabili fisse** | Il budget-pesi, con la larghezza **risolta per descrittore** perché il budget sia davvero centrato, e lo **scarto stampato per ogni tier** (3,9-21,8%). Tre tier: ~300, ~1 200, ~4 700 pesi. Quattro descrittori: 0, 1 o 2 one-hot, piccola da 6 e grande da 52. |
| **Metrica** | Latenza (min di 15 trial), istruzioni eBPF, e se il programma si compila e si carica. |

**Tier B (~1 200 pesi), il meglio abbinato (scarti 3,9-10,1%):**

| descrittore | n_in | larga | 2 layer | 4 layer | 8 layer |
|---|---:|---:|---:|---:|---:|
| `default` (2 one-hot) | 65 | **122 ns** | 183 (+50%) | 279 (+129%) | 293 (**+140%**) |
| `big_onehot` (1 grande) | 59 | **110 ns** | 161 (+46%) | 215 (+95%) | 268 (**+144%**) |
| `no_onehot` (0) | 11 | *crash* | *crash* | 501 ns | 457 ns |
| `small_onehot` (1 piccola) | 13 | *crash* | *crash* | *rifiutata* | 465 ns |

**Tier A (~300 pesi):**

| descrittore | n_in | larga | 2 layer | 4 layer | 8 layer |
|---|---:|---:|---:|---:|---:|
| `default` | 65 | **54 ns** | 56 | 58 | 70 (+30%) |
| `big_onehot` | 59 | 41 ns | **38** | 59 | 57 (+39%) |
| `no_onehot` | 11 | 107 ns | 110 | 107 | **102 (−5%)** |
| `small_onehot` | 13 | 93 ns | **92** | 105 | 112 (+20%) |

| | |
|---|---|
| **Conclusione 1** | Con un ingresso **grande e dominato da una one-hot** (`default`, `big_onehot`), allargare batte approfondire e il divario **cresce col budget**: +30-39% a 300 pesi, **+140-144%** a 1 200. Il meccanismo è una spesa fissa per strato, non aritmetica. |
| **Conclusione 2, nuova** | Con un ingresso **piccolo e denso** (`no_onehot`, n_in=11) il vantaggio **sparisce**: a 300 pesi la versione a 8 strati è marginalmente *più veloce* (102 contro 107 ns) e anche *più piccola* (1 280 contro 1 583 istruzioni). Una one-hot larga costa poco per pacchetto perché il datapath ne legge **una colonna**; un ingresso denso no, e allora allargare il primo strato moltiplica le letture di mappa. **La risposta dipende da com'è fatto il vettore d'ingresso**, non solo dal budget. |
| **Conclusione 3, il limite mangia prima le larghe** | A parità di budget, la forma larga sfonda lo **stack eBPF da 512 byte** prima di quella profonda, perché il primo strato è dove lo stack si consuma. Su `no_onehot` a 1 200 pesi: larga 1×63 (stack stimato 584) **crash**, 2×26 (288) **crash**, 4×17 (216) **carica**, 8×11 (168) **carica**. Con un ingresso piccolo e un budget medio, **la rete profonda è l'unica che sta in piedi**. |
| **Due limiti distinti, entrambi osservati** | `small_onehot` tier B mostra tutti e due: `1×57` e `2×25` muoiono nello **stack** (`Looks like the BPF stack limit is exceeded`, un abort di clang), mentre `4×16` passa la compilazione e viene rifiutata dal **verificatore** (`Program too large (5637 insns)`). Compilazione ed esecuzione sono soglie diverse e si incontrano in punti diversi. |
| **Il tier C non esiste** | ~4 700 pesi: **crash su tutti e quattro i descrittori e tutte e quattro le profondità**. Oltre ~1 300 pesi il modello non ci sta, larga o profonda che sia: non è una scelta di architettura, è il tetto del «tutto srotolato in una funzione». |
| **Limite dichiarato** | ⚠️ Il tier A ha scarti fino al 21,8%: a 300 pesi le larghezze intere fanno passi grossi (a 65 ingressi, quattro strati possono avere 262 o 359 pesi, niente in mezzo). Le differenze di 2-3 ns dentro quel tier non sono risolvibili. Il tier B è quello su cui appoggiarsi. |
| **Come rigirarlo** | `sudo python3 ipa/test/bench_depth_vs_width.py` |

> **La frase per la tesi.** Non «le reti larghe sono preferibili a quelle profonde»,
> ma: *con un ingresso dominato da feature one-hot — il caso di IPA — allargare
> batte approfondire, e sempre di più al crescere del budget; con un ingresso
> piccolo e denso il vantaggio sparisce, e oltre una certa taglia è la forma larga
> a non compilare più.* La prima è una legge che i dati non sostengono; la seconda
> è un risultato con un dominio di validità.

### D2 — A parametri fermi, la risposta cambia con la pipeline ✅

| | |
|---|---|
| **Ipotesi** | La conclusione di D1 vale anche fuori da P1. **Parzialmente falsa.** |
| **Variabile modificata** | Come lo stesso budget è disposto: 1, 2, 3, 4 o 5 hidden layer. |
| **Variabili fisse** | **I parametri: 592 ± 2%** (591, 599, 595, 604, 589 — la colonna `pesi` lo stampa a ogni cella). Famiglia coerente a imbuto (`h1 ≥ h`, hidden successivi uniformi), tutta dentro i soffitti di P2 e P3, così che tutte e quattro le pipeline corrano tutti e cinque i punti. |
| **Metrica** | Istruzioni, latenza, throughput, tail call, costo mappe, tempo di compilazione. |

**Latenza (ns/pacchetto) a parametri fermi:**

| hidden layer | 1 | 2 | 3 | 4 | 5 | |
|---|---:|---:|---:|---:|---:|---|
| P1 specializzata | 78 | 80 | 68 | 95 | 81 | nessuna tendenza |
| P1.5 hardcoded | 91 | 87 | 75 | 102 | 98 | nessuna tendenza |
| P2 template | 219 | 246 | 308 | 351 | **402** | **+84%** |
| P3 modular | 414 | 493 | 496 | 643 | **654** | **+58%** |

**Istruzioni eBPF a parametri fermi:**

| hidden layer | 1 | 2 | 3 | 4 | 5 | |
|---|---:|---:|---:|---:|---:|---|
| P1 specializzata | 902 | 889 | 840 | 1 029 | 972 | piatta |
| P1.5 hardcoded | 1 774 | 1 638 | 1 723 | 1 748 | 1 627 | piatta |
| P2 template | 14 668 | 14 985 | 16 663 | 16 867 | **17 828** | **+22%** |
| P3 modular | 12 349 | 12 349 | 12 349 | 12 349 | 12 349 | **identica** |

| | |
|---|---|
| **Conclusione** | A questo budget le due P1 **non distinguono** larga da profonda: la dispersione lungo l'asse (68-95 ns) è più grande di qualunque tendenza. Per P2 e P3 invece la profondità costa, molto, e **per due ragioni diverse**: P2 deve srotolare ogni layer, quindi cresce in dimensione *e* in tempo; P3 riusa lo stesso layer — la sua riga di istruzioni è identica a tutti e cinque i punti — e paga **una tail call per layer**. |
| **Il risultato utile** | Chi sceglie l'architettura deve sapere **su quale pipeline girerà**. Su una hardcoded a ~600 pesi la profondità è quasi gratis; su P2 o P3 la stessa scelta costa il 58-84% di latenza a parità di parametri. |
| **Limite dichiarato** | ⚠️ «Nessuna tendenza» per le due P1 significa **sotto il rumore di questo run**, non «nessun effetto». La dispersione è ±20% e la serie non è monotona (78, 80, 68, 95, 81). D1 mostra che a 1 200 pesi l'effetto su P1 c'è ed è grande: qui il budget è la metà e la profondità arriva a 5 invece che a 8. |
| **Come rigirarlo** | `sudo python3 ipa/test/bench_scaling.py --axis isoparam --out results/` |

### D3 — Perché la profondità costa, quando costa ✅

| | |
|---|---|
| **Ipotesi** | Il costo di un layer in più non è aritmetico: è un costo fisso di transizione. |
| **Variabile modificata** | Il numero di layer, su tre assi indipendenti (`depth` a parametri crescenti, `isoparam` a parametri fermi, i tier di D1). |
| **Metrica** | Latenza per layer aggiunto, e tail call. |
| **Risultato** | P3 sull'asse `depth_camp` (1→4 strati da 8): **386 → 759 ns**, cioè ~124 ns per strato, con le istruzioni ferme a 12 349 e le tail call da 2 a 5 — il costo è interamente nei salti e nelle letture. P2: **243 → 456 ns e 14 668 → 16 867 istruzioni**, cioè ricompila e srotola. P1 specializzata: 77 → 136 ns, ~20 per strato. |
| **Conclusione** | Tre meccanismi distinti per lo stesso sintomo. In P3 si vede allo stato puro: **dimensione costante, tempo crescente** è la firma di un costo di transizione e non di calcolo. |
| **Come rigirarlo** | `sudo python3 ipa/test/bench_scaling.py --axis depth --out results/` |

## E. Traffico vero: il percorso reale, separato in due

Fino alla sezione D ogni cifra in ns veniva da `BPF_PROG_TEST_RUN`. Qui c'e' un
generatore che manda pacchetti veri, un contatore che li conta all'arrivo, e
**tre marcature temporali** che separano il costo della pipeline da quello del
trasporto.

| Marca | Dove | Delimita |
|---|---|---|
| T1 | ingresso del dispatcher | prima che il pacchetto sia guardato |
| T2 | subito prima di `bpf_redirect` | dopo parse, inferenza, scelta classe |
| T3 | ingresso del contatore, altro capo | dopo redirect, veth, NAPI |

> **Revisione 2026-09-23 — le cifre in pps di questa sezione vanno rimisurate.**
> Fino a questa data `bench_throughput` divideva i pacchetti per la durata del
> blocco su `pgctrl start`, che oltre alla trasmissione contiene il tempo morto
> di pktgen (T_RUN raccolto entro 100 ms, 125 ms di attesa fissa, controllo di
> fine ogni 100 ms): fino a ~225 ms su finestre da 0,3 s. Firma nei dati:
> `--mode compare`, hardcoded, tre giri con RX 1 240 424 / 1 238 514 / 1 240 533
> pps — lo stesso conteggio diviso lo stesso blocco quantizzato (~0,443 s). Ogni
> **rate** di E1 ed E4 ne e' affetto, di una quantita' che non dipende dalla
> pipeline e non e' costante fra le righe. **Le latenze di E3 no**: vengono da
> `bpf_ktime_get_ns`, non da un conteggio diviso una durata. Il banco misura ora
> a **finestra stazionaria** (`--window steady`, default: contatori letti a
> differenza mentre tutte le istanze trasmettono, poi `stop`); `--window count`
> riproduce il vecchio divisore per il confronto. La meccanica di pktgen citata
> e' del sorgente del kernel: NON VERIFICABILE DAL REPOSITORY; la verifica e' il
> confronto `steady`/`count` sullo stesso punto, sulla VM.

### E1 — Il datapath non perde pacchetti; a perdere e' il trasporto ⏳ ⚠️

| | |
|---|---|
| **Ipotesi** | Le perdite osservate su un banco `veth` sono della pipeline. |
| **Variabile modificata** | Il punto di conteggio: trasmessi (TX), elaborati (HIT), arrivati (RX), piu' i rifiutati da `veth_xmit`. |
| **Variabili fisse** | Modello, topologia, taglia del frame, durata della finestra. |
| **Metrica** | `TX − HIT`, `HIT − RX`, e i rifiutati contati a parte. |
| **Risultato** | Sweep a sei rate da 0,5 a 3,0 Mpps, cinque pipeline, tre giri: **perdita 0,000% su ogni riga**. Ogni pacchetto mancante all'appello e' stato rifiutato da `veth_xmit` a coda piena, cioe' non e' mai entrato nel nodo. |
| **Conclusione** | L'ipotesi e' falsa: la perdita e' **controspinta del trasporto**. Un solo numero di "perdita" avrebbe attribuito alla pipeline un difetto del banco. |
| **Revisione 2026-09-23** | ⚠️ Regge solo la meta' stretta: **dopo** l'ingresso (TX−HIT, HIT−RX) la pipeline non perde niente. "Controspinta del trasporto" per i respinti e' troppo: `veth_xmit` rifiuta perche' la coda d'ingresso **del nodo** e' piena, cioe' il nodo non la svuota in tempo — per il costo della pipeline o per il ritardo di risveglio del thread NAPI, e questo sweep non separa le due cause. Un rate con respinti non e' un rate che il nodo regge. Il banco ora decide il "sostenibile" sulla perdita **totale** (respinti compresi) e stampa accanto quella dopo l'ingresso. Le cifre in pps dello sweep sono inoltre affette dal divisore sbagliato (nota in testa alla sezione). |
| **Come rigirarlo** | `sudo python3 ipa/test/bench_throughput.py --mode rates --frames 64 --rounds 3 --threads 2 --rates 0.5,1,1.5,2,2.5,3 --out results/` |

### E2 — I due banchi misurano la stessa grandezza ✅ *(dopo una correzione)*

| | |
|---|---|
| **Ipotesi** | `test_suite` e il banco parametrico, che usano entrambi `BPF_PROG_TEST_RUN` sullo stesso programma, devono dare lo stesso numero. |
| **Che cosa diceva la misura prima** | No, e con uno scarto che non era nemmeno costante: −61 / −24 / −16 / −14 % su baseline, hardcoded, template, modular. Il claim era stato marcato **previsione smentita**. |
| **La causa, trovata** | Non l'ipotesi: la misura. `_sample()` misurava **riusando un solo pacchetto** per tutte le ripetizioni, e `BPF_PROG_TEST_RUN` non ripristina il buffer fra una e l'altra. Il datapath decrementa il TTL, che dopo ~40 esecuzioni restava inchiodato a 1: da lì in poi ogni ripetizione prendeva `if (ip->ttl <= 1) return XDP_PASS`. Quel ramo sta **dopo** l'inferenza — il modello girava, ed è il motivo per cui le curve scalavano in modo regolare e il difetto non si vedeva — ma saltava la coda di inoltro: decremento, checksum, `pkt_stats`, `cls_stats`, `mac_table`, `bpf_redirect`. |
| **Portata del difetto** | **Tutti e undici gli assi**, non solo la campagna: `_sample` è una sola e la chiamano tutti e quattro i worker. Ogni latenza prodotta dal banco parametrico prima del 22/09/2026 misurava «parse + inferenza», non «tutto il percorso». |
| **La correzione** | `prog_test_run_bench`, la stessa funzione che usa `test_suite`: rinfresca il frame ogni 200 esecuzioni partendo da TTL 255 (255 − 200 = 55), quindi nessuna ripetizione arriva alla scadenza. |
| **Risultato dopo** | baseline 28 contro 30 ns (+7%), hardcoded 71 contro 79 (+11%), template 276 contro 271 (−2%), modular 453 contro 428 (−6%). **Concordano entro ±11%, senza segno sistematico.** |
| **Conclusione** | Ipotesi **vera**. I due banchi misurano la stessa grandezza e si possono accostare. Lo scarto residuo su `hardcoded` ha una causa nota e non è rumore: `test_suite` usa i pesi veri del modello (1 026 istruzioni), il banco parametrico pesi sintetici a sparsità nulla (1 071) — sono due programmi diversi. |
| **Effetto collaterale, più importante del claim** | La correzione ha reso **confrontabili sweep diversi**. Il modello 65-4-4-7 compare sia sull'asse `degree` sia nella campagna, con istruzioni identiche al bit: prima i due sweep divergevano di un fattore uniforme 1,8, adesso concordano entro il 2% su tre righe su quattro. Era l'incoerenza più grave del banco e si è chiusa insieme a questa. |
| **Come rigirarlo** | `sudo python3 ipa/test/test_suite.py --only kernel` e `sudo python3 ipa/test/bench_scaling.py --axis campaign --out results/` **nella stessa sessione**, poi confrontare la riga `width_camp` x=4. Sessioni diverse non sono confrontabili: le cifre assolute dipendono dallo stato della macchina. |

### E3 — Il costo della pipeline si separa da quello del trasporto ✅

| | |
|---|---|
| **Ipotesi** | La latenza da arrivo a partenza tiene insieme due costi che si possono separare, e il secondo non dipende dalla pipeline. |
| **Variabile modificata** | Dove si prende il tempo: una marcatura sola (ingresso→uscita) contro tre (T1, T2, T3). |
| **Variabili fisse** | Modello, frame 64 B, generatore e nodo su core disgiunti, NAPI in thread. |
| **Metrica** | T2−T1, T3−T2, T3−T1, minimo per finestra, mediana fra tre giri. |
| **Risultato** | T2−T1: **27 / 50 / 57 / 183 / 271 ns** (baseline, p1_static, hardcoded, template, modular). T3−T2: **195–219 ns per tutte e cinque**, senza correlazione con il lavoro svolto. T3−T1: 224 / 268 / 275 / 405 / 509 ns. |
| **Conclusione** | Ipotesi vera. Il trasporto e' un costo comune di circa 200 ns che copriva quasi del tutto una baseline da 27 ns. La separazione **corregge al ribasso** la cifra della genericita': il costo di P2 sopra la baseline era stimato ~200 ns da un confronto fra latenze end-to-end, ed e' **156 ns**. P3 costa altri 88 ns sopra P2. |
| **Riproducibilita'** | Quattro sweep indipendenti, giorni diversi: scarti di 1–2 ns. E' la misura piu' stabile del progetto. Piatta anche sul rate: 27 ns a 0,5 Mpps e 27 ns a 3,0 Mpps. |
| **Limite dichiarato** | ⚠️ Build **strumentata**: due letture dell'orologio e due scritture per pacchetto che il datapath di produzione non fa. Se qualcosa, T2−T1 e' gonfiato. |
| **Come rigirarlo** | Come E1. |

### E4 — Il tetto misurato e' la via di ricezione, non l'inferenza ⏳ ⚠️

| | |
|---|---|
| **Ipotesi** | Il throughput osservato nello sweep e' una capacita' del nodo. |
| **Variabile modificata** | La presenza della pipeline: `--mode generator` carica lo **stesso percorso senza nessuna inferenza**, solo un contatore che scarta. |
| **Variabili fisse** | Generatore, code, veth, pinning dei core, taglia del frame. |
| **Metrica** | Offerti (TX + respinti), accettati, respinti da `veth_xmit`, perdita. |
| **Risultato** | Il generatore offre stabilmente ~5,1 Mpps; il veth ne accetta ~3,4; il 29–39% viene **rifiutato all'ingresso**. Perdita 0,00% su tutte e 29 le righe: RX identico a TX. Massimo osservato **3,73 Mpps**. |
| **Conclusione** | L'ipotesi e' falsa. Le pipeline, che nello sweep stavano fra 1,07 e 1,39 Mpps consegnati con perdita nulla, avevano ancora **circa 2× di margine**: il loro ginocchio non e' mai stato raggiunto. Ogni cifra in Mpps di questo progetto va citata come limite inferiore. |
| **Controprova** | Il budget per pacchetto fra tetto di ricezione (3,41 Mpps = 293 ns) e baseline sotto traffico (1,82 Mpps = 549 ns) differisce di 256 ns; la somma T2−T1 + T3−T2 della baseline, misurata indipendentemente, vale 224 ns. Concordano entro il 14%. |
| **Limite dichiarato** | ⚠️ Una coda piu' grande **non** alzerebbe il tetto: il disavanzo e' stazionario (~1,7 Mpps per tutta la finestra, mezzo milione di pacchetti), e una coda assorbe picchi, non uno squilibrio di rate. La profondita' compra latenza, non banda. Alzarla gonfierebbe T3−T2. |
| **Come rigirarlo** | `sudo python3 ipa/test/bench_throughput.py --mode generator --frames 64 --rounds 5 --threads 2 --rates 8,10,12,15,20,25 --out results/` — **da lanciare da solo**: in coda a `--mode rates` la stessa misura ha dato 1,26 Mpps invece di 3,73. |
| **Revisione 2026-09-23** | ⚠️ Il "circa 2× di margine" **non si ricava** da queste misure. (1) `--mode generator` non e' "lo stesso percorso senza inferenza": il contatore scarta **all'ingresso**, quindi mancano il redirect, il secondo veth e il contatore d'uscita che le pipeline attraversano. Il suo tetto e' un limite superiore del solo ingresso, non del percorso delle pipeline. (2) La baseline **sul percorso vero** stava a ~1,82 Mpps (la controprova stessa lo usa): le pipeline a 1,07–1,39 Mpps erano quindi al 60–75% della baseline, non a meta' di un tetto raggiungibile. (3) "Perdita nulla" escludeva i respinti (vedi E1). (4) Tutte le cifre in pps hanno il divisore sbagliato (nota in testa alla sezione). La controprova in ns (256 contro 224) confronta due differenze di rate misurate cosi', e va rifatta. Resta vero solo che ogni cifra in Mpps del progetto e' un limite inferiore — ora per un motivo in piu'. |
| **Rimisurato 2026-09-23** (finestra stazionaria, un run, 3 giri × 3 ripetizioni, 64 B, 2 thread generatore, DUT su cpu3) | Sola ricezione (`--mode generator`, contatore che scarta all'ingresso): **4,32 Mpps** a 8 Mpps di target, 6,37 offerti, 32% respinti; il ricevitore respinge gia' da 2 Mpps. Percorso vero, fase `saturazione` di `--mode compare`, respinti 51–79% su tutte (DUT saturo): baseline **3,98**, p1_static **3,56**, hardcoded **3,51**, template **2,25**, modular **1,72** Mpps; dispersione fra i giri 1–4%; controllo di validita' PASS. Rispetto al tetto di sola ricezione: **92 / 83 / 81 / 52 / 40%** in questo run; ma i due numeri vengono da run separati, e alla ripetizione la sola ricezione e' uscita 3,92 Mpps e la baseline 4,01 — il rapporto baseline/sola ricezione sta fra 0,92 e 1,02, cioe' **la baseline sta sul tetto di ricezione entro il rumore fra run**. Nessun "2× di margine" in nessuno dei due casi. Costo per pacchetto sopra la baseline (1/RX): **+30 / +33 / +194 / +330 ns**, contro T2−T1 di E3 **+23 / +30 / +156 / +244 ns**: P1 e P1.5 coincidono, P2 e P3 escono piu' alti del 24–35% sotto carico. A 1,56 Mpps offerti a tutte (sotto la capacita' di ciascuna) i respinti restano 1,0 / 1,2 / 2,4 / 3,7 / 11,9%: sotto capacita' non c'e' rate a perdita nulla con NAPI in thread su questa VM. Un solo run: da ripetere prima di citarlo come cifra. |
| **Stessa sessione, con `rxonly`** (2026-09-23, 5 giri × 3 ripetizioni, 64 B; il tetto di sola ricezione misurato a giri insieme alle pipeline) | Saturazione, mediana [min–max]: rxonly **4,77** [4,59–4,87], baseline **4,00** [3,85–4,12], p1_static **3,72** [3,48–3,80], hardcoded **3,50** [3,32–3,57], template **2,21** [2,14–2,29], modular **1,72** [1,68–1,79] Mpps; validita' PASS. Quota del tetto: **84 / 78 / 73 / 46 / 36%**. Costo sopra la baseline: **+19 / +36 / +202 / +331 ns** (run precedente +30 / +33 / +194 / +330: P2 e P3 si ripetono entro il 4%, P1 e P1.5 entro ~10 ns). P1 statica contro P1.5: mediane distanti il 6%, intervalli sovrapposti — **non separabili** su questo banco. A 1,55 Mpps offerti anche rxonly respinge il **2,3%**: baseline, P1 e P1.5 (1,3–2,0%) stanno su quel pavimento, cioe' i loro respinti sotto capacita' sono del trasporto; template (3,3%) e modular (9,8%, al 90% della sua capacita') lo superano. |
| **Il pavimento dei respinti, provato a togliere** (2026-09-23) | La coda del veth (256) non si allarga (`ethtool -G` non supportato) e il busy-poll del thread NAPI non c'e' (`threaded=2` rifiutato via sysfs con la NAPI presente; netlink/ynl assenti). Ipotesi: il pavimento e' il risveglio del vCPU del DUT dall'halt (cpuidle driver `none`). Prova: un ciclo `SCHED_IDLE` sulla cpu3 per tenerla sveglia. **Smentita**: rxonly a saturazione da 4,60 a 2,69 Mpps (±40%), respinti a 1,55 Mpps dall'1,1 al 35%, e cala anche l'offerto del generatore (7,56 → 6,63 Mpps) — il ciclo peggiora la macchina intera, non libera il DUT. Il pavimento (1–2% a 1,55 Mpps, variabile fra run) resta un limite dichiarato del banco; rxonly lo misura in ogni sessione. |
| **Con frame XDP grezzi** (2026-09-23, `--generator xdp`: `BPF_PROG_TEST_RUN` live frames, niente skb ne' copia di headroom; 5 giri, 64 B; validita' PASS) | Saturazione, ns/pacchetto sul DUT (pktgen → XDP): rxonly **210 → 50**, baseline **250 → 219**, p1_static **269 → 270**, hardcoded **285 → 271**, template **452 → 432**, modular **581 → 544**. Togliere la copia cambia quasi solo il tetto di sola ricezione (×4, 4,8 → 19,8 Mpps): per le pipeline che fanno redirect il costo assoluto resta entro il 10%. **Sopra la baseline**: P2 +202 → +213 ns, P3 +331 → +325 ns — **si ripetono entro il 5% con due generatori diversi**; P1 +19 → +50, P1.5 +36 → +52 ns (P1 e P1.5 a questa risoluzione vanno citati come "qualche decina di ns"). **P1 statica contro P1.5: 3,71 contro 3,69 Mpps con XDP, 3,72 contro 3,50 con pktgen — nessun vantaggio misurabile dello specializzare il nodo.** Aperto: la baseline costa 169 ns sopra rxonly con XDP e 40 con pktgen; la differenza fra i due generatori sta nel percorso di redirect e ritorno delle pagine, non nelle pipeline. Nota di metodo: al primo run (pool del generatore da 64 pagine, ricreata ogni 65 536 frame) offerto e RX erano accoppiati e la dispersione ±30–88%; con pool da 256 e chiamate da 2^20 frame la dispersione scende a pochi punti. |
| **Costo del nodo, dalla ricezione all'inoltro** (2026-09-23, `--generator xdp --egress-cpu 0`, 5 giri, 64 B) — **la cifra da citare** | Sulla CPU del DUT resta solo il nodo: presa del frame XDP dalla coda di ricezione, parse, inferenza, decisione, redirect e accodamento sul veth d'uscita; la ricezione del nodo a valle gira sulla cpu0. Costo = 1e9 / HIT (pacchetti su cui il programma ha deciso: l'uscita sulla cpu0 perde lo 0,2–4,5% e RX sottostimerebbe il nodo). **Baseline 117,0 · P1 statica 169,9 · P1.5 168,1 · P2 335,0 · P3 493,0 ns/pacchetto**; sola ricezione 51,7. Sopra la baseline: **+53 / +51 / +218 / +376 ns** (run di stima dello stesso giorno: +48 / +52 / +215 / +364). Contro il solo programma (T2−T1 di E3: 27 / 50 / 57 / 183 / 271 ns) il resto — ricezione, redirect, accodamento, e il costo sotto carico di mappe e tail call — vale 90 / 120 / 111 / 152 / 222 ns e cresce con la complessita' della pipeline. P1 statica e P1.5 indistinguibili. Limiti: "ricezione" e' la presa dalla coda del veth, non da una coda DMA; "inoltro" e' l'accodamento sul veth successivo, non un descrittore TX; un vCPU di una VM su host ibrido. Con pktgen e uscita separata il DUT rallenta (risveglio dei thread d'uscita da un'altra vCPU): quella combinazione non si usa. |
| **Costo del nodo al variare di pacchetto e scenario** (2026-09-23, stessa configurazione) | **Taglia** (pacchetto fisso): 64 / 512 / 1514 B → baseline 121 / 122 / 123, P1 statica 169 / 171 / 169, P1.5 171 / 176 / 177, P2 347 / 345 / 348, P3 497 / 520 / 512 ns: il nodo tocca solo le intestazioni, il costo e' per pacchetto. **TTL a giro 2–33**: costo invariato, e nessuna classe diversa — questo modello decide in base a nodo e stato dei link, non al TTL (gia' noto da test_fabric); controprova che il generatore scrive davvero il TTL: con 1–33 i pacchetti scaduti compaiono in MISS (227 075). **Per classe** (`--per-class`, 3 giri: stato dei link e TTL cercati per ciascuna delle 6 classi raggiungibili, classe decisa verificata per ogni pipeline): inoltro sulle 5 classi FORWARD → P1 statica 165–176, P1.5 168–177, P2 307–325, P3 466–525 ns; classe DROP → 170 / 182 / 284 / 442 ns. **Il costo dipende dalla pipeline, non dalla classe ne' dalla porta d'uscita** (entro ~±10%, che e' il rumore fra sessioni: la baseline, che fa sempre la stessa cosa, va da 117 a 147). Il DROP non costa sensibilmente meno dell'inoltro: sulla CPU del DUT evita redirect e accodamento ma paga la restituzione della pagina, che nell'inoltro avviene sulla CPU d'uscita — effetto del banco, non della pipeline. |

---

## F. Che cosa nessun test di questo progetto dimostra

Dichiarato per non far sembrare coperto ciò che non lo è.

- **Throughput assoluto.** ~~Tutte le cifre in Mpps sono `1/latenza`~~ — chiuso
  dalla sezione E: il traffico vero c'è, i pacchetti persi sono misurati e
  attribuiti. Resta aperto il **valore assoluto**: su questo banco il nodo non
  satura mai (il tetto è il generatore o la coda del `veth`), quindi la cifra in
  Mpps è un limite inferiore e ciò che si cita è la **differenza** rispetto alla
  baseline. Per un throughput assoluto servono due macchine e una scheda di rete
  che supporti XDP nativo.
- **Prestazioni citabili.** VM a 4 vCPU, nessun pinning dei core, nessuna
  frequenza fissata, nessun C-state disabilitato. Valgono i rapporti fra le
  colonne dentro una stessa esecuzione, mai le cifre assolute.
- **Latenze fra assi diversi.** A programma identico P2 misura ~250 ns su due
  assi e ~310 su altri due: la macchina si carica durante l'esecuzione. Lo sweep
  ha un allarme automatico, ma confronta **dentro** un asse.
- **Accuratezza del modello.** Il modello non è stato addestrato in questo
  lavoro. I test verificano che il datapath calcoli **la stessa cosa** del
  riferimento, non che quella cosa sia una buona politica di routing.
- **Reti oltre ~115 nodi.** `MAX_N_IN` è 128 in P2 e P3. Per dire qualcosa su una
  topologia da 500 nodi bisogna alzare quel soffitto e **rimisurare**, perché
  questi limiti sono scogliere.
