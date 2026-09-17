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
| **Come rigirarlo** | `python3 ipa/test/test_class_semantics.py` e la sezione `class_action` di `--only kernel`. |

### A2 — Il datapath consegna pacchetti veri, non solo aritmetica ✅

| | |
|---|---|
| **Ipotesi** | Un test che confronta logit con un riferimento non dimostra che il pacchetto esca dal nodo. |
| **Variabile modificata** | Il banco: `BPF_PROG_TEST_RUN` contro un fabric `veth` con XDP **native** e `bpf_redirect` reale. |
| **Variabili fisse** | Modello, pesi, descrittore. |
| **Metrica** | Pacchetto catturato sull'interfaccia d'uscita; DROP letto dal contatore `cls_stats`, non dal silenzio. |
| **Risultato** | **18/18** controlli, tutte e tre le pipeline, 6 classi su 7 raggiunte (la settima è `UNUSED`, irraggiungibile per costruzione). |
| **Conclusione** | Consegna, non solo inferenza. |
| **Come rigirarlo** | `sudo python3 ipa/test/test_fabric.py` |

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

## B. Il costo della flessibilità

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
| **Risultato** | 54 → 57 → 249 → 436 ns. Istruzioni 614 → 1 071 → 14 628 → 12 031. Tail call 1, 1, 1, 3. Letture di mappa 6 (P1.5), 11 (P2), 29 (P3). |
| **Conclusione** | **La flessibilità costa circa 8× in latenza** fra i due estremi, e il costo non è aritmetico: è in letture di mappa e salti fra programmi. |
| **Come rigirarlo** | `sudo python3 ipa/test/test_suite.py --only kernel` e `sudo python3 ipa/test/bench_scaling.py --out result/` |

### B2 — Il costo di aggiornare il modello differisce di due ordini di grandezza ✅

| | |
|---|---|
| **Ipotesi** | Compilare i pesi dentro il codice sposta il costo dal pacchetto al deployment. |
| **Variabile modificata** | La pipeline. |
| **Variabili fisse** | Modello e topologia; misurato su **tutti e sei** gli assi dello sweep. |
| **Metrica** | `update_ms`: tempo per installare un modello nuovo su un nodo già in servizio. |
| **Risultato** | P1 e P1.5 fra 1 162 e 1 690 ms (rigenerano C e chiamano clang); P2 e P3 fra 5 e 14 ms (scritture in mappa). |
| **Conclusione** | Circa 200×. È la metrica che decide se una pipeline è usabile in una rete che cambia. |
| **Nota metodologica** | `build_ms` e `update_ms` **non vanno confusi**: per P2/P3 il primo è una compilazione pagata una volta all'avvio del nodo, il secondo è il costo per modello. Metterli sullo stesso asse farebbe sembrare P2/P3 più costose di P1, cioè il rovescio della verità. |
| **Come rigirarlo** | `sudo python3 ipa/test/bench_scaling.py --out result/`; figura `scaling_depth_update.pdf` |

### B3 — L'AOT toglie il compilatore dal nodo senza costo per pacchetto ✅

| | |
|---|---|
| **Ipotesi** | Compilare l'oggetto fuori dal nodo elimina il costo di clang dal datapath, e la riduzione sui pesi letterali sopravvive dentro l'oggetto. |
| **Variabile modificata** | Dove avviene la compilazione: sul nodo (BCC) contro su una macchina di build (AOT). |
| **Variabili fisse** | Stesso modello, stessa topologia, **stessa sessione di misura**. |
| **Metrica** | Costo di messa in servizio; latenza per pacchetto. |
| **Risultato** | Aggiornamento 1 242 ms → 37 ms. Latenza 73 → 74 ns, cioè la stessa cifra. |
| **Conclusione** | Due ordini di grandezza sull'aggiornamento, nessun costo per pacchetto. |
| **Limite dichiarato** | ⚠️ La cifra di deploy varia molto fra esecuzioni (4,7 / 6,2 / 20,7 / 37,2 ms per lo stesso oggetto). Regge l'**ordine di grandezza** rispetto a 1,3 s, non il valore preciso. |
| **Come rigirarlo** | `make -C ipa/poc_aot && sudo ./ipa/poc_aot/loader_aot nn_aot_arch.o --node-id 7` |

---

## C. Che cosa costa, e che cosa no

### C1 — La dimensione del programma non predice la velocità ✅

| | |
|---|---|
| **Ipotesi** | Le istruzioni eBPF sono un proxy del costo per pacchetto. **Falsa.** |
| **Variabile modificata** | La pipeline (P2 contro P3). |
| **Variabili fisse** | Modello, topologia, run. |
| **Metrica** | Istruzioni contro latenza, con tail call e letture di mappa come variabili esplicative. |
| **Risultato** | P3 ha il **18% di istruzioni in meno** di P2 ed è il **61% più lento** (12 031 contro 14 628; 421 contro 262 ns). Le righe che lo spiegano: 3 tail call contro 1, 29 letture di mappa contro 11. |
| **Prova di rinforzo** | Lo stesso codice, cambiando un solo `#define` (`IPA_MAX_QUEUES` 1→8), misura 8 674 **o** 12 031 istruzioni — il 39% di differenza — **a parità di latenza** (419 contro 421 ns). Una metrica che si sposta del 39% senza che cambi nulla di ciò che gira non è una misura di costo. |
| **Conclusione** | `xlated` misura quanto è **grande** il programma caricato, non quanto **lavora**. In questo regime dominano letture di mappa e salti. |
| **Come rigirarlo** | `sudo python3 ipa/test/test_suite.py --only kernel` |

### C2 — La larghezza dell'ingresso è gratis a runtime; quella nascosta no ✅

| | |
|---|---|
| **Ipotesi** | Una rete più grande costa di più per pacchetto. **Falsa per la one-hot.** |
| **Variabile modificata** | Due assi separati: numero di nodi (10→100, cioè l'ingresso da 23 a 113) e neuroni per hidden layer (2→8). |
| **Variabili fisse** | Su ciascun asse, tutto il resto. |
| **Metrica** | Latenza minima su 7 trial. |
| **Risultato** | Nodi: P2 244→249 ns, P3 421→449 ns, piatte. Neuroni: P2 228→311 ns, P3 395→572 ns, in salita su tutte e quattro. |
| **Conclusione** | Una one-hot ha un solo uno, quindi il datapath legge **una colonna di pesi** qualunque sia la sua larghezza. Un layer denso più largo legge più pesi per pacchetto. **La rete può crescere quanto vuole, il modello no.** |
| **Come rigirarlo** | `sudo python3 ipa/test/bench_scaling.py --axis nodes --out result/` e `--axis width` |

### C3 — In P1 il conteggio istruzioni dipende dai valori dei pesi ✅

| | |
|---|---|
| **Ipotesi** | Se i pesi sono letterali nel C, il compilatore può cancellare i prodotti per zero: la dimensione del programma dipende dai **valori**, non solo dalla forma. |
| **Variabile modificata** | La frazione di pesi esattamente zero: 0, 25, 50, 75, 90%. |
| **Variabili fisse** | Forma 65-4-4-7, descrittore, topologia. I pesi sono un prefisso di un pool fisso, quindi una configurazione più grande **estende** la più piccola. |
| **Metrica** | Istruzioni eBPF e byte di codice nativo. |
| **Risultato** | P1.5: 1 071 → 224 istruzioni (4,8×). P1 specializzata: 614 → 216. P2: 14 628 a **tutte** le sparsità. P3: 12 031 a tutte. |
| **Conclusione** | Al 90% di zeri P1 sta **sotto il baseline** (155 istruzioni), cioè il programma che inferisce è più piccolo di quello che non inferisce. Per P2 e P3 uno zero è un byte in mappa come un altro. |
| **Come rigirarlo** | `sudo python3 ipa/test/bench_scaling.py --axis sparsity --out result/` |

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
| **Come rigirarlo** | `sudo python3 ipa/test/bench_scaling.py --axis nodes --out result/`; figura `duel_p1_vs_p15.pdf` |

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
| P2 template | 14 140 | 14 628 | 16 141 | 16 390 | **17 207** | **+22%** |
| P3 modular | 12 031 | 12 031 | 12 031 | 12 031 | 12 031 | **identica** |

| | |
|---|---|
| **Conclusione** | A questo budget le due P1 **non distinguono** larga da profonda: la dispersione lungo l'asse (68-95 ns) è più grande di qualunque tendenza. Per P2 e P3 invece la profondità costa, molto, e **per due ragioni diverse**: P2 deve srotolare ogni layer, quindi cresce in dimensione *e* in tempo; P3 riusa lo stesso layer — la sua riga di istruzioni è identica a tutti e cinque i punti — e paga **una tail call per layer**. |
| **Il risultato utile** | Chi sceglie l'architettura deve sapere **su quale pipeline girerà**. Su una hardcoded a ~600 pesi la profondità è quasi gratis; su P2 o P3 la stessa scelta costa il 58-84% di latenza a parità di parametri. |
| **Limite dichiarato** | ⚠️ «Nessuna tendenza» per le due P1 significa **sotto il rumore di questo run**, non «nessun effetto». La dispersione è ±20% e la serie non è monotona (78, 80, 68, 95, 81). D1 mostra che a 1 200 pesi l'effetto su P1 c'è ed è grande: qui il budget è la metà e la profondità arriva a 5 invece che a 8. |
| **Come rigirarlo** | `sudo python3 ipa/test/bench_scaling.py --axis isoparam --out result/` |

### D3 — Perché la profondità costa, quando costa ✅

| | |
|---|---|
| **Ipotesi** | Il costo di un layer in più non è aritmetico: è un costo fisso di transizione. |
| **Variabile modificata** | Il numero di layer, su tre assi indipendenti (`depth` a parametri crescenti, `isoparam` a parametri fermi, i tier di D1). |
| **Metrica** | Latenza per layer aggiunto, e tail call. |
| **Risultato** | P3: **+71 ns per layer** sull'asse `depth`, e la sua riga di istruzioni non si muove — il costo è interamente nelle tail call, che vanno da 2 a 7. P2: **+36 ns e +780 istruzioni per layer**, cioè srotolamento. P1: 15-40 ns per layer secondo D1, visibile solo sopra un certo budget. |
| **Conclusione** | Tre meccanismi distinti per lo stesso sintomo. In P3 si vede allo stato puro: **dimensione costante, tempo crescente** è la firma di un costo di transizione e non di calcolo. |
| **Come rigirarlo** | `sudo python3 ipa/test/bench_scaling.py --axis depth --out result/` |

## E. Che cosa nessun test di questo progetto dimostra

Dichiarato per non far sembrare coperto ciò che non lo è.

- **Throughput reale.** Tutte le cifre in Mpps sono `1/latenza` sotto
  `BPF_PROG_TEST_RUN`, cioè un ciclo sullo stesso buffer: niente scheda di rete,
  niente driver, nessuna allocazione, nessuna pressione di cache da traffico
  vero. È un **picco teorico**, non un throughput retto. Serve traffico generato a
  ritmo e la misura dei pacchetti persi.
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
