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

### D1 — A parità di budget-pesi, allargare batte approfondire (P1) ✅⚠️

| | |
|---|---|
| **Ipotesi** | Dato un numero di parametri, spenderli in un layer largo costa meno che in molti stretti. |
| **Variabile modificata** | La profondità, a budget abbinato: 3 tier (~300, ~1 200, ~4 700 pesi), ciascuno in versione larga (1 layer) e profonda (4 e 8 layer). |
| **Variabili fisse** | Il budget-pesi, **con lo scarto stampato per ogni tier**. Ripetuto su 4 descrittori (0, 1 o 2 one-hot; one-hot piccola da 6 e grande da 52). |
| **Metrica** | Istruzioni eBPF, latenza (minimo su 15 trial, con p50/p90/max). |

**Risultato, sui due descrittori dove il budget è davvero abbinato:**

| descrittore | tier | larga | profonda 4 | profonda 8 |
|---|---|---:|---:|---:|
| `default` (n_in 65) | A, scarto 6,7% | 53 ns | — | 70 ns (+32%) |
| `default` | B, scarto 10,1% | 120 ns | 277 (+131%) | 351 (+193%) |
| `big_onehot` (n_in 59) | A, scarto 7,3% | 41 ns | — | 57 ns (+39%) |
| `big_onehot` | B, scarto 14,9% | 106 ns | 207 (+95%) | 269 (+154%) |

Tier C (~4 700 pesi): **crash su tutti e quattro i descrittori**, larga o profonda
che sia, con `Looks like the BPF stack limit is exceeded`.

| | |
|---|---|
| **Conclusione** | Allargare batte approfondire, **e il divario cresce col budget**: +32-39% a ~300 pesi, +154-193% a ~1 200. Oltre ~1 300 pesi lo stack eBPF da 512 byte va in overflow comunque: non è una scelta di architettura, è il limite del «tutto srotolato in una funzione». |
| **⚠️ Quello che questo run NON sostiene** | Gli altri due descrittori (`no_onehot`, `small_onehot`) hanno uno scarto di budget del **140-160%** nel tier B: la forma «profonda 8» ha lì 2,6× i parametri della «larga», quindi è più lenta anche perché è un modello più grande. Quei numeri **non possono** sostenere la conclusione. E sono proprio i due senza one-hot grande, cioè quelli che dovevano dimostrare che il risultato non è un artefatto delle one-hot: **il controllo è la parte che non ha funzionato.** |
| **Causa e correzione** | Le forme erano **fisse** fra i descrittori (1×16, 4×11, 8×9) mentre `n_in` cambia da 65 a 11: con 65 ingressi il primo layer domina il budget e gli strati in più lo muovono poco, con 11 no. Ora la larghezza è **risolta per descrittore** per centrare il budget del tier (`solve_width`). Scarti dopo la correzione: tier A 6,6-19,7%, tier B 3,8-9,6%, tier C 0,8-3,8%. Il tier A resta grossolano perché a 300 pesi le larghezze intere fanno passi larghi — ed è stampato, non nascosto. |
| **Da rifare** | Un run sulle forme abbinate, che è ciò che permette di dire «non è un artefatto delle one-hot». Fino ad allora la conclusione vale su 2 descrittori su 4. |
| **Come rigirarlo** | `sudo python3 ipa/test/bench_depth_vs_width.py` |

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
