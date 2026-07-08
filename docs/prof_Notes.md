# Note del Professore — IPA / eBPF Design Space

> Questo file raccoglie il ragionamento del professore sullo spazio di progetto IPA/eBPF, estratto dalle conversazioni e dai materiali del corso. Serve come guida strutturale per orientare il lavoro di tesi/progetto.

---

## 1. Tesi Centrale

IPA/eBPF **non ha una sola implementazione naturale**.  
Esiste uno **spazio di progetto** in cui si può scegliere quanto specializzare il modello nel datapath e quanto invece mantenere flessibilità runtime.

> La valutazione non è solo *"quanto va veloce eBPF"*, ma:  
> **"quanto costa rendere IPA più flessibile nel datapath?"**

Questa è una domanda sperimentale molto buona e ben posizionata.

---

## 2. Tassonomia delle Implementazioni eBPF (Trade-off Prestazioni / Flessibilità)

### Livello 1 — Hardcoded Model (massime prestazioni, minima flessibilità)

Ogni modello è trasformato in un programma eBPF specifico:

```
model_id → model_<id>.o
```

Il programma contiene:
- feature extraction
- pesi hardcoded
- inferenza completa
- argmax + azione

**Pipeline:**
```
packet
  ↓ dispatcher
  ↓ tail call model_<id>
  ↓ action
```

**Vantaggi:**
- una sola tail call
- nessuna lookup per i pesi
- nessun passaggio intermedio
- codice completamente unrolled
- massime prestazioni

**Svantaggi:**
- ogni nuovo modello richiede generazione/compilazione/caricamento di un nuovo programma eBPF
- bassa flessibilità runtime

> Questa è la baseline **"best performance"**.

---

### Livello 2 — Pre-built Architecture Template (prestazioni intermedie, flessibilità media)

Un programma eBPF per ogni architettura tipica (non per ogni modello):

```
arch_8_6_6_4
arch_10_5_3
arch_12_6_6_7
```

Il pacchetto contiene `model_id`, e una map dice:
```
model_id → arch_id + weight_offset + alpha
```

**Pipeline:**
```
packet
  ↓ dispatcher
  ↓ model_registry[model_id]
  ↓ tail call arch_<shape>
  ↓ programma architetturale legge pesi da map
  ↓ inferenza completa
  ↓ action
```

**Vantaggi:**
- un solo programma eBPF supporta più modelli con la stessa architettura
- non serve ricompilare per cambiare pesi
- architettura comunque statica/unrolled
- buon compromesso

**Svantaggi:**
- lettura pesi da map → più overhead rispetto a pesi hardcoded
- supporta solo architetture predefinite

> Probabilmente la soluzione più interessante da discutere come **"practical flexible design"**.

---

### Livello 3 — Modular Neural Pipeline (massima flessibilità, prestazioni inferiori)

Il modello è scomposto in blocchi/layer:

```
layer_8_to_6
  ↓ tail call layer_6_to_6
  ↓ tail call layer_6_to_4
  ↓ action
```

Ogni modulo implementa una trasformazione tipica: **N input → M output**

Gli output intermedi passano tramite:
- `BPF_PERCPU_ARRAY` scratch map (soluzione pulita)
- oppure scratch area nell'header IPA (meno pulita)

**Pipeline:**
```
packet
  ↓ dispatcher
  ↓ layer block 1
  ↓ scratch map + tail call layer block 2
  ↓ scratch map + tail call layer block 3
  ↓ argmax/action
```

**Vantaggi:**
- massimo riuso dei blocchi
- supporta più architetture componendo moduli
- minore necessità di generare programmi completi
- più flessibilità runtime

**Svantaggi:**
- più tail calls
- map lookup per stato intermedio
- lettura pesi da map → maggiore overhead
- maggiore complessità
- limite al numero di tail calls consecutive

> Questa è la soluzione **"maximum flexibility"**.

---

## 3. Sintesi del Trade-off

> Aumentando la flessibilità:
> - diminuisce il grado di specializzazione del codice
> - aumentano map lookup, tail calls e passaggio di stato
> - diminuiscono le prestazioni massime

| Soluzione | Codice eBPF | Pesi | Tail call | Stato intermedio | Flessibilità | Prestazioni attese |
|---|---|---|---|---|---|---|
| Hardcoded model | 1 programma per modello | hardcoded | 1 | nessuno | bassa | massime |
| Template architetturale | 1 programma per architettura | BPF map | 1 | locale al programma | media | alte/intermedie |
| Moduli layer | 1 programma per blocco | BPF map | > 1 | scratch map/header | alta | inferiori |

---

## 4. Metriche Sperimentali Consigliate

Per dimostrare il trade-off, misurare sia le **datapath performance** che il **costo della flessibilità** (control-plane flexibility):

**Datapath performance:**
- latenza per pacchetto
- throughput massimo in Mpps
- CPU utilization
- numero di istruzioni eBPF
- numero di tail calls
- numero di map lookup

**Control-plane flexibility:**
- tempo di aggiornamento modello
- memoria occupata da programmi/mappe

**Esempio comparativo del costo della flessibilità:**
- **Hardcoded:** aggiornamento modello = ricompila/ricarica programma
- **Template:** aggiornamento modello = aggiorna weight map
- **Modulare:** aggiornamento modello/architettura = cambia sequenza layer + pesi

---

## 5. Formulazione da Paper (suggerita dal Professore)

> *We consider three implementation points in the IPA/eBPF design space. The first one hardcodes each neural model into a dedicated eBPF program, maximizing datapath performance at the cost of requiring code regeneration and program reloading for each model update. The second one relies on pre-built architectural templates, where each eBPF program implements a common neural architecture and retrieves model-specific quantized parameters from BPF maps. This reduces recompilation needs while preserving a statically verifiable inference structure. The third one decomposes neural inference into reusable eBPF layer modules connected through tail calls, using a per-CPU scratch map to exchange intermediate activations. This maximizes architectural flexibility, but introduces additional tail calls and map accesses, thus reducing the maximum achievable packet processing rate.*

---

## 6. Contesto: Cos'è IPA (dal paper del Professore)

**Intelligent PAckets (IPA)** è un paradigma in cui modelli di machine learning leggeri sono embeddati direttamente negli header dei pacchetti ed eseguiti hop-by-hop dai nodi di rete.

**Idea chiave:** spostare l'intelligenza dal dispositivo al pacchetto (stessa filosofia del Segment Routing, dove lo stato del flusso era spostato nell'header per risolvere i problemi di scalabilità di MPLS).

### Elaborazione IPA in un nodo
1. Il pacchetto viene parsato per estrarre il modello ML e i descrittori di input/output
2. Il modello viene caricato nell'ML execution engine
3. Il nodo costruisce il vettore di input (stato locale + feature del pacchetto)
4. Viene eseguita l'inferenza
5. La decisione viene interpretata e applicata (forwarding/DROP)

### Header IPA — Struttura
- **Model Description:** model ID, tipo, parameter size, scaling factor
- **Model Specifications:** architettura NN (input size, output size, hidden layers, neuroni per layer)
- **Input Descriptor:** feature types e occorrenze (interfaccia ingresso, queue occupancy, TTL, node ID)
- **Model Parameters:** pesi serializzati row-by-row
- **Output Descriptor:** composizione del vettore di output

### Caso d'uso principale: Fast Restoration
Il modello NN è addestrato per approssimare l'algoritmo LOCAL (Dijkstra locale hop-by-hop con ricomputazione del percorso in presenza di failure), senza richiedere esecuzione esplicita di algoritmi di grafo a runtime.

- **Configurazione di riferimento:** 2 hidden layers, 5 neuroni per layer, quantizzazione a 6 bit
- **Overhead header:** ~300 bytes (< 20% di un MTU standard da 1500 byte)
- **Risultato:** IPA supera Link Protection e Path Protection classici già da 2 failure simultanei

### Sfide aperte (future work da paper)
- Implementazione prototipo IPA-enabled node con inferenza a line-rate
- Esecuzione su hardware eterogeneo (CPU, GPU, FPGA/SmartNIC)
- Sicurezza: integrità del modello, autenticazione, prevenzione abusi

---

## 7. Struttura Suggerita per il Lavoro

Basandosi sul ragionamento del professore, il lavoro dovrebbe:

1. **Implementare i 3 livelli** dell'implementazione eBPF (hardcoded, template, modulare)
2. **Misurare le metriche** di datapath performance per ciascun livello
3. **Misurare il costo della flessibilità** (tempo aggiornamento modello, overhead memoria)
4. **Confrontare** i risultati con una tabella/grafico trade-off prestazioni vs flessibilità
5. **Discutere** quale punto dello spazio di progetto è più interessante per diversi scenari operativi

---

## 8. Riscontro Pratico: Vincoli del Verifier (Pipeline 1)

L'implementazione hardcoded (Livello 1) e quella dove la tesi "massime prestazioni, zero lookup" e piu difficile da ottenere in pratica, perche il verifier eBPF impone due vincoli che collidono direttamente con l'idea di "codice completamente unrolled":

- **Stack limitato a 512 byte per programma** — feature vector o tabelle di pesi troppo grandi per neurone eccedono il budget.
- **Esplosione del CFG** — ramificare (`switch`/`if`) su un valore runtime *dentro un ciclo per neurone* moltiplica il numero di path che il verifier deve esplorare (non li somma). Con 4 neuroni e due switch da 7 e 52 casi ripetuti per neurone, i path esplorati salgono a `(7*52)^4 ≈ 1.75*10^10`, ben oltre il budget di 1.000.000 istruzioni del verifier → `Permission denied`.
- **BCC (senza CO-RE) non rilocca correttamente dati globali/`.rodata`** per programmi XDP: un array `static const` dichiarato dentro una funzione BCC non e supportato da una vera map, quindi il suo indirizzo puo collassare a `0` al load, e l'accesso viene rifiutato dal verifier (`invalid mem access 'scalar'`).

**Soluzione adottata:** un solo `switch(_iface)` e un solo `switch(_node)` per l'intero programma (non uno per neurone), dove ogni `case` assegna il contributo per *tutti* i neuroni contemporaneamente. Il numero di branch resta `O(7+52)` indipendentemente dal numero di neuroni, e i valori restano scalari su stack (nessuna global, nessuna map) — preservando la proprieta "zero lookup pesi" del Livello 1 pur passando il verifier.

**Stesso bug, seconda occorrenza:** il pattern "array `static const` globale indicizzato a runtime" si ripresentava anche dopo l'argmax, in `static const __u32 IFINDEX_TABLE[6]` indicizzato da `best_cls` (0..5) per scegliere l'ifindex di uscita. Stesso sintomo (`R7 invalid mem access 'scalar'`), stessa causa (BCC non riloca dati `static`/globali per XDP), stessa soluzione: `switch (best_cls) { case 0: egress_ifindex = ...; break; ... }`. Qui non c'era rischio di esplosione combinatoria (best_cls e un solo scalare per pacchetto, non ripetuto per neurone) — bastava sostituire l'array con lo switch.

**Lezione generale:** qualunque tabella di lookup `static const`/globale indicizzata da un valore runtime non e sicura sotto BCC per XDP, indipendentemente dalla sua dimensione; la soluzione e sempre "switch sull'indice limitato", non "rimpicciolire l'array".

Questo e un dato sperimentale interessante da riportare nel paper: il costo della specializzazione massima (Livello 1) non e solo prestazionale, ma anche *di ingegneria* — occorre una codifica del branching ad-hoc per non violare i limiti del verifier, mentre i Livelli 2 e 3 evitano il problema a monte delegando i pesi a `BPF_ARRAY` map.

**Revisione dei Livelli 2 e 3 (verifica di conformita alla tassonomia):** un controllo su `ebpf_template_arch.py` e `ebpf_modular.py` ha trovato due bug, entrambi corretti:

1. **Stack overflow nel Livello 2** — `arch_65_4_4_7` dichiarava `long long iv[65]` (520 B), gia da solo oltre il limite di 512 B, prima di contare `h1[4]`, `h2[4]` e i puntatori. Sarebbe fallito al load come il Livello 1. Fix: solo 3 posizioni su 65 sono mai diverse da zero, quindi il prodotto scalare per ogni neurone si calcola direttamente da 3 scalari via indici aritmetici nella `BPF_ARRAY` (a differenza degli array `static const` che hanno rotto il Livello 1, una lookup di map con indice calcolato a runtime e sicura per il verifier).
2. **Disallineamento dell'encoding delle feature nei Livelli 2 e 3** — entrambi popolavano il vettore di input come `[0]=model_id, [1]=ttl, [2]=ingress_ifindex, [3]=input_size`, schema che NON corrisponde a come il modello e stato addestrato (`FRR_model.py`: 6 link_state (inutilizzati) + 6 ingress-iface one-hot [6..11] + 1 ttl [12] + 52 node one-hot [13..64], lo stesso schema del Livello 1). Pur rispettando fedelmente la tassonomia architetturale del professore (pesi da map, tail call, stato scratch), i due livelli non eseguivano lo stesso modello del Livello 1, rendendo invalido qualunque confronto di accuratezza tra le pipeline. Corretto per usare lo stesso encoding one-hot sparso del Livello 1.

**Stato:** il Livello 1 e confermato funzionante end-to-end su Kathara. I Livelli 2 e 3 non sono ancora stati rilanciati su Kathara dopo questo fix (il fix dello stack per il Livello 2 e motivato per ragionamento ma non ancora verificato dal verifier reale). Inoltre `test_kathara.sh` legge solo le map `pkt_stats`/`cls_stats` del Livello 1: i Livelli 2/3 usano nomi diversi (`pkt_stats_t2`/`_t3`) e un modello hit/miss/fake-hit diverso (`fwd_table` + `valid_keys`), quindi gli Step 8/9/11 dello script non generalizzano ancora a `test_kathara.sh template` / `modular` — lavoro di follow-up non ancora fatto.

---

*Ultimo aggiornamento: 2026-07-08*
