# Cosa è davvero "hardcoded" in Pipeline 1

Nota breve per rispondere a una domanda precisa: quando si dice che P1 ha la rete
*hardcoded*, che cosa è compilato nel programma e che cosa arriva a runtime?

La risposta corta: **i pesi sono compilati, i valori delle feature no.** Tutte le
feature — `link_state`, `ingress_iface`, `ttl`, `node` — sono lette mentre il
pacchetto passa. Nessuna è statica.

Ma i pesi vengono usati in **due modi diversi** a seconda del tipo di feature, e
i due modi danno due vantaggi diversi. Confonderli porta a conclusioni sbagliate
sul costo, ed è il motivo di questa nota.

---

## Meccanismo 1 — vettori densi: prodotti con costante

Riguarda `link_state`, `queue_occupancy`, `ttl`.

Il generatore emette letteralmente questo (estratto dal C reale del checkpoint
depositato, 65-4-4-7):

```c
long long ls0=0LL, ls1=0LL, ls2=0LL, ls3=0LL, ls4=0LL, ls5=0LL;
{ int _z=0; struct link_state_vec *_p = link_state.lookup(&_z);
  if (_p) { ls0=(long long)_p->v[0]; ls1=(long long)_p->v[1]; /* ... */ } }

/* e poi, per il neurone 0 del primo strato: */
ls0 * 8LL + ls1 * 7LL + ls2 * 33LL + ls3 * -11LL + ls4 * 38LL + ls5 * 1LL + ...
```

```
        RUNTIME                        COMPILE-TIME
   ┌───────────────┐              ┌──────────────────────┐
   │  mappa BPF    │              │  pesi come letterali │
   │  link_state   │              │  8  7  33  -11  38  1│
   └───────┬───────┘              └───────────┬──────────┘
           │ una lookup                       │
           ▼                                  ▼
      ls0 … ls5        ──────×──────►    somma dei prodotti
      (valori veri)                       nell'accumulatore
```

Una moltiplicazione ha **due operandi**. `ls0` è ignoto fino a runtime, ma `8LL`
è scritto nel codice. La strength reduction agisce sull'operando **costante**:
al compilatore non serve sapere quanto vale `ls0`.

| sorgente | cosa emette clang |
|---|---|
| `ls0 * 0LL` | niente — il termine sparisce |
| `ls0 * 8LL` | `ls0 << 3` |
| `ls5 * 1LL` | `ls5` |
| `ls2 * 33LL` | resta una moltiplicazione |

Sul checkpoint depositato, primo strato (260 pesi):

| | | |
|---|---:|---|
| zeri | 15 (6%) | il termine sparisce del tutto |
| potenze di due | 62 (24%) | la moltiplicazione diventa uno shift |
| restanti | 183 (70%) | moltiplicazione vera |
| **ripiegabile** | **30%** | |

---

## Meccanismo 2 — one-hot: nessun prodotto

Riguarda `node` e `ingress_iface`.

Matematicamente un one-hot è `Σ xᵢ · wᵢ` con un solo `xᵢ = 1` e tutti gli altri a
zero: 52 moltiplicazioni di cui 51 danno zero. Il generatore **non le scrive
proprio**. Emette uno switch che assegna direttamente il peso giusto:

```c
switch (_node) {                       /* _node = ipa->model_id, dal pacchetto */
    case 0: w_node_0 = 27LL; w_node_1 = -6LL;  w_node_2 =  7LL; w_node_3 =  0LL; break;
    case 1: w_node_0 = 12LL; w_node_1 = -6LL;  w_node_2 =  9LL; w_node_3 = -7LL; break;
    case 2: w_node_0 =  8LL; w_node_1 = -14LL; w_node_2 = -9LL; w_node_3 = 17LL; break;
    /* ... 52 casi in tutto ... */
}
```

```
   pacchetto ──► model_id = 37
                      │
                      ▼
            ┌─────────────────────────────────────┐
            │  switch (_node)                     │
            │    case  0:  w = 27, -6,   7,   0   │
            │    case  1:  w = 12, -6,   9,  -7   │
            │      ⋮                              │
   esegue ─►│    case 37:  w = -9, 14,  -2,   5   │ ◄── UNO solo
            │      ⋮                              │
            │    case 51:  w =  3, -8,  11,  -4   │
            └─────────────────────────────────────┘
                      │
                      ▼
              w_node_0 … w_node_3   ──► nell'accumulatore
```

Qui **non c'è niente da ridurre**: la riduzione è già fatta dal generatore, che
ha eliminato il prodotto a monte. L'indice resta a runtime; è il *peso* a essere
scelto fra alternative compilate.

---

## I due vantaggi, separati

| feature | forma nel C | vantaggio | da dove viene |
|---|---|---|---|
| `link_state`, `queue_occupancy`, `ttl` | somma di prodotti | **strength reduction** | i pesi sono costanti: clang ripiega zeri e shift |
| `node`, `ingress_iface` | `switch` | **un caso su N** invece di N prodotti | il generatore trasforma il one-hot in salto |

Il secondo è il più grosso. Per `node` sono 52 prodotti che diventano un salto
tabellato più quattro assegnazioni.

> **Errore da evitare.** Dire "la strength reduction elimina le moltiplicazioni
> per zero del one-hot" è sbagliato due volte: nel one-hot moltiplicazioni non
> ce ne sono, e la strength reduction non c'entra. Sono due ottimizzazioni
> distinte su due tipi di feature distinti.

---

## Perché il conteggio istruzioni inganna

P1 misura **971 istruzioni** e **67 ns**. A ~3 GHz sarebbero ~4.8 istruzioni per
ciclo, sopra il massimo pratico su x86 (3-4). Non è una contraddizione:

```
   programma CARICATO                 percorso ESEGUITO per pacchetto
   ┌────────────────────┐             ┌────────────────────┐
   │ 52 casi node       │             │  1 caso node       │
   │  6 casi iface      │   ────►     │  1 caso iface      │
   │ prodotti densi     │             │ prodotti densi     │
   │ (ripiegati)        │             │ (quelli rimasti)   │
   └────────────────────┘             └────────────────────┘
        971 istruzioni                   una frazione
```

`xlated` misura quanto è **grande** il programma, non quanto **lavoro fa** per
pacchetto. È la prima obiezione naturale davanti alla tabella dei risultati, e
la risposta è questa.

---

## Dove si colloca una "versione intermedia"

Lo spazio di progetto è un 2×2. Tre caselle sono occupate:

```
                     │  pesi LETTERALI        │  pesi da MAPPA
   ──────────────────┼────────────────────────┼─────────────────────
    descrittore      │  P1 hardcoded          │       —
    COMPILATO        │  971 istr / 67 ns      │
   ──────────────────┼────────────────────────┼─────────────────────
    descrittore      │  ← il buco             │  P2 template
    a RUNTIME        │    (P1b)               │  16 185 istr / 247 ns
```

Fra P1 e P2 ci sono ~180 ns, e quel salto **confonde due cambiamenti insieme**:
i pesi passano da letterali a mappa, *e* il descrittore da compilato a runtime.
Non si può attribuire il costo all'uno o all'altro.

La casella mancante li separa:

- **P1 → P1b** isola il costo del *descrittore a runtime*
- **P1b → P2** isola il costo dei *pesi presi da una mappa*

### Il vincolo tecnico

Non si può cambiare il set di feature a runtime **e** tenere i pesi letterali nel
senso pieno: i pesi sono indicizzati `fc1_w[j*n_in + offset + i]`, quindi sono
legati al layout per cui sono stati generati. Cambiare `n_in` o gli offset li fa
puntare alle colonne sbagliate.

La forma che funziona è **compilare per il sovrainsieme e disattivare a runtime**:
il descrittore in mappa dice quali feature contribuiscono, i termini delle altre
vengono saltati.

Il costo da misurare è proprio lì: oggi i termini sono aritmetica incondizionata
e ripiegata; in P1b ognuno starebbe dietro a una condizione. La strength
reduction sul singolo peso sopravvive (`x*0` resta folded, `x*8` resta uno
shift), ma si perdono l'unrolling pulito e la fusione dei termini fra loro.

**Previsione da verificare:** P1b finisce molto più vicina a P1 che a P2, perché
il grosso dei 180 ns viene dai *lookup* e non dal descrittore — P2 fa 18 letture
di mappa nel solo leaf, contro le 5 totali di P1.

---

*Numeri da `test_suite.py --only kernel`, VM 4 vCPU, modello 65-4-4-7, scale=24.
Le latenze assolute su VM non sono citabili come prestazioni di sistema: vale il
confronto fra righe dello stesso run. Vedi `docs/testing.md`.*
