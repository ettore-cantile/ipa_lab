# IPA/eBPF Design Space: Performance vs. Flexibility

> *Documento guida per la tesi — basato sul ragionamento del Prof. con ChatGPT (allegato PDF)*

## Tesi Centrale

IPA/eBPF non ha una sola implementazione naturale. Esiste uno **spazio di progetto** in cui si può scegliere quanto specializzare il modello nel datapath e quanto invece mantenere flessibilità runtime.

La domanda sperimentale chiave è: **quanto costa rendere IPA più flessibile nel datapath?**

---

## Tassonomia delle Implementazioni

| Soluzione | Codice eBPF | Pesi | Tail calls | Stato intermedio | Flessibilità | Prestazioni attese |
|---|---|---|---|---|---|---|
| **Hardcoded model** | 1 programma per modello | hardcoded | 1 | nessuno | ❌ bassa | ⭐⭐⭐ massime |
| **Template architetturale** | 1 programma per architettura | BPF map | 1 | locale al programma | ⚙️ media | ⭐⭐ alte/intermedie |
| **Moduli layer** | 1 programma per blocco | BPF map | >1 | scratch map / header | ✅ alta | ⭐ inferiori |

---

## Livello 1 — Hardcoded Model

**Obiettivo:** massime prestazioni, minima flessibilità.

Ogni modello viene trasformato in un programma eBPF dedicato:

```
model_id → model_<id>.o
```

Il programma contiene tutto inline: feature extraction, pesi hardcoded, inferenza completa, argmax, azione.

### Pipeline

```
packet
  ↓
dispatcher
  ↓ tail call
model_<id>
  ↓
action
```

### Vantaggi
- Una sola tail call
- Nessuna lookup per i pesi
- Nessun passaggio intermedio
- Codice completamente unrolled
- Massime prestazioni

### Svantaggi
- Ogni nuovo modello richiede generazione/compilazione/caricamento di un nuovo programma eBPF
- Bassa flessibilità runtime

---

## Livello 2 — Pre-built Architecture Template

**Obiettivo:** buon compromesso prestazioni/flessibilità.

Un programma eBPF per ogni **architettura tipica** (non per ogni modello):

```
arch_8_6_6_4
arch_10_5_3
arch_12_6_6_7
```

Il pacchetto contiene `model_id`; una map dice: `model_id → arch_id + weight_offset + alpha`.

### Pipeline

```
packet
  ↓
dispatcher
  ↓
model_registry[model_id]
  ↓ tail call
arch_<shape>
  ↓
programma architetturale legge pesi da map
  ↓
inferenza completa
  ↓
action
```

### Vantaggi
- Un solo programma eBPF supporta più modelli con la stessa architettura
- Non serve ricompilare per cambiare pesi
- Architettura comunque statica/unrolled

### Svantaggi
- Lettura pesi da map (overhead)
- Supporta solo architetture predefinite

---

## Livello 3 — Modular Neural Pipeline

**Obiettivo:** massima flessibilità, prestazioni inferiori.

Il modello è scomposto in blocchi/layer. Ogni modulo implementa: `N input → M output`.

```
layer_8_to_6
  ↓ tail call
layer_6_to_6
  ↓ tail call
layer_6_to_4
  ↓
action
```

Gli output intermedi passano tramite `BPF_PERCPU_ARRAY` scratch map (oppure scratch area nell'header IPA).

### Pipeline

```
packet
  ↓
dispatcher
  ↓
layer block 1
  ↓ scratch map + tail call
layer block 2
  ↓ scratch map + tail call
layer block 3
  ↓
argmax / action
```

### Vantaggi
- Massimo riuso dei blocchi
- Supporta più architetture componendo moduli
- Più flessibilità runtime

### Svantaggi
- Più tail calls
- Map lookup per stato intermedio
- Lettura pesi da map
- Limite al numero di tail calls consecutive

---

## Metriche Sperimentali da Misurare

Per dimostrare il trade-off, misurare **sia le performance del datapath che il costo della flessibilità nel control plane**:

### Datapath Performance
- Latenza per pacchetto (ns)
- Throughput massimo (Mpps)
- CPU utilization (%)
- Numero di istruzioni eBPF
- Numero di tail calls per pacchetto
- Numero di map lookup per pacchetto

### Control-Plane Flexibility Cost
| Soluzione | Aggiornamento modello |
|---|---|
| Hardcoded | Ricompila + ricarica programma eBPF |
| Template | Aggiorna weight map (nessuna ricompilazione) |
| Modulare | Cambia sequenza layer + pesi |

- Tempo di aggiornamento modello (ms)
- Memoria occupata da programmi/mappe

---

## Formulazione per il Paper

> *We consider three implementation points in the IPA/eBPF design space. The first one hardcodes each neural model into a dedicated eBPF program, maximizing datapath performance at the cost of requiring code regeneration and program reloading for each model update. The second one relies on pre-built architectural templates, where each eBPF program implements a common neural architecture and retrieves model-specific quantized parameters from BPF maps. This reduces recompilation needs while preserving a statically verifiable inference structure. The third one decomposes neural inference into reusable eBPF layer modules connected through tail calls, using a per-CPU scratch map to exchange intermediate activations. This maximizes architectural flexibility, but introduces additional tail calls and map accesses, thus reducing the maximum achievable packet processing rate.*

---

## Struttura del Repository Suggerita

```
ipa_lab/
├── docs/
│   ├── ebpf_design_space.md          ← questo file
│   └── pipeline_diagrams.html        ← schemi a blocchi interattivi
├── src/
│   ├── hardcoded/                    ← implementazione livello 1
│   ├── template/                     ← implementazione livello 2
│   └── modular/                      ← implementazione livello 3
└── experiments/
    └── benchmark/                    ← script di benchmark
```
