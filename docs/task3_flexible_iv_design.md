# Task 3 — IV flessibile a runtime per template (P2) e modular (P3)

> Design tecnico **prima** di scrivere codice. Va sviluppato e verificato sul box
> Linux (verifier), non su Windows.

## 1. Stato attuale

Entrambe le pipeline map-based hanno l'IV **cablato** al layout protocollare a 65:

- template (`ebpf_template_arch.py`): `T2_N_IN=65`, offset fissi
  (link_state `0..5`, iface one-hot `6..11`, ttl `12`, node one-hot `13..64`).
- modular (`ebpf_modular.py`): `PROTO_N_IN=65`; solo `layer_first` tocca l'IV,
  gli hop successivi sono già generici (leggono `layer_shapes`/`layer_weights`).

I pesi sono già in mappa (nessuna ricompilazione per modello). Manca solo:
**rendere runtime il LAYOUT delle feature** (quali, che size, a quale offset dei
pesi), così modelli diversi usano subset diversi senza ricompilare.

## 2. Da dove arriva il descrittore a runtime — decisione chiave

Due opzioni:

- **A) Header del pacchetto** (`n_feature_types` + coppie `feat*`). No: il
  datapath oggi legge solo `model_id`, aggiungerebbe costo/pacchetto e si
  fiderebbe di un byte auto-dichiarato.
- **B) Registry map per-modello** (RACCOMANDATA). Una mappa `model_desc` keyed
  by `model_id`, popolata dal control plane **al momento della registrazione**
  (stesso punto in cui carica pesi/shapes). Coerente col design map-based,
  autorevole (CP, non il pacchetto), zero fiducia nel traffico.

```c
#define MAX_FEAT 4          /* = slot feature dell'header IPA */
struct feat_ent { __u8 code; __u8 size; __u16 woff; };  /* woff = offset colonna in fc1 */
struct model_desc {
    __u8 n_feat; __u8 n_in; __u8 n_out; __u8 _pad;
    struct feat_ent feats[MAX_FEAT];
};
/* BPF_HASH(model_desc, __u32 model_id, struct model_desc) */
```

Il CP la riempie da `derive_shape()` (Python) → già ho l'ordine + le size +
posso calcolare `woff` cumulativo. Un solo posto nuovo lato userspace.

## 3. Il vincolo verifier — perché non è un loop generico

Non si può ciclare su "un nome di mappa qualsiase": le mappe (`link_state`,
`queue_state`) sono **simboli compile-time**. Quindi il programma compilato deve
avere il codice per **tutti i 5 tipi noti**, e a runtime il descrittore dice
**quali** sono attivi, con **quale size** e **quale offset**.

Struttura del primo layer (per neurone `j`, unrolled su `MAX_FEAT`):

```c
struct model_desc *d = bpf_map_lookup_elem(&model_desc, &model_id);
if (!d) return XDP_PASS;
long long acc = bias_j;                 /* bias letto da arch_weights[woff_bias + j] */
#pragma unroll
for (int f = 0; f < MAX_FEAT; f++) {
    if (f >= d->n_feat) break;
    struct feat_ent e = d->feats[f];
    switch (e.code) {
      case FEAT_TTL:                    /* scalar */
        acc += (long long)_ttl * W(e.woff + j*d->n_in);      break;
      case FEAT_LINK_STATE:             /* dense: unroll fino a MAX_INTERFACES */
        #pragma unroll
        for (int i = 0; i < MAX_INTERFACES; i++)
            if (i < e.size) acc += ls[i] * W(e.woff + j*d->n_in + i);
        break;
      case FEAT_QUEUE_OCC:              /* dense: unroll fino a MAX_QUEUES */
        ... qs[i] ...                                          break;
      case FEAT_INGRESS_IFACE:          /* one-hot: 1 peso runtime-indexed */
        if (_iface) acc += W(e.woff + j*d->n_in + (_iface-1)); break;
      case FEAT_NODE:                   /* one-hot */
        if (_node <= d->..) acc += W(e.woff + j*d->n_in + _node); break;
    }
}
```

dove `W(idx)` = lookup bounded in `arch_weights` con il check già esistente
`if (idx >= MAX_WEIGHT_ENTRIES) return XDP_PASS;`. `n_in` diventa **runtime** ma
l'indice resta bounded → verifier-safe (è già il pattern di template oggi, righe
~421/445; qui si sostituiscono le costanti `12`/`13` con `e.woff`).

Ceilings compile-time necessari (per l'unroll): `MAX_FEAT=4`,
`MAX_INTERFACES`, `MAX_QUEUES`, `MAX_NODES` — presi da un tetto di topologia.

## 4. Cosa cambia per pipeline

**template (P2):** sostituire il blocco fc1 a offset fissi con il loop
descrittore-driven sopra. fc2/out restano invariati (leggono già shapes/pesi da
mappa). Aggiungere la mappa `model_desc` + seeding lato CP.

**modular (P3):** toccare **solo `layer_first`** (unico hop che vede l'IV a 65).
Stesso loop descrittore-driven per il primo hop. Gli hop nascosti sono già
generici → invariati.

## 5. Decisioni da prendere (servono prima del codice)

1. **Sorgente descrittore**: registry map (B) — confermi?
2. **Ceilings** `MAX_FEAT/MAX_INTERFACES/MAX_QUEUES/MAX_NODES`: valori? (es. 4 /
   16 / 8 / 64 — generosi ma il verifier deve reggere l'unroll).
3. **Kernel target**: `#pragma unroll` (portabile, stile attuale) vs `bpf_loop()`
   (5.13+, più leggero sul verifier). Default: unroll.
4. **Header IPA**: le coppie `feat*` restano metadata/osservabilità (registry
   autorevole) — confermi che NON diventano la sorgente?

## 6. Rischi

- **Budget verifier**: il primo layer unrolled cresce (switch × MAX_FEAT ×
  neuroni × MAX size). Con ceilings generosi potrebbe sfiorare i limiti di
  complessità → tenere i MAX stretti al necessario.
- **Costo/pacchetto**: +1 lookup (`model_desc`) e offset runtime. Marginale
  rispetto ai lookup pesi che template/modular già fanno.
- **Identità design-space**: P2/P3 diventano descrittore-flessibili come P1.
  Cambia la narrativa della tesi (non più "P2/P3 = 65 fisso") — da concordare
  col relatore.

## 7. Stima

Template + modular `layer_first` + mappa `model_desc` + seeding CP + confronto
verifier vs baseline: **~1 giorno** di sviluppo **su Linux** con iterazione sul
verifier. Non testabile su Windows.
