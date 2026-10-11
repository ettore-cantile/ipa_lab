# Sintesi sulla popolazione: campagna_2026-10-10

## Le somme

Ogni riga e' un'affermazione e la sua prova sulla popolazione: su quanti modelli regge, o l'intervallo che copre.

| affermazione | sulla popolazione |
|---|---:|
| rete neurale P1, ns per pacchetto (P-core) | 58 [27–86] |
| rete neurale P1.5, ns per pacchetto (P-core) | 67 [39–94] |
| rete neurale P2, ns per pacchetto (P-core) | 235 [194–328] |
| rete neurale P3, ns per pacchetto (P-core) | 396 [292–580] |
| P1 ≤ P2 ≤ P3 nel costo della rete neurale (P-core) | 30/30 |
| P2 costa P1 per | 4.5 [2.5–8.7] |
| P3 costa P1 per | 7.1 [5.2–13.6] |
| P3 costa P2 per | 1.6 [1.4–2.1] |
| legge di P1 (P-core) | 31 ns + 0.22 ns/MAC + 0 ns/strato; r² 0.93, errore mediano 3% su modelli non visti (n=27) |
| legge di P1.5 (P-core) | 38 ns + 0.19 ns/MAC + 1 ns/strato; r² 0.79, errore mediano 6% su modelli non visti (n=27) |
| legge di P2 (P-core) | 151 ns + 0.03 ns/MAC + 25 ns/strato; r² 0.82, errore mediano 4% su modelli non visti (n=27) |
| legge di P3 (P-core) | 168 ns + 0.68 ns/MAC + 45 ns/strato; r² 0.97, errore mediano 3% su modelli non visti (n=27) |
| contare le MAC eseguite spiega il costo meglio della forma | 3/4 pipeline |
| stesse istruzioni per pacchetto su P-core ed E-core | differenza massima 0.3% su 150 coppie modello-pipeline |
| l'E-core perde soprattutto nella parte fissa del nodo | cicli fissi E/P 1.57 [1.50–1.59]; ρ(quota rete, capacita' E/P) = 0.77 |
| con ≥50% di pesi a zero, misurato / previsto dalla legge densa | P1 0.65 [0.55–0.75], P1.5 0.74 [0.68–0.79], P2 1.01 [1.01–1.02], P3 1.01 [1.00–1.03] |
| a parita' di pesi, ogni strato in piu' costa (ns, P-core) | P1 3 [3–3], P1.5 4 [4–4], P2 24 [24–24], P3 56 [56–56] |
| costo a traffico leggero / costo a nodo saturo (P-core) | 1.04 [0.67–1.29] |

## La popolazione

**Attenzione: popolazione degli assi.** Questi modelli sono gli assi parametrici della campagna, costruiti variando UN parametro alla volta attorno al 65-4-4-7 e (quasi) tutti con lo stesso seme: una prima indicazione, non la generalita' che dara' remeasure_popolazione.sh.

30 punti, 28 modelli distinti (lo stesso 65-4-4-7 compare in piu' assi).

Per famiglia: depth 6, isoparam 5, iv_dense 4, iv_onehot 3, nodes 5, sparsity 3, width 4.

| grandezza | intervallo |
|---|---:|
| ingressi (n_in) | 5–113 |
| strati nascosti | 1–6 |
| neuroni per strato (max) | 2–8 |
| uscite | 7–7 |
| pesi | 151–663 |
| MAC dalla forma | 136–640 |
| MAC eseguite | 36–256 |
| feature one-hot | 0–2 |
| colonne dense | 5–17 |
| pesi a zero (frazione) | 0.01–0.91 |

## Quanto costa la rete neurale, su tutta la popolazione

ns per pacchetto della sola rete neurale: tempo di CPU a nodo saturo meno la baseline dello stesso run. n = modelli misurati.

**P-core**

| pipeline | n | min | 10° | mediana | 90° | max |
|---|---:|---:|---:|---:|---:|---:|
| P1 | 30 | 27 | 41 | 58 | 76 | 86 |
| P1.5 | 30 | 39 | 49 | 67 | 84 | 94 |
| P2 | 30 | 194 | 207 | 235 | 297 | 328 |
| P3 | 30 | 292 | 349 | 396 | 508 | 580 |

Capacita' del nodo, milioni di pacchetti al secondo per core (P-core):

| pipeline | n | min | 10° | mediana | 90° | max |
|---|---:|---:|---:|---:|---:|---:|
| baseline | 30 | 14.43 | 14.71 | 14.99 | 15.18 | 15.27 |
| P1 | 30 | 6.56 | 7.03 | 8.03 | 9.16 | 10.65 |
| P1.5 | 30 | 6.24 | 6.67 | 7.47 | 8.55 | 9.41 |
| P2 | 30 | 2.53 | 2.76 | 3.33 | 3.66 | 3.85 |
| P3 | 30 | 1.54 | 1.74 | 2.17 | 2.41 | 2.78 |

**E-core**

| pipeline | n | min | 10° | mediana | 90° | max |
|---|---:|---:|---:|---:|---:|---:|
| P1 | 30 | 24 | 43 | 60 | 79 | 92 |
| P1.5 | 30 | 38 | 58 | 72 | 90 | 94 |
| P2 | 30 | 222 | 237 | 256 | 335 | 365 |
| P3 | 30 | 345 | 412 | 460 | 611 | 705 |

Capacita' del nodo, milioni di pacchetti al secondo per core (E-core):

| pipeline | n | min | 10° | mediana | 90° | max |
|---|---:|---:|---:|---:|---:|---:|
| baseline | 30 | 9.43 | 9.45 | 9.54 | 9.58 | 9.60 |
| P1 | 30 | 5.08 | 5.44 | 6.08 | 6.75 | 7.76 |
| P1.5 | 30 | 5.02 | 5.13 | 5.65 | 6.14 | 7.02 |
| P2 | 30 | 2.13 | 2.27 | 2.77 | 2.93 | 3.06 |
| P3 | 30 | 1.24 | 1.40 | 1.77 | 1.94 | 2.22 |

## L'ordine fra le pipeline regge su ogni modello?

**P-core** — rapporto fra i costi della rete neurale, mediana [min–max] sui modelli, e su quanti la prima costa piu' della seconda:

| confronto | rapporto | la prima costa di piu' |
|---|---:|---:|
| P1.5 / P1 | 1.16 [0.99–1.46] | 26/30 |
| P2 / P1 | 4.54 [2.51–8.68] | 30/30 |
| P3 / P1 | 7.12 [5.24–13.63] | 30/30 |
| P3 / P2 | 1.59 [1.43–2.12] | 30/30 |
| P2 / P1.5 | 3.90 [2.52–5.96] | 30/30 |

P1 ≤ P2 ≤ P3 su 30/30 modelli.

**E-core** — rapporto fra i costi della rete neurale, mediana [min–max] sui modelli, e su quanti la prima costa piu' della seconda:

| confronto | rapporto | la prima costa di piu' |
|---|---:|---:|
| P1.5 / P1 | 1.23 [0.99–1.56] | 27/30 |
| P2 / P1 | 4.88 [3.20–10.30] | 30/30 |
| P3 / P1 | 8.29 [5.84–16.94] | 30/30 |
| P3 / P2 | 1.71 [1.55–2.05] | 30/30 |
| P2 / P1.5 | 3.91 [3.06–6.62] | 30/30 |

P1 ≤ P2 ≤ P3 su 30/30 modelli.

## Istruzioni caricate contro eseguite

Questa campagna non registrava i programmi caricati (prog_size.csv nasce con remeasure_popolazione.sh).

## Le istruzioni per pacchetto non dipendono dal core

|E/P − 1| delle istruzioni per pacchetto, in %, su ogni modello:

| pipeline | n | mediana % | massimo % |
|---|---:|---:|---:|
| baseline | 30 | 0.21 | 0.31 |
| P1 | 30 | 0.18 | 0.27 |
| P1.5 | 30 | 0.16 | 0.26 |
| P2 | 30 | 0.01 | 0.05 |
| P3 | 30 | 0.01 | 0.03 |

## Che cosa cambia su un core piu' lento

Capacita' e IPC dell'E-core in rapporto al P-core (stessa frequenza, 3,5 GHz), mediana [min–max] sui modelli:

| pipeline | n | capacita' E/P | IPC E/P |
|---|---:|---:|---:|
| baseline | 30 | 0.64 [0.62–0.66] | 0.65 [0.63–0.68] |
| P1 | 30 | 0.74 [0.72–0.86] | 0.76 [0.71–0.90] |
| P1.5 | 30 | 0.74 [0.71–0.83] | 0.75 [0.70–0.87] |
| P2 | 30 | 0.83 [0.76–0.85] | 0.84 [0.76–0.86] |
| P3 | 30 | 0.81 [0.77–0.87] | 0.82 [0.80–0.89] |

Cicli per pacchetto E/P: parte fissa del nodo (baseline) 1.57 [1.50–1.59]; rete neurale:

| pipeline | n | cicli della rete E/P |
|---|---:|---:|
| P1 | 30 | 1.04 [0.79–1.11] |
| P1.5 | 30 | 1.08 [0.84–1.19] |
| P2 | 30 | 1.09 [1.05–1.22] |
| P3 | 30 | 1.14 [1.07–1.20] |

Piu' la rete neurale pesa sul pacchetto, meno conta il core: ρ di rango fra la quota di cicli della rete (P-core) e la capacita' E/P = 0.77 su 120 coppie modello-pipeline.

## Una legge di costo, stimata su tutti i modelli

costo della rete = a + b × MAC + c × strati (minimi quadrati sulla popolazione). Errore = errore relativo su un modello lasciato fuori dalla stima (mediana e 90° percentile, %): quanto la legge sbaglia su un modello che non ha visto. Le MAC eseguite contano una one-hot come una colonna sola; le non nulle tolgono i pesi a zero.

**ns per pacchetto, P-core**

| pipeline | variabili | n | a (ns) | b (ns/MAC) | c (ns/strato) | r² | errore 50° | errore 90° |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| P1 | MAC eseguite + strati | 27 | 31 | 0.22 | 0.1 | 0.93 | 3 | 10 |
| P1 | MAC dalla forma + strati | 27 | 51 | 0.01 | 1.3 | 0.05 | 17 | 37 |
| P1 | MAC eseguite non nulle + strati | 27 | 31 | 0.22 | 0.2 | 0.93 | 3 | 10 |
| P1.5 | MAC eseguite + strati | 27 | 38 | 0.19 | 1.4 | 0.79 | 6 | 13 |
| P1.5 | MAC dalla forma + strati | 27 | 49 | 0.03 | 1.8 | 0.28 | 11 | 29 |
| P1.5 | MAC eseguite non nulle + strati | 27 | 38 | 0.19 | 1.4 | 0.79 | 6 | 13 |
| P2 | MAC eseguite + strati | 27 | 151 | 0.03 | 24.9 | 0.82 | 4 | 11 |
| P2 | MAC dalla forma + strati | 27 | 149 | 0.02 | 24.7 | 0.82 | 4 | 13 |
| P2 | MAC eseguite non nulle + strati | 27 | 151 | 0.03 | 24.9 | 0.82 | 4 | 11 |
| P3 | MAC eseguite + strati | 27 | 168 | 0.68 | 44.9 | 0.97 | 3 | 4 |
| P3 | MAC dalla forma + strati | 27 | 242 | -0.00 | 49.2 | 0.72 | 6 | 18 |
| P3 | MAC eseguite non nulle + strati | 27 | 168 | 0.68 | 45.0 | 0.97 | 3 | 4 |

**istruzioni per pacchetto, P-core** (stessa forma: b in istruzioni per MAC, c per strato)

| pipeline | variabili | n | a | b | c | r² | errore 50° | errore 90° |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| P1 | MAC eseguite + strati | 27 | 315 | 3.65 | -0.4 | 0.94 | 3 | 11 |
| P1 | MAC dalla forma + strati | 27 | 618 | 0.32 | 15.8 | 0.08 | 19 | 42 |
| P1 | MAC eseguite non nulle + strati | 27 | 318 | 3.66 | 0.6 | 0.94 | 3 | 11 |
| P1.5 | MAC eseguite + strati | 27 | 550 | 2.79 | 15.4 | 0.78 | 4 | 16 |
| P1.5 | MAC dalla forma + strati | 27 | 690 | 0.56 | 20.8 | 0.31 | 9 | 28 |
| P1.5 | MAC eseguite non nulle + strati | 27 | 552 | 2.79 | 16.1 | 0.78 | 4 | 16 |
| P2 | MAC eseguite + strati | 27 | 2253 | 1.69 | 499.1 | 0.88 | 3 | 12 |
| P2 | MAC dalla forma + strati | 27 | 2336 | 0.34 | 502.3 | 0.87 | 2 | 12 |
| P2 | MAC eseguite non nulle + strati | 27 | 2256 | 1.68 | 499.6 | 0.88 | 3 | 12 |
| P3 | MAC eseguite + strati | 27 | 2252 | 12.03 | 897.6 | 0.99 | 1 | 4 |
| P3 | MAC dalla forma + strati | 27 | 3478 | 0.27 | 968.4 | 0.77 | 9 | 16 |
| P3 | MAC eseguite non nulle + strati | 27 | 2262 | 12.05 | 900.7 | 0.99 | 1 | 5 |

**ns per pacchetto, E-core**

| pipeline | variabili | n | a (ns) | b (ns/MAC) | c (ns/strato) | r² | errore 50° | errore 90° |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| P1 | MAC eseguite + strati | 27 | 25 | 0.21 | 2.5 | 0.88 | 5 | 11 |
| P1 | MAC dalla forma + strati | 27 | 43 | 0.02 | 3.4 | 0.18 | 12 | 30 |
| P1 | MAC eseguite non nulle + strati | 27 | 25 | 0.21 | 2.5 | 0.88 | 5 | 11 |
| P1.5 | MAC eseguite + strati | 27 | 41 | 0.15 | 3.5 | 0.74 | 3 | 16 |
| P1.5 | MAC dalla forma + strati | 27 | 48 | 0.03 | 3.7 | 0.46 | 5 | 22 |
| P1.5 | MAC eseguite non nulle + strati | 27 | 41 | 0.15 | 3.5 | 0.74 | 3 | 16 |
| P2 | MAC eseguite + strati | 27 | 159 | 0.15 | 26.8 | 0.86 | 2 | 10 |
| P2 | MAC dalla forma + strati | 27 | 172 | 0.01 | 27.5 | 0.82 | 4 | 11 |
| P2 | MAC eseguite non nulle + strati | 27 | 159 | 0.15 | 26.8 | 0.86 | 2 | 10 |
| P3 | MAC eseguite + strati | 27 | 194 | 0.60 | 59.9 | 0.98 | 1 | 5 |
| P3 | MAC dalla forma + strati | 27 | 255 | 0.01 | 63.4 | 0.84 | 6 | 11 |
| P3 | MAC eseguite non nulle + strati | 27 | 194 | 0.61 | 60.0 | 0.98 | 1 | 5 |

**ns per pacchetto a traffico leggero (media T2−T1 meno la baseline), P-core**

| pipeline | variabili | n | a (ns) | b (ns/MAC) | c (ns/strato) | r² | errore 50° | errore 90° |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| P1 | MAC eseguite + strati | 27 | 17 | 0.35 | -0.4 | 0.93 | 6 | 15 |
| P1 | MAC dalla forma + strati | 27 | 50 | 0.02 | 1.4 | 0.04 | 22 | 54 |
| P1 | MAC eseguite non nulle + strati | 27 | 17 | 0.35 | -0.3 | 0.93 | 6 | 15 |
| P1.5 | MAC eseguite + strati | 27 | 30 | 0.27 | 2.3 | 0.86 | 6 | 14 |
| P1.5 | MAC dalla forma + strati | 27 | 49 | 0.03 | 3.2 | 0.20 | 12 | 43 |
| P1.5 | MAC eseguite non nulle + strati | 27 | 30 | 0.27 | 2.3 | 0.86 | 5 | 13 |
| P2 | MAC eseguite + strati | 27 | 151 | 0.05 | 27.5 | 0.77 | 4 | 13 |
| P2 | MAC dalla forma + strati | 27 | 146 | 0.03 | 27.1 | 0.79 | 6 | 12 |
| P2 | MAC eseguite non nulle + strati | 27 | 151 | 0.05 | 27.6 | 0.77 | 4 | 13 |
| P3 | MAC eseguite + strati | 27 | 168 | 0.67 | 50.2 | 0.97 | 3 | 7 |
| P3 | MAC dalla forma + strati | 27 | 241 | -0.00 | 54.5 | 0.75 | 8 | 14 |
| P3 | MAC eseguite non nulle + strati | 27 | 168 | 0.67 | 50.4 | 0.97 | 3 | 7 |

## Lo stesso modello misurato piu' volte

Stessa forma, stessi pesi, cartelle diverse: la dispersione della misura, non del modello (ns di rete neurale, P-core).

| cartelle | P1 | P1.5 | P2 | P3 |
|---|---:|---:|---:|---:|
| depth_2, nodes_52, width_4 | 49–51 | 57–58 | 235–236 | 366–370 |

## Pesi a zero

ns di rete neurale misurati e, fra parentesi, il rapporto con la legge stimata sui modelli densi (1 = la sparsita' non cambia niente, < 1 = il modello dimagrisce):

| modello | pesi a zero | P1 | P1.5 | P2 | P3 |
|---|---:|---:|---:|---:|---:|
| sparsity_0 | 3% | 44 (0.90) | 52 (0.91) | 222 (0.97) | 352 (0.99) |
| sparsity_50 | 56% | 36 (0.75) | 45 (0.79) | 229 (1.01) | 356 (1.00) |
| sparsity_90 | 91% | 27 (0.55) | 39 (0.68) | 234 (1.02) | 367 (1.03) |

## Larga o profonda, a parita' di pesi

Cinque forme con ~592 pesi, da 1 a 5 strati: ns di rete neurale con 1 strato → con 5, e la pendenza per strato (minimi quadrati), P-core.

| composizione | pipeline | 1 → 5 strati | variazione | ns per strato |
|---|---:|---:|---:|---:|
| ipa65 | P1 | 61 → 72 | +17% | 3 |
| ipa65 | P1.5 | 71 → 84 | +19% | 4 |
| ipa65 | P2 | 216 → 304 | +41% | 24 |
| ipa65 | P3 | 321 → 537 | +67% | 56 |

## Traffico leggero contro nodo saturo

A traffico leggero (T2−T1, sotto la capacita') contro a nodo saturo (tempo di CPU), sempre la sola rete neurale. media/saturo ≈ 1 vuol dire che il costo di un pacchetto non dipende dal carico; minimo/media dice quanto costa il pacchetto che trova cache e predittori caldi rispetto a quello tipico.

| core | pipeline | n | media leggero / saturo | minimo / media |
|---|---:|---:|---:|---:|
| P-core | P1 | 30 | 1.01 [0.67–1.29] | 0.73 [0.59–0.96] |
| P-core | P1.5 | 30 | 1.06 [0.80–1.26] | 0.71 [0.59–0.89] |
| P-core | P2 | 30 | 1.05 [0.95–1.20] | 0.84 [0.71–0.91] |
| P-core | P3 | 30 | 1.04 [0.95–1.14] | 0.84 [0.79–0.90] |
| E-core | P1 | 30 | 1.18 [0.93–1.73] | 0.77 [0.49–0.91] |
| E-core | P1.5 | 30 | 1.16 [0.97–1.35] | 0.79 [0.70–0.90] |
| E-core | P2 | 30 | 1.03 [0.96–1.16] | 0.92 [0.86–0.96] |
| E-core | P3 | 30 | 1.03 [0.99–1.10] | 0.94 [0.91–0.96] |

