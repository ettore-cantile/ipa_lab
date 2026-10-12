# Sintesi sulla popolazione: popolazione_2026-10

## Le somme

Ogni riga e' un'affermazione e la sua prova sulla popolazione: su quanti modelli regge, o l'intervallo che copre.

| affermazione | sulla popolazione |
|---|---:|
| P2 ha un tetto sui pesi che le altre pipeline non hanno | 6/91 modelli fuori da P2 |
| P1 decide esattamente come il riferimento intero | 91/91 modelli |
| P2 decide esattamente come il riferimento intero | 85/85 modelli |
| P3 decide esattamente come il riferimento intero | 91/91 modelli |
| rete neurale P1, ns per pacchetto (P-core) | 52 [19–155] |
| rete neurale P1.5, ns per pacchetto (P-core) | 59 [19–156] |
| rete neurale P2, ns per pacchetto (P-core) | 225 [129–446] |
| rete neurale P3, ns per pacchetto (P-core) | 420 [240–852] |
| P1 ≤ P2 ≤ P3 nel costo della rete neurale (P-core) | 85/85 |
| P2 costa P1 per | 4.3 [2.7–12.8] |
| P3 costa P1 per | 7.8 [4.9–24.6] |
| P3 costa P2 per | 1.9 [1.4–2.3] |
| istruzioni eseguite per strato in piu' (legge, P-core) | P1 -6 (r² 0.97), P1.5 -4 (r² 0.91), P2 370 (r² 0.94), P3 901 (r² 0.99) |
| istruzioni caricate per strato in piu' (legge) | P1 -5 (r² 0.99), P1.5 -58 (r² 0.57), P2 +887 (r² 0.96), P3 sempre 12288 |
| legge di P1 (P-core) | 22 ns + 0.26 ns/MAC + 1 ns/strato; r² 0.98, errore mediano 6% su modelli non visti (n=83) |
| legge di P1.5 (P-core) | 29 ns + 0.26 ns/MAC + 1 ns/strato; r² 0.95, errore mediano 9% su modelli non visti (n=83) |
| legge di P2 (P-core) | 103 ns + 0.42 ns/MAC + 20 ns/strato; r² 0.93, errore mediano 6% su modelli non visti (n=77) |
| legge di P3 (P-core) | 154 ns + 0.77 ns/MAC + 46 ns/strato; r² 0.99, errore mediano 3% su modelli non visti (n=83) |
| contare le MAC eseguite spiega il costo meglio della forma | 4/4 pipeline |
| la dimensione di P1 predice il suo lavoro (ρ di rango) | 0.98 su 91 modelli |
| la dimensione di P1.5 predice il suo lavoro (ρ di rango) | 0.90 su 91 modelli |
| la dimensione di P2 predice il suo lavoro (ρ di rango) | 0.77 su 85 modelli |
| P2 e' il programma piu' grande ma P3 esegue di piu' | 85/85 |
| stesse istruzioni per pacchetto su P-core ed E-core | differenza massima 0.3% su 449 coppie modello-pipeline |
| stesse istruzioni anche sul LP E-core | differenza massima 0.7% su 56 coppie |
| l'E-core perde soprattutto nella parte fissa del nodo | cicli fissi E/P 1.56 [1.50–1.60]; ρ(quota rete, capacita' E/P) = 0.76 |
| capacita' del LP E-core rispetto al P-core | 0.43 [0.32–0.53] |
| a parita' di forma, i pesi cambiano il costo di | P1 ≤5%, P1.5 ≤6%, P2 ≤5%, P3 ≤2% |
| con ≥50% di pesi a zero, misurato / previsto dalla legge densa | P1 0.53 [0.31–0.85], P1.5 0.71 [0.27–0.99], P2 1.03 [0.91–1.14], P3 1.00 [0.91–1.03] |
| a parita' di pesi, ogni strato in piu' costa (ns, P-core) | P1 4 [3–4], P1.5 4 [4–4], P2 27 [26–28], P3 58 [57–59] |
| costo a traffico leggero / costo a nodo saturo (P-core) | P1 0.77 [0.48–1.02], P1.5 0.83 [0.50–1.02], P2 1.03 [0.94–1.09], P3 1.02 [0.94–1.11] |
| costo a traffico leggero / costo a nodo saturo (E-core) | P1 1.26 [0.34–2.73], P1.5 1.22 [0.30–2.52], P2 1.08 [0.93–1.35], P3 1.07 [0.82–1.13] |
| il trasporto (T3−T2 minimo, senza attesa) e' un costo comune, ns | P-core 199 [187–221], E-core 240 [226–274] |
| il trasporto non dipende dalla pipeline | differenza fra la piu' cara e la meno cara 4 [1–17]% su 182 modelli-core |
| il massimo inoltrato al crescere del rate coincide con la capacita' a massima spinta (entro il rumore fra sessioni) | rapporto 0.99 [0.88–1.03] su 48 curve |
| oltre la capacita' si perde prima del programma, alla coda | quota persa prima di XDP 1.000 [0.689–1.000] |
| due core reggono il doppio di uno (entro il rumore fra sessioni) | 99 [94–103]% del doppio su 80 coppie |
| le classi che inoltrano costano uguale | differenza fra la piu' cara e la meno cara 0 [0–9]% |
| scartare costa in piu' (effetto del banco: la memoria del pacchetto si libera sul nodo) | 51 [17–63] ns |
| TTL diversi pacchetto per pacchetto contro pacchetto fisso | 0 [-6–4]% sul tempo del nodo |
| la taglia del pacchetto non cambia il costo | differenza fra 64 e 1514 byte 1.2 [0.3–3.1]% (30 coppie) |
| la rete a nodo saturo / la rete da sola a chiamate singole (P-core) | P1 1.37 [0.95–3.55], P1.5 1.23 [1.02–3.19], P2 0.94 [0.77–1.10], P3 0.91 [0.84–0.97] |
| generare e compilare P1 per un modello nuovo (fuori dal nodo), ms | P1 49 [34–114], P1.5 61 [34–181] |
| installare un modello su un nodo in servizio, ms | P1 0.6 [0.3–1.5], P1.5 0.9 [0.3–5.6], P2 0.3 [0.2–0.4], P3 0.3 [0.2–0.5] |
| letture di tabella per pacchetto | P1 5 [4–5], P1.5 6 [5–6], P2 12 [11–12], P3 35 [23–54] |
| P3: letture di tabella e salti crescono con gli strati | +6.0 letture per strato; salti = strati su 89/89 modelli |
| la stessa misura rifatta in un'altra sessione cambia di | 1.8 % in mediana, 5.0 % al 90° percentile, 7.0 % al massimo (30 coppie) |
| misure fuori dalle conclusioni (disturbate o bocciate) | 2/526 |
| curve disturbate tenute senza le finestre colpite | 8 curve, 17/1920 finestre tolte |

## La popolazione

Per famiglia: base 53, replica 20, sparsita 8, imbuto 10.

| grandezza | intervallo |
|---|---:|
| ingressi (n_in) | 5–117 |
| strati nascosti | 1–6 |
| neuroni per strato (max) | 2–8 |
| uscite | 3–7 |
| pesi | 21–1349 |
| MAC dalla forma | 16–1296 |
| MAC eseguite | 16–480 |
| feature one-hot | 0–2 |
| colonne dense | 4–17 |
| pesi a zero (frazione) | 0.00–0.93 |

Modelli per composizione dell'ingresso e profondita':

| composizione | 1 strati | 2 strati | 3 strati | 4 strati | 5 strati | 6 strati |
|---|---:|---:|---:|---:|---:|---:|
| dense17 | 3 | 4 | 3 | 2 | 1 | 5 |
| dense5 | 5 | 2 | 1 | 2 | 0 | 1 |
| ipa117 | 4 | 1 | 2 | 1 | 0 | 2 |
| ipa17 | 2 | 4 | 2 | 1 | 0 | 2 |
| ipa65 | 2 | 8 | 2 | 3 | 1 | 1 |
| mixed33 | 2 | 1 | 6 | 3 | 0 | 2 |
| onehot105 | 1 | 2 | 1 | 5 | 0 | 1 |

P2 non sa eseguire 6 modelli su 91 (MAX_WEIGHT_ENTRIES): m019, m022, m043, m067, m068, m069. Le altre pipeline li eseguono tutti.

## Correttezza su ogni modello

Riferimento intero contro eBPF (verify_synth_kernel, BPF_PROG_TEST_RUN, 200 ingressi per modello): deve coincidere al 100%. P1.5 non e' in questo controllo (verify_synth_kernel prova P1 con il nodo congelato, P2 e P3).

| pipeline | OK | NO | non applicabile | errore | quali |
|---|---:|---:|---:|---:|---:|
| P1 | 91 | 0 | 0 | 0 | - |
| P2 | 85 | 0 | 6 | 0 | - |
| P3 | 91 | 0 | 0 | 0 | - |

## Il nodo senza rete neurale

Ricevere (rxonly) e ricevere + inoltrare (baseline) non dipendono dal modello: una misura per tipo di core.

| core | programma | Mpps | ns CPU | istr/pk | IPC |
|---|---:|---:|---:|---:|---:|
| P-core | rxonly | 19.29 | 40 | 383 | 2.50 |
| P-core | baseline | 14.52 | 67 | 607 | 2.60 |
| E-core | rxonly | 14.77 | 68 | 367 | 1.60 |
| E-core | baseline | 9.48 | 106 | 607 | 1.70 |
| LP E-core | rxonly | 4.26 | 172 | 395 | 0.90 |
| LP E-core | baseline | 3.42 | 291 | 613 | 0.90 |

## Quanto costa la rete neurale, su tutta la popolazione

ns per pacchetto della sola rete neurale: tempo di CPU a nodo saturo meno la baseline dello stesso run. n = modelli misurati.

**P-core**

| pipeline | n | min | 10° | mediana | 90° | max |
|---|---:|---:|---:|---:|---:|---:|
| P1 | 91 | 19 | 27 | 52 | 105 | 155 |
| P1.5 | 91 | 19 | 36 | 59 | 107 | 156 |
| P2 | 85 | 129 | 159 | 225 | 315 | 446 |
| P3 | 91 | 240 | 299 | 420 | 608 | 852 |

Capacita' del nodo, milioni di pacchetti al secondo per core (P-core):

| pipeline | n | min | 10° | mediana | 90° | max |
|---|---:|---:|---:|---:|---:|---:|
| baseline | 91 | 14.48 | 14.74 | 15.01 | 15.19 | 15.27 |
| P1 | 91 | 4.52 | 5.84 | 8.44 | 10.63 | 11.72 |
| P1.5 | 91 | 4.50 | 5.76 | 7.97 | 9.78 | 11.64 |
| P2 | 85 | 1.95 | 2.62 | 3.44 | 4.44 | 5.11 |
| P3 | 91 | 1.09 | 1.49 | 2.06 | 2.74 | 3.26 |

**E-core**

| pipeline | n | min | 10° | mediana | 90° | max |
|---|---:|---:|---:|---:|---:|---:|
| P1 | 91 | 13 | 20 | 49 | 95 | 150 |
| P1.5 | 91 | 14 | 25 | 61 | 105 | 156 |
| P2 | 85 | 134 | 171 | 246 | 351 | 493 |
| P3 | 91 | 276 | 338 | 480 | 715 | 968 |

Capacita' del nodo, milioni di pacchetti al secondo per core (E-core):

| pipeline | n | min | 10° | mediana | 90° | max |
|---|---:|---:|---:|---:|---:|---:|
| baseline | 91 | 9.25 | 9.33 | 9.41 | 9.47 | 9.54 |
| P1 | 91 | 3.92 | 4.98 | 6.42 | 7.91 | 8.34 |
| P1.5 | 91 | 3.81 | 4.74 | 6.00 | 7.61 | 8.33 |
| P2 | 85 | 1.67 | 2.19 | 2.83 | 3.60 | 4.16 |
| P3 | 91 | 0.93 | 1.22 | 1.71 | 2.25 | 2.61 |

## L'ordine fra le pipeline regge su ogni modello?

**P-core** — rapporto fra i costi della rete neurale, mediana [min–max] sui modelli, e su quanti la prima costa piu' della seconda:

| confronto | rapporto | la prima costa di piu' |
|---|---:|---:|
| P1.5 / P1 | 1.12 [0.93–1.68] | 77/91 |
| P2 / P1 | 4.32 [2.67–12.75] | 85/85 |
| P3 / P1 | 7.77 [4.86–24.65] | 91/91 |
| P3 / P2 | 1.87 [1.36–2.30] | 85/85 |
| P2 / P1.5 | 3.90 [2.37–9.60] | 85/85 |

P1 ≤ P2 ≤ P3 su 85/85 modelli.

**E-core** — rapporto fra i costi della rete neurale, mediana [min–max] sui modelli, e su quanti la prima costa piu' della seconda:

| confronto | rapporto | la prima costa di piu' |
|---|---:|---:|
| P1.5 / P1 | 1.18 [0.95–1.85] | 75/91 |
| P2 / P1 | 5.09 [3.17–20.35] | 85/85 |
| P3 / P1 | 9.34 [5.93–39.60] | 91/91 |
| P3 / P2 | 1.91 [1.47–2.51] | 85/85 |
| P2 / P1.5 | 4.15 [2.61–19.01] | 85/85 |

P1 ≤ P2 ≤ P3 su 85/85 modelli.

## Istruzioni caricate contro eseguite

Caricate = istruzioni dei programmi della pipeline, contate dal kernel al caricamento (prog_census). Eseguite = istruzioni per pacchetto dai contatori hardware, meno la baseline: la sola rete neurale. ρ = correlazione di rango fra le due sulla popolazione (1 = la dimensione ordina i modelli come il lavoro).

| pipeline | n | caricate | eseguite (rete) | ρ |
|---|---:|---:|---:|---:|
| P1 | 91 | 624 [239–2315] | 556 [157–2250] | 0.98 |
| P1.5 | 91 | 961 [282–4313] | 740 [168–2447] | 0.90 |
| P2 | 85 | 16813 [14604–18937] | 3972 [2038–7910] | 0.77 |
| P3 | 91 | 12288 [12288–12288] | 6969 [3851–15456] | - |

P2 piu' grande di P3: 85/85; P3 esegue piu' di P2: 85/85; tutte e due insieme (la dimensione ordina al contrario del lavoro): 85/85.

## Le istruzioni per pacchetto non dipendono dal core

|E/P − 1| delle istruzioni per pacchetto, in %, su ogni modello:

| pipeline | n | mediana % | massimo % |
|---|---:|---:|---:|
| baseline | 91 | 0.20 | 0.30 |
| P1 | 91 | 0.15 | 0.30 |
| P1.5 | 91 | 0.17 | 0.29 |
| P2 | 85 | 0.01 | 0.09 |
| P3 | 91 | 0.01 | 0.08 |

LP E-core contro P-core: massimo 0.7% su 56 coppie.

## Che cosa cambia su un core piu' lento

Capacita' e IPC dell'E-core in rapporto al P-core (stessa frequenza, 3,5 GHz), mediana [min–max] sui modelli:

| pipeline | n | capacita' E/P | IPC E/P |
|---|---:|---:|---:|
| baseline | 91 | 0.63 [0.61–0.66] | 0.65 [0.63–0.68] |
| P1 | 91 | 0.77 [0.70–0.91] | 0.79 [0.71–0.94] |
| P1.5 | 91 | 0.76 [0.68–0.88] | 0.78 [0.70–0.91] |
| P2 | 85 | 0.82 [0.77–0.87] | 0.84 [0.78–0.89] |
| P3 | 91 | 0.83 [0.72–0.89] | 0.84 [0.70–0.89] |

Cicli per pacchetto E/P: parte fissa del nodo (baseline) 1.56 [1.50–1.60]; rete neurale:

| pipeline | n | cicli della rete E/P |
|---|---:|---:|
| P1 | 91 | 0.94 [0.55–1.17] |
| P1.5 | 91 | 0.99 [0.59–1.34] |
| P2 | 85 | 1.10 [1.02–1.18] |
| P3 | 91 | 1.13 [1.05–1.40] |

Piu' la rete neurale pesa sul pacchetto, meno conta il core: ρ di rango fra la quota di cicli della rete (P-core) e la capacita' E/P = 0.76 su 358 coppie modello-pipeline.

LP E-core (2,5 GHz), 14 modelli dal piu' leggero al piu' pesante:

| pipeline | n | capacita' LP/P | mancate LLC/pk |
|---|---:|---:|---:|
| baseline | 14 | 0.26 [0.22–0.27] | 13.5 [13.1–13.9] |
| P1 | 14 | 0.35 [0.32–0.45] | 13.7 [12.9–17.9] |
| P1.5 | 14 | 0.35 [0.32–0.44] | 17.4 [13.5–18.2] |
| P2 | 14 | 0.45 [0.42–0.48] | 16.1 [13.0–19.3] |
| P3 | 14 | 0.48 [0.45–0.53] | 19.0 [13.5–21.2] |

## Una legge di costo, stimata su tutti i modelli

costo della rete = a + b × MAC + c × strati (minimi quadrati sulla popolazione). Errore = errore relativo su un modello lasciato fuori dalla stima (mediana e 90° percentile, %): quanto la legge sbaglia su un modello che non ha visto. Le MAC eseguite contano una one-hot come una colonna sola; le non nulle tolgono i pesi a zero.

**ns per pacchetto, P-core**

| pipeline | variabili | n | a (ns) | b (ns/MAC) | c (ns/strato) | r² | errore 50° | errore 90° |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| P1 | MAC eseguite + strati | 83 | 22 | 0.26 | 1.1 | 0.98 | 6 | 24 |
| P1 | MAC dalla forma + strati | 83 | 8 | 0.06 | 9.0 | 0.58 | 26 | 71 |
| P1 | MAC eseguite non nulle + strati | 83 | 22 | 0.26 | 1.2 | 0.98 | 6 | 24 |
| P1.5 | MAC eseguite + strati | 83 | 29 | 0.26 | 0.9 | 0.95 | 9 | 26 |
| P1.5 | MAC dalla forma + strati | 83 | 14 | 0.06 | 8.4 | 0.61 | 21 | 68 |
| P1.5 | MAC eseguite non nulle + strati | 83 | 29 | 0.26 | 0.9 | 0.95 | 8 | 25 |
| P2 | MAC eseguite + strati | 77 | 103 | 0.42 | 19.6 | 0.93 | 6 | 18 |
| P2 | MAC dalla forma + strati | 77 | 77 | 0.10 | 32.7 | 0.69 | 10 | 33 |
| P2 | MAC eseguite non nulle + strati | 77 | 103 | 0.43 | 19.6 | 0.93 | 6 | 18 |
| P3 | MAC eseguite + strati | 83 | 154 | 0.77 | 46.3 | 0.99 | 3 | 8 |
| P3 | MAC dalla forma + strati | 83 | 115 | 0.15 | 70.9 | 0.79 | 9 | 21 |
| P3 | MAC eseguite non nulle + strati | 83 | 154 | 0.77 | 46.3 | 0.99 | 3 | 8 |

**istruzioni per pacchetto, P-core** (stessa forma: b in istruzioni per MAC, c per strato)

| pipeline | variabili | n | a | b | c | r² | errore 50° | errore 90° |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| P1 | MAC eseguite + strati | 83 | 190 | 4.38 | -6.3 | 0.97 | 14 | 36 |
| P1 | MAC dalla forma + strati | 83 | -52 | 0.94 | 128.5 | 0.53 | 34 | 121 |
| P1 | MAC eseguite non nulle + strati | 83 | 189 | 4.40 | -6.2 | 0.97 | 13 | 36 |
| P1.5 | MAC eseguite + strati | 83 | 341 | 4.27 | -3.9 | 0.91 | 17 | 60 |
| P1.5 | MAC dalla forma + strati | 83 | 74 | 1.10 | 119.2 | 0.61 | 27 | 97 |
| P1.5 | MAC eseguite non nulle + strati | 83 | 341 | 4.30 | -3.8 | 0.91 | 17 | 59 |
| P2 | MAC eseguite + strati | 77 | 1628 | 7.85 | 369.9 | 0.94 | 6 | 18 |
| P2 | MAC dalla forma + strati | 77 | 1120 | 2.06 | 609.0 | 0.72 | 12 | 32 |
| P2 | MAC eseguite non nulle + strati | 77 | 1628 | 7.89 | 370.1 | 0.94 | 6 | 18 |
| P3 | MAC eseguite + strati | 83 | 1870 | 14.85 | 901.3 | 0.99 | 3 | 6 |
| P3 | MAC dalla forma + strati | 83 | 1111 | 2.80 | 1375.3 | 0.79 | 11 | 28 |
| P3 | MAC eseguite non nulle + strati | 83 | 1869 | 14.94 | 901.6 | 0.99 | 3 | 6 |

**ns per pacchetto, E-core**

| pipeline | variabili | n | a (ns) | b (ns/MAC) | c (ns/strato) | r² | errore 50° | errore 90° |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| P1 | MAC eseguite + strati | 83 | 18 | 0.26 | 1.2 | 0.95 | 15 | 46 |
| P1 | MAC dalla forma + strati | 83 | 3 | 0.06 | 9.1 | 0.56 | 30 | 90 |
| P1 | MAC eseguite non nulle + strati | 83 | 18 | 0.26 | 1.2 | 0.95 | 15 | 45 |
| P1.5 | MAC eseguite + strati | 83 | 28 | 0.24 | 1.7 | 0.88 | 16 | 65 |
| P1.5 | MAC dalla forma + strati | 83 | 12 | 0.06 | 8.6 | 0.63 | 24 | 75 |
| P1.5 | MAC eseguite non nulle + strati | 83 | 28 | 0.24 | 1.7 | 0.88 | 16 | 65 |
| P2 | MAC eseguite + strati | 77 | 112 | 0.51 | 20.2 | 0.94 | 5 | 17 |
| P2 | MAC dalla forma + strati | 77 | 80 | 0.13 | 35.8 | 0.69 | 12 | 31 |
| P2 | MAC eseguite non nulle + strati | 77 | 112 | 0.51 | 20.3 | 0.94 | 6 | 17 |
| P3 | MAC eseguite + strati | 83 | 153 | 0.79 | 61.8 | 0.98 | 3 | 6 |
| P3 | MAC dalla forma + strati | 83 | 110 | 0.17 | 86.3 | 0.84 | 9 | 21 |
| P3 | MAC eseguite non nulle + strati | 83 | 153 | 0.79 | 61.8 | 0.98 | 3 | 6 |

**istruzioni caricate** (dimensione dei programmi, stessa forma: b per MAC, c per strato)

| pipeline | variabili | n | a | b | c | r² | errore 50° | errore 90° |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| P1 | MAC eseguite + strati | 83 | 232 | 4.37 | -4.8 | 0.99 | 4 | 10 |
| P1 | MAC dalla forma + strati | 83 | -5 | 0.90 | 131.1 | 0.53 | 31 | 90 |
| P1 | MAC eseguite non nulle + strati | 83 | 231 | 4.40 | -4.8 | 0.99 | 4 | 10 |
| P1.5 | MAC eseguite + strati | 83 | 686 | 5.91 | -57.8 | 0.57 | 40 | 77 |
| P1.5 | MAC dalla forma + strati | 83 | 102 | 2.84 | 54.3 | 0.96 | 11 | 25 |
| P1.5 | MAC eseguite non nulle + strati | 83 | 686 | 5.95 | -57.7 | 0.57 | 40 | 78 |
| P2 | MAC eseguite + strati | 77 | 12774 | -0.11 | 886.7 | 0.96 | 2 | 3 |
| P2 | MAC dalla forma + strati | 77 | 12816 | -0.20 | 886.9 | 0.96 | 2 | 3 |
| P2 | MAC eseguite non nulle + strati | 77 | 12774 | -0.12 | 886.9 | 0.96 | 2 | 3 |
| P3 | MAC eseguite + strati | 83 | 12288 | -0.00 | -0.0 | 1.00 | 0 | 0 |
| P3 | MAC dalla forma + strati | 83 | 12288 | -0.00 | -0.0 | 1.00 | 0 | 0 |
| P3 | MAC eseguite non nulle + strati | 83 | 12288 | 0.00 | -0.0 | 1.00 | 0 | 0 |

**ns per pacchetto a traffico leggero (media T2−T1 meno la baseline), P-core**

| pipeline | variabili | n | a (ns) | b (ns/MAC) | c (ns/strato) | r² | errore 50° | errore 90° |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| P1 | MAC eseguite + strati | 83 | 10 | 0.27 | 1.0 | 0.99 | 7 | 19 |
| P1 | MAC dalla forma + strati | 83 | -5 | 0.06 | 9.5 | 0.55 | 30 | 101 |
| P1 | MAC eseguite non nulle + strati | 83 | 10 | 0.27 | 1.0 | 0.99 | 7 | 18 |
| P1.5 | MAC eseguite + strati | 83 | 17 | 0.27 | 0.9 | 0.96 | 12 | 36 |
| P1.5 | MAC dalla forma + strati | 83 | 1 | 0.06 | 9.1 | 0.60 | 28 | 89 |
| P1.5 | MAC eseguite non nulle + strati | 83 | 17 | 0.27 | 0.9 | 0.96 | 12 | 36 |
| P2 | MAC eseguite + strati | 77 | 103 | 0.44 | 20.2 | 0.93 | 7 | 17 |
| P2 | MAC dalla forma + strati | 77 | 76 | 0.11 | 33.6 | 0.70 | 11 | 31 |
| P2 | MAC eseguite non nulle + strati | 77 | 103 | 0.44 | 20.2 | 0.93 | 7 | 17 |
| P3 | MAC eseguite + strati | 83 | 146 | 0.79 | 50.1 | 0.98 | 3 | 9 |
| P3 | MAC dalla forma + strati | 83 | 105 | 0.15 | 75.1 | 0.80 | 10 | 22 |
| P3 | MAC eseguite non nulle + strati | 83 | 146 | 0.79 | 50.1 | 0.98 | 3 | 9 |

## Quanto conta il seme dei pesi

Stessa forma, semi diversi (uno con pesi normali): ns di rete neurale, media ± coefficiente di variazione, P-core.

| gruppo | modello | semi | P1 | P1.5 | P2 | P3 |
|---|---:|---:|---:|---:|---:|---:|
| r0 | dense5 5-2-3 | 4 | 20 ± 5% | 20 ± 6% | 133 ± 2% | 246 ± 2% |
| r1 | ipa17 17-4-4-5 | 4 | 46 ± 2% | 54 ± 2% | 190 ± 4% | 336 ± 2% |
| r2 | mixed33 33-4-4-4-5 | 4 | 53 ± 2% | 57 ± 3% | 226 ± 1% | 422 ± 0% |
| r3 | ipa65 65-8-8-3 | 4 | 69 ± 2% | 81 ± 1% | 212 ± 5% | 405 ± 2% |
| r4 | onehot105 105-8-8-8-8-5 | 4 | 104 ± 3% | 108 ± 1% | - | 607 ± 2% |
| r5 | dense17 17-8-8-8-8-8-8-3 | 4 | 147 ± 4% | 149 ± 3% | 439 ± 2% | 848 ± 0% |

## Pesi a zero

ns di rete neurale misurati e, fra parentesi, il rapporto con la legge stimata sui modelli densi (1 = la sparsita' non cambia niente, < 1 = il modello dimagrisce):

| modello | pesi a zero | P1 | P1.5 | P2 | P3 |
|---|---:|---:|---:|---:|---:|
| m073 | 46% | 46 (1.01) | 53 (1.01) | 242 (1.24) | 362 (1.02) |
| m077 | 49% | 41 (0.74) | 53 (0.87) | 251 (1.02) | 483 (1.03) |
| m075 | 49% | 52 (0.63) | 54 (0.61) | 229 (0.89) | 468 (1.01) |
| m079 | 51% | 48 (0.85) | 63 (0.99) | 203 (1.03) | 318 (0.92) |
| m074 | 88% | 29 (0.63) | 43 (0.83) | 223 (1.14) | 364 (1.03) |
| m078 | 89% | 20 (0.35) | 33 (0.54) | 249 (1.01) | 481 (1.02) |
| m080 | 90% | 30 (0.53) | 45 (0.71) | 203 (1.04) | 314 (0.91) |
| m076 | 93% | 26 (0.31) | 24 (0.27) | 232 (0.91) | 468 (1.00) |

## Larga o profonda, a parita' di pesi

Cinque forme con ~592 pesi, da 1 a 5 strati: ns di rete neurale con 1 strato → con 5, e la pendenza per strato (minimi quadrati), P-core.

| composizione | pipeline | 1 → 5 strati | variazione | ns per strato |
|---|---:|---:|---:|---:|
| ipa65 | P1 | 66 → 76 | +14% | 3 |
| ipa65 | P1.5 | 79 → 91 | +15% | 4 |
| ipa65 | P2 | 203 → 310 | +53% | 28 |
| ipa65 | P3 | 322 → 547 | +70% | 59 |
| dense17 | P1 | 72 → 87 | +21% | 4 |
| dense17 | P1.5 | 74 → 83 | +13% | 4 |
| dense17 | P2 | 219 → 315 | +44% | 26 |
| dense17 | P3 | 392 → 608 | +55% | 57 |

## Traffico leggero contro nodo saturo

A traffico leggero (T2−T1, sotto la capacita') contro a nodo saturo (tempo di CPU), sempre la sola rete neurale. media/saturo ≈ 1 vuol dire che il costo di un pacchetto non dipende dal carico; minimo/media dice quanto costa il pacchetto che trova cache e predittori caldi rispetto a quello tipico.

| core | pipeline | n | media leggero / saturo | minimo / media |
|---|---:|---:|---:|---:|
| P-core | P1 | 91 | 0.77 [0.48–1.02] | 0.89 [0.63–1.02] |
| P-core | P1.5 | 91 | 0.83 [0.50–1.02] | 0.90 [0.66–1.01] |
| P-core | P2 | 85 | 1.03 [0.94–1.09] | 0.87 [0.81–0.93] |
| P-core | P3 | 91 | 1.02 [0.94–1.11] | 0.86 [0.80–0.91] |
| E-core | P1 | 91 | 1.26 [0.34–2.73] | 0.74 [0.34–0.92] |
| E-core | P1.5 | 91 | 1.22 [0.30–2.52] | 0.74 [0.41–0.91] |
| E-core | P2 | 85 | 1.08 [0.93–1.35] | 0.89 [0.84–0.94] |
| E-core | P3 | 91 | 1.07 [0.82–1.13] | 0.93 [0.88–0.97] |

## Il trasporto verso il nodo successivo

T3−T2 (redirect, cavo virtuale, ricezione) dalla misura a tre orologi, ns. Il minimo e' il trasporto senza attesa. La media contiene anche la coda: qui l'uscita gira sul core del nodo, e la media cresce col rate.

| core | programma | n | minimo | media per rate |
|---|---:|---:|---:|---:|
| P-core | baseline | 91 | 194 [188–199] | 0.25 Mpps 550 [524–573], 0.5 Mpps 1192 [1124–1257] |
| P-core | P1 | 91 | 197 [187–208] | 0.25 Mpps 548 [523–591], 0.5 Mpps 1207 [1133–1274] |
| P-core | P1.5 | 91 | 198 [190–206] | 0.25 Mpps 549 [527–580], 0.5 Mpps 1201 [1137–1274] |
| P-core | P2 | 85 | 204 [195–210] | 0.25 Mpps 563 [531–614], 0.5 Mpps 1219 [1156–1329] |
| P-core | P3 | 91 | 204 [194–221] | 0.25 Mpps 574 [545–649], 0.5 Mpps 1244 [1178–1416] |
| E-core | baseline | 91 | 239 [229–266] | 0.25 Mpps 629 [601–684], 0.5 Mpps 1233 [1176–1373] |
| E-core | P1 | 91 | 236 [228–268] | 0.25 Mpps 628 [586–692], 0.5 Mpps 1222 [1165–1307] |
| E-core | P1.5 | 91 | 236 [226–266] | 0.25 Mpps 630 [587–705], 0.5 Mpps 1216 [1176–1323] |
| E-core | P2 | 85 | 242 [237–274] | 0.25 Mpps 656 [618–714], 0.5 Mpps 1245 [1169–1383] |
| E-core | P3 | 91 | 243 [232–272] | 0.25 Mpps 653 [613–707], 0.5 Mpps 1242 [1178–1366] |

## Al crescere del traffico

Ginocchio = rate chiesto piu' alto senza perdite; massimo inoltrato contro la capacita' misurata a massima spinta sullo stesso modello.

| core | modello | pipeline | ginocchio Mpps | max inoltrati | capacita' | collo |
|---|---:|---:|---:|---:|---:|---:|
| P-core | m000 | P1 | 8.0 | 9.33 | 10.63 | nessuna |
| P-core | m000 | P1.5 | 8.0 | 9.07 | 9.35 | ingresso: programma o ricezione (manca rxonly) |
| P-core | m000 | P2 | 4.0 | 4.43 | 4.46 | ingresso: programma o ricezione (manca rxonly) |
| P-core | m000 | P3 | 2.5 | 3.20 | 3.13 | ingresso: programma o ricezione (manca rxonly) |
| P-core | m013 | P1 | 5.0 | 5.81 | 5.85 | ingresso: programma o ricezione (manca rxonly) |
| P-core | m013 | P1.5 | 5.0 | 5.41 | 5.58 | ingresso: programma o ricezione (manca rxonly) |
| P-core | m013 | P2 | 2.5 | 2.60 | 2.54 | ingresso: programma o ricezione (manca rxonly) |
| P-core | m013 | P3 | 1.0 | 1.50 | 1.51 | ingresso: programma o ricezione (manca rxonly) |
| P-core | m025 | P1 | 6.0 | 7.08 | 7.35 | ingresso: programma o ricezione (manca rxonly) |
| P-core | m025 | P1.5 | 6.0 | 7.15 | 7.34 | ingresso: programma o ricezione (manca rxonly) |
| P-core | m025 | P2 | 3.5 | 3.59 | 3.68 | ingresso: programma o ricezione (manca rxonly) |
| P-core | m025 | P3 | 1.5 | 2.10 | 2.10 | ingresso: programma o ricezione (manca rxonly) |
| P-core | m031 | P1 | 7.0 | 7.72 | 7.88 | ingresso: programma o ricezione (manca rxonly) |
| P-core | m031 | P1.5 | 7.0 | 7.77 | 7.90 | ingresso: programma o ricezione (manca rxonly) |
| P-core | m031 | P2 | 3.5 | 3.81 | 3.98 | ingresso: programma o ricezione (manca rxonly) |
| P-core | m031 | P3 | 2.0 | 2.45 | 2.46 | ingresso: programma o ricezione (manca rxonly) |
| P-core | m037 | P1 | 4.0 | 4.48 | 4.66 | ingresso: programma o ricezione (manca rxonly) |
| P-core | m037 | P1.5 | 4.0 | 4.50 | 4.66 | ingresso: programma o ricezione (manca rxonly) |
| P-core | m037 | P2 | 1.5 | 2.03 | 2.02 | ingresso: programma o ricezione (manca rxonly) |
| P-core | m037 | P3 | 1.0 | 1.10 | 1.09 | ingresso: programma o ricezione (manca rxonly) |
| P-core | m042 | P1 | 9.0 | 9.40 | 9.62 | ingresso: programma o ricezione (manca rxonly) |
| P-core | m042 | P1.5 | 8.0 | 9.18 | 9.18 | ingresso: programma o ricezione (manca rxonly) |
| P-core | m042 | P2 | 3.5 | 3.79 | 3.91 | ingresso: programma o ricezione (manca rxonly) |
| P-core | m042 | P3 | 1.5 | 2.14 | 2.12 | ingresso: programma o ricezione (manca rxonly) |
| E-core | m000 | P1 | 7.0 | 7.16 | 7.61 | ingresso: programma o ricezione (manca rxonly) |
| E-core | m000 | P1.5 | 6.0 | 7.08 | 6.90 | ingresso: programma o ricezione (manca rxonly) |
| E-core | m000 | P2 | 3.5 | 3.58 | 3.67 | ingresso: programma o ricezione (manca rxonly) |
| E-core | m000 | P3 | 2.0 | 2.50 | 2.51 | ingresso: programma o ricezione (manca rxonly) |
| E-core | m013 | P1 | 4.0 | 4.63 | 4.82 | ingresso: programma o ricezione (manca rxonly) |
| E-core | m013 | P1.5 | 4.0 | 4.36 | 4.52 | ingresso: programma o ricezione (manca rxonly) |
| E-core | m013 | P2 | 2.0 | 2.09 | 2.11 | ingresso: programma o ricezione (manca rxonly) |
| E-core | m013 | P3 | 1.0 | 1.29 | 1.29 | ingresso: programma o ricezione (manca rxonly) |
| E-core | m025 | P1 | 5.0 | 5.84 | 5.93 | ingresso: programma o ricezione (manca rxonly) |
| E-core | m025 | P1.5 | 5.0 | 5.88 | 5.92 | ingresso: programma o ricezione (manca rxonly) |
| E-core | m025 | P2 | 2.5 | 2.86 | 2.88 | ingresso: programma o ricezione (manca rxonly) |
| E-core | m025 | P3 | 1.5 | 1.78 | 1.80 | ingresso: programma o ricezione (manca rxonly) |
| E-core | m031 | P1 | 5.0 | 5.93 | 5.98 | ingresso: programma o ricezione (manca rxonly) |
| E-core | m031 | P1.5 | 5.0 | 5.99 | 6.00 | ingresso: programma o ricezione (manca rxonly) |
| E-core | m031 | P2 | 3.0 | 3.13 | 3.15 | ingresso: programma o ricezione (manca rxonly) |
| E-core | m031 | P3 | 1.5 | 2.00 | 2.02 | ingresso: programma o ricezione (manca rxonly) |
| E-core | m037 | P1 | 3.5 | 3.94 | 4.01 | ingresso: programma o ricezione (manca rxonly) |
| E-core | m037 | P1.5 | 3.5 | 3.95 | 3.97 | ingresso: programma o ricezione (manca rxonly) |
| E-core | m037 | P2 | 1.5 | 1.67 | 1.68 | ingresso: programma o ricezione (manca rxonly) |
| E-core | m037 | P3 | 0.5 | 0.93 | 0.94 | ingresso: programma o ricezione (manca rxonly) |
| E-core | m042 | P1 | 7.0 | 7.17 | 7.46 | ingresso: programma o ricezione (manca rxonly) |
| E-core | m042 | P1.5 | 6.0 | 6.55 | 6.68 | ingresso: programma o ricezione (manca rxonly) |
| E-core | m042 | P2 | 3.0 | 3.13 | 3.17 | ingresso: programma o ricezione (manca rxonly) |
| E-core | m042 | P3 | 1.5 | 1.68 | 1.71 | ingresso: programma o ricezione (manca rxonly) |

## Due core del nodo

| core | modello | pipeline | 1 core | 2 core | % del doppio |
|---|---:|---:|---:|---:|---:|
| P-core | m000 | baseline | 14.87 | 29.48 | 99 |
| P-core | m000 | P1 | 10.63 | 20.54 | 97 |
| P-core | m000 | P1.5 | 9.35 | 18.25 | 98 |
| P-core | m000 | P2 | 4.46 | 8.96 | 101 |
| P-core | m000 | P3 | 3.13 | 6.16 | 99 |
| P-core | m008 | baseline | 14.80 | 29.61 | 100 |
| P-core | m008 | P1 | 9.11 | 18.05 | 99 |
| P-core | m008 | P1.5 | 8.40 | 16.66 | 99 |
| P-core | m008 | P2 | 3.89 | 8.04 | 103 |
| P-core | m008 | P3 | 2.64 | 5.25 | 99 |
| P-core | m017 | baseline | 14.85 | 29.57 | 100 |
| P-core | m017 | P1 | 8.85 | 17.80 | 101 |
| P-core | m017 | P1.5 | 8.03 | 15.80 | 98 |
| P-core | m017 | P2 | 3.50 | 6.91 | 99 |
| P-core | m017 | P3 | 2.36 | 4.53 | 96 |
| P-core | m025 | baseline | 14.86 | 28.95 | 97 |
| P-core | m025 | P1 | 7.35 | 14.60 | 99 |
| P-core | m025 | P1.5 | 7.34 | 14.47 | 99 |
| P-core | m025 | P2 | 3.68 | 7.32 | 99 |
| P-core | m025 | P3 | 2.10 | 4.13 | 98 |
| P-core | m036 | baseline | 14.85 | 29.36 | 99 |
| P-core | m036 | P1 | 9.11 | 18.15 | 100 |
| P-core | m036 | P1.5 | 9.06 | 18.17 | 100 |
| P-core | m036 | P2 | 2.95 | 5.99 | 101 |
| P-core | m036 | P3 | 1.60 | 3.08 | 97 |
| P-core | m037 | baseline | 14.94 | 28.49 | 95 |
| P-core | m037 | P1 | 4.66 | 9.26 | 99 |
| P-core | m037 | P1.5 | 4.66 | 9.32 | 100 |
| P-core | m037 | P2 | 2.02 | 3.79 | 94 |
| P-core | m037 | P3 | 1.09 | 2.13 | 97 |
| P-core | m042 | baseline | 15.02 | 29.23 | 97 |
| P-core | m042 | P1 | 9.62 | 19.46 | 101 |
| P-core | m042 | P1.5 | 9.18 | 18.65 | 102 |
| P-core | m042 | P2 | 3.91 | 7.74 | 99 |
| P-core | m042 | P3 | 2.12 | 4.14 | 98 |
| P-core | m049 | baseline | 14.92 | 29.29 | 98 |
| P-core | m049 | P1 | 6.62 | 12.92 | 98 |
| P-core | m049 | P1.5 | 6.29 | 12.30 | 98 |
| P-core | m049 | P2 | 2.74 | 5.25 | 96 |
| P-core | m049 | P3 | 1.63 | 3.13 | 96 |
| E-core | m000 | baseline | 9.40 | 18.87 | 100 |
| E-core | m000 | P1 | 7.61 | 15.34 | 101 |
| E-core | m000 | P1.5 | 6.90 | 13.86 | 100 |
| E-core | m000 | P2 | 3.67 | 7.24 | 99 |
| E-core | m000 | P3 | 2.51 | 4.97 | 99 |
| E-core | m008 | baseline | 9.50 | 18.80 | 99 |
| E-core | m008 | P1 | 6.85 | 13.59 | 99 |
| E-core | m008 | P1.5 | 6.29 | 12.44 | 99 |
| E-core | m008 | P2 | 3.31 | 6.56 | 99 |
| E-core | m008 | P3 | 2.26 | 4.45 | 98 |
| E-core | m017 | baseline | 9.37 | 18.90 | 101 |
| E-core | m017 | P1 | 6.45 | 13.01 | 101 |
| E-core | m017 | P1.5 | 5.90 | 11.97 | 101 |
| E-core | m017 | P2 | 2.93 | 5.83 | 100 |
| E-core | m017 | P3 | 1.97 | 3.91 | 99 |
| E-core | m025 | baseline | 9.44 | 18.75 | 99 |
| E-core | m025 | P1 | 5.93 | 11.72 | 99 |
| E-core | m025 | P1.5 | 5.92 | 11.81 | 100 |
| E-core | m025 | P2 | 2.88 | 5.69 | 99 |
| E-core | m025 | P3 | 1.80 | 3.54 | 98 |
| E-core | m036 | baseline | 9.39 | 18.97 | 101 |
| E-core | m036 | P1 | 6.81 | 13.75 | 101 |
| E-core | m036 | P1.5 | 6.83 | 13.69 | 100 |
| E-core | m036 | P2 | 2.58 | 5.08 | 99 |
| E-core | m036 | P3 | 1.29 | 2.57 | 100 |
| E-core | m037 | baseline | 9.44 | 18.95 | 100 |
| E-core | m037 | P1 | 4.01 | 7.95 | 99 |
| E-core | m037 | P1.5 | 3.97 | 7.93 | 100 |
| E-core | m037 | P2 | 1.68 | 3.33 | 99 |
| E-core | m037 | P3 | 0.94 | 1.86 | 99 |
| E-core | m042 | baseline | 9.44 | 18.99 | 101 |
| E-core | m042 | P1 | 7.46 | 15.11 | 101 |
| E-core | m042 | P1.5 | 6.68 | 13.39 | 100 |
| E-core | m042 | P2 | 3.17 | 6.28 | 99 |
| E-core | m042 | P3 | 1.71 | 3.39 | 99 |
| E-core | m049 | baseline | 9.40 | 18.97 | 101 |
| E-core | m049 | P1 | 5.20 | 10.29 | 99 |
| E-core | m049 | P1.5 | 4.97 | 9.86 | 99 |
| E-core | m049 | P2 | 2.30 | 4.52 | 98 |
| E-core | m049 | P3 | 1.41 | 2.76 | 98 |

## Classi diverse

Una sessione per classe decisa: differenza fra la classe che inoltra piu' cara e la meno cara, e quanto costa in piu' scartare (ns, mediana delle classi).

| modello | pipeline | classi FORWARD | spread FORWARD | DROP − FORWARD ns |
|---|---:|---:|---:|---:|
| m000 | P1 | 1 | 0% | - |
| m000 | P1.5 | 1 | 0% | - |
| m000 | P2 | 1 | 0% | - |
| m000 | P3 | 1 | 0% | - |
| m008 | P1 | 4 | 2% | 51 |
| m008 | P1.5 | 4 | 1% | 55 |
| m008 | P2 | 4 | 9% | 31 |
| m008 | P3 | 4 | 1% | 51 |
| m017 | P1 | 1 | 0% | - |
| m017 | P1.5 | 1 | 0% | - |
| m017 | P2 | 1 | 0% | - |
| m017 | P3 | 1 | 0% | - |
| m025 | P1 | 2 | 1% | 63 |
| m025 | P1.5 | 2 | 1% | 61 |
| m025 | P2 | 2 | 7% | 41 |
| m025 | P3 | 2 | 1% | 35 |
| m036 | P1 | 1 | 0% | 53 |
| m036 | P1.5 | 1 | 0% | 51 |
| m036 | P2 | 1 | 0% | 43 |
| m036 | P3 | 1 | 0% | 47 |
| m037 | P1 | 1 | 0% | 52 |
| m037 | P1.5 | 1 | 0% | 59 |
| m037 | P2 | 1 | 0% | 27 |
| m037 | P3 | 1 | 0% | 17 |
| m042 | P1 | 1 | 0% | - |
| m042 | P1.5 | 1 | 0% | - |
| m042 | P2 | 1 | 0% | - |
| m042 | P3 | 1 | 0% | - |
| m049 | P1 | 2 | 0% | - |
| m049 | P1.5 | 2 | 2% | - |
| m049 | P2 | 2 | 1% | - |
| m049 | P3 | 2 | 1% | - |

## Pacchetti tutti uguali contro pacchetti diversi

TTL diversi a ogni pacchetto (2–31): il modello decide classi diverse, compreso lo scarto. ns di CPU per pacchetto contro il pacchetto fisso dello stesso modello.

| modello | pipeline | fisso | TTL misti | Δ |
|---|---:|---:|---:|---:|
| m000 | P1 | 94 | 95 | +1% |
| m000 | P1.5 | 107 | 110 | +3% |
| m000 | P2 | 224 | 221 | -2% |
| m000 | P3 | 320 | 311 | -3% |
| m004 | P1 | 158 | 155 | -1% |
| m004 | P1.5 | 170 | 170 | +0% |
| m004 | P2 | 347 | 355 | +2% |
| m004 | P3 | 584 | 591 | +1% |
| m006 | P1 | 106 | 108 | +1% |
| m006 | P1.5 | 114 | 114 | -0% |
| m006 | P2 | 296 | 294 | -1% |
| m006 | P3 | 538 | 547 | +2% |
| m009 | P1 | 104 | 105 | +0% |
| m009 | P1.5 | 112 | 112 | -0% |
| m009 | P2 | 266 | 268 | +1% |
| m009 | P3 | 400 | 391 | -2% |
| m011 | P1 | 124 | 124 | +0% |
| m011 | P1.5 | 128 | 133 | +4% |
| m011 | P2 | 328 | 330 | +1% |
| m011 | P3 | 483 | 495 | +2% |
| m018 | P1 | 107 | 106 | -1% |
| m018 | P1.5 | 114 | 117 | +3% |
| m018 | P2 | 317 | 309 | -2% |
| m018 | P3 | 461 | 466 | +1% |
| m023 | P1 | 103 | 102 | -1% |
| m023 | P1.5 | 102 | 101 | -2% |
| m023 | P2 | 210 | 207 | -1% |
| m023 | P3 | 335 | 329 | -2% |
| m029 | P1 | 133 | 133 | -0% |
| m029 | P1.5 | 133 | 133 | +0% |
| m029 | P2 | 348 | 352 | +1% |
| m029 | P3 | 610 | 610 | +0% |
| m034 | P1 | 169 | 176 | +4% |
| m034 | P1.5 | 170 | 173 | +1% |
| m034 | P2 | 378 | 362 | -4% |
| m034 | P3 | 637 | 641 | +1% |
| m037 | P1 | 214 | 216 | +1% |
| m037 | P1.5 | 214 | 218 | +2% |
| m037 | P2 | 494 | 512 | +4% |
| m037 | P3 | 915 | 910 | -1% |
| m040 | P1 | 135 | 136 | +1% |
| m040 | P1.5 | 137 | 136 | -1% |
| m040 | P2 | 249 | 247 | -1% |
| m040 | P3 | 468 | 476 | +2% |
| m046 | P1 | 126 | 125 | -1% |
| m046 | P1.5 | 135 | 134 | -1% |
| m046 | P2 | 261 | 246 | -6% |
| m046 | P3 | 411 | 401 | -2% |

## Taglia del pacchetto

Differenza fra la taglia piu' cara e la meno cara, per modello e pipeline: 1.2 [0.3–3.1]% su 30 coppie.

## Il programma da solo

bench_solo.py su ogni modello, P-core: latenza da solo (BPF_PROG_TEST_RUN, minimo su 7 misure), e la sola rete (meno la baseline dello stesso modello); build = caricare la pipeline da zero; installare = un modello nuovo su un nodo in servizio (P1: caricare l'oggetto compilato; P2, P3: scrivere le tabelle); letture di tabella e salti per pacchetto. Pacchetto e ingressi sono quelli del traffico (TTL 32, stato dei link che inoltra); una misura che non ha inoltrato resta fuori.

| pipeline | n | chiamata singola ns | rete ns | rete, ciclo caldo ns | build ms | generare e compilare P1 ms | installare ms | letture | salti |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| baseline | 89 | 38 [35–40] | - | - | 712.4 [707.0–724.7] | - | 0.0 [0.0–0.0] | 3.0 [3.0–3.0] | 0 [0–0] |
| P1 | 89 | 77 [44–177] | 40 [6–140] | - | 3.8 [3.3–26.9] | 49 [34–114] | 0.6 [0.3–1.5] | 5.0 [4.0–5.0] | 1 [1–1] |
| P1.5 | 89 | 88 [46–185] | 50 [7–148] | - | 1.8 [1.1–6.9] | 61 [34–181] | 0.9 [0.3–5.6] | 6.0 [5.0–6.0] | 1 [1–1] |
| P2 | 83 | 275 [157–598] | 237 [118–562] | - | 1571.8 [1456.6–1749.6] | - | 0.3 [0.2–0.4] | 12.0 [11.0–12.0] | 1 [1–1] |
| P3 | 89 | 504 [300–999] | 466 [262–963] | - | 1219.3 [1200.5–1234.1] | - | 0.3 [0.2–0.5] | 35.0 [23.0–54.0] | 4 [2–7] |

Ciclo caldo: blocchi di esecuzioni di fila finche' il TTL che scende non cambia la classe decisa; si usa solo dove il blocco e' lungo almeno 10 esecuzioni.

La sola rete sotto traffico divisa per la sola rete da sola, modello per modello:

| pipeline | nodo saturo / ciclo caldo | traffico leggero, minimo / ciclo caldo | nodo saturo / chiamata singola | traffico leggero, media / chiamata singola |
|---|---:|---:|---:|---:|
| P1 | - | - | 1.37 [0.95–3.55] | 1.06 [0.78–2.50] |
| P1.5 | - | - | 1.23 [1.02–3.19] | 1.04 [0.85–2.14] |
| P2 | - | - | 0.94 [0.77–1.10] | 0.97 [0.79–1.07] |
| P3 | - | - | 0.91 [0.84–0.97] | 0.92 [0.86–1.00] |

## Quanto varia la stessa misura

Variazione in % del valore: mediana, 90° percentile, massimo. Una differenza dentro la variazione fra sessioni non e' una differenza; un rapporto fra due misure di sessioni diverse puo' superare 1 per questo solo motivo.

| che cosa | n | mediana % | 90° % | max % |
|---|---:|---:|---:|---:|
| i giri di una misura ((max − min) / mediana) | 898 | 1.3 | 3.3 | 7.8 |
| il nodo senza rete in sessioni diverse, P-core | 91 | 1.1 | 2.1 | 3.5 |
| il nodo senza rete in sessioni diverse, E-core | 91 | 0.4 | 1.0 | 1.7 |
| stesso modello e versione, due sessioni | 30 | 1.8 | 5.0 | 7.0 |

## Misure fuori dalle conclusioni

Non entrano in nessun intervallo ne' in nessuna legge. disturbata = la macchina non e' rimasta nelle condizioni dichiarate (run_disturbed in env.csv); bocciata = il controllo di validita' del banco l'ha respinta (throughput_report.md). Si rifanno con POP_RIFAI_DISTURBATE=1 remeasure_popolazione.sh.

**disturbata** (2): solo/m026, solo/m030

**curve tenute senza le finestre disturbate** (ogni punto con almeno 2 giri puliti): carico_Ecore/m013 (7/240), carico_Ecore/m031 (3/240), carico_Ecore/m037 (1/240), carico_Ecore/m042 (3/240), carico_Pcore/m000 (1/240), carico_Pcore/m031 (1/240), carico_Pcore/m037 (0/240), carico_Pcore/m042 (1/240)

