# Campagna: campagna_2026-10-06

## Capacita' a un core: lo stesso nodo su core diversi

Nodo: P-core a 3496 MHz misurati; E-core a 3493 MHz misurati; LP E-core a 2498 MHz misurati. Generatore e uscita su P-core in tutte le righe.

| pipeline | P-core Mpps | P-core ns CPU | P-core cicli/pk | P-core istr/pk | P-core IPC | E-core Mpps | E-core ns CPU | E-core cicli/pk | E-core istr/pk | E-core IPC | LP E-core Mpps | LP E-core ns CPU | LP E-core cicli/pk | LP E-core istr/pk | LP E-core IPC |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| rxonly | 19.47 | 41 | 161 | 384 | 2.40 | 12.78 | 78 | 263 | 368 | 1.40 | 4.11 | 176 | 468 | 398 | 0.90 |
| baseline | 15.27 | 66 | 225 | 606 | 2.70 | 9.39 | 106 | 360 | 607 | 1.70 | 3.29 | 283 | 733 | 620 | 0.80 |
| P1 | 8.56 | 117 | 402 | 1220 | 3.00 | 6.35 | 158 | 540 | 1223 | 2.30 | 3.10 | 322 | 804 | 1225 | 1.50 |
| P1.5 | 8.04 | 124 | 432 | 1426 | 3.30 | 5.84 | 171 | 587 | 1430 | 2.40 | 2.91 | 343 | 857 | 1432 | 1.70 |
| P2 | 3.45 | 290 | 1013 | 4556 | 4.50 | 2.83 | 354 | 1224 | 4556 | 3.70 | 1.57 | 636 | 1587 | 4557 | 2.90 |
| P3 | 2.36 | 425 | 1483 | 6573 | 4.40 | 1.94 | 515 | 1785 | 6573 | 3.70 | 1.10 | 908 | 2266 | 6576 | 2.90 |

Rapporto con il P-core (capacita', cicli per pacchetto, istruzioni per pacchetto, IPC):

| pipeline | E-core/P Mpps | E-core/P cicli | E-core/P istr | E-core/P IPC | LP E-core/P Mpps | LP E-core/P cicli | LP E-core/P istr | LP E-core/P IPC |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| rxonly | 0.66 | 1.63 | 0.96 | 0.58 | 0.21 | 2.90 | 1.04 | 0.38 |
| baseline | 0.61 | 1.60 | 1.00 | 0.63 | 0.22 | 3.25 | 1.02 | 0.30 |
| P1 | 0.74 | 1.34 | 1.00 | 0.77 | 0.36 | 2.00 | 1.00 | 0.50 |
| P1.5 | 0.73 | 1.36 | 1.00 | 0.73 | 0.36 | 1.98 | 1.00 | 0.52 |
| P2 | 0.82 | 1.21 | 1.00 | 0.82 | 0.46 | 1.57 | 1.00 | 0.64 |
| P3 | 0.82 | 1.20 | 1.00 | 0.84 | 0.47 | 1.53 | 1.00 | 0.66 |

Contatori per pacchetto (LLC = mancate dell'ultimo livello, GHz = cicli/(durata x core), uscita = cicli del core d'uscita per pacchetto):

| core | pipeline | LLC/pk | br-miss/pk | GHz | nodo % | uscita cicli/pk | respinti % |
|---|---:|---:|---:|---:|---:|---:|---:|
| P-core | rxonly | 0.000 | 0.100 | 3.10 | 79 | 0 | 1.3 |
| P-core | baseline | 0.000 | 0.100 | 3.50 | 100 | 222 | 0.4 |
| P-core | P1 | 0.000 | 0.100 | 3.50 | 100 | 362 | 25.6 |
| P-core | P1.5 | 0.000 | 0.100 | 3.50 | 100 | 398 | 29.4 |
| P-core | P2 | 0.000 | 0.200 | 3.50 | 100 | 726 | 70.5 |
| P-core | P3 | 0.000 | 0.200 | 3.50 | 100 | 872 | 81.3 |
| E-core | rxonly | 0.000 | 0.200 | 3.40 | 100 | 0 | 7.8 |
| E-core | baseline | 0.000 | 0.100 | 3.40 | 100 | 342 | 15.2 |
| E-core | P1 | 0.000 | 0.100 | 3.40 | 100 | 480 | 37.8 |
| E-core | P1.5 | 0.000 | 0.100 | 3.40 | 100 | 525 | 40.1 |
| E-core | P2 | 0.000 | 0.100 | 3.50 | 100 | 731 | 75.5 |
| E-core | P3 | 0.000 | 0.100 | 3.50 | 100 | 817 | 85.1 |
| LP E-core | rxonly | 3.400 | 0.100 | 1.90 | 72 | 1 | 0.5 |
| LP E-core | baseline | 14.000 | 0.100 | 2.40 | 93 | 527 | 1.6 |
| LP E-core | P1 | 18.100 | 0.100 | 2.50 | 100 | 647 | 51.1 |
| LP E-core | P1.5 | 18.500 | 0.100 | 2.50 | 100 | 657 | 51.9 |
| LP E-core | P2 | 19.300 | 0.100 | 2.50 | 100 | 844 | 78.6 |
| LP E-core | P3 | 16.100 | 0.200 | 2.50 | 100 | 907 | 86.8 |

## Due core del nodo

| core | pipeline | 1 core Mpps | 2 core Mpps | % del doppio | ns CPU per core | IPC | respinti % |
|---|---:|---:|---:|---:|---:|---:|---:|
| P-core | rxonly | 19.47 | 36.41 | 94 | 42 | 2.30 | 1.9 |
| P-core | baseline | 15.27 | 29.11 | 95 | 67 | 2.60 | 2.1 |
| P-core | P1 | 8.56 | 17.46 | 102 | 114 | 3.10 | 26.1 |
| P-core | P1.5 | 8.04 | 16.19 | 101 | 124 | 3.30 | 29.7 |
| P-core | P2 | 3.45 | 6.63 | 96 | 301 | 4.30 | 72.0 |
| P-core | P3 | 2.36 | 4.60 | 98 | 434 | 4.30 | 81.6 |
| E-core | rxonly | 12.78 | 29.85 | 117 | 67 | 1.60 | 6.1 |
| E-core | baseline | 9.39 | 19.09 | 102 | 105 | 1.70 | 15.8 |
| E-core | P1 | 6.35 | 12.74 | 100 | 157 | 2.30 | 37.2 |
| E-core | P1.5 | 5.84 | 11.71 | 100 | 171 | 2.40 | 41.0 |
| E-core | P2 | 2.83 | 5.60 | 99 | 357 | 3.70 | 75.6 |
| E-core | P3 | 1.94 | 3.84 | 99 | 521 | 3.70 | 85.5 |

## Saturazione al crescere del rate (bench_bitrate)

Ginocchio = rate chiesto piu' alto con perdita totale <= 0.1% (finestre limitate dal generatore escluse). Latenze end-to-end mediane, in µs.

| core | pipeline | ginocchio Mpps | max inoltrati Mpps | p50 a basso carico | p50 al massimo | IPC al massimo | collo |
|---|---:|---:|---:|---:|---:|---:|---:|
| P-core | rxonly | 12.0 | 11.87 | - | - | 2.04 | riferimento |
| P-core | baseline | 8.0 | 9.02 | 17 | 16 | 2.42 | banco: nodo non saturo |
| P-core | P1 | 8.0 | 8.66 | 17 | 34 | 3.15 | ingresso: programma eBPF |
| P-core | P1.5 | 8.0 | 8.17 | 17 | 35 | 3.45 | ingresso: programma eBPF |
| P-core | P2 | 3.0 | 3.45 | 18 | 84 | 4.55 | ingresso: programma eBPF |
| P-core | P3 | 2.0 | 2.37 | 19 | 120 | 4.49 | ingresso: programma eBPF |
| E-core | rxonly | 12.0 | 11.99 | - | - | 1.79 | riferimento |
| E-core | baseline | 9.0 | 9.34 | 12 | 29 | 1.78 | ingresso: programma eBPF |
| E-core | P1 | 6.0 | 6.24 | 13 | 45 | 2.31 | ingresso: programma eBPF |
| E-core | P1.5 | 5.0 | 5.81 | 13 | 49 | 2.49 | ingresso: programma eBPF |
| E-core | P2 | 2.5 | 2.81 | 14 | 103 | 3.73 | ingresso: programma eBPF |
| E-core | P3 | 1.5 | 1.93 | 16 | 148 | 3.69 | ingresso: programma eBPF |
| LP E-core | rxonly | 1.5 | 3.67 | - | - | 0.95 | riferimento |
| LP E-core | baseline | 3.0 | 4.09 | 13 | 66 | 1.08 | ingresso: programma eBPF |
| LP E-core | P1 | 2.5 | 2.94 | 13 | 91 | 1.52 | ingresso: programma eBPF |
| LP E-core | P1.5 | 2.5 | 2.90 | 13 | 52 | 1.73 | ingresso: programma eBPF |
| LP E-core | P2 | 1.5 | 1.66 | 14 | 162 | 3.06 | ingresso: programma eBPF |
| LP E-core | P3 | 1.0 | 1.18 | 15 | 258 | 3.14 | ingresso: programma eBPF |

## Tre marcature (build strumentata)

T2−T1 = la sola pipeline, T3−T2 = redirect + veth + ricezione (mediana dei minimi da 0,5 Mpps in su); T3−T1 al rate piu' basso = latenza minima arrivo → ripartenza. ns.

| core | pipeline | T2−T1 | T3−T2 | T3−T1 minimo |
|---|---:|---:|---:|---:|
| P-core | baseline | 26 | 206 | 221 |
| P-core | P1 | 60 | 207 | 259 |
| P-core | P1.5 | 69 | 208 | 274 |
| P-core | P2 | 216 | 218 | 442 |
| P-core | P3 | 331 | 222 | 609 |
| E-core | baseline | 28 | 240 | 282 |
| E-core | P1 | 72 | 243 | 329 |
| E-core | P1.5 | 84 | 240 | 346 |
| E-core | P2 | 266 | 253 | 555 |
| E-core | P3 | 434 | 256 | 727 |

## Per classe, P-core (ns di CPU, IPC fra parentesi)

| pipeline | classe 0 (FOR) | classe 1 (FOR) | classe 2 (FOR) | classe 3 (FOR) | classe 4 (FOR) | classe 5 (DRO) |
|---|---:|---:|---:|---:|---:|---:|
| baseline | 64 (2.70) | 66 (2.60) | 65 (2.70) | 64 (2.70) | 65 (2.70) | 66 (2.70) |
| P1 | 118 (3.00) | 118 (3.00) | 119 (2.90) | 120 (2.90) | 120 (2.90) | 166 (1.80) |
| P1.5 | 124 (3.30) | 126 (3.20) | 127 (3.20) | 126 (3.20) | 126 (3.20) | 176 (2.00) |
| P2 | 274 (4.50) | 245 (4.50) | 268 (4.50) | 262 (4.40) | 266 (4.50) | 304 (3.50) |
| P3 | 416 (4.50) | 418 (4.50) | 426 (4.40) | 421 (4.50) | 418 (4.50) | 467 (4.00) |

## Per taglia del frame, P-core (ns di CPU)

| pipeline | 64 B | 512 B | 1514 B |
|---|---:|---:|---:|
| rxonly | 40 | 41 | 40 |
| baseline | 65 | 66 | 66 |
| P1 | 118 | 120 | 119 |
| P1.5 | 127 | 126 | 127 |
| P2 | 286 | 284 | 287 |
| P3 | 419 | 419 | 418 |

## Assi parametrici sotto traffico (xdp_gen)

Per ogni punto: ns di CPU per pacchetto, poi istruzioni per pacchetto e IPC. La baseline (senza inferenza) e' nella colonna di riferimento.

### Larghezza: 65-v-v-7 — nodo su Ecore

ns di CPU per pacchetto:

| punto | baseline | P1 | P1.5 | P2 | P3 |
|---|---:|---:|---:|---:|---:|
| 2 | 105 | 142 | 155 | 340 | 496 |
| 4 | 106 | 156 | 170 | 359 | 519 |
| 6 | 106 | 168 | 181 | 372 | 555 |
| 8 | 105 | 187 | 199 | 394 | 588 |

istruzioni per pacchetto / IPC:

| punto | baseline | P1 | P1.5 | P2 | P3 |
|---|---:|---:|---:|---:|---:|
| 2 | 607 / 1.70 | 1050 / 2.20 | 1254 / 2.30 | 4295 / 3.70 | 6075 / 3.50 |
| 4 | 606 / 1.70 | 1212 / 2.30 | 1418 / 2.40 | 4558 / 3.70 | 6576 / 3.70 |
| 6 | 607 / 1.70 | 1422 / 2.50 | 1626 / 2.60 | 4823 / 3.70 | 7210 / 3.80 |
| 8 | 608 / 1.70 | 1747 / 2.70 | 1980 / 2.90 | 5081 / 3.70 | 7894 / 3.90 |

### Larghezza: 65-v-v-7 — nodo su Pcore

ns di CPU per pacchetto:

| punto | baseline | P1 | P1.5 | P2 | P3 |
|---|---:|---:|---:|---:|---:|
| 2 | 66 | 104 | 114 | 282 | 391 |
| 4 | 66 | 115 | 124 | 295 | 445 |
| 6 | 66 | 124 | 138 | 301 | 452 |
| 8 | 65 | 145 | 158 | 315 | 496 |

istruzioni per pacchetto / IPC:

| punto | baseline | P1 | P1.5 | P2 | P3 |
|---|---:|---:|---:|---:|---:|
| 2 | 606 / 2.70 | 1049 / 2.90 | 1252 / 3.10 | 4295 / 4.40 | 6074 / 4.50 |
| 4 | 606 / 2.70 | 1210 / 3.00 | 1415 / 3.30 | 4558 / 4.40 | 6576 / 4.20 |
| 6 | 606 / 2.60 | 1420 / 3.30 | 1622 / 3.40 | 4825 / 4.60 | 7211 / 4.60 |
| 8 | 606 / 2.70 | 1744 / 3.50 | 1978 / 3.60 | 5082 / 4.60 | 7895 / 4.60 |

### Profondita': 65-4×d-7 — nodo su Ecore

ns di CPU per pacchetto:

| punto | baseline | P1 | P1.5 | P2 | P3 |
|---|---:|---:|---:|---:|---:|
| 1 | 107 | 148 | 162 | 328 | 447 |
| 2 | 106 | 156 | 170 | 355 | 517 |
| 3 | 105 | 160 | 176 | 394 | 591 |
| 4 | 106 | 166 | 182 | 403 | 665 |
| 5 | 106 | 170 | 183 | 442 | 730 |
| 6 | 106 | 176 | 189 | 470 | 801 |

istruzioni per pacchetto / IPC:

| punto | baseline | P1 | P1.5 | P2 | P3 |
|---|---:|---:|---:|---:|---:|
| 1 | 607 / 1.70 | 1150 / 2.30 | 1361 / 2.40 | 4094 / 3.60 | 5489 / 3.60 |
| 2 | 607 / 1.70 | 1212 / 2.30 | 1418 / 2.40 | 4558 / 3.70 | 6575 / 3.70 |
| 3 | 607 / 1.70 | 1267 / 2.30 | 1478 / 2.40 | 5157 / 3.80 | 7662 / 3.80 |
| 4 | 608 / 1.70 | 1334 / 2.30 | 1541 / 2.50 | 5450 / 3.90 | 8758 / 3.80 |
| 5 | 607 / 1.70 | 1374 / 2.40 | 1577 / 2.50 | 6059 / 4.00 | 9853 / 3.90 |
| 6 | 607 / 1.70 | 1441 / 2.40 | 1642 / 2.50 | 6550 / 4.00 | 10954 / 4.00 |

### Profondita': 65-4×d-7 — nodo su Pcore

ns di CPU per pacchetto:

| punto | baseline | P1 | P1.5 | P2 | P3 |
|---|---:|---:|---:|---:|---:|
| 1 | 66 | 113 | 121 | 264 | 351 |
| 2 | 66 | 116 | 128 | 287 | 421 |
| 3 | 66 | 119 | 131 | 329 | 486 |
| 4 | 66 | 124 | 132 | 344 | 545 |
| 5 | 66 | 125 | 134 | 368 | 595 |
| 6 | 64 | 132 | 138 | 396 | 652 |

istruzioni per pacchetto / IPC:

| punto | baseline | P1 | P1.5 | P2 | P3 |
|---|---:|---:|---:|---:|---:|
| 1 | 606 / 2.70 | 1149 / 2.90 | 1358 / 3.20 | 4092 / 4.40 | 5488 / 4.50 |
| 2 | 606 / 2.60 | 1210 / 3.00 | 1416 / 3.20 | 4558 / 4.60 | 6576 / 4.50 |
| 3 | 606 / 2.70 | 1264 / 3.00 | 1476 / 3.20 | 5157 / 4.50 | 7663 / 4.50 |
| 4 | 605 / 2.60 | 1330 / 3.10 | 1539 / 3.30 | 5450 / 4.50 | 8759 / 4.60 |
| 5 | 606 / 2.70 | 1372 / 3.10 | 1575 / 3.40 | 6059 / 4.70 | 9856 / 4.70 |
| 6 | 606 / 2.70 | 1439 / 3.10 | 1640 / 3.40 | 6550 / 4.70 | 10952 / 4.80 |

### A parita' di pesi (~592): da 1 a 5 strati — nodo su Ecore

ns di CPU per pacchetto:

| punto | baseline | P1 | P1.5 | P2 | P3 |
|---|---:|---:|---:|---:|---:|
| 1 | 105 | 173 | 183 | 340 | 476 |
| 2 | 106 | 169 | 185 | 365 | 537 |
| 3 | 106 | 172 | 186 | 379 | 595 |
| 4 | 106 | 182 | 195 | 439 | 705 |
| 5 | 105 | 183 | 194 | 446 | 740 |

istruzioni per pacchetto / IPC:

| punto | baseline | P1 | P1.5 | P2 | P3 |
|---|---:|---:|---:|---:|---:|
| 1 | 607 / 1.70 | 1466 / 2.50 | 1680 / 2.70 | 4163 / 3.60 | 5951 / 3.60 |
| 2 | 607 / 1.70 | 1460 / 2.50 | 1657 / 2.60 | 4622 / 3.70 | 6858 / 3.70 |
| 3 | 607 / 1.70 | 1428 / 2.40 | 1640 / 2.60 | 4996 / 3.80 | 7536 / 3.70 |
| 4 | 607 / 1.70 | 1605 / 2.60 | 1816 / 2.70 | 5968 / 3.90 | 9588 / 3.90 |
| 5 | 607 / 1.70 | 1553 / 2.50 | 1764 / 2.60 | 6116 / 4.00 | 10084 / 3.90 |

### A parita' di pesi (~592): da 1 a 5 strati — nodo su Pcore

ns di CPU per pacchetto:

| punto | baseline | P1 | P1.5 | P2 | P3 |
|---|---:|---:|---:|---:|---:|
| 1 | 66 | 128 | 137 | 276 | 380 |
| 2 | 66 | 125 | 141 | 299 | 433 |
| 3 | 66 | 130 | 144 | 318 | 480 |
| 4 | 66 | 135 | 148 | 368 | 581 |
| 5 | 66 | 135 | 147 | 373 | 607 |

istruzioni per pacchetto / IPC:

| punto | baseline | P1 | P1.5 | P2 | P3 |
|---|---:|---:|---:|---:|---:|
| 1 | 606 / 2.60 | 1464 / 3.30 | 1678 / 3.50 | 4163 / 4.30 | 5951 / 4.50 |
| 2 | 606 / 2.60 | 1458 / 3.30 | 1654 / 3.40 | 4622 / 4.40 | 6859 / 4.50 |
| 3 | 606 / 2.70 | 1425 / 3.10 | 1637 / 3.30 | 4996 / 4.50 | 7538 / 4.50 |
| 4 | 606 / 2.60 | 1602 / 3.40 | 1814 / 3.50 | 5968 / 4.60 | 9589 / 4.70 |
| 5 | 606 / 2.60 | 1550 / 3.30 | 1761 / 3.40 | 6118 / 4.70 | 10082 / 4.80 |

### Sparsita': % di pesi a zero, 65-4-4-7 — nodo su Ecore

ns di CPU per pacchetto:

| punto | baseline | P1 | P1.5 | P2 | P3 |
|---|---:|---:|---:|---:|---:|
| 0 | 106 | 154 | 168 | 357 | 517 |
| 50 | 107 | 143 | 157 | 354 | 523 |
| 90 | 106 | 132 | 143 | 355 | 514 |

istruzioni per pacchetto / IPC:

| punto | baseline | P1 | P1.5 | P2 | P3 |
|---|---:|---:|---:|---:|---:|
| 0 | 607 / 1.70 | 1212 / 2.30 | 1407 / 2.40 | 4556 / 3.70 | 6571 / 3.70 |
| 50 | 607 / 1.70 | 1081 / 2.20 | 1298 / 2.40 | 4554 / 3.70 | 6572 / 3.60 |
| 90 | 607 / 1.70 | 941 / 2.10 | 1137 / 2.30 | 4557 / 3.70 | 6575 / 3.70 |

### Sparsita': % di pesi a zero, 65-4-4-7 — nodo su Pcore

ns di CPU per pacchetto:

| punto | baseline | P1 | P1.5 | P2 | P3 |
|---|---:|---:|---:|---:|---:|
| 0 | 66 | 113 | 120 | 295 | 420 |
| 50 | 66 | 104 | 112 | 298 | 424 |
| 90 | 64 | 95 | 106 | 298 | 423 |

istruzioni per pacchetto / IPC:

| punto | baseline | P1 | P1.5 | P2 | P3 |
|---|---:|---:|---:|---:|---:|
| 0 | 606 / 2.70 | 1210 / 3.10 | 1403 / 3.40 | 4556 / 4.40 | 6573 / 4.50 |
| 50 | 606 / 2.60 | 1080 / 3.00 | 1296 / 3.30 | 4555 / 4.40 | 6571 / 4.40 |
| 90 | 606 / 2.70 | 939 / 2.80 | 1136 / 3.10 | 4558 / 4.40 | 6575 / 4.40 |

## Condizioni

| misura | data | DUT | MHz misurati | alimentazione | contatori hw |
|---|---:|---:|---:|---:|---:|
| assi_Ecore/depth_1 | 2026-10-06 17:07:39 | cpu12 (E, modulo L2 con 13-15) | 3488 | BATTERIA | instructions, cycles, cache-misses, bran |
| assi_Ecore/depth_2 | 2026-10-06 17:08:08 | cpu12 (E, modulo L2 con 13-15) | 3479 | BATTERIA | instructions, cycles, cache-misses, bran |
| assi_Ecore/depth_3 | 2026-10-06 17:08:38 | cpu12 (E, modulo L2 con 13-15) | 3482 | BATTERIA | instructions, cycles, cache-misses, bran |
| assi_Ecore/depth_4 | 2026-10-06 17:40:15 | cpu12 (E, modulo L2 con 13-15) | 3482 | BATTERIA | instructions, cycles, cache-misses, bran |
| assi_Ecore/depth_5 | 2026-10-06 17:09:20 | cpu12 (E, modulo L2 con 13-15) | 3488 | BATTERIA | instructions, cycles, cache-misses, bran |
| assi_Ecore/depth_6 | 2026-10-06 17:09:49 | cpu12 (E, modulo L2 con 13-15) | 3483 | BATTERIA | instructions, cycles, cache-misses, bran |
| assi_Ecore/isoparam_1 | 2026-10-06 17:10:18 | cpu12 (E, modulo L2 con 13-15) | 3493 | BATTERIA | instructions, cycles, cache-misses, bran |
| assi_Ecore/isoparam_2 | 2026-10-06 17:10:47 | cpu12 (E, modulo L2 con 13-15) | 3483 | BATTERIA | instructions, cycles, cache-misses, bran |
| assi_Ecore/isoparam_3 | 2026-10-06 17:40:44 | cpu12 (E, modulo L2 con 13-15) | 3492 | BATTERIA | instructions, cycles, cache-misses, bran |
| assi_Ecore/isoparam_4 | 2026-10-06 17:11:30 | cpu12 (E, modulo L2 con 13-15) | 3487 | BATTERIA | instructions, cycles, cache-misses, bran |
| assi_Ecore/isoparam_5 | 2026-10-06 17:11:59 | cpu12 (E, modulo L2 con 13-15) | 3492 | BATTERIA | instructions, cycles, cache-misses, bran |
| assi_Ecore/sparsity_0 | 2026-10-06 17:12:28 | cpu12 (E, modulo L2 con 13-15) | 3482 | BATTERIA | instructions, cycles, cache-misses, bran |
| assi_Ecore/sparsity_50 | 2026-10-06 17:12:58 | cpu12 (E, modulo L2 con 13-15) | 3481 | BATTERIA | instructions, cycles, cache-misses, bran |
| assi_Ecore/sparsity_90 | 2026-10-06 17:13:27 | cpu12 (E, modulo L2 con 13-15) | 3482 | BATTERIA | instructions, cycles, cache-misses, bran |
| assi_Ecore/width_2 | 2026-10-06 17:05:59 | cpu12 (E, modulo L2 con 13-15) | 3490 | BATTERIA | instructions, cycles, cache-misses, bran |
| assi_Ecore/width_4 | 2026-10-06 17:06:28 | cpu12 (E, modulo L2 con 13-15) | 3485 | BATTERIA | instructions, cycles, cache-misses, bran |
| assi_Ecore/width_6 | 2026-10-06 17:39:45 | cpu12 (E, modulo L2 con 13-15) | 3490 | BATTERIA | instructions, cycles, cache-misses, bran |
| assi_Ecore/width_8 | 2026-10-06 17:07:10 | cpu12 (E, modulo L2 con 13-15) | 3490 | BATTERIA | instructions, cycles, cache-misses, bran |
| assi_Pcore/depth_1 | 2026-10-06 16:59:42 | cpu6 (P, fratello 7) | 3494 | rete (AC) | instructions, cycles, cache-misses, bran |
| assi_Pcore/depth_2 | 2026-10-06 17:00:11 | cpu6 (P, fratello 7) | 3503 | rete (AC) | instructions, cycles, cache-misses, bran |
| assi_Pcore/depth_3 | 2026-10-06 17:00:40 | cpu6 (P, fratello 7) | 3493 | BATTERIA | instructions, cycles, cache-misses, bran |
| assi_Pcore/depth_4 | 2026-10-06 17:38:47 | cpu6 (P, fratello 7) | 3489 | BATTERIA | instructions, cycles, cache-misses, bran |
| assi_Pcore/depth_5 | 2026-10-06 17:01:23 | cpu6 (P, fratello 7) | 3486 | BATTERIA | instructions, cycles, cache-misses, bran |
| assi_Pcore/depth_6 | 2026-10-06 17:01:52 | cpu6 (P, fratello 7) | 3504 | BATTERIA | instructions, cycles, cache-misses, bran |
| assi_Pcore/isoparam_1 | 2026-10-06 17:02:21 | cpu6 (P, fratello 7) | 3496 | BATTERIA | instructions, cycles, cache-misses, bran |
| assi_Pcore/isoparam_2 | 2026-10-06 17:02:51 | cpu6 (P, fratello 7) | 3494 | BATTERIA | instructions, cycles, cache-misses, bran |
| assi_Pcore/isoparam_3 | 2026-10-06 17:39:16 | cpu6 (P, fratello 7) | 3490 | BATTERIA | instructions, cycles, cache-misses, bran |
| assi_Pcore/isoparam_4 | 2026-10-06 17:03:33 | cpu6 (P, fratello 7) | 3493 | BATTERIA | instructions, cycles, cache-misses, bran |
| assi_Pcore/isoparam_5 | 2026-10-06 17:04:03 | cpu6 (P, fratello 7) | 3489 | BATTERIA | instructions, cycles, cache-misses, bran |
| assi_Pcore/sparsity_0 | 2026-10-06 17:04:32 | cpu6 (P, fratello 7) | 3489 | BATTERIA | instructions, cycles, cache-misses, bran |
| assi_Pcore/sparsity_50 | 2026-10-06 17:05:01 | cpu6 (P, fratello 7) | 3501 | BATTERIA | instructions, cycles, cache-misses, bran |
| assi_Pcore/sparsity_90 | 2026-10-06 17:05:30 | cpu6 (P, fratello 7) | 3489 | BATTERIA | instructions, cycles, cache-misses, bran |
| assi_Pcore/width_2 | 2026-10-06 16:58:01 | cpu6 (P, fratello 7) | 3490 | rete (AC) | instructions, cycles, cache-misses, bran |
| assi_Pcore/width_4 | 2026-10-06 16:58:30 | cpu6 (P, fratello 7) | 3496 | rete (AC) | instructions, cycles, cache-misses, bran |
| assi_Pcore/width_6 | 2026-10-06 17:38:17 | cpu6 (P, fratello 7) | 3493 | BATTERIA | instructions, cycles, cache-misses, bran |
| assi_Pcore/width_8 | 2026-10-06 16:59:13 | cpu6 (P, fratello 7) | 3504 | rete (AC) | instructions, cycles, cache-misses, bran |
| ecore/bitrate | 2026-10-06 16:54:14 | cpu12 (E, modulo L2 con 13-15) | 3475 | rete (AC) | instructions, cycles, cache-misses, bran |
| ecore/compare | 2026-10-06 16:47:42 | cpu12 (E, modulo L2 con 13-15) | 3493 | rete (AC) | instructions, cycles, cache-misses, bran |
| ecore/cores2 | 2026-10-06 16:48:16 | cpu12 (E, modulo L2 con 13-15), cpu16 (E, modulo L2 con 17-19) | 3482 | rete (AC) | instructions, cycles, cache-misses, bran |
| ecore/rates | 2026-10-06 16:49:25 | cpu12 (E, modulo L2 con 13-15) | 3472 | rete (AC) | instructions, cycles, cache-misses, bran |
| lpe/bitrate | 2026-10-06 16:57:29 | cpu20 (LPE, modulo L2 con 21) | 2501 | rete (AC) | instructions, cycles, cache-misses, bran |
| lpe/compare | 2026-10-06 16:54:51 | cpu20 (LPE, modulo L2 con 21) | 2498 | rete (AC) | instructions, cycles, cache-misses, bran |
| pcore/bitrate | 2026-10-06 16:47:05 | cpu6 (P, fratello 7) | 3497 | rete (AC) | instructions, cycles, cache-misses, bran |
| pcore/compare | 2026-10-06 16:36:00 | cpu6 (P, fratello 7) | 3496 | rete (AC) | instructions, cycles, cache-misses, bran |
| pcore/cores2 | 2026-10-06 16:36:36 | cpu6 (P, fratello 7), cpu8 (P, fratello 9) | 3503 | rete (AC) | instructions, cycles, cache-misses, bran |
| pcore/frames | 2026-10-06 16:41:07 | cpu6 (P, fratello 7) | 3498 | rete (AC) | instructions, cycles, cache-misses, bran |
| pcore/per_class | 2026-10-06 16:39:47 | cpu6 (P, fratello 7) | 3497 | rete (AC) | instructions, cycles, cache-misses, bran |
| pcore/rates | 2026-10-06 16:42:16 | cpu6 (P, fratello 7) | 3494 | rete (AC) | instructions, cycles, cache-misses, bran |

