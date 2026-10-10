# Campagna: campagna_2026-10-10

## La sola rete neurale del checkpoint (T2−T1, xdp_gen)

ns di rete neurale per pacchetto, minimo / media, baseline sottratta (stessi rate degli assi):

| core | P1 | P1.5 | P2 | P3 |
|---|---:|---:|---:|---:|
| P-core | 36 / 38 | 44 / 57 | 198 / 262 | 320 / 365 |
| E-core | 44 / 66 | 56 / 78 | 238 / 250 | 401 / 439 |

## Costo per MAC eseguita sotto traffico — nodo su P-core

Media T2−T1 meno la baseline contro le MAC eseguite per pacchetto (una one-hot conta h1), su ingressi densi, ingressi one-hot, larghezza e profondita'. r² con le MAC contate dalla forma per confronto.

| pipeline | punti | ns per MAC | r² (eseguite) | r² (dalla forma) |
|---|---:|---:|---:|---:|
| P1 | 17 | 0.34 | 0.94 | 0.02 |
| P1.5 | 17 | 0.25 | 0.88 | 0.11 |
| P2 | 17 | 0.03 | 0.00 | 0.05 |
| P3 | 17 | 0.62 | 0.24 | 0.02 |

## Costo per MAC eseguita sotto traffico — nodo su E-core

Media T2−T1 meno la baseline contro le MAC eseguite per pacchetto (una one-hot conta h1), su ingressi densi, ingressi one-hot, larghezza e profondita'. r² con le MAC contate dalla forma per confronto.

| pipeline | punti | ns per MAC | r² (eseguite) | r² (dalla forma) |
|---|---:|---:|---:|---:|
| P1 | 17 | 0.24 | 0.65 | 0.00 |
| P1.5 | 17 | 0.14 | 0.45 | 0.14 |
| P2 | 17 | 0.11 | 0.02 | 0.04 |
| P3 | 17 | 0.60 | 0.16 | 0.02 |

## Assi parametrici sotto traffico (xdp_gen)

Per ogni punto: ns di CPU per pacchetto, poi istruzioni per pacchetto e IPC. La baseline (senza inferenza) e' nella colonna di riferimento.

### Larghezza: 65-v-v-7 — nodo su Ecore

ns di CPU per pacchetto:

| punto | baseline | P1 | P1.5 | P2 | P3 |
|---|---:|---:|---:|---:|---:|
| 2 | 105 | 142 | 155 | 352 | 516 |
| 4 | 105 | 154 | 168 | 362 | 537 |
| 6 | 105 | 166 | 180 | 384 | 574 |
| 8 | 106 | 186 | 199 | 395 | 600 |

istruzioni per pacchetto / IPC:

| punto | baseline | P1 | P1.5 | P2 | P3 |
|---|---:|---:|---:|---:|---:|
| 2 | 607 / 1.70 | 1050 / 2.20 | 1254 / 2.30 | 4295 / 3.70 | 6073 / 3.50 |
| 4 | 608 / 1.70 | 1212 / 2.30 | 1418 / 2.40 | 4558 / 3.70 | 6574 / 3.70 |
| 6 | 607 / 1.70 | 1422 / 2.50 | 1625 / 2.60 | 4823 / 3.70 | 7209 / 3.70 |
| 8 | 607 / 1.70 | 1747 / 2.70 | 1979 / 2.90 | 5082 / 3.70 | 7893 / 3.80 |

T2−T1, la sola pipeline (build strumentata), minimo / media in ns, mediana fra giri e rate:

| punto | baseline | P1 | P1.5 | P2 | P3 |
|---|---:|---:|---:|---:|---:|
| 2 | 28 / 55 | 62 / 110 | 72 / 109 | 252 / 292 | 408 / 464 |
| 4 | 28 / 54 | 71 / 107 | 84 / 135 | 268 / 325 | 434 / 486 |
| 6 | 28 / 54 | 82 / 118 | 96 / 146 | 286 / 342 | 468 / 528 |
| 8 | 27 / 54 | 102 / 154 | 115 / 156 | 304 / 372 | 502 / 578 |

### Larghezza: 65-v-v-7 — nodo su Pcore

ns di CPU per pacchetto:

| punto | baseline | P1 | P1.5 | P2 | P3 |
|---|---:|---:|---:|---:|---:|
| 2 | 66 | 103 | 110 | 281 | 400 |
| 4 | 66 | 116 | 123 | 301 | 436 |
| 6 | 66 | 123 | 137 | 312 | 455 |
| 8 | 66 | 142 | 160 | 314 | 497 |

istruzioni per pacchetto / IPC:

| punto | baseline | P1 | P1.5 | P2 | P3 |
|---|---:|---:|---:|---:|---:|
| 2 | 606 / 2.60 | 1049 / 2.90 | 1252 / 3.30 | 4294 / 4.40 | 6074 / 4.30 |
| 4 | 606 / 2.70 | 1210 / 3.00 | 1416 / 3.30 | 4558 / 4.30 | 6575 / 4.30 |
| 6 | 606 / 2.70 | 1419 / 3.30 | 1623 / 3.40 | 4823 / 4.40 | 7210 / 4.50 |
| 8 | 606 / 2.60 | 1744 / 3.50 | 1978 / 3.50 | 5083 / 4.60 | 7894 / 4.50 |

T2−T1, la sola pipeline (build strumentata), minimo / media in ns, mediana fra giri e rate:

| punto | baseline | P1 | P1.5 | P2 | P3 |
|---|---:|---:|---:|---:|---:|
| 2 | 27 / 54 | 51 / 78 | 58 / 99 | 212 / 290 | 314 / 416 |
| 4 | 26 / 55 | 59 / 95 | 68 / 113 | 222 / 288 | 336 / 418 |
| 6 | 27 / 56 | 70 / 116 | 80 / 135 | 237 / 303 | 366 / 449 |
| 8 | 27 / 55 | 88 / 134 | 98 / 152 | 248 / 330 | 412 / 512 |

### Profondita': 65-4×d-7 — nodo su Ecore

ns di CPU per pacchetto:

| punto | baseline | P1 | P1.5 | P2 | P3 |
|---|---:|---:|---:|---:|---:|
| 1 | 105 | 149 | 164 | 327 | 450 |
| 2 | 106 | 156 | 170 | 357 | 522 |
| 3 | 106 | 163 | 177 | 392 | 594 |
| 4 | 104 | 166 | 181 | 403 | 661 |
| 5 | 104 | 170 | 183 | 444 | 741 |
| 6 | 105 | 176 | 189 | 470 | 810 |

istruzioni per pacchetto / IPC:

| punto | baseline | P1 | P1.5 | P2 | P3 |
|---|---:|---:|---:|---:|---:|
| 1 | 608 / 1.70 | 1151 / 2.20 | 1361 / 2.40 | 4094 / 3.60 | 5488 / 3.50 |
| 2 | 607 / 1.70 | 1212 / 2.30 | 1418 / 2.40 | 4557 / 3.70 | 6576 / 3.60 |
| 3 | 607 / 1.70 | 1267 / 2.30 | 1478 / 2.40 | 5156 / 3.80 | 7662 / 3.70 |
| 4 | 607 / 1.70 | 1333 / 2.30 | 1541 / 2.50 | 5450 / 3.90 | 8758 / 3.80 |
| 5 | 607 / 1.70 | 1374 / 2.30 | 1577 / 2.50 | 6058 / 3.90 | 9853 / 3.80 |
| 6 | 607 / 1.70 | 1442 / 2.40 | 1642 / 2.50 | 6549 / 4.00 | 10952 / 3.90 |

T2−T1, la sola pipeline (build strumentata), minimo / media in ns, mediana fra giri e rate:

| punto | baseline | P1 | P1.5 | P2 | P3 |
|---|---:|---:|---:|---:|---:|
| 1 | 28 / 56 | 66 / 114 | 83 / 124 | 240 / 286 | 368 / 424 |
| 2 | 28 / 56 | 70 / 104 | 86 / 134 | 268 / 336 | 432 / 488 |
| 3 | 28 / 54 | 78 / 128 | 89 / 133 | 306 / 376 | 506 / 569 |
| 4 | 28 / 55 | 84 / 131 | 97 / 146 | 318 / 364 | 571 / 628 |
| 5 | 28 / 54 | 86 / 132 | 100 / 146 | 354 / 412 | 653 / 710 |
| 6 | 28 / 57 | 94 / 144 | 107 / 156 | 384 / 432 | 716 / 775 |

### Profondita': 65-4×d-7 — nodo su Pcore

ns di CPU per pacchetto:

| punto | baseline | P1 | P1.5 | P2 | P3 |
|---|---:|---:|---:|---:|---:|
| 1 | 68 | 110 | 117 | 272 | 360 |
| 2 | 64 | 115 | 123 | 300 | 433 |
| 3 | 66 | 118 | 126 | 332 | 491 |
| 4 | 67 | 123 | 132 | 341 | 537 |
| 5 | 67 | 126 | 134 | 371 | 597 |
| 6 | 68 | 131 | 138 | 396 | 648 |

istruzioni per pacchetto / IPC:

| punto | baseline | P1 | P1.5 | P2 | P3 |
|---|---:|---:|---:|---:|---:|
| 1 | 606 / 2.60 | 1148 / 3.00 | 1358 / 3.30 | 4093 / 4.30 | 5488 / 4.40 |
| 2 | 606 / 2.70 | 1210 / 3.00 | 1415 / 3.30 | 4558 / 4.40 | 6575 / 4.30 |
| 3 | 606 / 2.70 | 1264 / 3.10 | 1476 / 3.30 | 5156 / 4.40 | 7662 / 4.50 |
| 4 | 606 / 2.60 | 1331 / 3.10 | 1539 / 3.30 | 5450 / 4.60 | 8757 / 4.70 |
| 5 | 606 / 2.60 | 1372 / 3.10 | 1575 / 3.40 | 6059 / 4.70 | 9852 / 4.70 |
| 6 | 606 / 2.60 | 1439 / 3.20 | 1640 / 3.40 | 6550 / 4.70 | 10950 / 4.80 |

T2−T1, la sola pipeline (build strumentata), minimo / media in ns, mediana fra giri e rate:

| punto | baseline | P1 | P1.5 | P2 | P3 |
|---|---:|---:|---:|---:|---:|
| 1 | 27 / 54 | 54 / 94 | 62 / 114 | 208 / 268 | 290 / 376 |
| 2 | 26 / 56 | 60 / 102 | 68 / 112 | 222 / 309 | 338 / 405 |
| 3 | 27 / 54 | 64 / 110 | 72 / 117 | 254 / 318 | 402 / 491 |
| 4 | 26 / 56 | 68 / 112 | 78 / 130 | 264 / 322 | 434 / 564 |
| 5 | 26 / 54 | 71 / 116 | 80 / 128 | 298 / 378 | 487 / 614 |
| 6 | 27 / 53 | 76 / 112 | 86 / 137 | 318 / 410 | 534 / 662 |

### A parita' di pesi (~592): da 1 a 5 strati — nodo su Ecore

ns di CPU per pacchetto:

| punto | baseline | P1 | P1.5 | P2 | P3 |
|---|---:|---:|---:|---:|---:|
| 1 | 105 | 168 | 180 | 333 | 472 |
| 2 | 105 | 170 | 183 | 369 | 542 |
| 3 | 106 | 172 | 185 | 380 | 592 |
| 4 | 104 | 182 | 195 | 439 | 713 |
| 5 | 105 | 184 | 196 | 447 | 744 |

istruzioni per pacchetto / IPC:

| punto | baseline | P1 | P1.5 | P2 | P3 |
|---|---:|---:|---:|---:|---:|
| 1 | 608 / 1.70 | 1466 / 2.50 | 1680 / 2.70 | 4163 / 3.60 | 5950 / 3.60 |
| 2 | 608 / 1.70 | 1460 / 2.50 | 1658 / 2.60 | 4622 / 3.70 | 6858 / 3.70 |
| 3 | 607 / 1.70 | 1427 / 2.40 | 1640 / 2.60 | 4995 / 3.80 | 7536 / 3.70 |
| 4 | 607 / 1.70 | 1604 / 2.60 | 1816 / 2.70 | 5968 / 3.90 | 9588 / 3.90 |
| 5 | 607 / 1.70 | 1553 / 2.50 | 1764 / 2.60 | 6117 / 3.90 | 10083 / 3.90 |

T2−T1, la sola pipeline (build strumentata), minimo / media in ns, mediana fra giri e rate:

| punto | baseline | P1 | P1.5 | P2 | P3 |
|---|---:|---:|---:|---:|---:|
| 1 | 28 / 55 | 86 / 120 | 96 / 134 | 248 / 304 | 390 / 436 |
| 2 | 28 / 54 | 86 / 121 | 100 / 148 | 308 / 361 | 450 / 496 |
| 3 | 28 / 55 | 88 / 135 | 100 / 148 | 290 / 336 | 502 / 556 |
| 4 | 28 / 55 | 100 / 148 | 110 / 160 | 350 / 396 | 618 / 685 |
| 5 | 28 / 54 | 98 / 143 | 140 / 178 | 360 / 408 | 659 / 716 |

### A parita' di pesi (~592): da 1 a 5 strati — nodo su Pcore

ns di CPU per pacchetto:

| punto | baseline | P1 | P1.5 | P2 | P3 |
|---|---:|---:|---:|---:|---:|
| 1 | 66 | 127 | 137 | 282 | 387 |
| 2 | 66 | 126 | 140 | 302 | 441 |
| 3 | 67 | 126 | 144 | 315 | 486 |
| 4 | 66 | 137 | 151 | 362 | 571 |
| 5 | 66 | 137 | 150 | 370 | 603 |

istruzioni per pacchetto / IPC:

| punto | baseline | P1 | P1.5 | P2 | P3 |
|---|---:|---:|---:|---:|---:|
| 1 | 606 / 2.60 | 1464 / 3.30 | 1677 / 3.50 | 4163 / 4.20 | 5949 / 4.40 |
| 2 | 606 / 2.60 | 1458 / 3.30 | 1655 / 3.40 | 4622 / 4.40 | 6858 / 4.50 |
| 3 | 606 / 2.60 | 1425 / 3.20 | 1638 / 3.30 | 4996 / 4.50 | 7536 / 4.40 |
| 4 | 606 / 2.70 | 1602 / 3.40 | 1814 / 3.40 | 5968 / 4.70 | 9586 / 4.80 |
| 5 | 606 / 2.70 | 1550 / 3.20 | 1761 / 3.40 | 6118 / 4.70 | 10080 / 4.80 |

T2−T1, la sola pipeline (build strumentata), minimo / media in ns, mediana fra giri e rate:

| punto | baseline | P1 | P1.5 | P2 | P3 |
|---|---:|---:|---:|---:|---:|
| 1 | 27 / 53 | 72 / 107 | 80 / 124 | 205 / 285 | 308 / 381 |
| 2 | 27 / 56 | 73 / 128 | 83 / 135 | 226 / 290 | 352 / 446 |
| 3 | 26 / 56 | 78 / 116 | 86 / 144 | 248 / 314 | 382 / 486 |
| 4 | 27 / 54 | 81 / 130 | 93 / 140 | 292 / 390 | 474 / 593 |
| 5 | 26 / 53 | 82 / 128 | 92 / 144 | 300 / 372 | 498 / 627 |

### Sparsita': % di pesi a zero, 65-4-4-7 — nodo su Ecore

ns di CPU per pacchetto:

| punto | baseline | P1 | P1.5 | P2 | P3 |
|---|---:|---:|---:|---:|---:|
| 0 | 104 | 153 | 168 | 360 | 518 |
| 50 | 106 | 143 | 157 | 354 | 522 |
| 90 | 105 | 129 | 142 | 355 | 516 |

istruzioni per pacchetto / IPC:

| punto | baseline | P1 | P1.5 | P2 | P3 |
|---|---:|---:|---:|---:|---:|
| 0 | 608 / 1.70 | 1212 / 2.30 | 1406 / 2.40 | 4556 / 3.70 | 6572 / 3.70 |
| 50 | 608 / 1.70 | 1082 / 2.20 | 1298 / 2.40 | 4554 / 3.70 | 6572 / 3.60 |
| 90 | 607 / 1.70 | 940 / 2.10 | 1137 / 2.30 | 4558 / 3.70 | 6575 / 3.70 |

T2−T1, la sola pipeline (build strumentata), minimo / media in ns, mediana fra giri e rate:

| punto | baseline | P1 | P1.5 | P2 | P3 |
|---|---:|---:|---:|---:|---:|
| 0 | 28 / 56 | 70 / 106 | 84 / 131 | 271 / 327 | 436 / 496 |
| 50 | 28 / 54 | 60 / 93 | 73 / 104 | 266 / 309 | 432 / 480 |
| 90 | 28 / 56 | 48 / 98 | 59 / 96 | 266 / 320 | 430 / 498 |

### Sparsita': % di pesi a zero, 65-4-4-7 — nodo su Pcore

ns di CPU per pacchetto:

| punto | baseline | P1 | P1.5 | P2 | P3 |
|---|---:|---:|---:|---:|---:|
| 0 | 69 | 113 | 121 | 291 | 422 |
| 50 | 68 | 104 | 113 | 297 | 423 |
| 90 | 67 | 94 | 106 | 300 | 434 |

istruzioni per pacchetto / IPC:

| punto | baseline | P1 | P1.5 | P2 | P3 |
|---|---:|---:|---:|---:|---:|
| 0 | 606 / 2.50 | 1210 / 3.10 | 1403 / 3.30 | 4555 / 4.50 | 6572 / 4.50 |
| 50 | 606 / 2.60 | 1080 / 3.00 | 1295 / 3.30 | 4555 / 4.40 | 6572 / 4.40 |
| 90 | 606 / 2.60 | 940 / 2.90 | 1136 / 3.10 | 4557 / 4.30 | 6574 / 4.30 |

T2−T1, la sola pipeline (build strumentata), minimo / media in ns, mediana fra giri e rate:

| punto | baseline | P1 | P1.5 | P2 | P3 |
|---|---:|---:|---:|---:|---:|
| 0 | 27 / 54 | 58 / 97 | 68 / 112 | 224 / 315 | 350 / 435 |
| 50 | 27 / 54 | 48 / 88 | 58 / 102 | 222 / 328 | 338 / 441 |
| 90 | 27 / 56 | 42 / 78 | 50 / 92 | 221 / 279 | 342 / 420 |

### Nodi della rete: (13+n)-4-4-7 — nodo su Ecore

ns di CPU per pacchetto:

| punto | baseline | P1 | P1.5 | P2 | P3 |
|---|---:|---:|---:|---:|---:|
| 10 | 105 | 157 | 171 | 369 | 538 |
| 25 | 106 | 157 | 169 | 358 | 533 |
| 52 | 105 | 155 | 169 | 360 | 531 |
| 75 | 105 | 154 | 169 | 356 | 536 |
| 100 | 105 | 154 | 168 | 355 | 525 |

istruzioni per pacchetto / IPC:

| punto | baseline | P1 | P1.5 | P2 | P3 |
|---|---:|---:|---:|---:|---:|
| 10 | 607 / 1.70 | 1236 / 2.30 | 1435 / 2.40 | 4560 / 3.70 | 6576 / 3.60 |
| 25 | 607 / 1.70 | 1230 / 2.30 | 1416 / 2.40 | 4559 / 3.70 | 6576 / 3.60 |
| 52 | 607 / 1.70 | 1212 / 2.30 | 1419 / 2.40 | 4558 / 3.70 | 6574 / 3.70 |
| 75 | 608 / 1.70 | 1201 / 2.30 | 1411 / 2.40 | 4558 / 3.70 | 6575 / 3.60 |
| 100 | 607 / 1.70 | 1182 / 2.20 | 1402 / 2.40 | 4558 / 3.70 | 6573 / 3.60 |

T2−T1, la sola pipeline (build strumentata), minimo / media in ns, mediana fra giri e rate:

| punto | baseline | P1 | P1.5 | P2 | P3 |
|---|---:|---:|---:|---:|---:|
| 10 | 28 / 56 | 72 / 105 | 85 / 135 | 271 / 314 | 437 / 500 |
| 25 | 28 / 56 | 74 / 124 | 84 / 122 | 270 / 308 | 438 / 498 |
| 52 | 28 / 58 | 71 / 106 | 84 / 134 | 268 / 319 | 468 / 525 |
| 75 | 30 / 56 | 70 / 117 | 83 / 118 | 268 / 324 | 432 / 483 |
| 100 | 29 / 56 | 70 / 114 | 84 / 129 | 265 / 310 | 434 / 483 |

### Nodi della rete: (13+n)-4-4-7 — nodo su Pcore

ns di CPU per pacchetto:

| punto | baseline | P1 | P1.5 | P2 | P3 |
|---|---:|---:|---:|---:|---:|
| 10 | 66 | 116 | 125 | 288 | 417 |
| 25 | 66 | 118 | 123 | 304 | 417 |
| 52 | 65 | 114 | 123 | 300 | 432 |
| 75 | 65 | 113 | 120 | 296 | 429 |
| 100 | 66 | 111 | 121 | 298 | 428 |

istruzioni per pacchetto / IPC:

| punto | baseline | P1 | P1.5 | P2 | P3 |
|---|---:|---:|---:|---:|---:|
| 10 | 606 / 2.60 | 1233 / 3.10 | 1432 / 3.30 | 4560 / 4.50 | 6577 / 4.50 |
| 25 | 606 / 2.60 | 1227 / 3.00 | 1413 / 3.30 | 4559 / 4.30 | 6577 / 4.50 |
| 52 | 606 / 2.60 | 1210 / 3.00 | 1415 / 3.30 | 4558 / 4.30 | 6575 / 4.40 |
| 75 | 606 / 2.60 | 1199 / 3.00 | 1408 / 3.40 | 4558 / 4.40 | 6576 / 4.40 |
| 100 | 606 / 2.60 | 1180 / 3.10 | 1400 / 3.30 | 4557 / 4.40 | 6575 / 4.40 |

T2−T1, la sola pipeline (build strumentata), minimo / media in ns, mediana fra giri e rate:

| punto | baseline | P1 | P1.5 | P2 | P3 |
|---|---:|---:|---:|---:|---:|
| 10 | 27 / 54 | 62 / 96 | 70 / 112 | 224 / 296 | 340 / 449 |
| 25 | 26 / 54 | 60 / 102 | 70 / 112 | 224 / 312 | 340 / 422 |
| 52 | 26 / 56 | 60 / 100 | 68 / 102 | 224 / 284 | 341 / 438 |
| 75 | 27 / 54 | 58 / 94 | 68 / 112 | 224 / 285 | 336 / 420 |
| 100 | 26 / 54 | 56 / 90 | 64 / 106 | 224 / 309 | 338 / 416 |

### Ingressi densi: n-8-8-7, ogni colonna moltiplicata — nodo su Ecore

ns di CPU per pacchetto:

| punto | baseline | P1 | P1.5 | P2 | P3 |
|---|---:|---:|---:|---:|---:|
| 5 | 106 | 170 | 169 | 350 | 557 |
| 9 | 106 | 171 | 171 | 366 | 586 |
| 13 | 105 | 188 | 190 | 388 | 619 |
| 17 | 104 | 197 | 196 | 401 | 653 |

istruzioni per pacchetto / IPC:

| punto | baseline | P1 | P1.5 | P2 | P3 |
|---|---:|---:|---:|---:|---:|
| 5 | 607 / 1.70 | 1484 / 2.60 | 1484 / 2.60 | 4265 / 3.50 | 7371 / 3.80 |
| 9 | 607 / 1.70 | 1566 / 2.70 | 1566 / 2.70 | 4561 / 3.60 | 7880 / 3.90 |
| 13 | 607 / 1.70 | 1773 / 2.70 | 1772 / 2.70 | 4851 / 3.60 | 8385 / 3.90 |
| 17 | 607 / 1.70 | 1860 / 2.80 | 1861 / 2.80 | 5145 / 3.70 | 8892 / 4.00 |

T2−T1, la sola pipeline (build strumentata), minimo / media in ns, mediana fra giri e rate:

| punto | baseline | P1 | P1.5 | P2 | P3 |
|---|---:|---:|---:|---:|---:|
| 5 | 28 / 55 | 89 / 138 | 87 / 137 | 260 / 308 | 469 / 530 |
| 9 | 28 / 56 | 90 / 140 | 93 / 141 | 277 / 324 | 500 / 562 |
| 13 | 27 / 54 | 106 / 148 | 106 / 145 | 294 / 342 | 527 / 583 |
| 17 | 28 / 56 | 111 / 154 | 110 / 151 | 312 / 358 | 556 / 620 |

### Ingressi densi: n-8-8-7, ogni colonna moltiplicata — nodo su Pcore

ns di CPU per pacchetto:

| punto | baseline | P1 | P1.5 | P2 | P3 |
|---|---:|---:|---:|---:|---:|
| 5 | 66 | 140 | 140 | 279 | 482 |
| 9 | 66 | 133 | 134 | 299 | 510 |
| 13 | 66 | 143 | 142 | 310 | 542 |
| 17 | 66 | 152 | 153 | 319 | 555 |

istruzioni per pacchetto / IPC:

| punto | baseline | P1 | P1.5 | P2 | P3 |
|---|---:|---:|---:|---:|---:|
| 5 | 606 / 2.60 | 1481 / 3.00 | 1481 / 3.00 | 4264 / 4.40 | 7372 / 4.40 |
| 9 | 606 / 2.60 | 1564 / 3.40 | 1564 / 3.30 | 4560 / 4.40 | 7880 / 4.40 |
| 13 | 606 / 2.60 | 1770 / 3.50 | 1770 / 3.60 | 4851 / 4.50 | 8386 / 4.40 |
| 17 | 606 / 2.60 | 1858 / 3.50 | 1860 / 3.50 | 5146 / 4.60 | 8893 / 4.60 |

T2−T1, la sola pipeline (build strumentata), minimo / media in ns, mediana fra giri e rate:

| punto | baseline | P1 | P1.5 | P2 | P3 |
|---|---:|---:|---:|---:|---:|
| 5 | 27 / 56 | 78 / 138 | 79 / 130 | 209 / 270 | 384 / 484 |
| 9 | 27 / 55 | 80 / 130 | 80 / 138 | 227 / 275 | 406 / 505 |
| 13 | 26 / 56 | 95 / 155 | 94 / 144 | 238 / 300 | 434 / 522 |
| 17 | 26 / 55 | 100 / 154 | 100 / 164 | 250 / 323 | 460 / 546 |

### Ingressi one-hot: n-8-8-7, la larghezza in una one-hot — nodo su Ecore

ns di CPU per pacchetto:

| punto | baseline | P1 | P1.5 | P2 | P3 |
|---|---:|---:|---:|---:|---:|
| 16 | 105 | 170 | 181 | 344 | 581 |
| 32 | 104 | 163 | 177 | 341 | 586 |
| 65 | 105 | 162 | 181 | 338 | 583 |

istruzioni per pacchetto / IPC:

| punto | baseline | P1 | P1.5 | P2 | P3 |
|---|---:|---:|---:|---:|---:|
| 16 | 608 / 1.70 | 1476 / 2.50 | 1676 / 2.70 | 4159 / 3.50 | 7511 / 3.80 |
| 32 | 607 / 1.70 | 1436 / 2.60 | 1644 / 2.70 | 4160 / 3.50 | 7512 / 3.80 |
| 65 | 607 / 1.70 | 1434 / 2.60 | 1675 / 2.70 | 4155 / 3.60 | 7507 / 3.80 |

T2−T1, la sola pipeline (build strumentata), minimo / media in ns, mediana fra giri e rate:

| punto | baseline | P1 | P1.5 | P2 | P3 |
|---|---:|---:|---:|---:|---:|
| 16 | 28 / 56 | 122 / 160 | 98 / 148 | 252 / 291 | 480 / 538 |
| 32 | 28 / 56 | 84 / 130 | 94 / 134 | 251 / 300 | 480 / 532 |
| 65 | 28 / 57 | 82 / 121 | 95 / 136 | 248 / 292 | 475 / 529 |

### Ingressi one-hot: n-8-8-7, la larghezza in una one-hot — nodo su Pcore

ns di CPU per pacchetto:

| punto | baseline | P1 | P1.5 | P2 | P3 |
|---|---:|---:|---:|---:|---:|
| 16 | 66 | 144 | 143 | 260 | 477 |
| 32 | 67 | 140 | 140 | 264 | 475 |
| 65 | 66 | 136 | 139 | 273 | 468 |

istruzioni per pacchetto / IPC:

| punto | baseline | P1 | P1.5 | P2 | P3 |
|---|---:|---:|---:|---:|---:|
| 16 | 606 / 2.60 | 1473 / 2.90 | 1672 / 3.30 | 4157 / 4.60 | 7511 / 4.50 |
| 32 | 606 / 2.60 | 1433 / 2.90 | 1641 / 3.40 | 4158 / 4.50 | 7513 / 4.50 |
| 65 | 606 / 2.60 | 1432 / 3.00 | 1672 / 3.50 | 4154 / 4.40 | 7508 / 4.60 |

T2−T1, la sola pipeline (build strumentata), minimo / media in ns, mediana fra giri e rate:

| punto | baseline | P1 | P1.5 | P2 | P3 |
|---|---:|---:|---:|---:|---:|
| 16 | 27 / 56 | 82 / 138 | 86 / 132 | 196 / 278 | 390 / 494 |
| 32 | 27 / 56 | 74 / 132 | 82 / 135 | 200 / 260 | 412 / 519 |
| 65 | 26 / 55 | 73 / 134 | 82 / 136 | 200 / 280 | 386 / 479 |

## Condizioni

| misura | data | DUT | MHz misurati | alimentazione | contatori hw |
|---|---:|---:|---:|---:|---:|
| assi_Ecore/checkpoint/rates | 2026-10-10 18:11:08 | cpu12 (E, modulo L2 con 13-15) | 3480 | BATTERIA | instructions, cycles, cache-misses, bran |
| assi_Ecore/depth_1 | 2026-10-10 17:24:59 | cpu12 (E, modulo L2 con 13-15) | 3464 | BATTERIA | instructions, cycles, cache-misses, bran |
| assi_Ecore/depth_1/rates | 2026-10-10 17:25:25 | cpu12 (E, modulo L2 con 13-15) | 3440 | BATTERIA | instructions, cycles, cache-misses, bran |
| assi_Ecore/depth_2 | 2026-10-10 17:01:45 | cpu12 (E, modulo L2 con 13-15) | 3498 | BATTERIA | instructions, cycles, cache-misses, bran |
| assi_Ecore/depth_2/rates | 2026-10-10 17:02:11 | cpu12 (E, modulo L2 con 13-15) | 3486 | BATTERIA | instructions, cycles, cache-misses, bran |
| assi_Ecore/depth_3 | 2026-10-10 17:02:40 | cpu12 (E, modulo L2 con 13-15) | 3491 | BATTERIA | instructions, cycles, cache-misses, bran |
| assi_Ecore/depth_3/rates | 2026-10-10 17:03:06 | cpu12 (E, modulo L2 con 13-15) | 3500 | BATTERIA | instructions, cycles, cache-misses, bran |
| assi_Ecore/depth_4 | 2026-10-10 17:03:35 | cpu12 (E, modulo L2 con 13-15) | 3500 | BATTERIA | instructions, cycles, cache-misses, bran |
| assi_Ecore/depth_4/rates | 2026-10-10 17:04:02 | cpu12 (E, modulo L2 con 13-15) | 3481 | BATTERIA | instructions, cycles, cache-misses, bran |
| assi_Ecore/depth_5 | 2026-10-10 17:04:31 | cpu12 (E, modulo L2 con 13-15) | 3458 | BATTERIA | instructions, cycles, cache-misses, bran |
| assi_Ecore/depth_5/rates | 2026-10-10 17:04:57 | cpu12 (E, modulo L2 con 13-15) | 3453 | BATTERIA | instructions, cycles, cache-misses, bran |
| assi_Ecore/depth_6 | 2026-10-10 17:05:27 | cpu12 (E, modulo L2 con 13-15) | 3475 | BATTERIA | instructions, cycles, cache-misses, bran |
| assi_Ecore/depth_6/rates | 2026-10-10 17:05:53 | cpu12 (E, modulo L2 con 13-15) | 3463 | BATTERIA | instructions, cycles, cache-misses, bran |
| assi_Ecore/isoparam_1 | 2026-10-10 17:06:22 | cpu12 (E, modulo L2 con 13-15) | 3473 | BATTERIA | instructions, cycles, cache-misses, bran |
| assi_Ecore/isoparam_1/rates | 2026-10-10 17:06:48 | cpu12 (E, modulo L2 con 13-15) | 3468 | BATTERIA | instructions, cycles, cache-misses, bran |
| assi_Ecore/isoparam_2 | 2026-10-10 17:07:17 | cpu12 (E, modulo L2 con 13-15) | 3479 | BATTERIA | instructions, cycles, cache-misses, bran |
| assi_Ecore/isoparam_2/rates | 2026-10-10 17:07:44 | cpu12 (E, modulo L2 con 13-15) | 3477 | BATTERIA | instructions, cycles, cache-misses, bran |
| assi_Ecore/isoparam_3 | 2026-10-10 17:08:13 | cpu12 (E, modulo L2 con 13-15) | 3463 | BATTERIA | instructions, cycles, cache-misses, bran |
| assi_Ecore/isoparam_3/rates | 2026-10-10 17:08:39 | cpu12 (E, modulo L2 con 13-15) | 3477 | BATTERIA | instructions, cycles, cache-misses, bran |
| assi_Ecore/isoparam_4 | 2026-10-10 17:09:08 | cpu12 (E, modulo L2 con 13-15) | 3471 | BATTERIA | instructions, cycles, cache-misses, bran |
| assi_Ecore/isoparam_4/rates | 2026-10-10 17:09:34 | cpu12 (E, modulo L2 con 13-15) | 3465 | BATTERIA | instructions, cycles, cache-misses, bran |
| assi_Ecore/isoparam_5 | 2026-10-10 17:10:04 | cpu12 (E, modulo L2 con 13-15) | 3466 | BATTERIA | instructions, cycles, cache-misses, bran |
| assi_Ecore/isoparam_5/rates | 2026-10-10 17:10:30 | cpu12 (E, modulo L2 con 13-15) | 3465 | BATTERIA | instructions, cycles, cache-misses, bran |
| assi_Ecore/iv_dense_13 | 2026-10-10 18:18:05 | cpu12 (E, modulo L2 con 13-15) | 3469 | BATTERIA | instructions, cycles, cache-misses, bran |
| assi_Ecore/iv_dense_13/rates | 2026-10-10 18:18:31 | cpu12 (E, modulo L2 con 13-15) | 3469 | BATTERIA | instructions, cycles, cache-misses, bran |
| assi_Ecore/iv_dense_17 | 2026-10-10 18:19:00 | cpu12 (E, modulo L2 con 13-15) | 3480 | BATTERIA | instructions, cycles, cache-misses, bran |
| assi_Ecore/iv_dense_17/rates | 2026-10-10 18:19:26 | cpu12 (E, modulo L2 con 13-15) | 3464 | BATTERIA | instructions, cycles, cache-misses, bran |
| assi_Ecore/iv_dense_5 | 2026-10-10 18:16:14 | cpu12 (E, modulo L2 con 13-15) | 3456 | BATTERIA | instructions, cycles, cache-misses, bran |
| assi_Ecore/iv_dense_5/rates | 2026-10-10 18:16:40 | cpu12 (E, modulo L2 con 13-15) | 3449 | BATTERIA | instructions, cycles, cache-misses, bran |
| assi_Ecore/iv_dense_9 | 2026-10-10 18:17:09 | cpu12 (E, modulo L2 con 13-15) | 3483 | BATTERIA | instructions, cycles, cache-misses, bran |
| assi_Ecore/iv_dense_9/rates | 2026-10-10 18:17:35 | cpu12 (E, modulo L2 con 13-15) | 3452 | BATTERIA | instructions, cycles, cache-misses, bran |
| assi_Ecore/iv_onehot_16 | 2026-10-10 18:19:56 | cpu12 (E, modulo L2 con 13-15) | 3468 | BATTERIA | instructions, cycles, cache-misses, bran |
| assi_Ecore/iv_onehot_16/rates | 2026-10-10 18:20:22 | cpu12 (E, modulo L2 con 13-15) | 3470 | BATTERIA | instructions, cycles, cache-misses, bran |
| assi_Ecore/iv_onehot_32 | 2026-10-10 18:20:51 | cpu12 (E, modulo L2 con 13-15) | 3451 | BATTERIA | instructions, cycles, cache-misses, bran |
| assi_Ecore/iv_onehot_32/rates | 2026-10-10 18:21:17 | cpu12 (E, modulo L2 con 13-15) | 3468 | BATTERIA | instructions, cycles, cache-misses, bran |
| assi_Ecore/iv_onehot_65 | 2026-10-10 18:21:47 | cpu12 (E, modulo L2 con 13-15) | 3450 | BATTERIA | instructions, cycles, cache-misses, bran |
| assi_Ecore/iv_onehot_65/rates | 2026-10-10 18:22:13 | cpu12 (E, modulo L2 con 13-15) | 3470 | BATTERIA | instructions, cycles, cache-misses, bran |
| assi_Ecore/nodes_10 | 2026-10-10 18:11:37 | cpu12 (E, modulo L2 con 13-15) | 3438 | BATTERIA | instructions, cycles, cache-misses, bran |
| assi_Ecore/nodes_10/rates | 2026-10-10 18:12:03 | cpu12 (E, modulo L2 con 13-15) | 3440 | BATTERIA | instructions, cycles, cache-misses, bran |
| assi_Ecore/nodes_100 | 2026-10-10 18:15:18 | cpu12 (E, modulo L2 con 13-15) | 3466 | BATTERIA | instructions, cycles, cache-misses, bran |
| assi_Ecore/nodes_100/rates | 2026-10-10 18:15:44 | cpu12 (E, modulo L2 con 13-15) | 3365 | BATTERIA | instructions, cycles, cache-misses, bran |
| assi_Ecore/nodes_25 | 2026-10-10 18:33:46 | cpu12 (E, modulo L2 con 13-15) | 3454 | BATTERIA | instructions, cycles, cache-misses, bran |
| assi_Ecore/nodes_25/rates | 2026-10-10 18:34:12 | cpu12 (E, modulo L2 con 13-15) | 3466 | BATTERIA | instructions, cycles, cache-misses, bran |
| assi_Ecore/nodes_52 | 2026-10-10 18:13:28 | cpu12 (E, modulo L2 con 13-15) | 3463 | BATTERIA | instructions, cycles, cache-misses, bran |
| assi_Ecore/nodes_52/rates | 2026-10-10 18:13:54 | cpu12 (E, modulo L2 con 13-15) | 3470 | BATTERIA | instructions, cycles, cache-misses, bran |
| assi_Ecore/nodes_75 | 2026-10-10 18:14:23 | cpu12 (E, modulo L2 con 13-15) | 3474 | BATTERIA | instructions, cycles, cache-misses, bran |
| assi_Ecore/nodes_75/rates | 2026-10-10 18:14:49 | cpu12 (E, modulo L2 con 13-15) | 3468 | BATTERIA | instructions, cycles, cache-misses, bran |
| assi_Ecore/sparsity_0 | 2026-10-10 17:10:59 | cpu12 (E, modulo L2 con 13-15) | 3479 | BATTERIA | instructions, cycles, cache-misses, bran |
| assi_Ecore/sparsity_0/rates | 2026-10-10 17:11:25 | cpu12 (E, modulo L2 con 13-15) | 3456 | BATTERIA | instructions, cycles, cache-misses, bran |
| assi_Ecore/sparsity_50 | 2026-10-10 17:11:54 | cpu12 (E, modulo L2 con 13-15) | 3490 | BATTERIA | instructions, cycles, cache-misses, bran |
| assi_Ecore/sparsity_50/rates | 2026-10-10 17:12:20 | cpu12 (E, modulo L2 con 13-15) | 3471 | BATTERIA | instructions, cycles, cache-misses, bran |
| assi_Ecore/sparsity_90 | 2026-10-10 17:12:49 | cpu12 (E, modulo L2 con 13-15) | 3476 | BATTERIA | instructions, cycles, cache-misses, bran |
| assi_Ecore/sparsity_90/rates | 2026-10-10 17:13:15 | cpu12 (E, modulo L2 con 13-15) | 3450 | BATTERIA | instructions, cycles, cache-misses, bran |
| assi_Ecore/width_2 | 2026-10-10 16:57:11 | cpu12 (E, modulo L2 con 13-15) | 3452 | BATTERIA | instructions, cycles, cache-misses, bran |
| assi_Ecore/width_2/rates | 2026-10-10 16:57:37 | cpu12 (E, modulo L2 con 13-15) | 3461 | BATTERIA | instructions, cycles, cache-misses, bran |
| assi_Ecore/width_4 | 2026-10-10 16:58:06 | cpu12 (E, modulo L2 con 13-15) | 3436 | BATTERIA | instructions, cycles, cache-misses, bran |
| assi_Ecore/width_4/rates | 2026-10-10 16:58:32 | cpu12 (E, modulo L2 con 13-15) | 3474 | BATTERIA | instructions, cycles, cache-misses, bran |
| assi_Ecore/width_6 | 2026-10-10 16:59:01 | cpu12 (E, modulo L2 con 13-15) | 3491 | BATTERIA | instructions, cycles, cache-misses, bran |
| assi_Ecore/width_6/rates | 2026-10-10 16:59:27 | cpu12 (E, modulo L2 con 13-15) | 3400 | BATTERIA | instructions, cycles, cache-misses, bran |
| assi_Ecore/width_8 | 2026-10-10 16:59:56 | cpu12 (E, modulo L2 con 13-15) | 3491 | BATTERIA | instructions, cycles, cache-misses, bran |
| assi_Ecore/width_8/rates | 2026-10-10 17:00:22 | cpu12 (E, modulo L2 con 13-15) | - | BATTERIA | instructions, cycles, cache-misses, bran |
| assi_Pcore/checkpoint/rates | 2026-10-10 17:59:38 | cpu6 (P, fratello 7) | 3494 | BATTERIA | instructions, cycles, cache-misses, bran |
| assi_Pcore/depth_1 | 2026-10-10 16:44:16 | cpu6 (P, fratello 7) | 3506 | BATTERIA | instructions, cycles, cache-misses, bran |
| assi_Pcore/depth_1/rates | 2026-10-10 16:44:42 | cpu6 (P, fratello 7) | 3496 | BATTERIA | instructions, cycles, cache-misses, bran |
| assi_Pcore/depth_2 | 2026-10-10 16:45:11 | cpu6 (P, fratello 7) | 3501 | BATTERIA | instructions, cycles, cache-misses, bran |
| assi_Pcore/depth_2/rates | 2026-10-10 16:45:37 | cpu6 (P, fratello 7) | 3500 | BATTERIA | instructions, cycles, cache-misses, bran |
| assi_Pcore/depth_3 | 2026-10-10 16:46:06 | cpu6 (P, fratello 7) | 3505 | BATTERIA | instructions, cycles, cache-misses, bran |
| assi_Pcore/depth_3/rates | 2026-10-10 16:46:32 | cpu6 (P, fratello 7) | - | BATTERIA | instructions, cycles, cache-misses, bran |
| assi_Pcore/depth_4 | 2026-10-10 16:47:02 | cpu6 (P, fratello 7) | 3499 | BATTERIA | instructions, cycles, cache-misses, bran |
| assi_Pcore/depth_4/rates | 2026-10-10 16:47:28 | cpu6 (P, fratello 7) | 3497 | BATTERIA | instructions, cycles, cache-misses, bran |
| assi_Pcore/depth_5 | 2026-10-10 16:47:57 | cpu6 (P, fratello 7) | 3494 | BATTERIA | instructions, cycles, cache-misses, bran |
| assi_Pcore/depth_5/rates | 2026-10-10 16:48:23 | cpu6 (P, fratello 7) | 3498 | BATTERIA | instructions, cycles, cache-misses, bran |
| assi_Pcore/depth_6 | 2026-10-10 16:48:53 | cpu6 (P, fratello 7) | 3494 | BATTERIA | instructions, cycles, cache-misses, bran |
| assi_Pcore/depth_6/rates | 2026-10-10 16:49:19 | cpu6 (P, fratello 7) | 3495 | BATTERIA | instructions, cycles, cache-misses, bran |
| assi_Pcore/isoparam_1 | 2026-10-10 16:49:49 | cpu6 (P, fratello 7) | 3496 | BATTERIA | instructions, cycles, cache-misses, bran |
| assi_Pcore/isoparam_1/rates | 2026-10-10 16:50:15 | cpu6 (P, fratello 7) | - | BATTERIA | instructions, cycles, cache-misses, bran |
| assi_Pcore/isoparam_2 | 2026-10-10 16:50:44 | cpu6 (P, fratello 7) | 3502 | BATTERIA | instructions, cycles, cache-misses, bran |
| assi_Pcore/isoparam_2/rates | 2026-10-10 16:51:09 | cpu6 (P, fratello 7) | 3488 | BATTERIA | instructions, cycles, cache-misses, bran |
| assi_Pcore/isoparam_3 | 2026-10-10 16:51:39 | cpu6 (P, fratello 7) | 3500 | BATTERIA | instructions, cycles, cache-misses, bran |
| assi_Pcore/isoparam_3/rates | 2026-10-10 16:52:05 | cpu6 (P, fratello 7) | 3501 | BATTERIA | instructions, cycles, cache-misses, bran |
| assi_Pcore/isoparam_4 | 2026-10-10 16:52:34 | cpu6 (P, fratello 7) | 3500 | BATTERIA | instructions, cycles, cache-misses, bran |
| assi_Pcore/isoparam_4/rates | 2026-10-10 16:53:00 | cpu6 (P, fratello 7) | - | BATTERIA | instructions, cycles, cache-misses, bran |
| assi_Pcore/isoparam_5 | 2026-10-10 16:53:30 | cpu6 (P, fratello 7) | 3496 | BATTERIA | instructions, cycles, cache-misses, bran |
| assi_Pcore/isoparam_5/rates | 2026-10-10 16:53:56 | cpu6 (P, fratello 7) | 3506 | BATTERIA | instructions, cycles, cache-misses, bran |
| assi_Pcore/iv_dense_13 | 2026-10-10 18:06:34 | cpu6 (P, fratello 7) | 3498 | BATTERIA | instructions, cycles, cache-misses, bran |
| assi_Pcore/iv_dense_13/rates | 2026-10-10 18:07:00 | cpu6 (P, fratello 7) | 3495 | BATTERIA | instructions, cycles, cache-misses, bran |
| assi_Pcore/iv_dense_17 | 2026-10-10 18:07:30 | cpu6 (P, fratello 7) | 3496 | BATTERIA | instructions, cycles, cache-misses, bran |
| assi_Pcore/iv_dense_17/rates | 2026-10-10 18:07:56 | cpu6 (P, fratello 7) | 3492 | BATTERIA | instructions, cycles, cache-misses, bran |
| assi_Pcore/iv_dense_5 | 2026-10-10 18:04:43 | cpu6 (P, fratello 7) | 3493 | BATTERIA | instructions, cycles, cache-misses, bran |
| assi_Pcore/iv_dense_5/rates | 2026-10-10 18:05:09 | cpu6 (P, fratello 7) | 3496 | BATTERIA | instructions, cycles, cache-misses, bran |
| assi_Pcore/iv_dense_9 | 2026-10-10 18:05:39 | cpu6 (P, fratello 7) | 3489 | BATTERIA | instructions, cycles, cache-misses, bran |
| assi_Pcore/iv_dense_9/rates | 2026-10-10 18:06:05 | cpu6 (P, fratello 7) | 3491 | BATTERIA | instructions, cycles, cache-misses, bran |
| assi_Pcore/iv_onehot_16 | 2026-10-10 18:08:25 | cpu6 (P, fratello 7) | 3497 | BATTERIA | instructions, cycles, cache-misses, bran |
| assi_Pcore/iv_onehot_16/rates | 2026-10-10 18:08:51 | cpu6 (P, fratello 7) | 3494 | BATTERIA | instructions, cycles, cache-misses, bran |
| assi_Pcore/iv_onehot_32 | 2026-10-10 18:09:21 | cpu6 (P, fratello 7) | 3497 | BATTERIA | instructions, cycles, cache-misses, bran |
| assi_Pcore/iv_onehot_32/rates | 2026-10-10 18:09:47 | cpu6 (P, fratello 7) | 3506 | BATTERIA | instructions, cycles, cache-misses, bran |
| assi_Pcore/iv_onehot_65 | 2026-10-10 18:10:16 | cpu6 (P, fratello 7) | 3497 | BATTERIA | instructions, cycles, cache-misses, bran |
| assi_Pcore/iv_onehot_65/rates | 2026-10-10 18:10:42 | cpu6 (P, fratello 7) | 3503 | BATTERIA | instructions, cycles, cache-misses, bran |
| assi_Pcore/nodes_10 | 2026-10-10 18:00:08 | cpu6 (P, fratello 7) | 3504 | BATTERIA | instructions, cycles, cache-misses, bran |
| assi_Pcore/nodes_10/rates | 2026-10-10 18:00:34 | cpu6 (P, fratello 7) | 3492 | BATTERIA | instructions, cycles, cache-misses, bran |
| assi_Pcore/nodes_100 | 2026-10-10 18:03:48 | cpu6 (P, fratello 7) | 3496 | BATTERIA | instructions, cycles, cache-misses, bran |
| assi_Pcore/nodes_100/rates | 2026-10-10 18:04:14 | cpu6 (P, fratello 7) | 3495 | BATTERIA | instructions, cycles, cache-misses, bran |
| assi_Pcore/nodes_25 | 2026-10-10 18:01:03 | cpu6 (P, fratello 7) | 3493 | BATTERIA | instructions, cycles, cache-misses, bran |
| assi_Pcore/nodes_25/rates | 2026-10-10 18:01:29 | cpu6 (P, fratello 7) | 3504 | BATTERIA | instructions, cycles, cache-misses, bran |
| assi_Pcore/nodes_52 | 2026-10-10 18:01:58 | cpu6 (P, fratello 7) | 3494 | BATTERIA | instructions, cycles, cache-misses, bran |
| assi_Pcore/nodes_52/rates | 2026-10-10 18:02:24 | cpu6 (P, fratello 7) | 3496 | BATTERIA | instructions, cycles, cache-misses, bran |
| assi_Pcore/nodes_75 | 2026-10-10 18:02:53 | cpu6 (P, fratello 7) | 3494 | BATTERIA | instructions, cycles, cache-misses, bran |
| assi_Pcore/nodes_75/rates | 2026-10-10 18:03:19 | cpu6 (P, fratello 7) | 3493 | BATTERIA | instructions, cycles, cache-misses, bran |
| assi_Pcore/sparsity_0 | 2026-10-10 16:54:25 | cpu6 (P, fratello 7) | 3503 | BATTERIA | instructions, cycles, cache-misses, bran |
| assi_Pcore/sparsity_0/rates | 2026-10-10 16:54:51 | cpu6 (P, fratello 7) | 3511 | BATTERIA | instructions, cycles, cache-misses, bran |
| assi_Pcore/sparsity_50 | 2026-10-10 16:55:20 | cpu6 (P, fratello 7) | 3494 | BATTERIA | instructions, cycles, cache-misses, bran |
| assi_Pcore/sparsity_50/rates | 2026-10-10 16:55:46 | cpu6 (P, fratello 7) | 3495 | BATTERIA | instructions, cycles, cache-misses, bran |
| assi_Pcore/sparsity_90 | 2026-10-10 16:56:16 | cpu6 (P, fratello 7) | 3493 | BATTERIA | instructions, cycles, cache-misses, bran |
| assi_Pcore/sparsity_90/rates | 2026-10-10 16:56:42 | cpu6 (P, fratello 7) | 3496 | BATTERIA | instructions, cycles, cache-misses, bran |
| assi_Pcore/width_2 | 2026-10-10 16:40:36 | cpu6 (P, fratello 7) | 3492 | BATTERIA | instructions, cycles, cache-misses, bran |
| assi_Pcore/width_2/rates | 2026-10-10 16:41:02 | cpu6 (P, fratello 7) | 3494 | BATTERIA | instructions, cycles, cache-misses, bran |
| assi_Pcore/width_4 | 2026-10-10 16:41:31 | cpu6 (P, fratello 7) | 3495 | BATTERIA | instructions, cycles, cache-misses, bran |
| assi_Pcore/width_4/rates | 2026-10-10 16:41:57 | cpu6 (P, fratello 7) | 3495 | BATTERIA | instructions, cycles, cache-misses, bran |
| assi_Pcore/width_6 | 2026-10-10 16:42:26 | cpu6 (P, fratello 7) | 3493 | BATTERIA | instructions, cycles, cache-misses, bran |
| assi_Pcore/width_6/rates | 2026-10-10 16:42:52 | cpu6 (P, fratello 7) | 3492 | BATTERIA | instructions, cycles, cache-misses, bran |
| assi_Pcore/width_8 | 2026-10-10 16:43:21 | cpu6 (P, fratello 7) | 3504 | BATTERIA | instructions, cycles, cache-misses, bran |
| assi_Pcore/width_8/rates | 2026-10-10 16:43:47 | cpu6 (P, fratello 7) | 3493 | BATTERIA | instructions, cycles, cache-misses, bran |

