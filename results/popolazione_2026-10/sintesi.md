# Population summary: popolazione_2026-10

## The claims

Every row is a claim and its evidence over the population: on how many models it holds, or the range it covers.

| claim | over the population |
|---|---:|
| P2 has a weight ceiling the other pipelines do not have | 6/109 models outside P2 |
| P1 decides exactly like the integer reference | 109/109 models |
| P2 decides exactly like the integer reference | 103/103 models |
| P3 decides exactly like the integer reference | 109/109 models |
| neural network P1, ns per packet (P-core) | 53 [19–155] |
| neural network P1.5, ns per packet (P-core) | 58 [19–156] |
| neural network P2, ns per packet (P-core) | 226 [129–446] |
| neural network P3, ns per packet (P-core) | 421 [240–852] |
| P1 ≤ P2 ≤ P3 in neural network cost (P-core) | 103/103 |
| P2 costs P1 times | 4.4 [2.7–12.8] |
| P3 costs P1 times | 7.8 [4.9–24.6] |
| P3 costs P2 times | 1.9 [1.4–2.3] |
| instructions executed per extra layer (law, P-core) | P1 -6 (r² 0.97), P1.5 -4 (r² 0.91), P2 370 (r² 0.94), P3 901 (r² 0.99) |
| loaded instructions per extra layer (law) | P1 -5 (r² 0.99), P1.5 -58 (r² 0.57), P2 +887 (r² 0.96), P3 always 12288 |
| law of P1 (P-core) | 22 ns + 0.26 ns/MAC + 1 ns/layer; r² 0.98, median error 6% on unseen models (n=83) |
| law of P1.5 (P-core) | 29 ns + 0.26 ns/MAC + 1 ns/layer; r² 0.95, median error 9% on unseen models (n=83) |
| law of P2 (P-core) | 103 ns + 0.42 ns/MAC + 20 ns/layer; r² 0.93, median error 6% on unseen models (n=77) |
| law of P3 (P-core) | 154 ns + 0.77 ns/MAC + 46 ns/layer; r² 0.99, median error 3% on unseen models (n=83) |
| counting executed MACs explains the cost better than the shape | 4/4 pipelines |
| the size of P1 predicts its work (rank ρ) | 0.98 over 109 models |
| the size of P1.5 predicts its work (rank ρ) | 0.90 over 109 models |
| the size of P2 predicts its work (rank ρ) | 0.79 over 103 models |
| P2 is the largest program but P3 executes more | 103/103 |
| same instructions per packet on P-core and E-core | maximum difference 0.3% over 534 model-pipeline pairs |
| same instructions on the LP E-core too | maximum difference 0.7% over 56 pairs |
| the E-core loses mostly in the node's fixed part | fixed cycles E/P 1.56 [1.50–1.61]; ρ(network share, capacity E/P) = 0.76 |
| LP E-core capacity relative to the P-core | 0.43 [0.32–0.53] |
| with the same shape, the weights change the cost by | P1 ≤5%, P1.5 ≤6%, P2 ≤5%, P3 ≤2% |
| with ≥50% zero weights, measured / predicted by the dense law | P1 0.53 [0.31–0.85], P1.5 0.71 [0.27–0.99], P2 1.03 [0.91–1.14], P3 1.00 [0.91–1.03] |
| with the same weights, every extra layer costs (ns, P-core) | P1 4 [3–4], P1.5 4 [4–4], P2 27 [26–28], P3 58 [57–59] |
| cost at light traffic / cost with a saturated node (P-core) | P1 0.77 [0.48–1.02], P1.5 0.83 [0.50–1.02], P2 1.03 [0.94–1.09], P3 1.02 [0.94–1.11] |
| cost at light traffic / cost with a saturated node (E-core) | P1 1.26 [0.34–2.73], P1.5 1.22 [0.30–2.52], P2 1.08 [0.93–1.35], P3 1.07 [0.82–1.13] |
| the transport (minimum T3−T2, no waiting) is a common cost, ns | P-core 199 [187–221], E-core 240 [226–274] |
| the transport does not depend on the pipeline | difference between the most and least expensive 4 [1–17]% over 182 model-cores |
| the maximum forwarded under growing rate matches the full-load capacity (within the noise between sessions) | ratio 0.99 [0.88–1.03] over 48 curves |
| above capacity packets are lost before the program, in the queue | share lost before XDP 1.000 [0.689–1.000] |
| two cores carry twice one core (within the noise between sessions) | 99 [94–103]% of double over 80 pairs |
| the forwarding classes cost the same | difference between the most and least expensive 0 [0–9]% |
| dropping costs more (a bench effect: the packet memory is freed on the node) | 51 [17–63] ns |
| a different TTL per packet against a fixed packet | 0 [-6–4]% on the node time |
| the packet size does not change the cost | difference between 64 and 1514 bytes 1.2 [0.3–3.1]% (30 pairs) |
| the network with a saturated node / the network alone in a warm loop (P-core) | P1 1.33 [1.10–1.65], P1.5 1.28 [1.07–1.77], P2 1.08 [1.00–1.12], P3 1.11 [1.07–1.16] |
| the fastest packet under traffic / the warm loop | P1 0.99 [0.95–1.03], P1.5 1.04 [0.92–1.16], P2 0.95 [0.95–0.95], P3 0.97 [0.96–0.98] |
| generating and compiling P1 for a new model (off the node), ms | P1 50 [34–114], P1.5 61 [34–181] |
| installing a model on a running node, ms | P1 0.6 [0.3–1.5], P1.5 0.9 [0.3–5.6], P2 0.3 [0.2–0.4], P3 0.3 [0.2–0.5] |
| table lookups per packet | P1 5 [4–5], P1.5 6 [5–6], P2 12 [11–12], P3 36 [23–54] |
| P3: table lookups and tail calls grow with the layers | +6.0 lookups per layer; tail calls = layers on 108/108 models |
| the same measurement repeated in another session changes by | 1.8 % median, 5.0 % at the 90th percentile, 7.0 % at most (30 pairs) |
| measurements left out of the conclusions (disturbed or rejected) | 2/580 |
| disturbed measurements kept without the affected rounds | 12 measurements, 26/1980 rounds or windows removed |

## The population

By family: base 53, replica 20, sparsita 8, imbuto 10, strati 18.

| quantity | range |
|---|---:|
| inputs (n_in) | 5–117 |
| hidden layers | 1–6 |
| neurons per layer (max) | 2–8 |
| outputs | 3–7 |
| weights | 21–1349 |
| MACs from the shape | 16–1296 |
| executed MACs | 16–480 |
| one-hot features | 0–2 |
| dense columns | 4–17 |
| zero weights (fraction) | 0.00–0.93 |

Models per input layout and depth:

| layout | 1 layers | 2 layers | 3 layers | 4 layers | 5 layers | 6 layers |
|---|---:|---:|---:|---:|---:|---:|
| dense17 | 4 | 5 | 4 | 3 | 2 | 6 |
| dense5 | 5 | 2 | 1 | 2 | 0 | 1 |
| ipa117 | 4 | 1 | 2 | 1 | 0 | 2 |
| ipa17 | 2 | 4 | 2 | 1 | 0 | 2 |
| ipa65 | 3 | 9 | 3 | 4 | 2 | 2 |
| mixed33 | 3 | 2 | 7 | 4 | 1 | 3 |
| onehot105 | 1 | 2 | 1 | 5 | 0 | 1 |

P2 cannot run 6 models out of 109 (MAX_WEIGHT_ENTRIES): m019, m022, m043, m067, m068, m069. The other pipelines run them all.

Models without a full-load measurement (see the logs): E-core: 1 (m108).

## Correctness on every model

Integer reference against eBPF (check_kernel_vs_reference, BPF_PROG_TEST_RUN, 200 inputs per model): it must match 100%. P1.5 is not in this check (check_kernel_vs_reference tests P1 with the frozen node, P2 and P3).

| pipeline | OK | NO | not applicable | error | which |
|---|---:|---:|---:|---:|---:|
| P1 | 109 | 0 | 0 | 0 | - |
| P2 | 103 | 0 | 6 | 0 | - |
| P3 | 109 | 0 | 0 | 0 | - |

## The node without a neural network

Receiving (rxonly) and receiving + forwarding (baseline) do not depend on the model: one measurement per core type.

| core | program | Mpps | ns CPU | ins/pk | IPC |
|---|---:|---:|---:|---:|---:|
| P-core | rxonly | 19.29 | 40 | 383 | 2.50 |
| P-core | baseline | 14.52 | 67 | 607 | 2.60 |
| E-core | rxonly | 14.77 | 68 | 367 | 1.60 |
| E-core | baseline | 9.48 | 106 | 607 | 1.70 |
| LP E-core | rxonly | 4.26 | 172 | 395 | 0.90 |
| LP E-core | baseline | 3.42 | 291 | 613 | 0.90 |

## What the neural network costs, over the whole population

ns per packet of the neural network alone: CPU time with the node saturated minus the baseline of the same run. n = models measured.

**P-core**

| pipeline | n | min | 10th | median | 90th | max |
|---|---:|---:|---:|---:|---:|---:|
| P1 | 109 | 19 | 28 | 53 | 103 | 155 |
| P1.5 | 109 | 19 | 37 | 58 | 107 | 156 |
| P2 | 103 | 129 | 166 | 226 | 310 | 446 |
| P3 | 109 | 240 | 307 | 421 | 607 | 852 |

Node capacity, million packets per second per core (P-core):

| pipeline | n | min | 10th | median | 90th | max |
|---|---:|---:|---:|---:|---:|---:|
| baseline | 109 | 14.48 | 14.76 | 15.04 | 15.23 | 15.38 |
| P1 | 109 | 4.52 | 5.86 | 8.44 | 10.54 | 11.72 |
| P1.5 | 109 | 4.50 | 5.78 | 8.04 | 9.70 | 11.64 |
| P2 | 103 | 1.95 | 2.65 | 3.43 | 4.31 | 5.11 |
| P3 | 109 | 1.09 | 1.49 | 2.05 | 2.68 | 3.26 |

**E-core**

| pipeline | n | min | 10th | median | 90th | max |
|---|---:|---:|---:|---:|---:|---:|
| P1 | 108 | 13 | 22 | 50 | 90 | 150 |
| P1.5 | 108 | 14 | 31 | 61 | 100 | 156 |
| P2 | 102 | 134 | 186 | 248 | 342 | 493 |
| P3 | 108 | 276 | 343 | 481 | 701 | 968 |

Node capacity, million packets per second per core (E-core):

| pipeline | n | min | 10th | median | 90th | max |
|---|---:|---:|---:|---:|---:|---:|
| baseline | 108 | 9.25 | 9.33 | 9.40 | 9.47 | 9.54 |
| P1 | 108 | 3.92 | 5.08 | 6.38 | 7.75 | 8.34 |
| P1.5 | 108 | 3.81 | 4.84 | 5.99 | 7.31 | 8.33 |
| P2 | 102 | 1.67 | 2.23 | 2.82 | 3.42 | 4.16 |
| P3 | 108 | 0.93 | 1.24 | 1.70 | 2.23 | 2.61 |

## Does the order between pipelines hold on every model?

**P-core** — ratio between the neural network costs, median [min–max] over the models, and on how many the first costs more than the second:

| comparison | ratio | the first costs more |
|---|---:|---:|
| P1.5 / P1 | 1.11 [0.93–1.68] | 89/109 |
| P2 / P1 | 4.36 [2.67–12.75] | 103/103 |
| P3 / P1 | 7.82 [4.86–24.65] | 109/109 |
| P3 / P2 | 1.88 [1.36–2.30] | 103/103 |
| P2 / P1.5 | 3.91 [2.37–9.60] | 103/103 |

P1 ≤ P2 ≤ P3 on 103/103 models.

**E-core** — ratio between the neural network costs, median [min–max] over the models, and on how many the first costs more than the second:

| comparison | ratio | the first costs more |
|---|---:|---:|
| P1.5 / P1 | 1.21 [0.95–1.85] | 89/108 |
| P2 / P1 | 5.03 [3.17–20.35] | 102/102 |
| P3 / P1 | 9.36 [5.85–39.60] | 108/108 |
| P3 / P2 | 1.93 [1.47–2.51] | 102/102 |
| P2 / P1.5 | 4.12 [2.61–19.01] | 102/102 |

P1 ≤ P2 ≤ P3 on 102/102 models.

## Loaded against executed instructions

Loaded = instructions of the pipeline's programs, counted by the kernel at load time (prog_census). Executed = instructions per packet from the hardware counters, minus the baseline: the neural network alone. ρ = rank correlation between the two over the population (1 = size orders the models like the work).

| pipeline | n | loaded | executed (network) | ρ |
|---|---:|---:|---:|---:|
| P1 | 109 | 650 [239–2315] | 562 [157–2250] | 0.98 |
| P1.5 | 109 | 961 [282–4313] | 743 [168–2447] | 0.90 |
| P2 | 103 | 16813 [14604–18937] | 3972 [2038–7910] | 0.79 |
| P3 | 109 | 12288 [12288–12288] | 7014 [3851–15456] | - |

P2 larger than P3: 103/103; P3 executes more than P2: 103/103; both together (size orders opposite to the work): 103/103.

## Instructions per packet do not depend on the core

|E/P − 1| of the instructions per packet, in %, on every model:

| pipeline | n | median % | maximum % |
|---|---:|---:|---:|
| baseline | 108 | 0.20 | 0.30 |
| P1 | 108 | 0.15 | 0.30 |
| P1.5 | 108 | 0.17 | 0.29 |
| P2 | 102 | 0.01 | 0.09 |
| P3 | 108 | 0.01 | 0.08 |

LP E-core against P-core: maximum 0.7% over 56 pairs.

## What changes on a slower core

E-core capacity and IPC relative to the P-core (same frequency, 3.5 GHz), median [min–max] over the models:

| pipeline | n | capacity E/P | IPC E/P |
|---|---:|---:|---:|
| baseline | 108 | 0.63 [0.61–0.66] | 0.65 [0.63–0.68] |
| P1 | 108 | 0.76 [0.69–0.91] | 0.78 [0.70–0.94] |
| P1.5 | 108 | 0.75 [0.68–0.88] | 0.77 [0.70–0.91] |
| P2 | 102 | 0.82 [0.77–0.87] | 0.84 [0.78–0.89] |
| P3 | 108 | 0.83 [0.72–0.89] | 0.84 [0.70–0.89] |

Cycles per packet E/P: fixed part of the node (baseline) 1.56 [1.50–1.61]; neural network:

| pipeline | n | network cycles E/P |
|---|---:|---:|
| P1 | 108 | 0.95 [0.55–1.20] |
| P1.5 | 108 | 1.01 [0.59–1.34] |
| P2 | 102 | 1.09 [1.02–1.18] |
| P3 | 108 | 1.13 [1.05–1.40] |

The more the neural network weighs on the packet, the less the core matters: rank ρ between the network's cycle share (P-core) and the E/P capacity = 0.76 over 426 model-pipeline pairs.

LP E-core (2.5 GHz), 14 models from the lightest to the heaviest:

| pipeline | n | capacity LP/P | LLC misses/pk |
|---|---:|---:|---:|
| baseline | 14 | 0.26 [0.22–0.27] | 13.5 [13.1–13.9] |
| P1 | 14 | 0.35 [0.32–0.45] | 13.7 [12.9–17.9] |
| P1.5 | 14 | 0.35 [0.32–0.44] | 17.4 [13.5–18.2] |
| P2 | 14 | 0.45 [0.42–0.48] | 16.1 [13.0–19.3] |
| P3 | 14 | 0.48 [0.45–0.53] | 19.0 [13.5–21.2] |

## A cost law, fitted on every model

network cost = a + b × MAC + c × layers (least squares over the population). Error = relative error on a model left out of the fit (median and 90th percentile, %): how wrong the law is on a model it has not seen. Executed MACs count a one-hot as a single column; the non-zero ones remove zero weights.

**ns per packet, P-core**

| pipeline | variables | n | a (ns) | b (ns/MAC) | c (ns/layer) | r² | error 50th | error 90th |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| P1 | executed MACs + layers | 83 | 22 | 0.26 | 1.1 | 0.98 | 6 | 24 |
| P1 | shape MACs + layers | 83 | 8 | 0.06 | 9.0 | 0.58 | 26 | 71 |
| P1 | executed non-zero MACs + layers | 83 | 22 | 0.26 | 1.2 | 0.98 | 6 | 24 |
| P1.5 | executed MACs + layers | 83 | 29 | 0.26 | 0.9 | 0.95 | 9 | 26 |
| P1.5 | shape MACs + layers | 83 | 14 | 0.06 | 8.4 | 0.61 | 21 | 68 |
| P1.5 | executed non-zero MACs + layers | 83 | 29 | 0.26 | 0.9 | 0.95 | 8 | 25 |
| P2 | executed MACs + layers | 77 | 103 | 0.42 | 19.6 | 0.93 | 6 | 18 |
| P2 | shape MACs + layers | 77 | 77 | 0.10 | 32.7 | 0.69 | 10 | 33 |
| P2 | executed non-zero MACs + layers | 77 | 103 | 0.43 | 19.6 | 0.93 | 6 | 18 |
| P3 | executed MACs + layers | 83 | 154 | 0.77 | 46.3 | 0.99 | 3 | 8 |
| P3 | shape MACs + layers | 83 | 115 | 0.15 | 70.9 | 0.79 | 9 | 21 |
| P3 | executed non-zero MACs + layers | 83 | 154 | 0.77 | 46.3 | 0.99 | 3 | 8 |

**instructions per packet, P-core** (same form: b in instructions per MAC, c per layer)

| pipeline | variables | n | a | b | c | r² | error 50th | error 90th |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| P1 | executed MACs + layers | 83 | 190 | 4.38 | -6.3 | 0.97 | 14 | 36 |
| P1 | shape MACs + layers | 83 | -52 | 0.94 | 128.5 | 0.53 | 34 | 121 |
| P1 | executed non-zero MACs + layers | 83 | 189 | 4.40 | -6.2 | 0.97 | 13 | 36 |
| P1.5 | executed MACs + layers | 83 | 341 | 4.27 | -3.9 | 0.91 | 17 | 60 |
| P1.5 | shape MACs + layers | 83 | 74 | 1.10 | 119.2 | 0.61 | 27 | 97 |
| P1.5 | executed non-zero MACs + layers | 83 | 341 | 4.30 | -3.8 | 0.91 | 17 | 59 |
| P2 | executed MACs + layers | 77 | 1628 | 7.85 | 369.9 | 0.94 | 6 | 18 |
| P2 | shape MACs + layers | 77 | 1120 | 2.06 | 609.0 | 0.72 | 12 | 32 |
| P2 | executed non-zero MACs + layers | 77 | 1628 | 7.89 | 370.1 | 0.94 | 6 | 18 |
| P3 | executed MACs + layers | 83 | 1870 | 14.85 | 901.3 | 0.99 | 3 | 6 |
| P3 | shape MACs + layers | 83 | 1111 | 2.80 | 1375.3 | 0.79 | 11 | 28 |
| P3 | executed non-zero MACs + layers | 83 | 1869 | 14.94 | 901.6 | 0.99 | 3 | 6 |

**ns per packet, E-core**

| pipeline | variables | n | a (ns) | b (ns/MAC) | c (ns/layer) | r² | error 50th | error 90th |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| P1 | executed MACs + layers | 83 | 18 | 0.26 | 1.2 | 0.95 | 15 | 46 |
| P1 | shape MACs + layers | 83 | 3 | 0.06 | 9.1 | 0.56 | 30 | 90 |
| P1 | executed non-zero MACs + layers | 83 | 18 | 0.26 | 1.2 | 0.95 | 15 | 45 |
| P1.5 | executed MACs + layers | 83 | 28 | 0.24 | 1.7 | 0.88 | 16 | 65 |
| P1.5 | shape MACs + layers | 83 | 12 | 0.06 | 8.6 | 0.63 | 24 | 75 |
| P1.5 | executed non-zero MACs + layers | 83 | 28 | 0.24 | 1.7 | 0.88 | 16 | 65 |
| P2 | executed MACs + layers | 77 | 112 | 0.51 | 20.2 | 0.94 | 5 | 17 |
| P2 | shape MACs + layers | 77 | 80 | 0.13 | 35.8 | 0.69 | 12 | 31 |
| P2 | executed non-zero MACs + layers | 77 | 112 | 0.51 | 20.3 | 0.94 | 6 | 17 |
| P3 | executed MACs + layers | 83 | 153 | 0.79 | 61.8 | 0.98 | 3 | 6 |
| P3 | shape MACs + layers | 83 | 110 | 0.17 | 86.3 | 0.84 | 9 | 21 |
| P3 | executed non-zero MACs + layers | 83 | 153 | 0.79 | 61.8 | 0.98 | 3 | 6 |

**loaded instructions** (program size, same form: b per MAC, c per layer)

| pipeline | variables | n | a | b | c | r² | error 50th | error 90th |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| P1 | executed MACs + layers | 83 | 232 | 4.37 | -4.8 | 0.99 | 4 | 10 |
| P1 | shape MACs + layers | 83 | -5 | 0.90 | 131.1 | 0.53 | 31 | 90 |
| P1 | executed non-zero MACs + layers | 83 | 231 | 4.40 | -4.8 | 0.99 | 4 | 10 |
| P1.5 | executed MACs + layers | 83 | 686 | 5.91 | -57.8 | 0.57 | 40 | 77 |
| P1.5 | shape MACs + layers | 83 | 102 | 2.84 | 54.3 | 0.96 | 11 | 25 |
| P1.5 | executed non-zero MACs + layers | 83 | 686 | 5.95 | -57.7 | 0.57 | 40 | 78 |
| P2 | executed MACs + layers | 77 | 12774 | -0.11 | 886.7 | 0.96 | 2 | 3 |
| P2 | shape MACs + layers | 77 | 12816 | -0.20 | 886.9 | 0.96 | 2 | 3 |
| P2 | executed non-zero MACs + layers | 77 | 12774 | -0.12 | 886.9 | 0.96 | 2 | 3 |
| P3 | executed MACs + layers | 83 | 12288 | -0.00 | -0.0 | 1.00 | 0 | 0 |
| P3 | shape MACs + layers | 83 | 12288 | -0.00 | -0.0 | 1.00 | 0 | 0 |
| P3 | executed non-zero MACs + layers | 83 | 12288 | 0.00 | -0.0 | 1.00 | 0 | 0 |

**ns per packet at light traffic (mean T2−T1 minus the baseline), P-core**

| pipeline | variables | n | a (ns) | b (ns/MAC) | c (ns/layer) | r² | error 50th | error 90th |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| P1 | executed MACs + layers | 83 | 10 | 0.27 | 1.0 | 0.99 | 7 | 19 |
| P1 | shape MACs + layers | 83 | -5 | 0.06 | 9.5 | 0.55 | 30 | 101 |
| P1 | executed non-zero MACs + layers | 83 | 10 | 0.27 | 1.0 | 0.99 | 7 | 18 |
| P1.5 | executed MACs + layers | 83 | 17 | 0.27 | 0.9 | 0.96 | 12 | 36 |
| P1.5 | shape MACs + layers | 83 | 1 | 0.06 | 9.1 | 0.60 | 28 | 89 |
| P1.5 | executed non-zero MACs + layers | 83 | 17 | 0.27 | 0.9 | 0.96 | 12 | 36 |
| P2 | executed MACs + layers | 77 | 103 | 0.44 | 20.2 | 0.93 | 7 | 17 |
| P2 | shape MACs + layers | 77 | 76 | 0.11 | 33.6 | 0.70 | 11 | 31 |
| P2 | executed non-zero MACs + layers | 77 | 103 | 0.44 | 20.2 | 0.93 | 7 | 17 |
| P3 | executed MACs + layers | 83 | 146 | 0.79 | 50.1 | 0.98 | 3 | 9 |
| P3 | shape MACs + layers | 83 | 105 | 0.15 | 75.1 | 0.80 | 10 | 22 |
| P3 | executed non-zero MACs + layers | 83 | 146 | 0.79 | 50.1 | 0.98 | 3 | 9 |

## How much the weight seed matters

Same shape, different seeds (one with normal weights): ns of neural network, mean ± coefficient of variation, P-core.

| group | model | seeds | P1 | P1.5 | P2 | P3 |
|---|---:|---:|---:|---:|---:|---:|
| r0 | dense5 5-2-3 | 4 | 20 ± 5% | 20 ± 6% | 133 ± 2% | 246 ± 2% |
| r1 | ipa17 17-4-4-5 | 4 | 46 ± 2% | 54 ± 2% | 190 ± 4% | 336 ± 2% |
| r2 | mixed33 33-4-4-4-5 | 4 | 53 ± 2% | 57 ± 3% | 226 ± 1% | 422 ± 0% |
| r3 | ipa65 65-8-8-3 | 4 | 69 ± 2% | 81 ± 1% | 212 ± 5% | 405 ± 2% |
| r4 | onehot105 105-8-8-8-8-5 | 4 | 104 ± 3% | 108 ± 1% | - | 607 ± 2% |
| r5 | dense17 17-8-8-8-8-8-8-3 | 4 | 147 ± 4% | 149 ± 3% | 439 ± 2% | 848 ± 0% |

## Zero weights

Measured ns of neural network and, in brackets, the ratio to the law fitted on the dense models (1 = sparsity changes nothing, < 1 = the model gets lighter):

| model | zero weights | P1 | P1.5 | P2 | P3 |
|---|---:|---:|---:|---:|---:|
| m073 | 46% | 46 (1.01) | 53 (1.01) | 242 (1.24) | 362 (1.02) |
| m077 | 49% | 41 (0.74) | 53 (0.87) | 251 (1.02) | 483 (1.03) |
| m075 | 49% | 52 (0.63) | 54 (0.61) | 229 (0.89) | 468 (1.01) |
| m079 | 51% | 48 (0.85) | 63 (0.99) | 203 (1.03) | 318 (0.92) |
| m074 | 88% | 29 (0.63) | 43 (0.83) | 223 (1.14) | 364 (1.03) |
| m078 | 89% | 20 (0.35) | 33 (0.54) | 249 (1.01) | 481 (1.02) |
| m080 | 90% | 30 (0.53) | 45 (0.71) | 203 (1.04) | 314 (0.91) |
| m076 | 93% | 26 (0.31) | 24 (0.27) | 232 (0.91) | 468 (1.00) |

## Wide or deep, with the same weights

Five shapes per layout, with the same weights within each (~600 with ipa65, ~210-270 with dense17; at 4-5 layers the executed MACs grow by 16-43 %), from 1 to 5 layers: ns of neural network with 1 layer → with 5, and the slope per layer (least squares), P-core.

| layout | pipeline | 1 → 5 layers | change | ns per layer |
|---|---:|---:|---:|---:|
| ipa65 | P1 | 66 → 76 | +14% | 3 |
| ipa65 | P1.5 | 79 → 91 | +15% | 4 |
| ipa65 | P2 | 203 → 310 | +53% | 28 |
| ipa65 | P3 | 322 → 547 | +70% | 59 |
| dense17 | P1 | 72 → 87 | +21% | 4 |
| dense17 | P1.5 | 74 → 83 | +13% | 4 |
| dense17 | P2 | 219 → 315 | +44% | 26 |
| dense17 | P3 | 392 → 608 | +55% | 57 |

## Light traffic against a saturated node

At light traffic (T2−T1, below capacity) against a saturated node (CPU time), always the neural network alone. mean/saturated ≈ 1 means the cost of a packet does not depend on the load; minimum/mean says how much the packet that finds warm caches and predictors costs compared with the typical one.

| core | pipeline | n | light mean / saturated | minimum / mean |
|---|---:|---:|---:|---:|
| P-core | P1 | 91 | 0.77 [0.48–1.02] | 0.89 [0.63–1.02] |
| P-core | P1.5 | 91 | 0.83 [0.50–1.02] | 0.90 [0.66–1.01] |
| P-core | P2 | 85 | 1.03 [0.94–1.09] | 0.87 [0.81–0.93] |
| P-core | P3 | 91 | 1.02 [0.94–1.11] | 0.86 [0.80–0.91] |
| E-core | P1 | 91 | 1.26 [0.34–2.73] | 0.74 [0.34–0.92] |
| E-core | P1.5 | 91 | 1.22 [0.30–2.52] | 0.74 [0.41–0.91] |
| E-core | P2 | 85 | 1.08 [0.93–1.35] | 0.89 [0.84–0.94] |
| E-core | P3 | 91 | 1.07 [0.82–1.13] | 0.93 [0.88–0.97] |

## The transport to the next node

T3−T2 (redirect, virtual cable, reception) from the three-clock measurement, ns. The minimum is the transport without waiting. The mean also contains the queue: here the egress runs on the node core, and the mean grows with the rate.

| core | program | n | minimum | mean per rate |
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

## Under growing traffic

Knee = highest requested rate without loss; maximum forwarded against the capacity measured at full load on the same model.

| core | model | pipeline | knee Mpps | max forwarded | capacity | bottleneck |
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

## Two node cores

| core | model | pipeline | 1 core | 2 cores | % of double |
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

## Different classes

One session per decided class: difference between the most and least expensive forwarding class, and how much more dropping costs (ns, median over the classes).

| model | pipeline | FORWARD classes | FORWARD spread | DROP − FORWARD ns |
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

## Identical packets against different packets

A different TTL for every packet (2–31): the model decides different classes, drop included. ns of CPU per packet against the fixed packet of the same model.

| model | pipeline | fixed | mixed TTL | Δ |
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

## Packet size

Difference between the most and least expensive size, per model and pipeline: 1.2 [0.3–3.1]% over 30 pairs.

## The program alone

bench_program_alone.py on every model, P-core: latency alone (BPF_PROG_TEST_RUN, minimum of 7 measurements), and the network alone (minus the baseline of the same model); build = loading the pipeline from scratch; install = a new model on a running node (P1: loading the compiled object; P2, P3: writing the tables); table lookups and tail calls per packet. Packet and inputs are those of the traffic (TTL 32, link state that forwards); a measurement that did not forward is left out.

| pipeline | n | single call ns | network ns | network, warm loop ns | build ms | generate and compile P1 ms | install ms | lookups | tail calls |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| baseline | 108 | 38 [35–41] | - | 17 [16–17] | 711.7 [693.2–724.7] | - | 0.0 [0.0–0.0] | 3.0 [3.0–3.0] | 0 [0–0] |
| P1 | 108 | 80 [44–177] | 41 [6–140] | 42 [17–49] | 3.7 [3.3–58.0] | 50 [34–114] | 0.6 [0.3–1.5] | 5.0 [4.0–5.0] | 1 [1–1] |
| P1.5 | 108 | 88 [46–185] | 50 [7–148] | 48 [16–59] | 1.8 [1.1–6.9] | 61 [34–181] | 0.9 [0.3–5.6] | 6.0 [5.0–6.0] | 1 [1–1] |
| P2 | 102 | 276 [157–598] | 238 [118–562] | 214 [161–280] | 1571.4 [1438.2–1749.6] | - | 0.3 [0.2–0.4] | 12.0 [11.0–12.0] | 1 [1–1] |
| P3 | 108 | 504 [300–999] | 465 [262–963] | 381 [276–539] | 1217.5 [1188.8–1234.1] | - | 0.3 [0.2–0.5] | 35.5 [23.0–54.0] | 4 [2–7] |

Warm loop: blocks of consecutive runs as long as the decreasing TTL does not change the decided class; used only where the block is at least 10 runs long.

The network alone under traffic divided by the network alone by itself, model by model:

| pipeline | saturated node / warm loop | light traffic, minimum / warm loop | saturated node / single call | light traffic, mean / single call |
|---|---:|---:|---:|---:|
| P1 | 1.33 [1.10–1.65] | 0.99 [0.95–1.03] | 1.33 [0.95–3.55] | 1.06 [0.78–2.50] |
| P1.5 | 1.28 [1.07–1.77] | 1.04 [0.92–1.16] | 1.23 [1.02–3.19] | 1.04 [0.85–2.14] |
| P2 | 1.08 [1.00–1.12] | 0.95 [0.95–0.95] | 0.94 [0.77–1.10] | 0.97 [0.79–1.07] |
| P3 | 1.11 [1.07–1.16] | 0.97 [0.96–0.98] | 0.91 [0.84–0.97] | 0.92 [0.86–1.00] |

## How much the same measurement varies

Variation in % of the value: median, 90th percentile, maximum. A difference within the variation between sessions is not a difference; a ratio between two measurements from different sessions can exceed 1 for this reason alone.

| what | n | median % | 90th % | max % |
|---|---:|---:|---:|---:|
| the rounds of one measurement ((max − min) / median) | 1073 | 1.3 | 3.2 | 7.8 |
| the node without a network in different sessions, P-core | 109 | 1.1 | 2.4 | 5.0 |
| the node without a network in different sessions, E-core | 108 | 0.4 | 1.0 | 1.6 |
| same model and version, two sessions | 30 | 1.8 | 5.0 | 7.0 |

## Measurements left out of the conclusions

They enter no range and no law. disturbed = the machine did not stay in the declared conditions (run_disturbed in env.csv); rejected = the bench's validity check rejected it (throughput_report.md). They are redone with POP_RIFAI_DISTURBATE=1 run_population_campaign.sh.

**disturbed** (2): pop_Ecore/m108, solo/m093

**measurements kept without the disturbed rounds** (curves: every point, full load: every pipeline, with at least 2 clean rounds; full load only if the disturbance is throttling, removing the rounds within 1 s of an event): carico_Ecore/m013 (7/240), carico_Ecore/m031 (3/240), carico_Ecore/m037 (1/240), carico_Ecore/m042 (3/240), carico_Pcore/m000 (1/240), carico_Pcore/m031 (1/240), carico_Pcore/m037 (0/240), carico_Pcore/m042 (1/240), pop_Ecore/m098 (3/15), pop_Pcore/m101 (3/15), pop_Pcore/m103 (3/15), pop_Pcore/m107 (0/15)

