#!/usr/bin/env bash
# remeasure_popolazione.sh -- la campagna senza un modello privilegiato.
#
# Ogni misura della campagna di ottobre (remeasure_campagna.sh) girava sul
# checkpoint 65-4-4-7, e gli assi variavano un parametro alla volta attorno a
# lui. Qui ogni misura gira su una POPOLAZIONE di modelli sintetici
# (model_population.py: composizioni dell'ingresso, profondita', larghezze,
# uscite, semi, sparsita' diverse), o, per i test lunghi, su un sottoinsieme
# che va dal modello piu' leggero al piu' pesante. Le conclusioni le tira
# population_report.py: intervalli su tutta la popolazione, leggi di costo, e
# per ogni affermazione su quanti modelli regge.
#
#   cd ~/Scrivania/ipa_lab && bash ipa/test/remeasure_popolazione.sh             # tutto
#   cd ~/Scrivania/ipa_lab && bash ipa/test/remeasure_popolazione.sh genera pop  # sezioni
#   POP_TIER=quick bash ipa/test/remeasure_popolazione.sh                        # prova breve
#
# Sezioni (nell'ordine di "tutto"):
#   genera    la popolazione ($POP_TIER: quick ~30 modelli, base ~90, full ~140)
#             e il suo manifesto, copiato in $OUT/population.csv
#   corretto  equivalenza esatta riferimento intero / eBPF (BPF_PROG_TEST_RUN)
#             su ogni modello e ogni pipeline che lo sa eseguire
#   rif       i tetti che non dipendono dal modello: rxonly e baseline, una
#             volta per tipo di core
#   pop       OGNI modello, nodo sui core di $POP_CORES (default "P E"): a
#             massima spinta (capacita', ns di CPU, istruzioni e cicli per
#             pacchetto, dimensione dei programmi caricati) e, con POP_T2=1, a
#             traffico leggero con le tre marcature (T2-T1 a $POP_RATES Mpps)
#   lpe       il sottoinsieme "lpe" con il nodo sul LP E-core
#   carico    il sottoinsieme "carico": curve al crescere del rate, P ed E
#   core2     il sottoinsieme "core2": due core del nodo, P ed E
#   classi    il sottoinsieme "classi": una sessione per classe decisa (P)
#   mix       il sottoinsieme "mix": TTL diversi pacchetto per pacchetto (P)
#   taglie    il sottoinsieme "taglie": 64 / 512 / 1514 byte (P)
#   sintesi   population_report.py, anche da sola
#
# Il disegno dei core e' quello di remeasure_campagna.sh: cambia solo il core
# del NODO; generatore (cpu10) e uscita (cpu8) restano su P-core a 3500 MHz.
#
# CSV in results/popolazione_<data>/<sezione>/<modello>/ ($CAMPAGNA per
# cambiarlo), log in .../log/. Un modello che un banco non sa misurare
# (nessuna pipeline caricata, sonda vuota) lascia la sua cartella vuota e il
# log: il report lo conta come mancante, non lo nasconde.
#
# Ripresa: una misura il cui CSV c'e' gia' in $CAMPAGNA si salta, quindi la
# campagna si puo' interrompere e rilanciare con lo stesso comando (e la
# stessa CAMPAGNA), o spezzare su piu' sessioni. Un banco fallito non scrive
# il CSV e al rilancio si rifa'. POP_RIFAI=1 rimisura tutto comunque. Se la
# popolazione cambia (altro POP_TIER, altro disegno) la ripresa si rifiuta:
# gli id dei modelli indicherebbero modelli diversi da quelli misurati.
set -u
cd "$(dirname "$0")/../.."
ROOT="$PWD"
OUT="${CAMPAGNA:-$ROOT/results/popolazione_$(date +%Y-%m-%d)}"
LOG="${IPA_LOG_DIR:-$OUT/log}"
POP_TIER="${POP_TIER:-base}"
POP_CORES="${POP_CORES:-P E}"
POP_T2="${POP_T2:-1}"
# T2-T1 e' piatto sul rate; due rate sotto la capacita' del modello piu'
# pesante della popolazione sull'E-core, con l'uscita sulla CPU del nodo.
POP_RATES="${POP_RATES:-0.25,0.5}"
# POP_SOLO="m003 m017": solo questi modelli, in tutte le sezioni
POP_SOLO="${POP_SOLO:-}"
# giri delle curve al crescere del rate (5 nella campagna di ottobre)
CARICO_ROUNDS="${CARICO_ROUNDS:-3}"
POP_RIFAI="${POP_RIFAI:-0}"
mkdir -p "$LOG" "$OUT"

PY=python3
POPGEN=ipa/test/model_population.py

sudo -v || exit 1
( while true; do sudo -n true; sleep 50; done ) 2>/dev/null &
KEEP=$!
trap 'kill $KEEP 2>/dev/null; sudo chown -R "$(id -u):$(id -g)" "$ROOT/results" "$ROOT/ipa" "$LOG"' EXIT

bench() {
    local name=$1; shift
    local t0=$SECONDS
    sudo $PY "$@" > "$LOG/$name.log" 2>&1
    local rc=$?
    local dist
    dist=$(grep -c -E "NON ha girato nelle condizioni|NON e' rimasta nelle condizioni" "$LOG/$name.log")
    local hw
    hw=$(grep -c "istruzioni per ciclo non misurate" "$LOG/$name.log")
    printf '%-34s rc=%-3s %5ss%s%s\n' "$name" "$rc" "$((SECONDS - t0))" \
        "$([ "$dist" != 0 ] && echo '  [macchina disturbata: vedi il log]')" \
        "$([ "$hw" != 0 ] && echo '  [niente contatori hardware]')"
}

# La misura c'e' gia'? (ripresa). <cartella relativa a $OUT> <file>
fatto() {
    [ "$POP_RIFAI" = 1 ] && return 1
    if [ -s "$OUT/$1/$2" ]; then
        printf '%-34s gia misurato, saltato\n' "${1//\//_}"
        return 0
    fi
    return 1
}

dut_of()  { case $1 in P) echo 6;; E) echo 12;; L) echo 20;; esac; }
dut2_of() { case $1 in P) echo 6,8;; E) echo 12,16;; esac; }
egress2_of() { case $1 in P) echo 3,5;; E) echo 6,8;; esac; }
EGRESS=8
GEN=10
PIPES=baseline,p1_static,hardcoded,template,modular
RATES=0.5,1,1.5,2,2.5,3,3.5,4,5,6,7,8,9,10,11,12

# I modelli di un sottoinsieme (o tutti), filtrati da POP_SOLO.
models() {     # [sottoinsieme]
    local args=(--list)
    [ -n "${1:-}" ] && args+=(--subset "$1")
    local d
    for d in $($PY $POPGEN "${args[@]}"); do
        if [ -n "$POP_SOLO" ] && ! [[ " $POP_SOLO " == *" $(id_of "$d") "* ]]; then
            continue
        fi
        echo "$d"
    done
}
id_of() { basename "$1" | cut -d_ -f1; }

compare1() {    # <tipo> <cartella> <modello> [argomenti in piu']
    local k=$1 dir=$2 d=$3; shift 3
    local csv=compare.csv
    [[ " $* " == *" --per-class "* ]] && csv=per_class.csv
    fatto "$dir" "$csv" && return
    bench "${dir//\//_}" ipa/test/bench_throughput.py --mode compare --generator xdp \
        --rounds 3 --gen-cpus $GEN --dut-cpus "$(dut_of "$k")" --egress-cpu $EGRESS \
        --model "$d" --topology "$d" --method "$PIPES" --out "$OUT/$dir" "$@"
}

rates1() {      # <tipo> <cartella> <modello> <rates>
    local k=$1 dir=$2 d=$3 rates=$4
    fatto "$dir" rates_raw.csv && return
    bench "${dir//\//_}" ipa/test/bench_throughput.py --mode rates --generator xdp \
        --frames 64 --rounds 3 --gen-cpus $GEN --dut-cpus "$(dut_of "$k")" \
        --model "$d" --topology "$d" --method "$PIPES" --rates "$rates" \
        --out "$OUT/$dir"
}

sec_genera() {
    echo "== popolazione ($POP_TIER)"
    $PY $POPGEN --tier "$POP_TIER" > "$LOG/popolazione.log" 2>&1 || {
        echo "model_population.py fallito: vedi $LOG/popolazione.log"; exit 1; }
    tail -n 8 "$LOG/popolazione.log" | sed 's/^/  /'
    stessa_popolazione
    $PY $POPGEN --manifest "$OUT/population.csv"
}

# Il manifesto in $OUT e' quello dei modelli gia' misurati: se la popolazione
# generata adesso e' un'altra, la ripresa mescolerebbe modelli diversi sotto
# gli stessi id.
stessa_popolazione() {
    local cur=ipa/synth/population/population.csv
    [ -f "$OUT/population.csv" ] || return 0
    [ "$POP_RIFAI" = 1 ] && return 0
    if ! cmp -s "$cur" "$OUT/population.csv"; then
        echo "la popolazione generata ($cur) non e' quella gia' misurata in"
        echo "$OUT/population.csv: altra CAMPAGNA, lo stesso POP_TIER, o"
        echo "POP_RIFAI=1 per rimisurare tutto"
        exit 1
    fi
}

sec_corretto() {
    echo "== correttezza: riferimento intero contro eBPF, ogni modello"
    local f="$OUT/corretto/corretto.csv"
    mkdir -p "$OUT/corretto"
    { [ -s "$f" ] && [ "$POP_RIFAI" != 1 ]; } || echo "id,pipeline,esito,rc" > "$f"
    local d p id rc esito
    for d in $(models); do
        id=$(id_of "$d")
        for p in p1 p2 p3; do
            # ripresa: un esito conclusivo resta; un errore si riprova
            if grep -q -E "^$id,$p,(OK|NO|N/A)," "$f"; then
                continue
            fi
            sed -i "/^$id,$p,/d" "$f"
            sudo $PY ipa/test/verify_synth_kernel.py --scenario "$d" \
                --pipeline $p --n 200 > "$LOG/corretto_${id}_$p.log" 2>&1
            rc=$?
            esito=$(grep -E '^ +(OK |NO |N/A) ' "$LOG/corretto_${id}_$p.log" \
                    | tail -n 1 | awk '{print $1}')
            echo "$id,$p,${esito:-errore},$rc" >> "$f"
        done
        printf '  %-6s %s\n' "$id" "$(grep "^$id," "$f" | cut -d, -f2,3 | tr '\n' ' ')"
    done
}

sec_rif() {
    for k in $POP_CORES L; do
        echo "== tetti senza modello, nodo su $k-core (cpu$(dut_of "$k"))"
        fatto "rif_${k}core" compare.csv && continue
        bench "rif_${k}core" ipa/test/bench_throughput.py --mode compare \
            --generator xdp --rounds 3 --gen-cpus $GEN --dut-cpus "$(dut_of "$k")" \
            --egress-cpu $EGRESS --method rxonly,baseline --out "$OUT/rif_${k}core"
    done
}

sec_pop() {
    local n
    n=$(models | wc -l)
    for k in $POP_CORES; do
        echo "== popolazione, nodo su $k-core (cpu$(dut_of "$k")): $n modelli"
        local d id
        for d in $(models); do
            id=$(id_of "$d")
            compare1 "$k" "pop_${k}core/$id" "$d"
            [ "$POP_T2" = 1 ] && rates1 "$k" "pop_${k}core/$id/rates" "$d" "$POP_RATES"
        done
    done
}

sec_lpe() {
    echo "== LP E-core (cpu20, 2500 MHz), sottoinsieme lpe"
    local d
    for d in $(models lpe); do
        compare1 L "lpe/$(id_of "$d")" "$d"
    done
}

sec_carico() {
    local d k id
    for k in P E; do
        echo "== curve al crescere del rate, $k-core, sottoinsieme carico"
        for d in $(models carico); do
            id=$(id_of "$d")
            fatto "carico_${k}core/$id" bitrate.csv && continue
            bench "carico_${k}_$id" ipa/test/bench_bitrate.py --generator xdp \
                --gen-cpus $GEN --dut-cpus "$(dut_of "$k")" --egress-cpu $EGRESS \
                --rates "$RATES" --rounds "$CARICO_ROUNDS" --model "$d" \
                --topology "$d" --method "$PIPES" --no-plot \
                --out "$OUT/carico_${k}core/$id"
        done
    done
}

sec_core2() {
    local d k id
    for k in P E; do
        echo "== due core del nodo, $k-core, sottoinsieme core2"
        for d in $(models core2); do
            id=$(id_of "$d")
            fatto "core2_${k}core/$id" compare.csv && continue
            bench "core2_${k}_$id" ipa/test/bench_throughput.py --mode compare \
                --generator xdp --rounds 3 --gen-cpus 10,1 \
                --dut-cpus "$(dut2_of "$k")" --egress-cpu "$(egress2_of "$k")" \
                --model "$d" --topology "$d" --method "$PIPES" \
                --out "$OUT/core2_${k}core/$id"
        done
    done
}

sec_classi() {
    echo "== una sessione per classe decisa, P-core, sottoinsieme classi"
    local d
    for d in $(models classi); do
        compare1 P "classi/$(id_of "$d")" "$d" --per-class
    done
}

sec_mix() {
    echo "== TTL diversi pacchetto per pacchetto, P-core, sottoinsieme mix"
    local d
    for d in $(models mix); do
        compare1 P "mix/$(id_of "$d")" "$d" --ttl-mix 2-31
    done
}

sec_taglie() {
    echo "== taglie del frame, P-core, sottoinsieme taglie"
    local d
    for d in $(models taglie); do
        compare1 P "taglie/$(id_of "$d")" "$d" --frames 64,512,1514
    done
}

sec_sintesi() {
    [ -f "$OUT/population.csv" ] || $PY $POPGEN --manifest "$OUT/population.csv"
    $PY ipa/test/population_report.py "$OUT" > "$OUT/sintesi.md" 2> "$LOG/sintesi.log" \
        && echo "sintesi: $OUT/sintesi.md" \
        || echo "sintesi fallita: vedi $LOG/sintesi.log"
}

ALL="genera corretto rif pop lpe carico core2 classi mix taglie"
SECTIONS="${*:-$ALL}"
[ "$SECTIONS" = tutto ] && SECTIONS=$ALL
echo "campagna in $OUT, log in $LOG, popolazione $POP_TIER"
# senza manifesto le sezioni non sanno su che modelli girare
if ! [[ " $SECTIONS " == *" genera "* ]] && \
        [ ! -f ipa/synth/population/population.csv ]; then
    sec_genera
fi
# con "genera" il controllo lo fa sec_genera, sulla popolazione appena fatta
[[ " $SECTIONS " == *" genera "* ]] || stessa_popolazione
needs_hw=0
for s in $SECTIONS; do
    case $s in genera|corretto|sintesi) ;; *) needs_hw=1 ;; esac
done
if [ $needs_hw = 1 ]; then
    if sudo $PY ipa/test/hw_counters.py --cpu 6,8,12,20 --seconds 0.2 \
            > "$LOG/hw_counters.log" 2>&1; then
        sed 's/^/  /' "$LOG/hw_counters.log"
    else
        echo "contatori hardware non disponibili: vedi $LOG/hw_counters.log"
        [ "${IPA_NO_HW:-0}" = 1 ] || exit 1
    fi
fi
for s in $SECTIONS; do
    case $s in
        genera|corretto|rif|pop|lpe|carico|core2|classi|mix|taglie|sintesi) "sec_$s" ;;
        *) echo "sezione sconosciuta: $s ($ALL sintesi)"; exit 2 ;;
    esac
done
[ "$SECTIONS" = sintesi ] || sec_sintesi
