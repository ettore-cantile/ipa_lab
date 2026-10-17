#!/usr/bin/env bash
# run_population_campaign.sh -- the measurement campaign on the model population.
#
#   bash ipa/test/run_population_campaign.sh                  # everything
#   bash ipa/test/run_population_campaign.sh genera pop       # some sections
#   CAMPAGNA=results/popolazione_2026-10 bash ipa/test/run_population_campaign.sh pop
#
# Sections, in order:
#   genera    generate the population (model_population.py) and its manifest
#   corretto  integer reference vs eBPF, every model and pipeline
#   rif       rxonly and baseline without a model, once per core type
#   pop       every model at full load on P-core and E-core (bench_capacity)
#   lpe       subset on the LP E-core
#   carico    subset under growing traffic (bench_load_curve)
#   core2     subset on two cores
#   classi    subset, one session per decided class
#   mix       subset, a different TTL per packet
#   taglie    subset, 64 / 512 / 1514 byte frames
#   solo      every model, the program alone (bench_program_alone)
#   sintesi   report_population.py -> $CAMPAGNA/sintesi.md
#
# Output in $CAMPAGNA (default results/popolazione_<date>/), one folder per
# section and model; full logs in $CAMPAGNA/log/. The campaign resumes where it
# stopped: a measurement already on disk is skipped. POP_RIFAI_DISTURBATE=1
# redoes the ones the report left out (escluse.csv).
set -u
cd "$(dirname "$0")/../.."
ROOT="$PWD"
OUT="${CAMPAGNA:-$ROOT/results/popolazione_$(date +%Y-%m-%d)}"
LOG="${IPA_LOG_DIR:-$OUT/log}"
POP_TIER="${POP_TIER:-base}"
POP_CORES="${POP_CORES:-P E}"
POP_T2="${POP_T2:-1}"
POP_RATES="${POP_RATES:-0.25,0.5}"
POP_SOLO="${POP_SOLO:-}"
CARICO_ROUNDS="${CARICO_ROUNDS:-3}"
POP_RIFAI="${POP_RIFAI:-0}"
POP_RIFAI_DISTURBATE="${POP_RIFAI_DISTURBATE:-0}"
mkdir -p "$LOG" "$OUT"

PY=python3
POPGEN=ipa/test/model_population.py

sudo -v || exit 1
( while true; do sudo -n true; sleep 50; done ) 2>/dev/null &
KEEP=$!
trap 'kill $KEEP 2>/dev/null; sudo chown -R "$(id -u):$(id -g)" "$ROOT/results" "$ROOT/ipa" "$LOG"' EXIT

esito() { [ "$1" = 0 ] && echo ok || echo "ERROR (rc=$1)"; }

bench() {
    local name=$1; shift
    local t0=$SECONDS
    sudo $PY "$@" > "$LOG/$name.log" 2>&1
    local rc=$?
    local dist
    dist=$(grep -c -E "did NOT run in the declared conditions|did NOT stay in the declared conditions" "$LOG/$name.log")
    local hw
    hw=$(grep -c "instructions per cycle not measured" "$LOG/$name.log")
    printf '  %-34s %-14s %5ss%s%s\n' "$name" "$(esito "$rc")" "$((SECONDS - t0))" \
        "$([ "$dist" != 0 ] && echo '  [machine disturbed: see the log]')" \
        "$([ "$hw" != 0 ] && echo '  [no hardware counters]')"
}

da_rifare() {   # <folder relative to $OUT>
    grep -q "RUN BOCCIATO" "$OUT/$1/throughput_report.md" 2>/dev/null && return 0
    [ "$POP_RIFAI_DISTURBATE" = 1 ] || return 1
    if [ -f "$OUT/escluse.csv" ]; then
        grep -q "^$1," "$OUT/escluse.csv" && return 0
    else
        grep -q "^run_disturbed,True" "$OUT/$1/env.csv" 2>/dev/null && return 0
    fi
    return 1
}

fatto() {
    [ "$POP_RIFAI" = 1 ] && return 1
    if [ -s "$OUT/$1/$2" ] && da_rifare "$1"; then
        printf '  %-34s to redo\n' "${1//\//_}"
        return 1
    fi
    if [ -s "$OUT/$1/$2" ]; then
        printf '  %-34s already measured, skipped\n' "${1//\//_}"
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

models() {     # [subset]
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

compare1() {    # <core type> <folder> <model> [extra arguments]
    local k=$1 dir=$2 d=$3; shift 3
    local csv=compare.csv
    [[ " $* " == *" --per-class "* ]] && csv=per_class.csv
    fatto "$dir" "$csv" && return
    bench "${dir//\//_}" ipa/test/bench_capacity.py --mode compare --generator xdp \
        --rounds 3 --gen-cpus $GEN --dut-cpus "$(dut_of "$k")" --egress-cpu $EGRESS \
        --model "$d" --topology "$d" --method "$PIPES" --out "$OUT/$dir" "$@"
}

rates1() {      # <core type> <folder> <model> <rates>
    local k=$1 dir=$2 d=$3 rates=$4
    fatto "$dir" rates_raw.csv && return
    bench "${dir//\//_}" ipa/test/bench_capacity.py --mode rates --generator xdp \
        --frames 64 --rounds 3 --gen-cpus $GEN --dut-cpus "$(dut_of "$k")" \
        --model "$d" --topology "$d" --method "$PIPES" --rates "$rates" \
        --out "$OUT/$dir"
}

sec_genera() {
    echo "== population ($POP_TIER)"
    $PY $POPGEN --tier "$POP_TIER" > "$LOG/popolazione.log" 2>&1 || {
        echo "model_population.py failed: see $LOG/popolazione.log"; exit 1; }
    tail -n 8 "$LOG/popolazione.log" | sed 's/^/  /'
    stessa_popolazione
    $PY $POPGEN --manifest "$OUT/population.csv"
}

stessa_popolazione() {
    local cur=ipa/synth/population/population.csv
    [ -f "$OUT/population.csv" ] || return 0
    [ "$POP_RIFAI" = 1 ] && return 0
    if ! head -n "$(wc -l < "$OUT/population.csv")" "$cur" \
            | cmp -s - "$OUT/population.csv"; then
        echo "the generated population ($cur) is not the one already measured in"
        echo "$OUT/population.csv: use another CAMPAGNA, the same POP_TIER, or"
        echo "POP_RIFAI=1 to measure everything again"
        exit 1
    fi
    if ! cmp -s "$cur" "$OUT/population.csv"; then
        echo "  population extended: $(( $(wc -l < "$cur") - $(wc -l < "$OUT/population.csv") )) new models, only those are measured"
        cp "$cur" "$OUT/population.csv"
    fi
}

sec_corretto() {
    echo "== correctness: integer reference against eBPF, every model"
    local f="$OUT/corretto/corretto.csv"
    mkdir -p "$OUT/corretto"
    { [ -s "$f" ] && [ "$POP_RIFAI" != 1 ]; } || echo "id,pipeline,esito,rc" > "$f"
    local d p id rc esito
    for d in $(models); do
        id=$(id_of "$d")
        for p in p1 p2 p3; do
            if grep -q -E "^$id,$p,(OK|NO|N/A)," "$f"; then
                continue
            fi
            sed -i "/^$id,$p,/d" "$f"
            sudo $PY ipa/test/check_kernel_vs_reference.py --scenario "$d" \
                --pipeline $p --n 200 > "$LOG/corretto_${id}_$p.log" 2>&1
            rc=$?
            esito=$(grep -E '^ +(OK |NO |N/A) ' "$LOG/corretto_${id}_$p.log" \
                    | tail -n 1 | awk '{print $1}')
            echo "$id,$p,${esito:-error},$rc" >> "$f"
        done
        printf '  %-6s %s\n' "$id" "$(grep "^$id," "$f" | cut -d, -f2,3 | tr '\n' ' ')"
    done
}

sec_rif() {
    for k in $POP_CORES L; do
        echo "== ceilings without a model, node on $k-core (cpu$(dut_of "$k"))"
        fatto "rif_${k}core" compare.csv && continue
        bench "rif_${k}core" ipa/test/bench_capacity.py --mode compare \
            --generator xdp --rounds 3 --gen-cpus $GEN --dut-cpus "$(dut_of "$k")" \
            --egress-cpu $EGRESS --method rxonly,baseline --out "$OUT/rif_${k}core"
    done
}

sec_pop() {
    local n
    n=$(models | wc -l)
    for k in $POP_CORES; do
        echo "== population, node on $k-core (cpu$(dut_of "$k")): $n models"
        local d id
        for d in $(models); do
            id=$(id_of "$d")
            compare1 "$k" "pop_${k}core/$id" "$d"
            [ "$POP_T2" = 1 ] && rates1 "$k" "pop_${k}core/$id/rates" "$d" "$POP_RATES"
        done
    done
}

sec_lpe() {
    echo "== LP E-core (cpu20, 2500 MHz), subset lpe"
    local d
    for d in $(models lpe); do
        compare1 L "lpe/$(id_of "$d")" "$d"
    done
}

sec_carico() {
    local d k id
    for k in P E; do
        echo "== growing-rate curves, $k-core, subset carico"
        for d in $(models carico); do
            id=$(id_of "$d")
            fatto "carico_${k}core/$id" bitrate.csv && continue
            bench "carico_${k}_$id" ipa/test/bench_load_curve.py --generator xdp \
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
        echo "== two node cores, $k-core, subset core2"
        for d in $(models core2); do
            id=$(id_of "$d")
            fatto "core2_${k}core/$id" compare.csv && continue
            bench "core2_${k}_$id" ipa/test/bench_capacity.py --mode compare \
                --generator xdp --rounds 3 --gen-cpus 10,1 \
                --dut-cpus "$(dut2_of "$k")" --egress-cpu "$(egress2_of "$k")" \
                --model "$d" --topology "$d" --method "$PIPES" \
                --out "$OUT/core2_${k}core/$id"
        done
    done
}

sec_classi() {
    echo "== one session per decided class, P-core, subset classi"
    local d
    for d in $(models classi); do
        compare1 P "classi/$(id_of "$d")" "$d" --per-class
    done
}

sec_mix() {
    echo "== a different TTL per packet, P-core, subset mix"
    local d
    for d in $(models mix); do
        compare1 P "mix/$(id_of "$d")" "$d" --ttl-mix 2-31
    done
}

sec_taglie() {
    echo "== frame sizes, P-core, subset taglie"
    local d
    for d in $(models taglie); do
        compare1 P "taglie/$(id_of "$d")" "$d" --frames 64,512,1514
    done
}

sec_solo() {
    echo "== the program alone, P-core (cpu$(dut_of P)), every model"
    local d id
    for d in $(models); do
        id=$(id_of "$d")
        fatto "compila/$id" compila.csv || \
            IPA_AOT_CACHE="$OUT/.aot_cache" $PY ipa/test/bench_program_alone.py \
                --compila --model "$d" --topology "$d" \
                --out "$OUT/compila/$id" > "$LOG/compila_$id.log" 2>&1 || \
            echo "compila_$id failed: see the log"
        fatto "solo/$id" solo.csv && continue
        local t0=$SECONDS
        sudo $PY ipa/test/host_conditions.py --run --cpu "$(dut_of P)" \
            --env "$OUT/solo/$id" -- \
            $PY ipa/test/bench_program_alone.py --model "$d" --topology "$d" \
            --out "$OUT/solo/$id" > "$LOG/solo_$id.log" 2>&1
        local rc=$?
        printf '  %-34s %-14s %5ss%s\n' "solo_$id" "$(esito "$rc")" "$((SECONDS - t0))" \
            "$(grep -q '^run_disturbed,True' "$OUT/solo/$id/env.csv" 2>/dev/null \
               && echo '  [machine disturbed: see the log]')"
    done
    rm -rf "$OUT/.aot_cache"
}

sec_sintesi() {
    [ -f "$OUT/population.csv" ] || $PY $POPGEN --manifest "$OUT/population.csv"
    $PY ipa/test/report_population.py "$OUT" > "$OUT/sintesi.md" 2> "$LOG/sintesi.log" \
        && echo "summary: $OUT/sintesi.md" \
        || echo "summary failed: see $LOG/sintesi.log"
}

ALL="genera corretto rif pop lpe carico core2 classi mix taglie solo"
SECTIONS="${*:-$ALL}"
[ "$SECTIONS" = tutto ] && SECTIONS=$ALL
echo "campaign in $OUT, logs in $LOG, population $POP_TIER"
if ! [[ " $SECTIONS " == *" genera "* ]] && \
        [ ! -f ipa/synth/population/population.csv ]; then
    sec_genera
fi
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
        echo "hardware counters not available: see $LOG/hw_counters.log"
        [ "${IPA_NO_HW:-0}" = 1 ] || exit 1
    fi
fi
for s in $SECTIONS; do
    case $s in
        genera|corretto|rif|pop|lpe|carico|core2|classi|mix|taglie|solo|sintesi) "sec_$s" ;;
        *) echo "unknown section: $s ($ALL sintesi)"; exit 2 ;;
    esac
done
[ "$SECTIONS" = sintesi ] || sec_sintesi
