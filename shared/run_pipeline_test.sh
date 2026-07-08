#!/bin/bash
# =============================================================================
# run_pipeline_test.sh  —  Wrapper rapido per testare le 3 pipeline in sequenza
# =============================================================================
# Da eseguire sull'HOST (non dentro Kathara) dopo kathara lstart.
#
# Esegue test_kathara.sh per ciascuna pipeline e salva i risultati in
# /tmp/pipeline_results/
#
# Usage:
#   bash /shared/run_pipeline_test.sh
#   bash /shared/run_pipeline_test.sh hardcoded    # solo pipeline 1
#
# Output:
#   /tmp/pipeline_results/hardcoded.log
#   /tmp/pipeline_results/template.log
#   /tmp/pipeline_results/modular.log
#   /tmp/pipeline_results/summary.txt
# =============================================================================

set -e

RESULTS_DIR="/tmp/pipeline_results"
mkdir -p "$RESULTS_DIR"

METHODS=("hardcoded" "template" "modular")

# Se viene passato un metodo specifico, testa solo quello
if [ -n "$1" ]; then
    METHODS=("$1")
fi

echo "================================================="
echo " IPA Pipeline Test Suite — Kathara"
echo " $(date)"
echo "================================================="
echo

SUMMARY="$RESULTS_DIR/summary.txt"
echo "Pipeline Test Results — $(date)" > "$SUMMARY"
echo "=========================================" >> "$SUMMARY"

for METHOD in "${METHODS[@]}"; do
    echo "--- Testing pipeline: $METHOD ---"
    LOG="$RESULTS_DIR/${METHOD}.log"

    bash /shared/test_kathara.sh "$METHOD" 2>&1 | tee "$LOG"

    # Estrai numero pacchetti ricevuti dal log
    RECEIVED=$(grep -oP 'Received\s*:\s*\K[0-9]+' "$LOG" | tail -1 || echo "?")
    STATUS=$(grep -o 'TEST PASSED\|TEST FAILED' "$LOG" | tail -1 || echo "UNKNOWN")

    echo "$METHOD: received=$RECEIVED  status=$STATUS" >> "$SUMMARY"
    echo

    # Pausa tra una pipeline e l'altra (tempo per cleanup XDP)
    if [ ${#METHODS[@]} -gt 1 ]; then
        echo "  [pause 5s before next pipeline...]"
        sleep 5
    fi
done

echo
echo "================================================="
echo " Summary:"
cat "$SUMMARY"
echo "================================================="
echo " Full logs in: $RESULTS_DIR/"
echo "================================================="
