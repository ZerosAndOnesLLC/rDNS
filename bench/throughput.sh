#!/bin/bash
#
# throughput.sh — peak-throughput benchmark for rDNS vs Unbound.
#
# Unlike run.sh (which caps offered load with -Q 50000 to measure
# latency-under-sustained-load), this script drives an effectively
# uncapped load and sweeps client concurrency to find each server's
# saturation point — the peak queries-per-second it can actually serve.
#
# Config via env vars (all optional):
#   DURATION   seconds per run                       (default 10)
#   CLIENTS    space-separated concurrency levels    (default "50 100 200 500")
#   THREADS    dnsperf sender threads (fixed)        (default half the cores)
#   QPS_CAP    dnsperf -Q ceiling, well above peak   (default 1000000)
#   WARMUP     "1" to warm caches, "0" to skip       (default 1)
#
# THREADS is deliberately decoupled from CLIENTS and kept well below the
# core count: the load generator and the server share this machine, so a
# fat sender thread pool would starve the server of CPU and cap the
# measured throughput at the load generator, not the server. We raise
# offered concurrency by adding clients (sockets), not threads.
#
# Example:  CLIENTS="100 400" DURATION=20 bash bench/throughput.sh
#
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
RDNS_BIN="$PROJECT_DIR/target/release/rdns"
QUERY_FILE="$SCRIPT_DIR/queryfile.txt"
RESULTS_DIR="$SCRIPT_DIR/results/throughput"

DURATION="${DURATION:-10}"
CLIENTS="${CLIENTS:-50 100 200 500}"
CORES="$(nproc 2>/dev/null || echo 4)"
THREADS="${THREADS:-$(( CORES / 2 > 0 ? CORES / 2 : 1 ))}"
QPS_CAP="${QPS_CAP:-1000000}"
WARMUP="${WARMUP:-1}"

RDNS_PORT=5553
UNBOUND_PORT=5554

mkdir -p "$RESULTS_DIR"

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

cleanup() {
    echo -e "\n${YELLOW}Cleaning up...${NC}"
    kill $RDNS_PID 2>/dev/null || true
    kill $UNBOUND_PID 2>/dev/null || true
    wait $RDNS_PID 2>/dev/null || true
    wait $UNBOUND_PID 2>/dev/null || true
}
trap cleanup EXIT

if [ ! -x "$RDNS_BIN" ]; then
    echo "ERROR: release binary not found at $RDNS_BIN"
    echo "Build it first:  cargo build --release"
    exit 1
fi

QUERIES=$(wc -l < "$QUERY_FILE")
echo -e "${BLUE}=== rDNS vs Unbound — Peak Throughput ===${NC}"
echo "Query file : $QUERIES queries"
echo "Duration   : ${DURATION}s per run"
echo "Clients    : $CLIENTS"
echo "Threads    : $THREADS sender threads (of $CORES cores; rest left for the server)"
echo "QPS cap    : $QPS_CAP (headroom; real peak is below this)"
echo ""

# --- Warmup: send each query once to populate cache ---
warmup() {
    local port=$1
    local name=$2
    [ "$WARMUP" = "1" ] || return 0
    echo -e "  Warming up ${name} cache..."
    dnsperf -s 127.0.0.1 -p "$port" -d "$QUERY_FILE" -c 1 -Q 500 > /dev/null 2>&1 || true
    sleep 1
}

# --- Single benchmark run: uncapped offered load ---
run_bench() {
    local name=$1
    local port=$2
    local clients=$3
    local outfile=$4

    echo -e "  ${GREEN}$name — ${clients} clients, ${DURATION}s${NC}"
    dnsperf -s 127.0.0.1 -p "$port" \
        -d "$QUERY_FILE" \
        -c "$clients" \
        -T "$THREADS" \
        -l "$DURATION" \
        -Q "$QPS_CAP" \
        2>&1 | tee "$outfile" | grep -E "Queries per second|Average Latency|Queries lost" | sed 's/^/    /'
    echo ""
}

extract_qps() {
    grep "Queries per second" "$1" 2>/dev/null | awk '{printf "%.0f", $NF}'
}
extract_avg_us() {
    # "Average Latency (s):  0.000093 (min ...)" -> field 4 is the avg in seconds
    grep "Average Latency" "$1" 2>/dev/null | awk '{printf "%.0f", $4*1000000}'
}
extract_lost_pct() {
    grep "Queries lost" "$1" 2>/dev/null | awk '{print $NF}' | tr -d '()%'
}

# ============================================================
# Start servers
# ============================================================
echo -e "${BLUE}--- Starting rDNS ---${NC}"
"$RDNS_BIN" -c "$SCRIPT_DIR/rdns-bench.toml" &
RDNS_PID=$!
sleep 1
kill -0 $RDNS_PID 2>/dev/null || { echo "ERROR: rDNS failed to start"; exit 1; }
echo "rDNS running (PID $RDNS_PID) on :$RDNS_PORT"

echo -e "${BLUE}--- Starting Unbound ---${NC}"
unbound -c "$SCRIPT_DIR/unbound-bench.conf" &
UNBOUND_PID=$!
sleep 1
kill -0 $UNBOUND_PID 2>/dev/null || { echo "ERROR: Unbound failed to start"; exit 1; }
echo "Unbound running (PID $UNBOUND_PID) on :$UNBOUND_PORT"
echo ""

warmup $RDNS_PORT "rDNS"
warmup $UNBOUND_PORT "Unbound"

# ============================================================
# Sweep concurrency levels
# ============================================================
for c in $CLIENTS; do
    echo -e "${BLUE}=== ${c} concurrent clients ===${NC}"
    run_bench "rDNS"    $RDNS_PORT    "$c" "$RESULTS_DIR/rdns-${c}c.txt"
    run_bench "Unbound" $UNBOUND_PORT "$c" "$RESULTS_DIR/unbound-${c}c.txt"
done

# ============================================================
# Summary
# ============================================================
echo -e "${BLUE}=== SUMMARY (peak throughput) ===${NC}"
echo ""
printf "%-9s %14s %12s %14s %12s %10s\n" "Clients" "rDNS QPS" "rDNS lat" "Unbound QPS" "Ubd lat" "Speedup"
printf "%-9s %14s %12s %14s %12s %10s\n" "-------" "--------" "--------" "-----------" "-------" "-------"

rdns_peak=0; ubd_peak=0
for c in $CLIENTS; do
    rq=$(extract_qps "$RESULTS_DIR/rdns-${c}c.txt")
    rl=$(extract_avg_us "$RESULTS_DIR/rdns-${c}c.txt")
    uq=$(extract_qps "$RESULTS_DIR/unbound-${c}c.txt")
    ul=$(extract_avg_us "$RESULTS_DIR/unbound-${c}c.txt")

    speedup=$(awk -v a="$rq" -v b="$uq" 'BEGIN{ if (b>0) printf "%.2fx", a/b; else print "n/a" }')
    printf "%-9s %14s %10sµs %14s %10sµs %10s\n" "$c" "$rq" "$rl" "$uq" "$ul" "$speedup"

    [ "${rq:-0}" -gt "$rdns_peak" ] && rdns_peak=$rq
    [ "${uq:-0}" -gt "$ubd_peak" ] && ubd_peak=$uq
done

echo ""
peak_speedup=$(awk -v a="$rdns_peak" -v b="$ubd_peak" 'BEGIN{ if (b>0) printf "%.2fx", a/b; else print "n/a" }')
echo -e "${GREEN}Peak rDNS   : ${rdns_peak} QPS${NC}"
echo -e "${GREEN}Peak Unbound: ${ubd_peak} QPS   (rDNS is ${peak_speedup} faster at peak)${NC}"
echo ""
echo "Raw results: $RESULTS_DIR/"
echo -e "${GREEN}Benchmark complete!${NC}"
