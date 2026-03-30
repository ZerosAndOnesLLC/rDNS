#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
RDNS_BIN="$PROJECT_DIR/target/release/rdns"
QUERY_FILE="$SCRIPT_DIR/queryfile.txt"
RESULTS_DIR="$SCRIPT_DIR/results"

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

QUERIES=$(wc -l < "$QUERY_FILE")
echo -e "${BLUE}=== rDNS vs Unbound Benchmark ===${NC}"
echo "Query file: $QUERIES queries"
echo ""

# --- Warmup function: send each query once to populate cache ---
warmup() {
    local port=$1
    local name=$2
    echo -e "  Warming up ${name} cache..."
    dnsperf -s 127.0.0.1 -p "$port" -d "$QUERY_FILE" -c 1 -Q 500 > /dev/null 2>&1 || true
    sleep 1
}

# --- Benchmark function ---
run_bench() {
    local name=$1
    local port=$2
    local clients=$3
    local duration=$4
    local outfile=$5

    echo -e "  ${GREEN}Running: $name (${clients} clients, ${duration}s)${NC}"
    dnsperf -s 127.0.0.1 -p "$port" \
        -d "$QUERY_FILE" \
        -c "$clients" \
        -T "$duration" \
        -l "$duration" \
        -Q 50000 \
        2>&1 | tee "$outfile"
    echo ""
}

# ============================================================
# Start rDNS
# ============================================================
echo -e "${BLUE}--- Starting rDNS ---${NC}"
"$RDNS_BIN" -c "$SCRIPT_DIR/rdns-bench.toml" &
RDNS_PID=$!
sleep 1

# Verify it's running
if ! kill -0 $RDNS_PID 2>/dev/null; then
    echo "ERROR: rDNS failed to start"
    exit 1
fi
echo "rDNS running (PID $RDNS_PID) on :5553"

# ============================================================
# Start Unbound
# ============================================================
echo -e "${BLUE}--- Starting Unbound ---${NC}"
unbound -c "$SCRIPT_DIR/unbound-bench.conf" &
UNBOUND_PID=$!
sleep 1

if ! kill -0 $UNBOUND_PID 2>/dev/null; then
    echo "ERROR: Unbound failed to start"
    exit 1
fi
echo "Unbound running (PID $UNBOUND_PID) on :5554"
echo ""

# ============================================================
# Test 1: Single-client throughput (cache warmup then cached)
# ============================================================
echo -e "${BLUE}=== Test 1: Single Client — Cached Queries ===${NC}"

warmup 5553 "rDNS"
warmup 5554 "Unbound"

run_bench "rDNS (1 client, cached)" 5553 1 10 "$RESULTS_DIR/rdns-1client.txt"
run_bench "Unbound (1 client, cached)" 5554 1 10 "$RESULTS_DIR/unbound-1client.txt"

# ============================================================
# Test 2: Multi-client throughput (10 concurrent)
# ============================================================
echo -e "${BLUE}=== Test 2: 10 Concurrent Clients — Cached Queries ===${NC}"

run_bench "rDNS (10 clients, cached)" 5553 10 10 "$RESULTS_DIR/rdns-10client.txt"
run_bench "Unbound (10 clients, cached)" 5554 10 10 "$RESULTS_DIR/unbound-10client.txt"

# ============================================================
# Test 3: High concurrency (50 clients)
# ============================================================
echo -e "${BLUE}=== Test 3: 50 Concurrent Clients — Cached Queries ===${NC}"

run_bench "rDNS (50 clients, cached)" 5553 50 10 "$RESULTS_DIR/rdns-50client.txt"
run_bench "Unbound (50 clients, cached)" 5554 50 10 "$RESULTS_DIR/unbound-50client.txt"

# ============================================================
# Summary
# ============================================================
echo -e "${BLUE}=== SUMMARY ===${NC}"
echo ""
echo "Results saved to $RESULTS_DIR/"
echo ""

extract_qps() {
    grep "Queries per second" "$1" 2>/dev/null | awk '{print $NF}' || echo "N/A"
}
extract_latency() {
    grep "Average Latency" "$1" 2>/dev/null | awk '{print $(NF-1), $NF}' || echo "N/A"
}

printf "%-35s %15s %15s\n" "Test" "QPS" "Avg Latency"
printf "%-35s %15s %15s\n" "---" "---" "---"

for test in 1client 10client 50client; do
    rdns_qps=$(extract_qps "$RESULTS_DIR/rdns-${test}.txt")
    rdns_lat=$(extract_latency "$RESULTS_DIR/rdns-${test}.txt")
    ub_qps=$(extract_qps "$RESULTS_DIR/unbound-${test}.txt")
    ub_lat=$(extract_latency "$RESULTS_DIR/unbound-${test}.txt")

    printf "%-35s %15s %15s\n" "rDNS ($test)" "$rdns_qps" "$rdns_lat"
    printf "%-35s %15s %15s\n" "Unbound ($test)" "$ub_qps" "$ub_lat"
    echo ""
done

echo -e "${GREEN}Benchmark complete!${NC}"
