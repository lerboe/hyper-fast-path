#!/usr/bin/env bash
# Runs the same benchmarks as `bench-local.sh`, with the load generated from
# `LOAD_GEN_HOST` over the network instead of from this machine.
set -euo pipefail

COLOR_RED='\033[0;31m'
COLOR_GREEN='\033[0;32m'
COLOR_YELLOW='\033[0;33m'
COLOR_OFF='\033[0m' # No Color

while getopts "n:" opt; do
    case $opt in
        n ) NAME=${OPTARG} ;;

        \?)
            echo "Invalid option: -$OPTARG"
            ;;
    esac
done

WORKSPACE=$(dirname "$(readlink -f "$0")")/..
RES_DIR=$WORKSPACE/res

if [[ -z ${NAME:-} ]]; then
    echo -e "${COLOR_RED}No run name given, use -n <name>${COLOR_OFF}"
    exit 1
fi

if [[ -z ${LOAD_GEN_HOST:-} ]]; then
    echo -e "${COLOR_RED}LOAD_GEN_HOST not set${COLOR_OFF}"
    exit 1
fi

OUT_DIR=$RES_DIR/$NAME

# the address the load generator reaches this machine under
SERVER_HOST=${SERVER_HOST:-$(uname -n)}
SERVER_PORT=${SERVER_PORT:-8080}
LOAD_GEN_DIR=/tmp/beeper-axum-bench

if [[ $(ulimit -n) -lt 10000 ]]; then
    echo -e "${COLOR_RED}Low open files limit ($(ulimit -n)). Please increase and try again.${COLOR_OFF}"
    exit 1
fi

function cpu_governor {
    echo -e "${COLOR_YELLOW}Set CPU governor: $1${COLOR_OFF}"
    echo $1 | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor >/dev/null
}

function kill_server {
    sudo pkill -f '[t]arget/release/example' || true
}

function start_server {
    kill_server
    RUST_LOG= sudo --preserve-env=RUST_LOG taskset -c 1 "$WORKSPACE/target/release/example" \
        --addr "0.0.0.0:$SERVER_PORT" "$@" &
    sleep 1
}

function ufw_active {
    sudo ufw status 2>/dev/null | grep -q "Status: active"
}

function firewall_rule {
    local ip
    ip=$(getent hosts "$LOAD_GEN_HOST" | awk '{ print $1; exit }')
    echo "from $ip to any port $SERVER_PORT proto tcp"
}

function open_port {
    ufw_active || return 0

    echo -e "${COLOR_YELLOW}Open port $SERVER_PORT to $LOAD_GEN_HOST${COLOR_OFF}"
    # shellcheck disable=SC2046
    sudo ufw allow $(firewall_rule) >/dev/null
}

function close_port {
    ufw_active || return 0

    echo -e "${COLOR_YELLOW}Close port $SERVER_PORT${COLOR_OFF}"
    # shellcheck disable=SC2046
    sudo ufw delete allow $(firewall_rule) >/dev/null || true
}

# runs oha on the load generator and copies its output to `log`
function load {
    local log=$1
    shift

    local remote_log
    remote_log=$LOAD_GEN_DIR/$(basename "$log")

    # oha only draws its progress on a terminal, which ssh only sets up on the
    # remote end when asked to
    # shellcheck disable=SC2029
    ssh -t "$LOAD_GEN_HOST" "~/.cargo/bin/oha $* -c 100 -z 15s --latency-correction -o $remote_log"
    scp -q "$LOAD_GEN_HOST:$remote_log" "$log"
}

function teardown {
    kill_server
    cpu_governor "schedutil"
    close_port
}

if ! ssh "$LOAD_GEN_HOST" "command -v ~/.cargo/bin/oha" >/dev/null; then
    echo -e "${COLOR_RED}oha not found on $LOAD_GEN_HOST${COLOR_OFF}"
    exit 1
fi

trap teardown EXIT
trap 'exit 1' INT TERM

cargo b -r --bin example

TESTS=(bl fp sp)
PROTOS=("" "--http2")
QPS=(1000 2000 3000 4000 5000 6000 7000 8000 9000 10000 11000 12000 13000 14000 15000)
FILE_SIZES=(16KB)

mkdir -p "$OUT_DIR"
ssh "$LOAD_GEN_HOST" "rm -rf $LOAD_GEN_DIR && mkdir -p $LOAD_GEN_DIR"
cpu_governor "performance"
open_port

for test in "${TESTS[@]}"; do
    # the baseline runs without any eBPF, the slow path serves an asset that is
    # not registered with the fast path
    SERVER_FLAGS=()
    [[ $test == bl ]] && SERVER_FLAGS+=(--no-fastpath)
    SUFFIX=""
    [[ $test == sp ]] && SUFFIX=-sp

    for proto in "${PROTOS[@]}"; do
        for size in "${FILE_SIZES[@]}"; do
            for qps in "${QPS[@]}"; do
                log=$OUT_DIR/$test${proto:+-http2}-${size}-${qps}.log
                req=http://$SERVER_HOST:$SERVER_PORT/${size}${SUFFIX}.txt

                echo -e "${COLOR_GREEN}==> $test${proto:+ http2} $size @ $qps qps from $LOAD_GEN_HOST${COLOR_OFF}"

                start_server "${SERVER_FLAGS[@]}"
                load "$log" ${proto:+"$proto"} -q "$qps" "$req"
                kill_server
            done
        done
    done
done
