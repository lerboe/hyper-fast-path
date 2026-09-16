#!/usr/bin/env bash
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
OUT_DIR=$RES_DIR/$NAME

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
    RUST_LOG= sudo --preserve-env=RUST_LOG taskset -c 1 "$WORKSPACE/target/release/example" "$@" &
    sleep 1
}

function load {
    taskset -c 2 oha "$@" -c 100 -z 30s --latency-correction
}

function teardown {
    kill_server
    cpu_governor "schedutil"

    exit 0
}

trap teardown INT TERM

cargo b -r --bin example

TESTS=(bl fp sp)
PROTOS=("" --http2)
QPS=(2000 4000 6000 8000 10000 12000 14000 16000 18000 20000)
FILE_SIZES=(8KB 16KB 32KB 48KB 64KB)

mkdir -p "$OUT_DIR"
cpu_governor "performance"

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
                req=http://127.0.0.1:8080/${size}${SUFFIX}.txt

                echo -e "${COLOR_GREEN}==> $test${proto:+ http2} $size @ $qps qps${COLOR_OFF}"

                start_server "${SERVER_FLAGS[@]}"
                load ${proto:+"$proto"} -q "$qps" -o "$log" "$req"
                kill_server
            done
        done
    done
done

teardown
