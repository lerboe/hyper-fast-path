#!/usr/bin/env bash
# Runs the same benchmarks as `bench-local.sh`, with the load generated from
# `LOAD_GEN_HOST` over the network instead of from this machine.
set -euo pipefail
shopt -s nullglob

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
LOAD_GEN_DIR=/tmp/hyper-fast-path-bench

# the CPU the server process is confined to. the SK_SKB program runs on
# whichever CPU handles the incoming packet, not on this one, so we also pin
# NIC interrupts and packet steering to it below (see `pin_networking`)
SERVER_CPU=${SERVER_CPU:-1}
IFACE=""

declare -A ORIG_SYSFS
IRQBALANCE_STOPPED=0

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
    RUST_LOG= sudo --preserve-env=RUST_LOG taskset -c "$SERVER_CPU" "$WORKSPACE/target/release/example" \
        --addr "0.0.0.0:$SERVER_PORT" "$@" &
    sleep 1
}

# determines the NIC used to reach $LOAD_GEN_HOST
function detect_iface {
    [[ -n $IFACE ]] && return 0

    local ip
    ip=$(getent hosts "$LOAD_GEN_HOST" | awk '{ print $1; exit }')
    IFACE=$(ip -o route get "$ip" | grep -oP '(?<=dev )\S+')

    if [[ -z $IFACE ]]; then
        echo -e "${COLOR_RED}Could not determine NIC used to reach $LOAD_GEN_HOST${COLOR_OFF}"
        exit 1
    fi
}

# lists the IRQ numbers assigned to $IFACE
function iface_irqs {
    if [[ -d /sys/class/net/$IFACE/device/msi_irqs ]]; then
        ls "/sys/class/net/$IFACE/device/msi_irqs"
    else
        grep "$IFACE" /proc/interrupts | cut -d: -f1 | tr -d ' ' || true
    fi
}

# writes $2 to $1, remembering its previous contents so `restore_networking`
# can put it back
function pin {
    local path=$1 value=$2
    [[ -e $path ]] || return 0
    [[ -v ORIG_SYSFS[$path] ]] || ORIG_SYSFS[$path]=$(cat "$path")
    echo "$value" | sudo tee "$path" >/dev/null
}

function stop_irqbalance {
    if systemctl is-active --quiet irqbalance 2>/dev/null; then
        echo -e "${COLOR_YELLOW}Stop irqbalance${COLOR_OFF}"
        sudo systemctl stop irqbalance
        IRQBALANCE_STOPPED=1
    fi
}

function restore_irqbalance {
    if [[ $IRQBALANCE_STOPPED -eq 1 ]]; then
        echo -e "${COLOR_YELLOW}Restart irqbalance${COLOR_OFF}"
        sudo systemctl start irqbalance || true
        IRQBALANCE_STOPPED=0
    fi
}

# the SK_SKB program runs on whatever CPU processes the incoming packet
# (hard IRQ / softirq), which by default can be any CPU and is independent
# of the `taskset` confinement of the server process above. this pins the
# NIC's IRQs to $SERVER_CPU and disables RPS/RFS/XPS packet steering, which
# would otherwise redistribute packet processing across CPUs regardless of
# IRQ affinity. this is best-effort: the kernel can still run parts of the
# receive path (e.g. socket backlog processing) on other CPUs in rare cases
function pin_networking {
    detect_iface
    stop_irqbalance

    local mask
    mask=$(printf '%x' $((1 << SERVER_CPU)))

    echo -e "${COLOR_YELLOW}Pin $IFACE IRQs and RPS/RFS/XPS to CPU $SERVER_CPU${COLOR_OFF}"

    local irq
    for irq in $(iface_irqs); do
        pin "/proc/irq/$irq/smp_affinity_list" "$SERVER_CPU"
    done

    local q
    for q in /sys/class/net/"$IFACE"/queues/rx-*; do
        pin "$q/rps_cpus" "$mask"
        pin "$q/rps_flow_cnt" 0
    done
    for q in /sys/class/net/"$IFACE"/queues/tx-*; do
        pin "$q/xps_cpus" "$mask"
    done
    pin /proc/sys/net/core/rps_sock_flow_entries 0
}

function restore_networking {
    local path
    for path in "${!ORIG_SYSFS[@]}"; do
        echo "${ORIG_SYSFS[$path]}" | sudo tee "$path" >/dev/null 2>&1 || true
    done
    ORIG_SYSFS=()

    restore_irqbalance
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
    ssh -p ${LOAD_GEN_HOST_SSH_PORT:-22} -t "$LOAD_GEN_HOST" "~/.cargo/bin/oha $* -c 100 -z 10s -t 5s --latency-correction -o $remote_log"
    scp -P ${LOAD_GEN_HOST_SSH_PORT:-22} -q "$LOAD_GEN_HOST:$remote_log" "$log"
}

function teardown {
    kill_server
    restore_networking
    cpu_governor "schedutil"
    close_port
}

if ! ssh -p ${LOAD_GEN_HOST_SSH_PORT:-22} "$LOAD_GEN_HOST" "command -v ~/.cargo/bin/oha" >/dev/null; then
    echo -e "${COLOR_RED}oha not found on $LOAD_GEN_HOST${COLOR_OFF}"
    exit 1
fi

trap teardown EXIT
trap 'exit 1' INT TERM

cargo b -r --bin example

TESTS=(sp)
PROTOS=("" "--http2")
FILE_SIZES=(32KB)

mkdir -p "$OUT_DIR"
ssh -p ${LOAD_GEN_HOST_SSH_PORT:-22} "$LOAD_GEN_HOST" "rm -rf $LOAD_GEN_DIR && mkdir -p $LOAD_GEN_DIR"
cpu_governor "performance"
pin_networking
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
            for qps in {500..5000..500}; do
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
