#!/usr/bin/env bash
# End to end tests of the fast path, for clients on the server's host and for
# ones reaching it over a veth pair from a network namespace of their own.
set -uo pipefail

COLOR_RED='\033[0;31m'
COLOR_GREEN='\033[0;32m'
COLOR_YELLOW='\033[0;33m'
COLOR_OFF='\033[0m' # No Color

WORKSPACE=$(dirname "$(readlink -f "$0")")/..
ASSETS=$WORKSPACE/example/assets
TMP=$(mktemp -d)
LOG=$TMP/server.log

SRV_NS=beeper-srv
CLI_NS=beeper-cli
SRV_IP=10.78.0.1
CLI_IP=10.78.0.2
PORT=8080

SIZES=(1KB 8KB 16KB 32KB 48KB 64KB)

PASSED=0
FAILED=0

function teardown_netns {
    sudo pkill -f '[t]arget/release/example' || true
    sudo ip netns del $SRV_NS 2>/dev/null || true
    sudo ip netns del $CLI_NS 2>/dev/null || true
}

function cleanup {
    teardown_netns
    rm -rf "$TMP"
}

# both ends get a namespace of their own, which keeps the host's firewall out
# of the way
function setup_netns {
    sudo ip netns add $SRV_NS
    sudo ip netns add $CLI_NS
    sudo ip -n $SRV_NS link add veth-srv type veth peer name veth-cli netns $CLI_NS
    sudo ip -n $SRV_NS addr add $SRV_IP/24 dev veth-srv
    sudo ip -n $CLI_NS addr add $CLI_IP/24 dev veth-cli
    for ns in $SRV_NS $CLI_NS; do
        sudo ip -n $ns link set lo up
    done
    sudo ip -n $SRV_NS link set veth-srv up
    sudo ip -n $CLI_NS link set veth-cli up
}

# `ip netns exec` would remount /sys, hiding the cgroup the fast path attaches to
function in_netns {
    local ns=$1
    shift

    # the files curl writes have to stay readable for the checks
    sudo --preserve-env=RUST_LOG nsenter --net=/run/netns/"$ns" sh -c 'umask 022 && exec "$@"' sh "$@"
}

# how long to give the fast path to put a dummy socket back into its pool
RECYCLE_WAIT=0.5

function start_server {
    # truncated up front, or the wait below could still find the last server's
    # line in it
    : >"$LOG"
    RUST_LOG=example=debug,tower_http=debug \
        in_netns $SRV_NS "$WORKSPACE/target/release/example" --addr 0.0.0.0:$PORT "$@" >>"$LOG" 2>&1 &

    for _ in $(seq 50); do
        grep -q "listening on" "$LOG" 2>/dev/null && return 0
        sleep 0.1
    done

    echo -e "${COLOR_RED}Server did not start:${COLOR_OFF}"
    cat "$LOG"
    exit 1
}

function stop_server {
    sudo pkill -f '[t]arget/release/example' || true

    for _ in $(seq 50); do
        pgrep -f '[t]arget/release/example' >/dev/null || return 0
        sleep 0.1
    done
}

# the namespace a client of `mode` lives in
function ns {
    [[ $1 == remote ]] && echo $CLI_NS || echo $SRV_NS
}

function client {
    local mode=$1
    shift

    in_netns "$(ns "$mode")" timeout 10 curl -sS "$@"
}

function host {
    [[ $1 == remote ]] && echo $SRV_IP || echo 127.0.0.1
}

# the number of requests for `file` user space has seen so far
function user_space_count {
    sed 's/\x1b\[[0-9;]*m//g' "$LOG" | grep "on_request" | grep -c "uri=[^ ]*/$1 " || true
}

function check {
    local name=$1
    shift

    if "$@"; then
        echo -e "${COLOR_GREEN}ok${COLOR_OFF}   $name"
        PASSED=$((PASSED + 1))
    else
        echo -e "${COLOR_RED}FAIL${COLOR_OFF} $name"
        FAILED=$((FAILED + 1))
    fi
}

function same_files {
    local expected=$1
    shift

    for f in "$@"; do
        cmp -s "$expected" "$f" || return 1
    done
}

# fetches `file` `n` times over a single connection, and checks every response
# as well as that at most `max_user` of the requests reached user space
function fetch {
    local mode=$1 proto=$2 file=$3 n=$4 max_user=$5

    local flags=()
    [[ $proto == h2 ]] && flags+=(--http2-prior-knowledge)

    local args=() outs=()
    for i in $(seq "$n"); do
        outs+=("$TMP/$mode-$proto-$file-$i")
        args+=("http://$(host "$mode"):$PORT/$file" -o "$TMP/$mode-$proto-$file-$i")
    done

    local before
    before=$(user_space_count "$file")

    client "$mode" "${flags[@]}" "${args[@]}" || return 1
    same_files "$ASSETS/$file" "${outs[@]}" || return 1

    # the log is written asynchronously
    sleep 0.2
    local seen=$(($(user_space_count "$file") - before))
    if ((seen > max_user)); then
        echo "     $seen of $n requests reached user space, expected at most $max_user"
        return 1
    fi
}

# a request body that reaches past the sk_buff its headers came in, followed
# by a fast path request on the same connection
function body_then_fetch {
    local mode=$1 file=$2
    local url=http://$(host "$mode"):$PORT
    local out=$TMP/$mode-body-$file

    local before
    before=$(user_space_count "$file")

    # the POST is answered with an error, so only the fast path request is
    # expected to succeed
    client "$mode" --data-binary "@$ASSETS/128KB.txt" "$url/1KB-sp.txt" -o /dev/null \
        --next -sS "$url/$file" -o "$out" || return 1

    same_files "$ASSETS/$file" "$out" || return 1

    sleep 0.2
    (($(user_space_count "$file") - before == 0))
}

# connections one after the other, each of which is lent the dummy the one
# before left its HTTP/2 state in
function reuses_dummy {
    local mode=$1

    for _ in 1 2 3; do
        fetch "$mode" h2 64KB.txt 3 1 || return 1
        sleep $RECYCLE_WAIT
    done
}

# a connection closed in the middle of a request body, which leaves its dummy
# expecting the rest of it
function aborted_body_then_fetch {
    local mode=$1

    in_netns "$(ns "$mode")" timeout 5 bash -c "exec 3<>/dev/tcp/$(host "$mode")/$PORT && \
        printf 'POST /1KB-sp.txt HTTP/1.1\r\nHost: beeper\r\nContent-Length: 1000000\r\n\r\npartial' >&3" ||
        return 1
    sleep $RECYCLE_WAIT

    fetch "$mode" h1 64KB.txt 3 0
}

# a connection that finds no dummy left is served by user space alone, and the
# fast path takes over again once one is free
function exhausted_pool {
    local mode=$1 file=64KB.txt

    in_netns "$(ns "$mode")" timeout 5 bash -c "exec 3<>/dev/tcp/$(host "$mode")/$PORT && sleep 2" &
    local holder=$!
    sleep 0.5

    local before
    before=$(user_space_count "$file")

    local res=0
    fetch "$mode" h1 "$file" 3 3 || res=1

    local seen=$(($(user_space_count "$file") - before))
    wait $holder

    ((res == 0)) || return 1
    if ((seen != 3)); then
        echo "     $seen of 3 requests reached user space, expected all of them"
        return 1
    fi

    sleep $RECYCLE_WAIT
    fetch "$mode" h1 "$file" 3 0
}

trap cleanup EXIT
trap 'exit 1' INT TERM

cargo b -r --bin example || exit 1

teardown_netns
setup_netns
start_server

for mode in local remote; do
    echo -e "${COLOR_YELLOW}==> $mode clients${COLOR_OFF}"

    for size in "${SIZES[@]}"; do
        check "$mode h1 fast path $size" fetch "$mode" h1 "$size.txt" 3 0
        check "$mode h1 slow path $size" fetch "$mode" h1 "$size-sp.txt" 2 2

        # the first request goes out before the client acknowledged the
        # server's SETTINGS, which the fast path leaves to user space
        check "$mode h2 fast path $size" fetch "$mode" h2 "$size.txt" 3 1
        check "$mode h2 slow path $size" fetch "$mode" h2 "$size-sp.txt" 1 1
    done

    check "$mode h1 request body, then fast path" body_then_fetch "$mode" 64KB.txt
done

stop_server
start_server --dummies 1

for mode in local remote; do
    echo -e "${COLOR_YELLOW}==> $mode clients, a single dummy socket${COLOR_OFF}"

    check "$mode h2 connections reusing a dummy" reuses_dummy "$mode"
    check "$mode h1 aborted request body, then fast path" aborted_body_then_fetch "$mode"
    check "$mode connection finding no dummy" exhausted_pool "$mode"
done

echo
if ((FAILED > 0)); then
    cp "$LOG" /tmp/beeper-axum-test-server.log
    echo -e "${COLOR_RED}$FAILED failed${COLOR_OFF}, $PASSED passed (server log in /tmp/beeper-axum-test-server.log)"
    exit 1
fi

echo -e "${COLOR_GREEN}$PASSED passed${COLOR_OFF}"
