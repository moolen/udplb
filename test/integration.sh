#!/bin/bash
set -eo pipefail

if [ -n "${DEBUG}" ]; then
    set -x
fi

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

cleanup () {
    docker-compose kill >/dev/null 2>&1
    docker-compose rm -f >/dev/null 2>&1
}

error () {
    echo -e "${RED}$1${NC}"
    docker-compose logs
    if [ -z ${DEBUG+x} ]; then
        cleanup
    fi
    exit 1
}

success () {
    echo -e "${GREEN}$1${NC}"
}

info () {
    echo -e "$1"
}

_exec () {
    TARGET=$1
    shift;
    docker-compose exec -T "$TARGET" "$@"
}

# $1=listener
# $2=sender
# $3=sport
_test_sport() {
    info " > it should fwd src-port $3 to $1"
    _exec "$1" /rcv -wait $wait -port 8125 >/dev/null 2>&1 &
    pid=$!
    sleep $sleep
    _exec "$2" /snd -sport "$3" >/dev/null 2>&1
    wait $pid || error "packet not seen at $1"
}

# $1=sender&receiver
# $2=loadbalancer
# $3=sport
_test_saddr() {
    info " > it should send traffic from port $3 to $1 via $2"
    _exec "$1" /rcv -wait $wait -port 8125 >/dev/null 2>&1 &
    pid=$!
    sleep $sleep
    _exec "$1" /snd -daddr "$2" -sport "$3" >/dev/null 2>&1
    wait $pid || error "no packet seen at $1"
}

trap 'cleanup ; printf "${RED}Tests Failed For Unexpected Reasons${NC}\n"'\
  HUP INT QUIT PIPE TERM

if ! (docker-compose build >/dev/null && docker-compose up -d >/dev/null); then
  error "docker-compose failed"
  exit 1
fi

success ">> waiting for fib to converge..."
sleep 4

wait=3s
sleep=1

#
# LB STRAT: SRC-PORT
#
success "# testing lb strategy: src-port"
_test_sport "tester_one" "tester_two" "5666"
_test_sport "tester_two" "tester_one" "60256"
success "✓ src-port works\n"

#
# LB STRAT: SRC-IP
#
success "# testing lb strategy: src-ip"
# 10.123.100.20 -> 10.123.100.10 -> 10.123.100.20
_test_saddr "tester_three" "10.123.100.10" "5666"
_test_saddr "tester_three" "10.123.100.10" "60256"
# 10.123.100.21 -> 10.123.100.10 -> 10.123.100.21
_test_saddr "tester_four" "10.123.100.10" "5666"
_test_saddr "tester_four" "10.123.100.10" "60256"
success "✓ src-ip works\n"

cleanup
success "\\o/ done with tests"
