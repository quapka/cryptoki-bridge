#!/bin/bash

set -e

cleanup() {
    if [ -n "$softfido_pid" ]; then
        kill "$softfido_pid"
    fi
}

build-cryptoki() {
    cd ..
    cargo build --features=mocked_communicator
    cd -
}

build-softfido() {
    cd softfido
    cargo build 
    cd -
}

sudo echo # just to get the sudo password while the stdout is not a mess

build-cryptoki

build-softfido

trap 'cleanup' ERR

PKCS11SPY="`pwd`/../target/debug/libcryptoki_bridge.so" \
    PKCS11SPY_OUTPUT="`pwd`/pkcs11_spy_log.txt" \
    ./softfido/target/debug/softfido\
    --token-label  'Meesign: testgrp' \
    --pkcs11-module "/usr/lib/pkcs11-spy.so" &

softfido_pid=$!

sudo modprobe vhci-hcd
sudo usbip attach -r 127.0.0.1 -d 1-1

sleep 1

python3 ./softfido/python/softfido_tests.py

kill "$softfido_pid"
