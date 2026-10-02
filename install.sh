#!/bin/sh
set -eu

if [ "${VOPONO_OPENVPN3:-0}" = "1" ]; then
    cargo install --path . --features openvpn3
else
    cargo install --path .
fi
