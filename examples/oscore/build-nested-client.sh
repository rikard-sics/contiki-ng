#!/bin/sh
# Build nested-oscore-client.native.
#
# Must be built in isolation.
# 'make all' will not properly set OSCORE_CLIENT_MODE.
# That flag controls whether the inner OSCORE response layer is decrypted.

set -e
cd "$(dirname "$0")"
make clean
make TARGET=native nested-oscore-client.native
