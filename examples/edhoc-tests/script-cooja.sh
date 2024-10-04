#!/bin/bash -e

# Contiki directory
CONTIKI=$1

# Time allocated for convergence
WAIT_TIME=$2

# Connect to the simulation
echo "Starting tunslip6"
make -C $CONTIKI/examples/rpl-border-router connect-router-cooja TARGET=zoul TUNSLIP6_ARGS="-p 60002 fd01::1/64" &
MPID=$!
printf "Waiting for network formation (%d seconds)\n" "$WAIT_TIME"
sleep $WAIT_TIME

exit 1
