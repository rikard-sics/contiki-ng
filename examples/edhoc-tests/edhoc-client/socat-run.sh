# sudo socat -d -d UDP6-RECVFROM:5683,bind=[fd00::1],fork UDP4-SENDTO:172.17.0.1:5683

# Remember to also switch the target IP in project-conf.h to fd00::1
# Also disable the RPL_NODE functionality

# Server IP address (internal or external)
# DEST_IP="23.97.187.154"
DEST_IP="172.17.0.1" # To host system
# DEST_IP="[fe80::42:26ff:fe66:461d]" # To host system IPv6

# Trap SIGINT (CTRL-C) and exit gracefully
trap "echo 'Exiting...'; exit" SIGINT

# Avoid packet duplication by forwarding to other port than 5683 or disabling Docker port
# publishing (is maybe only a problem when sending to the host system specifically)

# Loop until socat can bind to the IPv6 address and forward packets
until socat -d -d UDP6-RECVFROM:5683,bind=[fd00::1],fork UDP4-SENDTO:$DEST_IP:5683; do
    echo "Waiting for tun0 interface to be available..."
    sleep 0.1
done
