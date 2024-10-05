#!/bin/bash

# First try
# sudo socat -d -d UDP6-RECVFROM:5683,fork UDP6-SENDTO:[fd00::302:304:506:708]:5683

# Better
sudo socat -d -d UDP4-RECVFROM:5683,bind=172.17.0.3,fork UDP6-SENDTO:[fd00::302:304:506:708]:5683

