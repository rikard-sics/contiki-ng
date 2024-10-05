#!/bin/bash

# Set the Stockholm timezone
sudo rm /etc/localtime
sudo ln -s /usr/share/zoneinfo/Europe/Stockholm /etc/localtime

# Install useful programs
sudo apt install socat
sudo apt install nano
sudo apt install tcpdump

