#!/bin/bash

default_container(){
    echo "running default script"
    echo "Installing default packages such as ping or ifconfig"
    apt-get update && apt-get install sudo -y
    apt-get install net-tools -y && apt-get install iputils-ping -y
    apt-get install iperf3 -y
}

attacker_container(){
    echo "running attacker script"
    apt-get install python3-scapy -y
    apt-get install tcpdump -y
    apt-get install wireshark -y
}

if [ -z "$1" ]; then
    echo "Usage: ./setup.sh <type of container>"
    echo "Types of containers: attacker/default"
    exit 1
fi

SCRIPT_NAME=$1
case $SCRIPT_NAME in
    default)
        default_container
        ;;
    attacker)
        default_container
        attacker_container
        ;;
    *)
        echo "Invalid argument. Please use 'default' or 'attacker'."
        exit 1
        ;;
esac
