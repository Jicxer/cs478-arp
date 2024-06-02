#!/bin/bash

apt-get update && apt-get install sudo -y
apt-get install net-tools -y && apt-get install iputils-ping -y
apt-get install python3-scapy