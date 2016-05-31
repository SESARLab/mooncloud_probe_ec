#!/bin/bash

echo -e "\n\n******** Installing Encription Channel probe\n\n"
yum -y install nmap
pip2 install python-libnmap
cp nmapScript/* /usr/share/nmap/scripts/