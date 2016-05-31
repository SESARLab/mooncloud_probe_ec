#!/bin/bash

echo -e "MOON Cloud\n\n******** Installing Encription Channel probe\n\n"
yum -y install nmap
pip2 install python-libnmap
cp nmapScript/* /usr/share/nmap/scripts/
cp EncryptedChannel.py /usr/lib//usr/lib/python2.7/site-packages/testagent-0.1.0-py2.7.egg/testagent/probes/

