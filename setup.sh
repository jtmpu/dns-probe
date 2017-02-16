#!/bin/bash

echo "Installing dependencies..."
sudo apt install python-dnspython
echo "Done."

echo ""
echo "Setting up bin links."
sudo ln -s $(pwd)/dns-probe.py /usr/bin/dns-probe
