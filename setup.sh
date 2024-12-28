#!/bin/bash

# Update package list and install system dependency
sudo apt-get update
echo Installing Radare2...
sudo apt-get install -y radare2

# Install Python dependencies
echo Installing Python dependencies...
pip install -r requirements.txt

echo Setup completed!
