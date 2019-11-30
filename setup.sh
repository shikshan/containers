#!/bin/bash

echo "Setting up vagrant environment..."
vagrant plugin install vagrant-vbguest --local
vagrant up
echo "You can safely ignore the errors in the Guest Additions installation..."
echo "Rebooting the VM..."
vagrant reload
echo "Connecting to VM..."
vagrant ssh
exit 0
