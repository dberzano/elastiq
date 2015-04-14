#!/bin/bash

# docker-entrypoint.sh -- by Dario Berzano <dario.berzano@cern.ch>
#
# Entrypoint for a SLC6 Docker container for installing and testing elastiq. Drops into a shell
# when finished.

rpmfile="$1"

yum localinstall -y $rpmfile || exit 1

echo '--> Installed successfully - some debug:'
chkconfig | grep elastiq
rpm -qa | grep elastiq

echo '--> Running it'
service elastiq start

echo '--> Dropping into an interactive shell'
exec bash
