#!/bin/bash

# docker-entrypoint.sh -- by Dario Berzano <dario.berzano@cern.ch>
#
# Entrypoint for a generic Debian- or RHEL-based Docker container for installing and testing
# elastiq. Drops into a shell when finished installing

package="$1"
ext=${package##*.}

if [[ $ext == deb ]] ; then
  dpkg -i "$package" || exit 1
elif [[ $ext == rpm ]] ; then
  yum localinstall -y "$package" || exit 1
else
  echo "You must provide a .rpm or .deb package as argument."
  exit 2
fi

echo '--> Running elastiq'
service elastiq start

echo '--> Dropping into an interactive shell'
exec bash
