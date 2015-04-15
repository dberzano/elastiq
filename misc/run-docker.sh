#!/bin/bash

# run-docker.sh -- by Dario Berzano <dario.berzano@cern.ch>
#
# Run an appropriate Docker container to debug elastiq on several platforms. The "misc" directory is
# exposed in the container as readonly under /external by default. Runs an "entrypoint" script that
# must be in the same directory of this one.
# Configure variables here
docker_image_slc6='dberzano/slc6-elastiqenv'
docker_image_ubuntu1204='dberzano/ubuntu1204-elastiqenv'
ext_mountpoint='/external'

cd "$( dirname "$0" )"
os=$1

if [[ $os == slc6 ]] ; then
  ./create-packs.sh --python-version 2.6 --iteration 1 --verbose --targets rpm --suffix py26 || exit 2
  package=$( ls -1t dist/python-elastiq*py26*.rpm | head -n1 )
  docker_image=$docker_image_slc6
elif [[ $os == ubuntu1204 ]] ; then
  ./create-packs.sh --python-version 2.7 --iteration 1 --verbose --targets deb --suffix py27 || exit 2
  package=$( ls -1t dist/python-elastiq*py27*.deb | head -n1 )
  docker_image=$docker_image_ubuntu1204
else
  echo "${os}: not a valid os"
  exit 1
fi

set -e

echo "--> Created package: ${package}"
echo "--> Running image: ${docker_image}"

# Run a disposable container. Mount external volume as readonly
exec docker run -i -t --rm -v "${PWD}:${ext_mountpoint}:ro" "$docker_image" bash \
  "${ext_mountpoint}/docker-entrypoint.sh" "${ext_mountpoint}/${package}"
