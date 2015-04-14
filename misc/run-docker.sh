#!/bin/bash

# run-docker.sh -- by Dario Berzano <dario.berzano@cern.ch>
#
# Run an appropriate Docker container to debug elastiq on SLC6. The "misc" directory is exposed in
# the container as readonly under /external by default. Runs an "entrypoint" script that must be in
# the same directory of this one.

# Configure variables here
docker_image='dberzano/slc6-elastiqenv'
ext_mountpoint='/external'

set -e
cd "$( dirname "$0" )"

# create package for slc6
./create-packs.sh --python-version 2.6 --iteration 1 --verbose --targets rpm --suffix py26

rpmfile=$( ls -1t dist/python-elastiq*py26*.rpm | head -n1 )
echo "created rpm: ${rpmfile}"

# Run a disposable container. Mount external volume as readonly
exec docker run -i -t --rm -v "${PWD}:${ext_mountpoint}:ro" "$docker_image" \
  "${ext_mountpoint}/docker-entrypoint.sh" "${ext_mountpoint}/${rpmfile}"
