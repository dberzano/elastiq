#!/bin/bash

#
# create-packs.sh -- by Dario Berzano <dario.berzano@cern.ch>
#
# Uses the Effing Package Manager for creating packages to distribute.
#

function pe() {
  echo -e "\033[35m> $1\033[m"
}

package_src="$( cd `dirname "$0"`/.. ; pwd )"
cd "$package_src"

# parse cmdline args
while [ $# -gt 0 ] ; do
  case "$1" in
    --iteration)
      iteration="$2"
      shift
    ;;
    --verbose)
      verbose=1
    ;;
    --clean)
      clean=1
    ;;
    --targets)
      package_targets="$2"
      shift
    ;;
    --python-version)
      python_version="$2"
      shift
    ;;
    *)
      pe "invalid param: $1"
      exit 1
    ;;
  esac
  shift
done

# dest dir *can* be under current source dir
package_dest="$package_src/misc/dist"

# clean?
if [ "$clean" == 1 ] ; then
  pe 'cleaning up packages dir'
  rm -vf "${package_dest}"/*.{rpm,deb,pkg}
  exit $?
fi

if [ "$package_targets" == '' ] ; then
  package_targets='rpm'
fi

# work dir *cannot* be under current source dir
tmpdir_rsync=$( mktemp -d /tmp/create-pack-rsync-XXXXX )
[ $? == 0 ] || exit 1
tmpdir_fpm=$( mktemp -d /tmp/create-pack-fpm-XXXXX )

mkdir -p "$package_dest"

# exclusions
exclude_fpm=( '.git' '.gitignore' 'VERSION' 'README*' 'misc' 'tmp' )
exclude_rsync=( "${exclude_fpm[@]}" '*.pyc' '*.pyo' '*.example' )

[[ $python_version == '' ]] && python_version='2.7'

# version and "iteration"
if [ "$iteration" == '' ] ; then
  iteration=$( cat misc/dist/latest_iteration 2> /dev/null || echo 0 )
  iteration=$(( iteration + 1 ))
fi
echo $iteration > misc/dist/latest_iteration
version="$( cd pylib ; python -c 'import elastiq ; print elastiq.__version__' )"
pe "Python: $python_version (override with --python-version <v>)"
pe "version: $version, iteration: $iteration (override with --iteration <n>)"

for package_format in $package_targets ; do

  rm -rf "${tmpdir_rsync}"/* "${tmpdir_fpm}"/*

  case $package_format in
    rpm) python_libdir="/usr/lib/python${python_version}/site-packages" ;;
    deb) python_libdir="/usr/lib/python${python_version}/dist-packages" ;;
    osxpkg) python_libdir="/Library/Python/${python_version}/site-packages" ;;
  esac
  pe "format: $package_format (override: --targets \"fmt1 fmt2...\"), python libdir: $python_libdir" 

  mkdir -p "${tmpdir_rsync}/${python_libdir}"
  rsync -a "${package_src}/pylib/" "${tmpdir_rsync}/${python_libdir}" \
    $( for i in ${exclude_rsync[@]} ; do echo --exclude $i ; done ) || exit 1
  mkdir -p "${tmpdir_rsync}/bin/"
  rsync -a "${package_src}/bin/" "${tmpdir_rsync}/usr/bin" \
    $( for i in ${exclude_rsync[@]} ; do echo --exclude $i ; done ) || exit 1
  rsync -a "${package_src}/etc/" "${tmpdir_rsync}/etc" \
    $( for i in ${exclude_rsync[@]} ; do echo --exclude $i ; done ) || exit 1
  chmod -R u=rwX,g=rX,o=rX "${package_src}"

  config_files=$( cd "${tmpdir_rsync}" ; find etc -type f )
  echo $config_files

  if [ "$verbose" == 1 ] ; then
    pe 'python compiling'
    python -m compileall "${tmpdir_rsync}/${python_libdir}" || exit 1
  else
    python -m compileall -q "${tmpdir_rsync}/${python_libdir}" || exit 1
  fi

  if [ "$verbose" == 1 ] ; then
    pe 'listing directory structure'
    ( cd "$tmpdir_rsync" ; find . -ls )
  fi

  author='Dario Berzano <dario.berzano@cern.ch>'
  fpm \
    -s dir \
    -t $package_format \
    -a all \
    --force \
    --depends     "python >= $python_version" \
    --depends     'python-boto' \
    --depends     'screen' \
    --name        'python-elastiq' \
    --version     "$version" \
    --iteration   "$iteration" \
    --prefix      / \
    --package     "$package_dest" \
    --workdir     "$tmpdir_fpm" \
    --vendor      "$author" \
    --maintainer  "$author" \
    --description 'Up and downscale a cluster of VMs via EC2 based on their usage' \
    --url         'https://github.com/dberzano/elastiq' \
    --after-install 'misc/fpm-scripts/after-install.sh' \
    --before-remove 'misc/fpm-scripts/before-remove.sh' \
    -C            "$tmpdir_rsync" \
    $( for i in ${config_files[@]} ; do echo --config-files $i ; done ) \
    $( for i in ${exclude_fpm[@]} ; do echo --exclude $i ; done ) \
    . || exit 1

  if [ "$verbose" == 1 ] ; then
    if [ "$package_format" == 'rpm' ] ; then
      rpm_file=$( ls -1rt "$package_dest"/*.rpm | tail -n1 )
      pe 'rpm info'
      rpm -qip "$rpm_file"
      pe 'rpm contents'
      rpm -qlp "$rpm_file"
    fi
  fi

done

rm -rf "$tmpdir_rsync" "$tmpdir_fpm"
