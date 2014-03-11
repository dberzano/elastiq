#!/bin/bash

#
# setup.sh -- by Dario Berzano <dario.berzano@cern.ch>
#
# This script is to test setuptools for Elastiq. Not meant for production.
#

cd $( dirname "$0" )
while [ `pwd` != '\\' ] ; do
  [ -e setup.py ] && [ -d elastiq ] && break
  cd ..
done
if [ `pwd` == '\\' ] ; then
  echo 'Cannot find Elastiq base directory'
  exit 1
fi

export PyBase="/tmp/pythonpath"
export PyFull="${PyBase}/lib/python2.6/site-packages"
export PYTHONPATH="$PyFull"
export PATH="$PyBase/bin:$PATH"

if [ "$1" == 'env' ] ; then
  export PS1='ELASTIQ [\W] \$ > '
  exec bash -i
fi

rm -rf "$PyBase"
mkdir -p "$PyFull"

if [ "$1" == 'install' ] ; then
  python setup.py install "$@" --prefix="$PyBase"
elif [ "$1" == 'rpm' ] ; then
  T=$( mktemp /tmp/elastiq-rpm.XXXXX )
  python setup.py bdist_rpm --post-install=rpm/post-install.sh --post-uninstall=rpm/post-uninstall.sh > "$T" 2>&1
  if [ $? == 0 ] ; then
    RPM=$( ls -1rt $PWD/dist/*.noarch.rpm | tail -n1 )
    echo "Install with one of:"
    echo "  yum localinstall -y $RPM"
    echo "  rpm -ivh $RPM"
  else
    cat "$T"
  fi
  rm -f "$T"
elif [ "$1" == 'distclean' ] ; then
  rm -rf build/ dist/ *.egg-info/
else
  python setup.py "$@"
fi
