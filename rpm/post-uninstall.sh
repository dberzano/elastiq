#!/bin/sh
if [ $1 != 0 ] ; then
  # when $1 is 0 --> remove; else, upgrading
  exit 0
fi
chkconfig --del elastiq
rm -f /etc/init.d/elastiq
userdel elastiq --remove --force
groupdel elastiq
exit 0
