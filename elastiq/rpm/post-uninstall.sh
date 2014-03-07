#!/bin/sh
chkconfig --del elastiq
rm -f /etc/init.d/elastiq
userdel elastiq --remove --force
groupdel elastiq
exit 0
