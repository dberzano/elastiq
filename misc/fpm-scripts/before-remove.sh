#!/bin/bash

# stop process
/etc/init.d/elastiq stop

# deregister process 'elastiq'
if which chkconfig > /dev/null 2>&1 ; then
  chkconfig --del elastiq
  r=$?
else
  update-rc.d -f elastiq remove
  r=$?
fi
[[ $r == 0 ]] || exit $r

# delete user and group
proguser='elastiq'
userdel $proguser --remove --force
groupdel $proguser

exit 0
