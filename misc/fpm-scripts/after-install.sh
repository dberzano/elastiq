#!/bin/bash

# add user 'elastiq'
homedir='/var/lib/elastiq'
proguser='elastiq'
useradd $proguser --shell /sbin/nologin --no-create-home --system --user-group --home-dir "${homedir}"
r=$?
if [[ $r != 9 && $r != 0 ]] ; then
  exit 1
fi
mkdir -p "${homedir}"
chown root:${proguser} "${homedir}"
chmod u=rwx,g=rwx,o=x "${homedir}"

# register process 'elastiq'
chkconfig --add elastiq 2> /dev/null || update-rc.d elastiq defaults
r=$?
[[ $r == 0 ]] || exit $r

# configuration file perms
cf='/etc/elastiq.conf'
chown root:${proguser} "${cf}"
chmod u=rw,g=rw,o= "${cf}"

exit 0
