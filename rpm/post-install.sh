#!/bin/sh
useradd elastiq --shell /sbin/nologin --no-create-home --system --user-group --home-dir /var/lib/elastiq
R=$?
if [ $R != 9 ] && [ $R != 0 ] ; then
  exit 1
fi
mkdir -p /var/lib/elastiq /var/log/elastiq
chmod u=rwx,g=rwx,o=x /var/lib/elastiq /var/log/elastiq
chown elastiq:elastiq /var/lib/elastiq /var/log/elastiq
ln -nfs /usr/bin/elastiqctl /etc/init.d/elastiq
chkconfig --add elastiq

if [ ! -e /etc/elastiq.conf ] ; then
  cat > /etc/elastiq.conf <<_EoF_
[elastiq]
sleep_s = 5
check_queue_every_s = 15
check_vms_every_s = 45
waiting_jobs_threshold = 10
waiting_jobs_time_s = 100
n_jobs_per_vm = 4
idle_for_time_s = 3600
estimated_vm_deploy_time_s = 600
batch_plugin = htcondor
log_level = 0

[debug]
#dry_run_shutdown_vms = 1
#dry_run_boot_vms = 1

[quota]
min_vms = 0
max_vms = 3

[ec2]
api_url = https://dummy.ec2.server/ec2/
aws_access_key_id = my_username
aws_secret_access_key = my_password
image_id = ami-00000000
api_version = 2013-02-01
key_name =
flavour =
user_data_b64 =
_EoF_
fi

chown elastiq:elastiq /etc/elastiq.conf
chmod u=rw,g=rw,o= /etc/elastiq.conf

exit 0
