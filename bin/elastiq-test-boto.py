#!/usr/bin/python

# Test if Boto works by listing currently running instances. Uses three env
# params: EC2_URL, ...

import boto
import os

def main():

  ec2_url = os.environ.get('EC2_URL')
  ec2_access_key = os.environ.get('EC2_ACCESS_KEY')
  ec2_secret_key = os.environ.get('EC2_SECRET_KEY')
  ec2_api_version = os.environ.get('EC2_API_VERSION')

  print "Environment:"
  print "EC2_URL: %s" % ec2_url
  print "EC2_ACCESS_KEY: %s" % ec2_access_key
  print "EC2_SECRET_KEY: %s" % ec2_secret_key
  print "EC2_API_VERSION: %s" % ec2_api_version

  if ec2_url is None or ec2_access_key is None or ec2_secret_key is None:
    print "You must set all the proper EC2_* envvars for making it work."
    exit(1)

  # Initialize EC2 connection
  ec2h = boto.connect_ec2_endpoint(
    ec2_url,
    aws_access_key_id=ec2_access_key,
    aws_secret_access_key=ec2_secret_key,
    api_version=ec2_api_version)

  # Try to list VMs and images
  try:

    res = ec2h.get_all_reservations()

    print "\n=== Instances ==="
    for r in res:
      for i in r.instances:
        print "id=%s type=%s name=%s ip=%s key=%s state=%s" % (i.id, i.instance_type, i.public_dns_name, i.private_ip_address, i.key_name, i.state)

    img = ec2h.get_all_images()

    print "\n=== Images ==="
    for im in img:
      print "id=%s name=%s" % (im.id, im.name)


  except Exception, e:
    print "Boto can't talk to EC2: check your credentials"
    exit(2)

# Execute main() function when invoked as an executable
if __name__ == "__main__":
  main()
