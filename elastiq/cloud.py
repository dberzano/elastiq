import logging
import boto
import random

from elastiq.node import NodeCloud, NodeError


class Cloud(object):

  '''Abstract cloud backend. For now, it is dummy.'''

  def __init__(self, name, nodes_list=None, image_id=None, user_data=None, profile=None):
    '''Some common variables defined here. Others in specialized classes.
    Cloud classes are allowed to manipulate the nodes list.'''
    self._logger = logging.getLogger(__name__)
    self._prova = 'prova'
    self._name = name
    self._user_data = user_data
    self._image_id = image_id
    self._profile = profile


  def instances(self):
    '''Returns a list of Node objects corresponding to all instances.'''
    return None


  def scaleup(self, n):
    '''Start n more nodes. Returns the list of successful nodes.'''
    new_nodes = []
    for i in range(0,n):
      node = _run()
      if node is not None:
        new_nodes.append(node)
    return new_nodes


  def scaledown(self, nodes):
    '''Terminates the given nodes. Returns the number of successful
    terminations.'''
    return 0


  def _run(self):
    '''Requests an instance. Returns the instance ID, or None on failure.'''
    return None



class CloudError(Exception):
  '''Errors of the EventQueue class.'''
  pass


class CloudDummy(Cloud):

  '''Simulates a real cloud.'''

  def __init__(self, name, n_vms=10, nodes_list=None, image_id=None, user_data=None, profile=None, ec2_url=None, ec2_access_key=None, ec2_secret_key=None, ec2_api_ver=None):
    super(CloudDummy, self).__init__(name, nodes_list=nodes_list, image_id=image_id, user_data=user_data, profile=profile)

    base_states = [ 'running', 'terminated', 'error' ]
    states = [ base_states[i % len(base_states)] for i in range(0,n_vms) ]
    addresses = [ '172.16.38.%d' % i for i in range(1,n_vms+1) ]
    for i in range(0,n_vms):
      if i % 6 == 0:
        addresses[i] = ''

    self._instances = []
    for i in range(0,n_vms): # [0,n_vms[
      node = NodeCloud(
        cloud=self._name,
        cloud_id='i-%08x' % i,
        cloud_state=states[i],
        address=addresses[i]
      )
      self._instances.append(node)
    self._instancecount = n_vms


  def instances(self):
    '''Returns the list of instances. Sometimes (1/4) it simulates an error.'''
    if random.random() > 0.75:
      return None
    return self._instances


  def _run(self):
    ''''Runs an instance, simulates an error 1/4 times.'''
    if random.random() > 0.75:
      return None
    if self._instancecount % 2 == 0:
      state = 'running'
    else:
      state = 'error'
    node = NodeCloud(
      cloud=self._name,
      cloud_id='i-%08x' % self._instancecount,
      cloud_state=state,
      address='172.16.38.%d' % self._instancecount+1
    )
    self._instancecount+=1
    return node


class CloudEC2(Cloud):

  '''EC2 cloud.'''

  def __init__(self, name, nodes_list=None, image_id=None, user_data=None, profile=None, ec2_url=None, ec2_access_key=None, ec2_secret_key=None, ec2_api_ver=None):
    super(CloudEC2, self).__init__(name, nodes_list=nodes_list, image_id=image_id, user_data=user_data, profile=profile)
    self._ec2 = boto.connect_ec2_endpoint(
      ec2_url,
      aws_access_key_id=ec2_access_key,
      aws_secret_access_key=ec2_secret_key,
      api_version=ec2_api_ver
    )


  def instances(self):
    try:
      inst = self._ec2.get_only_instances()
    except Exception as e:
      self._logger.error(e)
      return None

    nodes = []

    for i in inst:
      node = NodeCloud(
        cloud=self._name,
        cloud_id=i.id,
        cloud_state=i.state,
        address=i.private_ip_address,
      )
      nodes.append(node)

    return nodes















