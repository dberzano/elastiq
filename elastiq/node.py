import logging
import pickle
from copy import copy


class NodeList:

  '''List of nodes managed by the infrastructure.'''

  def __init__(self, fn):
    self._logger = logging.getLogger(__name__)
    self._nodes = []
    self._fn = fn


  def get(self, node):
    '''Returns the node if it exists, None otherwise.'''
    for n in self._nodes:
      if n.cloud == node.cloud and n.cloud_id == node.cloud_id:
        return n
    return None


  def add(self, node):
    '''Adds a node to the list. Any type of node can be added:
    - NodeCloud (and Node) are just added (also checks for dups)
    - NodeBatch upgrades a NodeCloud to a Node if matches, elsewhere it is
      not considered
    Returns True on insert/update successful, False otherwise.'''
    if isinstance(node, NodeCloud):
      # note: Node is instance of NodeCloud and matches here
      for n in self._nodes:
        if n == node:  # overloaded
          self._logger.warning('Not adding cloud node %s/%s: already there' % (node.cloud, node.cloud_id))
          return False
      self._logger.info('Adding cloud node %s/%s' % (node.cloud, node.cloud_id))
      self._nodes.append(node)
      return True
    elif isinstance(node, NodeBatch):
      for n in copy(self._nodes): # shallow
        if node.match(n):
          self._logger.info('Adding batch information to node %s/%s' % (node.cloud, node.cloud_id))
          new_n = Node(n, node) # Node(cloud, batch)
          self._nodes.remove(n)
          self._nodes.append(new_n)
          return True
      self._logger.info('Batch node %s does not match any cloud node' % (node.address))
      return False

    return False


  def save(self):
    '''Saves the node list to a file. Uses pickle.'''
    with open(self._fn, 'w') as f:
      pickle.dump(self._nodes, f)


class NodeCloud:

  '''A cloud node.'''

  def __init__(self, copyfrom=None, address=None, cloud=None, cloud_id=None, cloud_state=None, requested_ts=None, cloud_upd_ts=None):
    if copyfrom is not None:
      self.address = copyfrom.address
      self.cloud = copyfrom.cloud
      self.cloud_state = copyfrom.cloud_state
      self.cloud_id = copyfrom.cloud_id
      self.requested_ts = copyfrom.requested_ts
      self.cloud_upd_ts = copyfrom.cloud_upd_ts
    else:
      self.address = address
      self.cloud = cloud
      self.cloud_state = cloud_state
      self.cloud_id = cloud_id
      self.requested_ts = requested_ts
      self.cloud_upd_ts = cloud_upd_ts


  def __eq__(self, other):
    '''Two cloud nodes are identical iif:
    - they belong to the same cloud
    - they have the same cloud_id'''
    if isinstance(other, NodeCloud):
      return other.cloud == self.cloud and other.cloud_id == self.cloud_id
    return NotImplemented


  def __ne__(self, other):
    '''Not equal: opposite of equal.'''
    r = self.__eq__(other)
    if r is NotImplemented:
      return r
    return not r


  def __str__(self):
    return '<NodeCloud> address=%s cloud=%s cloud_id=%s cloud_state=%s' % \
      (self.address, self.cloud, self.cloud_id, self.cloud_state)


  def match(self, other):
    if other.instanceof(NodeBatch):
      return other.match(self)
    return other.match(None) # error policy decided elsewhere


class NodeBatch:

  '''A batch node.'''

  def __init__(self, copyfrom=None, address=None, n_jobs=None, batch_upd_ts=None):
    if copyfrom is not None:
      self.address = copyfrom.address
      self.n_jobs = copyfrom.n_jobs
      self.batch_upd_ts = copyfrom.batch_upd_ts
    else:
      self.address = address
      self.n_jobs = n_jobs
      self.batch_upd_ts = batch_upd_ts


  def match(self, other):
    '''A batch node matches a cloud node when they have the same address.'''
    if other.instanceof(NodeCloud):
      return self.address == other.address
    raise NodeError('Can only match batch nodes to cloud nodes.')


  def __str__(self):
    return '<NodeBatch> address=%s n_jobs=%s batch_upd_ts=%s' % \
      (self.address, self.n_jobs, self.batch_upd_ts)


class Node(NodeCloud, NodeBatch):

  '''A batch+cloud node.'''

  def __init__(self, cloud, batch):
    NodeCloud.__init__(self, copyfrom=cloud)
    NodeBatch.__init__(self, copyfrom=batch)


  def __str__(self):
    return '<Node> %s %s' % (NodeCloud.__str__(self), NodeBatch.__str__(self))


class NodeError(Exception):
  '''Errors of the Node class.'''
  pass
