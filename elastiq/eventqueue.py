import logging
import time


class EventQueue:

  """Executes events at a certain time.
  """

  def __init__(self):
    self._logger = logging.getLogger(__name__)
    self._eq = []


  def push(self, evi):
    """Adds event to the event queue.
    """
    if not isinstance(evi, EventQueueItem):
      raise EventQueueError('Only EventQueueItem objects are accepted')
    self._eq.append(evi)
    self._logger.debug('Event %s scheduled' % (evi._function.__name__))


  def loop(self):
    """A single step of the execution loop. The event loop must be controlled
    externally.
    """
    now = time.time()  # utc timestamp

    self._logger.debug('Entering event loop:')

    for ev in self._eq[:]:
      if ev.isdue(now):
        self._logger.debug('>> Executing %s' % (ev.get_function_name()))
        ev.do()
        if not ev.reschedule():
          self._logger.debug('>> Not rescheduling %s' % (ev.get_function_name()))
          self._eq.remove(ev)
      else:
        self._logger.debug('>> Not due: %s' % (ev.get_function_name()))


  def print_status(self):
    self._logger.info('Queue has %d item(s):' % (len(self._eq)))
    count = 0
    for ev in self._eq:
      count=count+1
      self._logger.info(">> %d: %s" % (count, ev))


class EventQueueError(Exception):
  """Errors of the EventQueue class.
  """
  pass


class EventQueueItem():

  """A single event in the EventQueue list.
  """

  def __init__(self, function=None, when=None, reschedule_after=None, parameters={}):
    self._logger = logging.getLogger(__name__)
    self._logger.info( type(function).__name__ )

    if not hasattr(function, '__call__'):
      raise EventQueueError('\'function\' must be a function')

    self._function = function
    self._when = when
    self._reschedule_after = reschedule_after
    self._parameters = parameters


  def __str__(self):
    """String representation of the item.
    """
    if self._reschedule_after is None:
      reschedule = 'no'
    else:
      reschedule = str(self._reschedule_after)
    return '<Function: %s> <When: %d> <Reschedule: %s> <Parameters: %s>' % (self._function.__name__, self._when, reschedule, self._parameters)


  def isdue(self, ts=None):
    """Returns if the event is due at the given timestamp. If ts is omitted,
    take the current one.
    """
    if ts is None:
      ts = time.time()
    return ts >= self._when


  def reschedule(self):
    """Reschedules the event if possible, and returns True in such case.
    Returns False otherwise.
    """
    if self._reschedule_after is not None:
      self._when = time.time() + self._reschedule_after
      return True
    return False


  def get_function_name(self):
    return self._function.__name__


  def do(self):
    """Performs the given action by expanding the dict parameters. Returns what
    the function returns.
    """
    return self._function( **self._parameters )
