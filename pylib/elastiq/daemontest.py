from daemon import Daemon
import time

class Elastiq(Daemon):

  ## Constructor.
  #
  #  @param name      Daemon name
  #  @param pidfile   File where PID is written
  #  @param conffile  Configuration file
  #  @param logdir    Directory with logfiles (rotated)
  #  @param statefile File where the status of managed VMs is kept
  def __init__(self, name, pidfile, conffile, logdir, statefile):
    super(Elastiq, self).__init__(name, pidfile)
    self._conffile = conffile
    self._logdir = logdir
    self._statefile = statefile

  ## Action to perform when some exit signal is received.
  #
  #  @return When returning True, exiting continues, when returning False exiting is cancelled
  def onexit(self):
    return True

  ## Main loop
  #
  #  @return Exit code of the daemon: keep it in the range 0-255
  def run(self):

    while True:
      print 'ciao'
      time.sleep(1)

    return 0
