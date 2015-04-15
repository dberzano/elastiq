from daemon import Daemon
import time
import logging, logging.handlers
import os

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
    self._setup_log_files()


  ## Setup use of logfiles, rotated and deleted periodically.
  def _setup_log_files(self):

    if not os.path.isdir(self._logdir):
      os.mkdir(self._logdir, 0700)
    else:
      os.chmod(self._logdir, 0700)

    format = '%(asctime)s %(name)s %(levelname)s [%(module)s.%(funcName)s] %(message)s'
    datefmt = '%Y-%m-%d %H:%M:%S'

    log_file_handler = logging.handlers.RotatingFileHandler(self._logdir+'/elastiq.log',
      mode='a', maxBytes=1000000, backupCount=30)

    log_file_handler.setFormatter(logging.Formatter(format, datefmt))
    log_file_handler.doRollover()

    self.logctl.addHandler(log_file_handler)


  ## Action to perform when some exit signal is received.
  #
  #  @return When returning True, exiting continues, when returning False exiting is cancelled
  def onexit(self):
    self.logctl.info('Acklowledging exit request')
    time.sleep(1)
    return True


  ## Main loop
  #
  #  @return Exit code of the daemon: keep it in the range 0-255
  def run(self):

    while True:
      self.logctl.debug('Hello world (debug)')
      self.logctl.info('Hello world (info)')
      self.logctl.warning('Hello world (warning)')
      self.logctl.error('Hello world (error)')
      time.sleep(1)

    return 0
