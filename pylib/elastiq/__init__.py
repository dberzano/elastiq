from daemon import Daemon
import time
import logging, logging.handlers
import os
import re
from ConfigParser import SafeConfigParser


class Elastiq(Daemon):

  ## Current version of elastiq
  __version__ = '0.9.10'

  ## Configuration dictionary (two-levels deep)
  cf = {}
  cf['elastiq'] = {

    # Main loop
    'sleep_s': 5,
    'check_queue_every_s': 15,
    'check_vms_every_s': 45,
    'check_vms_in_error_every_s': 20,
    'estimated_vm_deploy_time_s': 600,

    # Conditions to start new VMs
    'waiting_jobs_threshold': 0,
    'waiting_jobs_time_s': 40,
    'n_jobs_per_vm': 4,

    # Conditions to stop idle VMs
    'idle_for_time_s': 3600,

    # Batch plugin
    'batch_plugin': 'htcondor',

    # Log level (lower is more verbose)
    'log_level': 0

  }
  cf['ec2'] = {

    # Configuration to access EC2 API
    'api_url': 'https://dummy.ec2.server/ec2/',
    'api_version': None,
    'aws_access_key_id': 'my_username',
    'aws_secret_access_key': 'my_password',

    # VM configuration
    'image_id': 'ami-00000000',
    'key_name': '',
    'flavour': '',
    'user_data_b64': ''

  }
  cf['quota'] = {

    # Min and max VMs
    'min_vms': 0,
    'max_vms': 3

  }
  cf['debug'] = {

    # Set to !0 to dry run
    'dry_run_shutdown_vms': 0,
    'dry_run_boot_vms': 0

  }
  cf['substitute'] = {

    # Variables substituted in the user-data template.
    # If set, they have precedence on automatic detection.
    # In most cases you do not need to set them manually.
    'ipv4': None,
    'ipv6': None,
    'fqdn': None

  }

  ec2h = None
  ec2img = None
  user_data = None
  _do_main_loop = True
  _robust_cmd_kill_timer = None

  # Alias to the batch plugin module
  BatchPlugin = None

  # List of owned instances (instance IDs)
  owned_instances = []

  # Text file containing the list of managed instances (one instance ID per line)
  state_file = None


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


  ## Setup use of logfiles, rotated and deleted periodically.
  #
  #  @return Nothing is returned
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


  ## Given any object it returns its type.
  #
  #  @return A string with the Python object type
  @staticmethod
  def _type2str(any):
    return type(any).__name__


  ## Returns the IPv4 address of a host given its HTCondor name. In case HTCondor uses NO_DNS,
  #  HTCondor names start with the IP address with dashes instead of dots, and such IP is returned.
  #  In any other case, the function returns the value returned by socket.gethostbyname().
  #
  #  @return A string with an IPv4 address corresponding to a certain HTCondor host
  @staticmethod
  def gethostbycondorname(name):
    htcondor_ip_name_re = r'^(([0-9]{1,3}-){3}[0-9]{1,3})\.'
    m = re.match(htcondor_ip_name_re, name)
    if m is not None:
      return m.group(1).replace('-', '.')
    else:
      return socket.gethostbyname(name)


  ## Parses the configuration file. Defaults are available for each option. Unknown options are
  #  ignored silently.
  #
  #  @return True if file was read successfully, False otherwise
  def _load_conf(self):

    cf_parser = SafeConfigParser()

    # Try to open configuration file (read() can get a list of files as well)
    conf_file_ok = True
    if len(cf_parser.read(self._conffile)) == 0:
      self.logctl.warning("Cannot read configuration file %s" % self._conffile)
      conf_file_ok = False

    for sec_name,sec_content in self.cf.iteritems():

      for key,val in sec_content.iteritems():

        try:
          new_val = cf_parser.get(sec_name, key)  # --> [sec_name]
          try:
            new_val = float(new_val)
          except ValueError:
            pass
          self.cf[sec_name][key] = new_val
          self.logctl.info("Configuration: %s.%s = %s (from file)", sec_name, key, str(new_val))
        except Exception, e:
          self.logctl.info("Configuration: %s.%s = %s (default)", sec_name, key, str(val))

    return conf_file_ok


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

    self._setup_log_files()

    while True:
      self.logctl.debug('Hello world (debug)')
      self.logctl.info('Hello world (info)')
      self.logctl.warning('Hello world (warning)')
      self.logctl.error('Hello world (error)')
      time.sleep(1)

    return 0
