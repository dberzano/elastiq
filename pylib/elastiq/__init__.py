from daemon import Daemon
import time
import logging, logging.handlers
import os
import re
from ConfigParser import SafeConfigParser
import subprocess
import threading


class Elastiq(Daemon):

  ## Current version of elastiq
  __version__ = '0.9.99'

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


  ## Execute the given shell command in the background, in a "robust" way. Command is repeated some
  #  times if it did not succeed before giving up, and a timeout is foreseen. Output from stdout is
  #  caught and returned.
  #
  #  @param params Command to run: might be a string (it will be passed unescaped to the shell) or
  #                an array where the first element is the command, and every parameter follows
  #  @param max_attempts Maximum number of tolerated errors before giving up
  #  @param suppress_stderr Send stderr to /dev/null
  #  @param timeout_sec Timeout the command after that many seconds
  #
  #  @return A dictionary where key `exitcode` is the exit code [0-255] and `output`, which might
  #          not be present, contains a string with the output from stdout
  def robust_cmd(self, params, max_attempts=5, suppress_stderr=True, timeout_sec=45):

    shell = isinstance(params, basestring)

    for n_attempts in range(1, max_attempts+1):

      sp = None
      if self._do_main_loop == False:
        self.logctl.debug('Not retrying command upon user request')
        return None

      try:
        if n_attempts > 1:
          self.logctl.info('Waiting %ds before retrying...' % n_attempts)
          time.sleep(n_attempts)

        if suppress_stderr:
          with open(os.devnull) as dev_null:
            sp = subprocess.Popen(params, stdout=subprocess.PIPE, stderr=dev_null, shell=shell)
        else:
          sp = subprocess.Popen(params, stdout=subprocess.PIPE, shell=shell)

        # Control the timeout
        self._robust_cmd_kill_timer = threading.Timer(
          timeout_sec, self._robust_cmd_timeout_callback, [sp])
        self._robust_cmd_kill_timer.start()
        cmdoutput = sp.communicate()[0]
        self._robust_cmd_kill_timer.cancel()
        self._robust_cmd_kill_timer = None

      except OSError:
        self.logctl.error('Command cannot be executed!')
        continue

      if sp.returncode > 0:
        self.logctl.debug('Command failed (returned %d)!' % sp.returncode)
      elif sp.returncode < 0:
        self.logctl.debug('Command terminated with signal %d' % -sp.returncode)
      else:
        self.logctl.info('Process exited OK');
        return {
          'exitcode': 0,
          'output': cmdoutput
        }

    if sp:
      self.logctl.error('Giving up after %d attempts: last exit code was %d' %
        (max_attempts, sp.returncode))
      return {
        'exitcode': sp.returncode
      }
    else:
      self.logctl.error('Giving up after %d attempts' % max_attempts)
      return None


  ## Private callback invoked when a command run via robust_cmd reaches timeout.
  #
  #  @return Nothing is returned
  def _robust_cmd_timeout_callback(self, subp):
    if subp.poll() is None:
      # not yet finished
      try:
        subp.kill()
        self.logctl.error('Command timeout reached: terminated')
      except:
        # might have become "not None" in the meanwhile
        pass


  ## Action to perform when some exit signal is received.
  #
  #  @return When returning True, exiting continues, when returning False exiting is cancelled
  def onexit(self):
    self.logctl.info('Termination requested: we will exit gracefully soon')
    self._do_main_loop = False
    try:
      self._robust_cmd_kill_timer.cancel()
    except Exception:
      pass

    return True


  ## Returns a boto Image object containing the image corresponding to a certain image AMI ID.
  #
  #  @param image_id The image unique identifier
  #
  #  @return An image object, or None if not found
  def ec2_image(self, image_id):
    found = False
    img = None
    try:
      for img in ec2h.get_all_images():
        if img.id == self.cf['ec2']['image_id']:
          found = True
          break
    except Exception:
      self.logctl.error('Cannot make an EC2 connection to retrieve image info!')

    if not found:
      return None

    return img


  ## Returns all running instances visible with current EC2 credentials, or None on errors. If
  #  hostnames is specified, it returns the sole running instances whose IP address matches the
  #  resolved input hostnames. Returned object is a list of boto instances.
  #
  #  @param hostnames An optional list of valid hostnames to filter EC2 results
  #
  #  @return List of instances, or None on error
  def ec2_running_instances(self, hostnames=None):
    try:
      try:
        res = ec2h.get_all_reservations()  # boto 2.34.1
      except AttributeError:
        self.logctl.debug('Using old boto call for getting reservations')
        res = ec2h.get_all_instances()  # boto 2.2.2
    except Exception, e:
      self.logctl.error('Cannot get list of EC2 instances (maybe wrong credentials?)')
      return None

    # Resolve IPs
    if hostnames is not None:
      ips = []
      for h in hostnames:
        try:
          ipv4 = self.gethostbycondorname(h)
          ips.append(ipv4)
        except Exception:
          # Don't add host if IP address could not be found
          self.logctl.warning('Ignoring hostname %s: cannot resolve IPv4 address' % h)

    if hostnames is not None:
      self.logctl.debug('Input hostnames: %s' % (','.join(hostnames)))
      self.logctl.debug('Input IPs: %s' % (','.join(ips)))
    else:
      self.logctl.debug('No input hostnames given')

    # Add only running instances
    inst = []
    for r in res:
      for i in r.instances:
        if i.state == 'running':
          if hostnames is None:
            # Append all
            inst.append(i)
          else:
            found = False
            for ipv4 in ips:
              if i.private_ip_address == ipv4:
                inst.append(i)
                self.logctl.debug('Found IP %s corresponding to instance' % ipv4)
                found = True
                break
            if not found:
              self.logctl.warning('Cannot find instance %s in the list of known IPs' % \
                i.private_ip_address)

    return inst


  ## Requests a certain number of VMs using the EC2 API. Returns a list of instance IDs of VMs
  #  launched successfully. Note: max_quota is honored by checking the *total* number of running
  #  VMs, and not only the ones recognized by HTCondor. This is done on purpose to avoid overflowing
  #  the cloud (possibly a commercial one) with misconfigured VMs that don't join the HTCondor
  #  cluster.
  #
  #  @param nvms Number of new VMs to request
  #
  #  @return List of instances successfully started
  def ec2_scale_up(self, nvms):

    # Try to get image if necessary
    if self.ec2img is None:
      self.ec2img = self.ec2_image(self.cf['ec2']['image_id'])
      if self.ec2img is None:
        self.logctl.error('Cannot scale up: image id %s not found' % self.cf['ec2']['image_id'])
        return []

    n_succ = 0
    n_fail = 0
    self.logctl.info('We need %d more VMs...' % nvms)

    inst = self.ec2_running_instances()
    if inst is None:
      self.logctl.error('No list of instances can be retrieved from EC2')
      return []

    n_running_vms = len(inst)  # number of *total* VMs running (also non-HTCondor ones)
    if self.cf['quota']['max_vms'] >= 1:
      # We have a "soft" quota: respect it
      n_vms_to_start = int( min(nvms, self.cf['quota']['max_vms']-n_running_vms) )
      if n_vms_to_start <= 0:
        self.logctl.warning(
          'Over quota (%d VMs already running out of %d): cannot launch any more VMs' % \
          (n_running_vms, self.cf['quota']['max_vms']) )
      else:
        self.logctl.warning('Quota enabled: requesting %d (out of desired %d) VMs' % \
          (n_vms_to_start, nvms) )
    else:
      n_vms_to_start = int(nvms)

    # Launch VMs
    inst_ok = []
    for i in range(1, n_vms_to_start+1):

      success = False
      if int(self.cf['debug']['dry_run_boot_vms']) == 0:
        try:

          # Returns the reservation
          reserv = self.ec2img.run(
            key_name=self.cf['ec2']['key_name'],
            user_data=user_data,
            instance_type=self.cf['ec2']['flavour']
          )

          # Get the single instance ID from the reservation
          new_inst_id = reserv.instances[0].id
          self.owned_instances.append( new_inst_id )
          inst_ok.append( new_inst_id )

          success = True
        except Exception:
          self.logctl.error('Cannot run instance via EC2: check your "hard" quota')

      else:
        self.logctl.info('Not running VM: dry run active')
        success = True

      if success:
        n_succ+=1
        self.logctl.info('VM launched OK. Requested: %d/%d | Success: %d | Failed: %d | ID: %s' % \
          (i, n_vms_to_start, n_succ, n_fail, new_inst_id))
      else:
        n_fail+=1
        self.logctl.info('VM launch fail. Requested: %d/%d | Success: %d | Failed: %d' % \
          (i, n_vms_to_start, n_succ, n_fail))

    # Dump owned instances to file (if something changed)
    if n_succ > 0:
      self.save_owned_instances()

    return inst_ok


  ## Asks the Cloud to shutdown hosts corresponding to the given hostnames by using the EC2
  # interface. Returns the list of instance IDs shut off successfully. Note: minimum number of VMs
  # is honored by considering, as number of currently running VMs, the sole VMs known by the batch
  # system. This behavior is different than what we do for the maximum quota, where we take into
  # account all the running VMs to avoid cloud overflowing.
  def ec2_scale_down(hosts, valid_hostnames=None):

    if len(hosts) == 0:
      self.logctl.warning('No hosts to shut down!')
      return []

    self.logctl.info('Requesting shutdown of %d VMs...' % len(hosts))

    # List EC2 instances with the "valid" hostnames
    inst = self.ec2_running_instances(valid_hostnames)
    if inst is None or len(inst) == 0:
      self.logctl.warning('No list of instances can be retrieved from EC2')
      return []

    # Resolve hostnames
    ips = []
    for h in hosts:
      try:
        ips.append( self.gethostbycondorname(h) )
      except Exception:
        self.logctl.warning('Cannot find IP for host to shut down %s: skipped' % h)

    # Now filter out only instances to shutdown
    inst_shutdown = []
    for ip in ips:
      found = False
      for i in inst:
        if i.private_ip_address == ip:
          inst_shutdown.append(i)
          found = True
          break
      if not found:
        self.logctl.warning('Cannot find instance for IP to shut down %s: skipped' % ip)

    # Print number of all valid instances
    self.logctl.debug(
      'Batch hosts: reqd to shutdown=%d | to shutdown matching EC2=%d | total matching EC2=%d' % \
      (len(hosts), len(inst_shutdown), len(inst)))

    # Shuffle the list
    random.shuffle(inst_shutdown)

    # Number of VMs to shutdown to honor the minimum quota of EC2 VMs matching batch hosts
    max_vms_to_shutdown = len(inst)-self.cf['quota']['min_vms']  # inst --> known by batch and EC2

    n_succ = 0
    n_fail = 0
    list_shutdown_ok = []

    if max_vms_to_shutdown <= 0:
      self.logctl.info('Not shutting down any VM to honor the minimum quota of %d' % \
        self.cf['quota']['min_vms'])

    else:

      self.logctl.info('Shutting down maximum %d VMs ' \
        '(total managed=%d, requested=%d, requested and managed=%d) to honor min quota of %d' % \
        (max_vms_to_shutdown, len(inst), len(hosts), \
          len(inst_shutdown), self.cf['quota']['min_vms']))

      for i in inst_shutdown:

        ipv4 = i.private_ip_address
        success = False
        if int(self.cf['debug']['dry_run_shutdown_vms']) == 0:
          try:
            i.terminate()
            list_shutdown_ok.append(i.id)
            self.owned_instances.remove(i.id)
            self.logctl.debug('Shutdown via EC2 of %s succeeded' % ipv4)
            success = True
          except Exception, e:
            self.logctl.error('Shutdown via EC2 failed for %s' % ipv4)
        else:
          # Dry run
          self.logctl.debug('Not shutting down %s via EC2: dry run' % ipv4);
          success = True

        # Messages
        if success:
          n_succ += 1
          self.logctl.info(
            'VM shutdown requested OK. Status: total=%d | success=%d | failed: %d | ID: %s' % \
            (n_succ+n_fail, n_succ, n_fail, i.id))
        else:
          n_fail += 1
          self.logctl.info(
            'VM shutdown request fail. Status: total=%d | success=%d | failed: %d' % \
            (n_succ+n_fail, n_succ, n_fail))

        # Check min quota
        if n_succ == max_vms_to_shutdown:
          break

      # Save to file the list of owned instances
      if n_succ > 0:
        self.save_owned_instances()

    return list_shutdown_ok


  ## Checks status of Virtual Machines currently associated to the batch system: starts new nodes to
  #  satisfy minimum quota requirements, and turn off idle nodes. Takes a list of worker statuses as
  #  input and returns an event dictionary scheduling self invocation.
  #
  #  @return Next action to schedule (dict)
  def check_vms(self):

    self.logctl.info("Checking batch system's VMs...")
    check_time = time.time()

    # Retrieve *all* running instances (also the non-owned ones) and filter out statuses of workers
    # which are not valid VMs: we are not interested in them
    rvms = self.ec2_running_instances()
    rips = []
    if rvms is not None:
      for inst in rvms:
        rips.append( inst.private_ip_address )
    if len(rips) == 0:
      rips = None
    new_workers_status = BatchPlugin.poll_status( self.st['workers_status'], rips )

    if new_workers_status is not None:
      #self.logctl.debug(new_workers_status)
      self.st['workers_status'] = new_workers_status
      new_workers_status = None

      hosts_shutdown = []
      for host,info in self.st['workers_status'].iteritems():
        if info['jobs'] != 0:
          continue
        if (check_time-info['unchangedsince']) > self.cf['elastiq']['idle_for_time_s']:
          self.logctl.info('Host %s is idle for more than %ds: requesting shutdown' % \
            (host, self.cf['elastiq']['idle_for_time_s']))
          self.st['workers_status'][host]['unchangedsince'] = check_time  # reset timer
          hosts_shutdown.append(host)

      if len(hosts_shutdown) > 0:
        inst_ok = self.ec2_scale_down(hosts_shutdown,
          valid_hostnames=self.st['workers_status'].keys())
        self.change_vms_allegedly_running(-len(inst_ok))

      # Scale up to reach the minimum quota, if any
      min_vms = self.cf['quota']['min_vms']
      if min_vms >= 1:
        rvms = self.ec2_running_instances( self.st['workers_status'].keys() )
        if rvms is None:
          self.logctl.warning(
            'Cannot get list of running instances for honoring min quota of %d' % min_vms)
        else:
          n_run = len(rvms)
          n_consider_run = n_run + self.st['vms_allegedly_running']
          self.logctl.info('VMs: running=%d | allegedly running=%d | considering=%d' % \
            (n_run, self.st['vms_allegedly_running'], n_consider_run))
          n_vms = min_vms - n_consider_run
          if n_vms > 0:
            self.logctl.info('Below minimum quota (%d VMs): requesting %d more VMs' % \
              (min_vms, n_vms))
            inst_ok = self.ec2_scale_up( n_vms, valid_hostnames=self.st['workers_status'].keys() )
            for inst in inst_ok:
              self.change_vms_allegedly_running(1, inst)
              self.st['event_queue'].append({
                'action': 'check_owned_instance',
                'when': time.time() + self.cf['elastiq']['estimated_vm_deploy_time_s'],
                'params': [ inst ]
              })

      # OK: schedule when configured
      sched_when = time.time() + self.cf['elastiq']['check_vms_every_s']

    else:
      # Not OK: reschedule ASAP
      sched_when = 0

    return {
      'action': 'check_vms',
      'when': sched_when
    }


  ## Checks if a certain instance ID is in the list of hosts attached to the batch system. If not,
  #  an instance termination is triggered.
  #
  #  @param instance_id Instance to check
  #
  #  @return Event to reschedule (reschedules self on error), or None
  def check_owned_instance(self, instance_id):

    self.logctl.info('Checking owned instance %s...' % instance_id)
    inst = None

    # Get information from EC2: we need the IP address
    try:

      try:
        inst_list = self.ec2h.get_only_instances( [ instance_id ] )  # boto 2.34.1
      except AttributeError:
        self.logctl.debug('Using old boto workaround for getting one instance through reservations')
        res_list = self.ec2h.get_all_instances( [ instance_id ] )  # boto 2.2.2
        inst_list = res_list[0].instances

      inst = inst_list[0]

    except Exception as e:
      self.logctl.error('Instance %s not found' % instance_id)
      return

    # Check if the instance is in the list (using cached status)
    found = False
    for h in self.st['workers_status'].keys():
      if self.gethostbycondorname(h) == inst.private_ip_address:
        found = True
        break

    # Deal with errors
    if not found:
      self.logctl.error(
        'Instance %s (with IP %s) has not joined the cluster after %ds: terminating it' % \
        (instance_id, inst.private_ip_address, self.cf['elastiq']['estimated_vm_deploy_time_s']) )

      try:
        inst.terminate()
        self.owned_instances.remove(instance_id)
        self.save_owned_instances()
        self.logctl.info('Forcing EC2 shutdown of %s: OK' % instance_id)
      except Exception as e:
        # Recheck in a while (10s) in case termination fails
        self.logctl.error('Forcing EC2 shutdown of %s failed: rescheduling check' % instance_id)
        return {
          'action': 'check_owned_instance',
          'when': time.time() + 10,
          'params': [ instance_id ]
        }

    else:
      self.logctl.debug('Instance %s (with IP %s) successfully joined the cluster within %ds' % \
        (instance_id, inst.private_ip_address, self.cf['elastiq']['estimated_vm_deploy_time_s']))

    return None


  ## Changes the number of VMs allegedly running by adding a delta.
  #
  #  @param delta Number of VMs to add (can be negative)
  #  @param instance_id Optional corresponding instance ID
  def change_vms_allegedly_running(self, delta, instance_id=None):
    self.st['vms_allegedly_running'] += delta
    if self.st['vms_allegedly_running'] < 0:
      self.st['vms_allegedly_running'] = 0
    self.logctl.info('Number of allegedly running VMs changed to %d' % \
      self.st['vms_allegedly_running'])

    # When incrementing, we should set an event to decrement of the same quantity
    if delta > 0:
      self.st['event_queue'].append({
        'action': 'change_vms_allegedly_running',
        'when': time.time() + self.cf['elastiq']['estimated_vm_deploy_time_s'],
        'params': [ -delta, instance_id ]
      })


  ## Checks batch queue and take actions of starting VMs when appropriate.
  #
  #  @return Event dict rescheduling self
  def check_queue(self):

    self.logctl.info('Checking queue...')
    check_time = time.time()
    n_waiting_jobs = BatchPlugin.poll_queue()

    if n_waiting_jobs is not None:

      # Correction factor
      corr = self.st['vms_allegedly_running'] * self.cf['elastiq']['n_jobs_per_vm']
      self.logctl.info('Jobs: waiting=%d | allegedly running=%d | considering=%d' % \
        (n_waiting_jobs, corr, n_waiting_jobs-corr))
      n_waiting_jobs -= corr

      if n_waiting_jobs > self.cf['elastiq']['waiting_jobs_threshold']:
        if self.st['first_seen_above_threshold'] != -1:

          if (check_time-self.st['first_seen_above_threshold']) > \
            self.cf['elastiq']['waiting_jobs_time_s']:
            # Above threshold time-wise and jobs-wise: do something

            self.logctl.info('Waiting jobs: %d (above threshold of %d for more than %ds)' % \
              (n_waiting_jobs, self.cf['elastiq']['waiting_jobs_threshold'],
              self.cf['elastiq']['waiting_jobs_time_s']))

            list_ok = self.ec2_scale_up(
              math.ceil(n_waiting_jobs / float(self.cf['elastiq']['n_jobs_per_vm'])) )

            for inst in list_ok:
              self.change_vms_allegedly_running(1, inst)
              self.st['event_queue'].append({
                'action': 'check_owned_instance',
                'when': time.time() + self.cf['elastiq']['estimated_vm_deploy_time_s'],
                'params': [ inst ]
              })
            self.st['first_seen_above_threshold'] = -1

          else:
            # Above threshold but not for enough time
            self.logctl.info('Waiting jobs: %d (still above threshold of %d for less than %ds)' % \
              (n_waiting_jobs, self.cf['elastiq']['waiting_jobs_threshold'],
              self.cf['elastiq']['waiting_jobs_time_s']) )

        else:
          # First time seen above threshold
          self.logctl.info('Waiting jobs: %d (first time above threshold of %d)' % \
            (n_waiting_jobs, self.cf['elastiq']['waiting_jobs_threshold']))
          self.st['first_seen_above_threshold'] = check_time

      else:
        # Not above threshold: reset
        self.logctl.info('Waiting jobs: %d (below threshold of %d)' % \
          (n_waiting_jobs, self.cf['elastiq']['waiting_jobs_threshold']))
        self.st['first_seen_above_threshold'] = -1

    else:
      self.logctl.error('Cannot get the number of waiting jobs this time, sorry')

    return {
      'action': 'check_queue',
      'when': time.time() + self.cf['elastiq']['check_queue_every_s']
    }


  ## Check virtual machines launched by us in error state, and relaunch them. Also clean up list of
  #  owned instances by removing unfound ones.
  def check_vm_errors(self):

    owned_instances_changed = False
    self.logctl.info('Check VMs in error state...')

    # Get all instances in "error" state
    try:

      try:
        all_instances = self.ec2h.get_only_instances()  # boto 2.34.1
      except AttributeError:
        self.logctl.debug('Using old boto workaround for getting all instances through reservations')
        all_instances = []
        all_res = self.ec2h.get_all_instances()
        for r in all_res:
          all_instances.extend( r.instances )  # boto 2.2.2

      # Clean up list from nonexisting instances
      new_owned_instances = []
      for o in self.owned_instances:
        keep = False
        for a in all_instances:
          if o == a.id:
            keep = True
            break
        if keep:
          new_owned_instances.append(o)
        else:
          self.logctl.debug('Unknown owned instance removed: %s' % o)
          owned_instances_changed = True
      if owned_instances_changed:
        self.owned_instances = new_owned_instances

      # Only the ones in error state (generator)
      error_instances = \
        ( x for x in all_instances if x.state == 'error' and x.id in self.owned_instances )

    except Exception as e:
      self.logctl.error('Cannot get list of owned EC2 instances in error: %s' % e)
      error_instances = []

    # Print them
    n_vms_to_restart = 0
    for ei in error_instances:

      # Operations to do if a VM is in error:
      # 1. Terminate it
      # 2. Remove it from the managed list
      # 3. Decrement VMs allegedly running
      # 3. Cancel event restoring VMs allegedly running
      # 4. Run new instances (ignoring errors)
      # 5. Increase VMs allegedly running

      # Terminate VM in error
      try:
        ei.terminate()
        self.logctl.debug('Shutdown via EC2 of %s in error state succeeded' % ei.id)
      except Exception as e:
        self.logctl.error('Shutdown via EC2 failed for %s in error state: %s' % (ei.id, e))
        continue

      # Remove from "owned" list
      self.owned_instances.remove(ei.id)
      owned_instances_changed = True

      # Change VMs allegedly running
      self.change_vms_allegedly_running(-1)

      # Remove event for the current instance
      self.st['event_queue'][:] = \
        [ x for x in self.st['event_queue'] \
        if x['action'] != 'change_vms_allegedly_running' or x['params'][1] != ei.id ]

      # Restart that number of VMs
      n_vms_to_restart = n_vms_to_restart + 1

    # Attempt to run replacement VMs (no retry in this case!)
    if n_vms_to_restart > 0:
      list_ok = self.ec2_scale_up( n_vms_to_restart, valid_hostnames=self.st['workers_status'].keys() )
      for inst in list_ok:
        self.change_vms_allegedly_running(1, inst)
        self.st['event_queue'].append({
          'action': 'check_owned_instance',
          'when': time.time() + self.cf['elastiq']['estimated_vm_deploy_time_s'],
          'params': [ inst ]
        })
      if len(list_ok) == n_vms_to_restart:
        self.logctl.debug('Successfully requested all the new replacement VMs: %s' % \
          ','.join(list_ok))
      else:
        self.logctl.debug('Cannot request all the replacement VMs: only %d/%d succeeded (%s)' % \
          (len(list_ok), n_vms_to_restart, ','.join(list_ok)))

    # Save to disk
    if owned_instances_changed:
      self.save_owned_instances()

    # Re-run this command in X seconds
    return {
      'action': 'check_vm_errors',
      'when': time.time() + self.cf['elastiq']['check_vms_in_error_every_s']
    }







  ## Gets the main IPv4 address used for outbound connections.
  #
  #  @return Our IPv4 address as seen from the outside as string or None on error
  def get_main_ipv4(self):
    try:
      # No data is actually transmitted (UDP)
      s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
      s.connect( ('8.8.8.8', 53) )
      real_ip = s.getsockname()[0]
      s.close()
      return real_ip
    except socket.error as e:
      self.logctl.error('Cannot retrieve current IPv4 address: %s' % e)
      return None


  ## Gets the main IPv6 address used for outbound connections.
  #
  #  @return Our IPv6 address as seen from the outside as string or None on error
  def get_main_ipv6(self):
    try:
      # No data is actually transmitted (UDP)
      s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
      s.connect( ('2001:4860:4860::8888', 53) )
      real_ip = s.getsockname()[0]
      s.close()
      return real_ip
    except socket.error as e:
      self.logctl.error('Cannot retrieve current IPv6 address: %s' % e)
      return None


  ## Overwrites the global list of running instances with the one provided by the file. If the file
  #  cannot be read, the list will be emptied. This is not considered an error but a warning.
  def load_owned_instances(self):
    self.owned_instances = []
    try:
      with open(self.state_file, 'r') as f:
        for line in f:
          # Strip spaces and skip empty lines
          inst = line.strip()
          if inst != '':
            self.owned_instances.append(inst)
      self.logctl.info('Loaded list of owned instances: %s' % ','.join(self.owned_instances))
    except IOError:
      self.logctl.warning('Cannot read initial state from %s' % self.state_file)


  ## Dumps the current list of owned instances to file, an instance ID per line.
  #
  #  @return True on success, False on error
  def save_owned_instances(self):
    try:
      with open(self.state_file, 'w') as f:
        for inst in self.owned_instances:
          f.write(inst + '\n')
      os.chmod(self.state_file, 0600)
      self.logctl.debug('Saved list of owned instances: %s' % ','.join(self.owned_instances))
    except (IOError, OSError) as e:
      self.logctl.error('Cannot save list of owned instances %s: %s' % (self.state_file, e))
      return False

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
