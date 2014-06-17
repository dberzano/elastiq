from elastiq.config import Config, ConfigError

def main(argv):

  config_defaults = {

    'elastiq': {

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

    },

    'substitute': {

      # Variables substituted in the user-data template.
      # If set, they have precedence on automatic detection.
      # In most cases you do not need to set them manually.
      'ipv4': None,
      'ipv6': None,
      'fqdn': None

    }

  }

  try:
    cf = Config('etc/elastiq.conf.example', config_defaults)
  except ConfigError as e:
    print "Error: %s" % e
