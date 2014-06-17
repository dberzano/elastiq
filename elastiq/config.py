import logging

from ConfigParser import SafeConfigParser


class Config:

  """Handles configuration.
  """

  def __init__(self, config_file_name, config_defaults):
    """
    """
    self._logger = logging.getLogger(__name__)
    self._fn = config_file_name
    if type(config_defaults) is not dict:
      raise ConfigError('Malformed configuration defaults')
    self._config = config_defaults
    self._parse()


  def _parse(self):

    cf_parser = SafeConfigParser()

    # open config: supports array of files as well
    if self._fn is not None and len( cf_parser.read(self._fn) ) == 0:
      raise ConfigError('Cannot read configuration file: %s' % self._fn)

    for sec_name,sec_content in self._config.iteritems():
      for key,val in sec_content.iteritems():
        using_default = True
        try:
          new_val = cf_parser.get(sec_name, key)  # --> [sec_name]
          try:
            new_val = float(new_val)
          except ValueError:
            pass
          self._config[sec_name][key] = new_val
          using_default = False
        except Exception, e:
          pass

        self._logger.info( '%s.%s = %s (%s)' % (sec_name, key, str(val), ('default' if using_default else 'from file')) )


    def get(self, section, key):
      """Gets a config value from [section] and key. Returns None if
      it cannot be found, the config value otherwise.
      """
      if section in self._config:
        return self._config[section].get(key)
      return None


class ConfigError(Exception):
  """Errors of the Config class.
  """
  pass
