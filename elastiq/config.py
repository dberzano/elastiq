import logging
from itertools import tee
from copy import deepcopy
import re
import ConfigParser


class Config:

  '''Handles configuration and defaults.'''

  def __init__(self, config_file_name, config_defaults):
    self._logger = logging.getLogger(__name__)
    self._fn = config_file_name
    if type(config_defaults) is not dict:
      raise ConfigError('Malformed configuration defaults')
    self._defaults = config_defaults
    self._parser = ConfigParser.SafeConfigParser()

    # open config: supports array of files as well
    if self._fn is not None and len( self._parser.read(self._fn) ) == 0:
      raise ConfigError('Cannot read configuration file: %s' % self._fn)


  def getint(self, section, key):
    '''Gets an int. Returns None if not found. No exceptions raised.'''
    return self._get(section, key, 'int')


  def getfloat(self, section, key):
    '''Gets a float. Returns None if not found. No exceptions raised.'''
    return self._get(section, key, 'float')


  def getboolean(self, section, key):
    '''Gets a boolean. Returns None if not found. No exceptions raised.
    Mapped to True: yes, true, on, 1.
    Mapped to False: no, false, off, 0.
    Case-insensitive.'''
    return self._get(section, key, 'boolean')


  def getstr(self, section, key):
    '''Gets a string. Returns None if not found. No exceptions raised.'''
    return self._get(section, key, 'str')


  def getsections(self, refilter=None):
    '''Gets the list of [sections] matching regexp refilter, or all if refilter
    is None (default).'''
    if refilter is None:
      return self._parser.sections()
    else:
      return ( sec for sec in self._parser.sections() if re.match(refilter, sec) )


  def _get(self, section, key, vtype):
    '''Gets a config value from [section] and key. Returns None if
    it cannot be found, the config value otherwise.'''
    try:
      if vtype == 'int':
        getf = self._parser.getint
      elif vtype == 'float':
        getf = self._parser.getfloat
      elif vtype == 'boolean':
        getf = self._parser.getboolean
      elif vtype == 'str':
        getf = self._parser.get
      else:
        raise ConfigError('Unsupported type: %s' % (vtype))

      return getf(section, key)

    except (ConfigParser.NoOptionError, ValueError) as e:
      # not found in file, or wrong type: load default
      # note: ignores default type (assumed to be correct)
      # note: if not found, returns None
      if section in self._defaults:
        return self._defaults[section].get(key) # None if not found
      else:
        return None

    return self._parser.getint(section, key)


class ConfigError(Exception):
  '''Errors of the Config class.'''
  pass
