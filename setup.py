#
# setup.py -- by Dario Berzano <dario.berzano@cern.ch>
#
# Installation of elastiq via setuptools. Install with:
#
#   python setup.py [-prefix=<instprefix>]
#

from setuptools import setup

if __name__ == '__main__':
  setup(

    # Metadata
    name = 'elastiq',
    version = '0.9.2',
    author = 'Dario Berzano',
    author_email = 'dario.berzano@cern.ch',
    description = 'Monitor a batch system status and queue to scale up/down a virtual cluster',

    # Packages
    packages = [ 'elastiq' ],
    zip_safe = False,
    scripts = [
      'elastiq/bin/elastiq-real.py',
      'elastiq/bin/elastiqctl',
      'elastiq/bin/elastiq-test-boto.py', ],  # these ones go to <prefix>/bin
    include_package_data = True,
    #package_data = {
    #  '': [ 'etc/*', 'plugins/*.py' ]
    #},

    # Dependencies
    install_requires = [
      'boto>=2.13.0'
    ]

  )
