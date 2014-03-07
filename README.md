elastiq
=======

elastiq is a lightweight Python daemon that allows a cluster of
virtual machines running a batch system to scale up and down
automatically.

**Scale up.** elastiq monitors the batch system's queue. If too many
jobs are waiting, it requests new virtual machines.

**Scale down.** elastiq monitors cluster's virtual machines. If some
machines are idle for some time, it turns them off.

**EC2.** elastiq communicates with the cloud via the ubiquitous EC2
interface. The [boto](https://github.com/boto/boto) library is used
for that.

**Quotas.** elastiq supports a quota for a minimum and maximum number
of virtual machines. It will always ensure that a minimum number of
virtual machines are running, and it will never run too many virtual
machines.

**Plugins.** elastiq can support several batch systems via plugins. It
already comes with support for
[HTCondor](http://research.cs.wisc.edu/htcondor/).

**IaaS embedded elasticity.** elastiq allows to run an entire IaaS
cluster that scales itself without using tools running outside the
virtual cluster. Run it on the head node of your virtual cluster and
it will scale it on any cloud exposing an EC2 interface.


Requirements
------------

*   Python 2.6 or greater
*   boto


Installation
------------


### The RPM way

Pick a release and an RPM from the
[releases](https://github.com/dberzano/elastiq/releases) page, and
install it with:

    yum localinstall elastiq-<ver>.rpm


### The Python way

To install system-wide, as root:

    python setup.py

To install in another directory:

    python setup.py --prefix=<instprefix>

See installation options with:

    python setup.py --help


Run in foreground
-----------------

Syntax:

    elastiq-real.py --config=<configfile> [--logdir=<logdir>]

Where:

*   `<configfile>` is the configuration file (mandatory)
*   `<logdir>` is a directory where to place logfiles, which are
    rotated periodically

If run like this, it will stay in the foreground. It is also possible
to run it as a system service: a script for running it in background
is provided.


Run in background
-----------------

To run it in the background use the `elastiqctl` command. It is
recommended to run it as an unprivileged user.

Syntax:

    elastiqctl [start|stop|status|restart|log|conf]

Where:

*   **start**, **stop** and **restart** are self-explanatory;
*   **status** tells whether the daemon is running;
*   **log** shows the log of elastiq in real time (quit with Ctrl-C);
*   **conf** shows some configuration information like the Python
    version, configuration file in use and log files directory.


### Default configuration

When running as unprivileged user:

*   **log directory:** `~/.elastiq/log`
*   **configuration file:** `~/.elastiq/elastiq.conf`

When running as root:

*   **log directory:** `/var/log/elastiq`
*   **configuration file:** `/etc/elastiq.conf`


Configuration
-------------

See the provided example `elastiq.conf.example` under the elastiq
installation directory.


Plugins
-------

See the `htcondor.py` plugin provided as an example.
