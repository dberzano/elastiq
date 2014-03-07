# GCC
source /cvmfs/sft.cern.ch/lcg/external/gcc/4.7.2/x86_64-slc6-gcc47-opt/setup.sh ''  # empty arg needed!

# Python 2.7
export PythonPrefix=/cvmfs/sft.cern.ch/lcg/external/Python/2.7.3/x86_64-slc6-gcc47-opt
export PATH="$PythonPrefix/bin:$PATH"
export LD_LIBRARY_PATH="$PythonPrefix/lib:$LD_LIBRARY_PATH"

# Boto
export PyBotoPrefix='/var/lib/condor/boto'
export PATH="$PyBotoPrefix/bin:$PATH"
export LD_LIBRARY_PATH="$PyBotoPrefix/lib:$LD_LIBRARY_PATH"
export PYTHONPATH="$PyBotoPrefix/lib/python2.7/site-packages:$PYTHONPATH" 


export PS1='boto [\W] \$> '
exec bash
