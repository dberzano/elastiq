#!/bin/bash

# Just launch elastiq

cd `dirname "$0"`
export PYTHONPATH=$(cd "$PWD/..";pwd):$PYTHONPATH

python2.6 bin/elastiq-real.py
