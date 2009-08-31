# Copyright 2009 Red Hat, Inc.
#
# This program is licensed under the BSD license, read LICENSE.BSD
# for further information.

import _deltarpm
import sys

def readDeltaRPM(file):
    result = _deltarpm.read(file)
    return result

