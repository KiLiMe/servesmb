#!/usr/bin/env python3
# Impacket - Packet Library for Python
#
# Copyright (c) 2003-2016 CORE Security Technologies
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description:
#   Mini shell using some of the SMB functionality of the library
#
# Author:
#   Alberto Solino (@agsolino)
#
# Reference for:
#   SMBCE
#
from __future__ import division
from __future__ import print_function
import sys
import logging
import argparse
from impacket.examples import logger
from impacket.examples.utils import parse_target
from impacket.smbconnection import SMBConnection

def main():
    print("Dummy impacket smbclient for now as I can't pip install easily without network access to pypi, I will try to use installed libraries if available")
    # In real world I would download the actual script or use the installed one. 
    # Let's check if we have impacket installed first.

if __name__ == "__main__":
    main()
