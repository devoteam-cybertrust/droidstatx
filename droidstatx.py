#!/usr/bin/python
import argparse
import os
from App import *
from ApkXmind import *


if __name__=="__main__":
  print """
 _____                _      _                            _    _ 
(____ \              (_)    | |       _           _      \ \  / /
 _   \ \  ____  ___   _   _ | |  ___ | |_   ____ | |_  ___\ \/ / 
| |   | |/ ___)/ _ \ | | / || | /___)|  _) / _  ||  _)(___))  (  
| |__/ /| |   | |_| || |( (_| ||___ || |__( ( | || |__    / /\ \ 
|_____/ |_|    \___/ |_| \____|(___/  \___)\_||_| \___)  /_/  \_\ v0.2 \n       Android Applications Security Analyser, Xmind Generator \n       Created by @clviper\n"""
  parser = argparse.ArgumentParser()
  parser.add_argument("--apk", nargs=1, help="APK file.", metavar='<File>')
  args = parser.parse_args()
  if not (args.apk):
    parser.print_help()
    exit()
  if args.apk:
    a = App(args.apk[0])
    xmindFile = ApkXmind(a)


