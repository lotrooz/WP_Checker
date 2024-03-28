import argparse
import os
import sys
from winappdbg import *

from Anti_Debugging import *
from Anti_VM import *
import Extract


def main():
    usage = "usage : WP_Checker.py [options] <filename>"

    parser = argparse.ArgumentParser(usage = usage)

    parser.add_argument('filename', nargs=1, help = 'Target PE') # one

    parser.add_argument('-d', '--debugging', action='store_true', help = 'Anti Debugging Check', dest = 'Anti_Debugging')

    parser.add_argument('-v', '--vm', action='store_true', help = 'Anti VM Check', dest = 'Anti_VM')

    parser.add_argument('-o', '--others', action='store_true', help = 'Others Check', dest = 'Others')

    parser.add_argument('-b', '--bypass', action='store_true', help = 'Bypass Mode', dest = 'Bypass')

    args = parser.parse_args()

    anti_event_handler = lambda: Extract.anti_create_event_handler(args.Bypass) # Bypass Mode Check

    anti_vm_event_handler = lambda: Extract.anti_vm_create_event_handler(args.Bypass)  # Bypass Mode Check

    if args.Anti_Debugging:
        with Debug(anti_event_handler(), bKillOnExit=True) as debug:
            debug.execv(args.filename)

            debug.loop()

    elif args.Anti_VM:
        with Debug(anti_vm_event_handler(), bKillOnExit=True) as debug:
            debug.execv(args.filename)

            debug.loop()



if __name__ == '__main__':
    main()
