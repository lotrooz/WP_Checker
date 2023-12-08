import argparse
from winappdbg import *

import Debugging as Debugging


def main():
    usage = "My Program"

    parser = argparse.ArgumentParser(usage)

    parser.add_argument("filename", help="File Name Come")

    options = parser.parse_args()

    debug_list = []

    debug_list.append(options.filename)

    Debugging.Debugging_Start(debug_list)


if __name__ == '__main__':
    main()
