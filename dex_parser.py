#!/usr/bin/python
# -*- coding: UTF-8 -*-

import sys
import getopt
from parser_util import parse_dex_header, parse_map


def read_file(path):
    with open(path, 'rb') as f:
        dex_data = bytearray(f.read())
    return dex_data


def parse_dex(dex_data):
    dex_header_data = parse_dex_header(dex_data)
    parse_map(dex_data, dex_header_data)


def main(argv):
    try:
        opts, args = getopt.getopt(argv, "hp:", ["path="])
    except getopt.GetoptError:
        print '-p <dex file path>'
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            print '-p <dex file path>'
            sys.exit()
        elif opt in ("-p", "--path"):
            parse_dex(read_file(arg))


if __name__ == "__main__":
    main(sys.argv[1:])
