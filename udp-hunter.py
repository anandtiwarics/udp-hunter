#!/usr/bin/env python
import sys
import argparse
from banner.banner import banners
from lib.core.udp_hunter import udp_hunter

localips = []
banner = "UDP Hunter v0.1beta - Updated on 26 February 2020"
hostipv4 = ""
hostipv6 = "::"
pack = []
port_list = []
probe_list = []
argerror = ""
target = []
failedtarget = []
filename = ""
helpdata = []
output = []
output_tuple = []
outputfilestr = ""
outputfilename = ""
probemasterfile = "udp.txt"
probehelp = "udphelp.txt"
probehelplist = []
probemaster = []
noise = "False"
timeout = 1.0
probedisplaylist = []
probedisplaystr = ""


def main():
    fd = open(probemasterfile, "r")
    for line in fd:
        if line != "\n":
            temp = line.rstrip('\n')
            if temp[:1] != "#":
                tempp = [x.strip() for x in temp.split(',')]
                probedisplaylist.append(tempp[1])
    probedisplaystr = ", ".join(probedisplaylist)
    banners(probedisplaystr, banner)
    parser = argparse.ArgumentParser(description='UDP Hunter', epilog='UDP Hunter')
    parser.add_argument("--hosts", help="Provide host names by commas", dest='host', required=False)
    parser.add_argument("--file", help="Provide file input", dest='filename', required=False)
    parser.add_argument("--output", help="Provide output", dest='output', required=False,
                        default='udphunter-output.txt')
    parser.add_argument("--verbose", help="Ignore verbose output --verbose=false", dest='verbose', required=False)
    parser.add_argument("--ports", help="Provide port(s)", dest='ports', required=False)
    parser.add_argument("--probes", help="Provide probe(s)", dest='probes', required=False)
    parser.add_argument("--retries", help="Provide retries", dest='retries', required=False, type=int, default=3)
    parser.add_argument("--noise", help="Provide noise", dest='noise', required=False)
    parser.add_argument("--timeout", help="Provide noise", dest='timeout', required=False, type=float, default=0.3)
    parser.add_argument("--lhost4", help="Provide IPv4 of listner interface", dest='lhost4', required=False)
    parser.add_argument("--lhost6", help="Provide IPv6 of listner interface", dest='lhost6', required=False)
    parser.add_argument("--configfile", help="Provide port(s)", dest='configfile', required=False, default='udp.txt')
    parser.add_argument("--probehelp", help="Provide port(s)", dest='probehelp', required=False, default='udphelp.txt')
    args = parser.parse_args()  # print(args.accumulate(args.integers))
    sys.stdout.write(str(udp_hunter(args)))


if __name__ == '__main__':
    print("\nPlease note that output file " + outputfilestr + " will be appended ... \n")
    main()
