from time import gmtime, strftime
from netaddr import IPNetwork
import os
import socket
import sys
import binascii
from lib.getlocaladdress.getlocaladdress import getlocaladdress
from lib.getsniffer.getsniffer import getsniffer

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


def udp_hunter(args):
    global probemasterfile, \
        probehelp, \
        sline, \
        target, \
        port_list, \
        probe_list, \
        filename, \
        outputfilename, \
        failedtarget, \
        helpdata

    if (args.lhost4 is None) or (args.lhost6 is None):
        if os.name == "posix":
            if args.lhost4 is None:
                hostipv4 = ""
            else:
                hostipv4 = args.lhost4
            if args.lhost6 is None:
                hostipv6 = "::"
            else:
                hostipv6 = args.lhost6
        else:
            print(getlocaladdress())
            inputval = input("Select a network adapter to set IPv4 and IPv6 listening hosts:\n")
            if args.lhost6 is None:
                hostipv6 = localips[int(inputval) - 1][1]
            else:
                hostipv6 = args.lhost6
            if args.lhost4 is None:
                hostipv4 = localips[int(inputval) - 1][2]
            else:
                hostipv4 = args.lhost4
    else:
        hostipv4 = args.lhost4
        hostipv6 = args.lhost6

    if hostipv4 == "":
        print("Listening IPs were set to IPv6 - ", hostipv6, " and IPv4 - Default", hostipv4)
    else:
        print("Listening IPs were set to IPv6 - ", hostipv6, " and IPv4 - ", hostipv4)
    if args.configfile:
        probemasterfile = args.configfile
    if args.probehelp:
        probehelp = args.probehelp

    fhelp = open(probehelp, "r")
    for line in fhelp:
        if line != "\n":
            temp = line.rstrip('\n')
            tempp = [x.strip() for x in temp.split(',')]
            flag = 'valid'
            for i in range(len(probehelplist)):
                if tempp[0] == probehelplist[i][0]:
                    flag = 'invalid'
                    probehelplist[i][1].append(tempp[1])
                    break
            if flag == 'valid':
                probehelplist.append([tempp[0], [tempp[1]]])

    f = open(probemasterfile, "r")
    for line in f:
        if line != "\n":
            temp = line.rstrip('\n')
            if temp[:1] != "#":
                tempp = [x.strip() for x in temp.split(',')]
                flag = 'valid'
                for i in range(len(probemaster)):
                    if int(probemaster[i][0]) == int(tempp[0]):
                        probemaster[i][1].append((tempp[1], tempp[2]))
                        flag = 'invalid'
                        break
                if flag == 'valid':
                    probemaster.append((int(tempp[0]), [(tempp[1], tempp[2])]))

    if args.host == args.filename:
        print('--host or --filename required')
        sys.exit()
    if args.host:
        hosts = args.host
        target = hosts.split(",")
    if args.filename:
        filename = args.filename
        f = open(filename, "r")
        for line in f:
            if line != "\n":
                sline = line.rstrip('\n')
            if "/" in sline:
                for ip in IPNetwork(sline):
                    target.append(str(ip))
            else:
                target.append(sline)
    if args.ports:
        ports = args.ports
        port_list = ports.split(",")
    if args.probes:
        probe_list = args.probes
        probe_list = probe_list.split(",")
    if args.output:
        outputfilename = args.output
    # if args.retries:
    #     retries = args.retries
    # if args.noise != None:
    #     noise = args.noise
    # if args.timeout != "True" and args.timeout != None:
    #     timeout = args.timeout

    # Create a pack/list which will include the probes and ports to be scanned with probe,
    # servicename, port number etc.
    if args.ports or args.probes:
        for i1 in range(len(probemaster)):
            for ports in port_list:
                if probemaster[i1][0] == int(ports):
                    for i2 in range(len(probemaster[i1][1])):
                        pack.append((probemaster[i1][0],
                                     probemaster[i1][1][i2][0],
                                     probemaster[i1][1][i2][1],
                                     binascii.unhexlify(probemaster[i1][1][i2][1])))
            # print probe_list,port_list
            for probes in probe_list:
                if 1 == 1:
                    for i2 in range(len(probemaster[i1][1])):
                        if probemaster[i1][1][i2][0] == probes:
                            pack.append((probemaster[i1][0],
                                         probemaster[i1][1][i2][0],
                                         probemaster[i1][1][i2][1],
                                         binascii.unhexlify(probemaster[i1][1][i2][1])))
    else:
        for i1 in range(len(probemaster)):
            for i2 in range(len(probemaster[i1][1])):
                pack.append((probemaster[i1][0],
                             probemaster[i1][1][i2][0],
                             probemaster[i1][1][i2][1],
                             binascii.unhexlify(probemaster[i1][1][i2][1])))
    # END OF --- Create a pack/list which will include the probes and ports to be scanned with probe, servicename,
    # port number etc.

    print("\nStarting UDP Hunter at " + strftime("%Y-%m-%d %H:%M:%S GMT", gmtime()))
    print("\nCommand with arguments  : " + " ".join(sys.argv))
    print("-----------------------------------------------------------------------------")
    if len(filename) > 0:
        print("Input File for Ips      : " + filename)
    if len(port_list) > 0:
        print("Port List               : " + str(port_list))
    elif len(probe_list) > 0:
        print("Probe List              : " + str(probe_list))
    else:
        print("Probe List              : ALL")
    printips = (str(", ".join(target))[:75] + '..') if len(str(", ".join(target))) > 75 else str(", ".join(target))
    print("Scanning report for IPs : " + printips)
    probelist = ""

    for probe in pack:
        probelist += probe[1] + ", "
    print("Sending probe(s)        : %s to %s IP(s)" % (probelist[:-2], str(len(target))))
    print("-----------------------------------------------------------------------------")

    target_v4 = []
    target_v6 = []

    for hostdata in target:
        if "." in hostdata:
            try:
                target_v4.append(socket.gethostbyname(hostdata))
            except socket.gaierror as err:
                failedtarget.append(str(hostdata) + " : Could not resolve hostname: " + str(err))
        else:
            target_v6.append(hostdata)

    target = target_v4

    f = open(outputfilename, 'a+')
    f.write("\n\n##### File was updated at " + strftime("%Y-%m-%d %H:%M:%S GMT", gmtime()) + " #####\n\n" + banner)
    f.truncate()
    f.close()

    try:
        if len(target) == 0:
            pass
        else:
            getsniffer(hostipv4, args)
    except Exception as e:
        print("Error occured: 30001, More information: " + str(e))
    finally:
        if len(target_v6) != 0:
            print("Starting testing of IPv6 IP address...")
            target = target_v6
            getsniffer(hostipv6, args)
        f = open(outputfilename, 'a+')
        helpdata = list(dict.fromkeys(helpdata))
        if len(helpdata) != 0:
            f.write(
                "\n\nFew known tools/script/commands/references for identified services.......\n" + "\n".join(helpdata))
        failedtarget = list(dict.fromkeys(failedtarget))
        if len(failedtarget) != 0:
            f.write("\n\nFailed Target(s): \n" + "\n".join(failedtarget))
        f.write("\n\n##### File updation ended at " + strftime("%Y-%m-%d %H:%M:%S GMT", gmtime()) + " ##### \n\n")
        f.truncate()
        f.close()
        if len(helpdata) != 0:
            print(
                "\n\nFew known tools/script/commands/references for identified services.......\n" + "\n".join(helpdata))
        if len(failedtarget) != 0:
            print("\nFailed target list will be appended to the output file...")
        print("\nYour feedbacks are welcome...\n\nEnd of UDP Hunter at " + strftime("%Y-%m-%d %H:%M:%S GMT", gmtime()))
