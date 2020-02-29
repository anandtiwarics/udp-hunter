import socket
import os
import threading
import binascii
from lib.udp_sender.udp_sender import udp_sender

outputfilename = ""
probemaster = []
pack = []
output_tuple = []
output = []
probehelplist = []
helpdata=[]


def getsniffer(host, args):
    if args.noise != None:
        noise = args.noise

    if args.output:
        outputfilename = args.output

    if args.timeout != "True" and args.timeout != None:
        timeout = args.timeout

    if args.host:
        hosts = args.host
        target = hosts.split(",")

    sock_add_family = socket.AF_INET
    sock_ip_proto = socket.IPPROTO_IP

    global port
    outputfilestr = ""
    sniffer = socket.socket(sock_add_family, socket.SOCK_RAW, socket.IPPROTO_UDP)
    sniffer.bind((host, 0))
    sniffer.setsockopt(sock_ip_proto, socket.IP_HDRINCL, 1)
    sniffer.settimeout(int(float(timeout) * 60))  # Set timeout - 60 seconds

    f = open(outputfilename, 'a+')  # a+
    f.write("Scanning following IPs: \n\n" + str(target) + "\n\n")
    f.truncate()
    f.close()

    if os.name == "nt":
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)  # might be not necessary in this case

    t = threading.Thread(target=udp_sender, args=(target, pack, args))
    t.start()
    printflag = "false"

    try:
        while True:
            raw_buffer = sniffer.recvfrom(65565)
            snif = binascii.hexlify(raw_buffer[0])
            source_ip = raw_buffer[1][0]
            destination_ip = ""
            if "." in source_ip:
                port = str(int(snif[40:44], 16))  # FOR IPv4
            elif ":" in source_ip:
                port = str(int(snif[0:4], 16))  # FOR IPv6

            if snif != "" and printflag == "false":
                print("%-40s %-10s %-5s %s" % ("IP", "PORT(UDP)", "STAT", "SERVICE"))
                printflag = "true"
            printservice = ""
            for i in range(len(probemaster)):
                if int(probemaster[i][0]) == int(port):
                    for ii in range(len(probemaster[i][1])):
                        if printservice != "":
                            printservice += "/"
                        printservice += probemaster[i][1][ii][0]
            if printservice == "":
                printservice = "Unknown Service"
            noisyport = "true"
            pack_port = []
            for i in range(len(pack)):
                pack_port.append(str(pack[i][0]))
            if '%' in str(source_ip):
                source_ip = str(source_ip)[0:str(source_ip).index('%')]
            if (((port in pack_port) and (str(source_ip) in target) and (noise in ["False", "false"])) or (
                    noise in ["True", "true"])) and ((str(source_ip), port) not in output_tuple):
                if str(source_ip) != "::1":
                    print("%-40s %-10s open  %s" % (str(source_ip), port, printservice))
                output.append([str(source_ip), port, printservice, snif])
                output_tuple.append((str(source_ip), port))
                if args.verbose not in ["false", "False"]:
                    outputfilestr = "Host: " + str(source_ip) + "; PORT: " + str(
                        port) + ";" + ' STATE: open' + "; UDP Service:" + str(printservice) + "; " + str(snif) + " \n\n"
                else:
                    outputfilestr = "Host: " + str(source_ip) + "; PORT: " + str(
                        port) + ";" + ' STATE: open' + "; UDP Service:" + str(printservice) + " \n\n"
                if args.output:
                    f = open(outputfilename, 'a+')
                    f.write(outputfilestr)
                    f.truncate()
                    f.close()

    except socket.timeout:
        if float(timeout) >= 1.0:
            print("\nINFO: Sniffer timeout was set to " + str(timeout) + " minutes")
        else:
            print("\nINFO: Sniffer timeout was set to " + str(float(timeout) * 60) + " seconds")

    except Exception as e:
        print("\nError occured: 20001, More information: :" + str(e))

    # handle CTRL-C
    except KeyboardInterrupt:
        # Windows turn off promiscuous mode
        if os.name == "nt":
            sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)

    finally:
        for phdata in probehelplist:
            for odata in output:
                if odata[1] == phdata[0]:
                    helpdata.append(str(odata[2]) + "(port " + str(odata[1]) + "):" + str(phdata[1]))
