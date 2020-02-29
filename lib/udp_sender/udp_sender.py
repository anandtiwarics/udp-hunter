import socket

failedtarget = []


def udp_sender(target, pack, args):
    if args.retries:
        retries = args.retries

    sock_add_family = socket.AF_INET
    for ip in target:
        for probe in pack:
            try:
                sender = socket.socket(sock_add_family, socket.SOCK_DGRAM)
                sender.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                for retry in range(retries):
                    sender.sendto(probe[3], (ip, probe[0]))  # sender.sendto(probe[2],(ip,port))
            except Exception as e:
                failedtarget.append(str(ip) + " : Could not send probe: " + str(e))
                pass
