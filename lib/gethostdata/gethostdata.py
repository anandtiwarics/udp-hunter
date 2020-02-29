import socket
import sys


def gethostdata(name):
    try:
        print(socket.gethostbyname(name))
    except socket.gaierror as err:
        print("Cannot resolve hostname: ", name, err)
    sys.exit()
