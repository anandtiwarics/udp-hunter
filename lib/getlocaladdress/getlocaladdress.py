import ifaddr

localips = []


def getlocaladdress():
    adapters = ifaddr.get_adapters()
    i = 1
    for adapter in adapters:
        localips.append((str(adapter.nice_name), str(adapter.ips[0].ip[0]), str(adapter.ips[1].ip)))
    for localip in localips:
        print(i, localip[0], ": IPv6", localip[1], ": IPv4", localip[2])
        i += 1
