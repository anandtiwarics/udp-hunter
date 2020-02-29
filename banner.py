#!/usr/bin/env python

def banners(probedisplaystr, banner):
    print(banner)
    print("""
    ooooo     ooo oooooooooo.   ooooooooo.        ooooo   ooooo                             .                      
    `888'     `8' `888'   `Y8b  `888   `Y88.      `888'   `888'                           .o8                      
     888       8   888      888  888   .d88'       888     888  oooo  oooo  ooo. .oo.   .o888oo  .ooooo.  oooo d8b 
     888       8   888      888  888ooo88P'        888ooooo888  `888  `888  `888P"Y88b    888   d88' `88b `888""8P 
     888       8   888      888  888               888     888   888   888   888   888    888   888ooo888  888     
     `88.    .8'   888     d88'  888               888     888   888   888   888   888    888 . 888    .o  888     
       `YbodP'    o888bood8P'   o888o             o888o   o888o  `V88V"V8P' o888o o888o   "888" `Y8bod8P' d888b    
    ....................NotSoSecure (c) 2020 | Developed by Savan Gadhiya - www.gadhiyasavan.com...................

    Usage: python udp-hunter.py --file=inputfile.txt --output=outputfile.txt [optional arguments] 
    Usage: python udp-hunter.py --file=inputfile.txt --output=outputfile.txt [--probes=NTPRequest,SNMPv3GetReques] [--ports=123,161,53] [--retries=3] [--noise=true] [--verbose=false] [--timeout=1.0] [--configfile]
    --host 		 - Single Host  - Required
    --file 		 - File of ips  - Required
    --output 	 - Output file - Required
    --probes 	 - Name of probe or 'all' (default: all probes) (Optional)
    """)
    print("Probe list - " + probedisplaystr)
    print("""
    --ports 	 - List of ports or 'all' (default: all ports) (Optional)
    --retries 	 - Number of packets to send to each host.  Default 2 (Optional)
    --noise 	 - To filter output from non-listed IPs  (Optional)
    --verbose	 - verbosity,  will show sniffer output also --- please keep this a true, by default this is true. This will help us to analyze output.
    --timeout 	 - Timeout 1.0, 2.0 in minutes (Optional)
    --lhost6         - Provide IPv6 of listner interface
    --lhost4         - Provide IPv4 of listner interface
    --configfile     - Configuration file location - default is 'udp.txt' in same directory
    --probehelp      - Help file location - default is 'udphelp.txt' in same directory
    """)
