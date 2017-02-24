#!/usr/bin/python

import sys, getopt
import socket
import subprocess
import itertools

# Get user input through the use of command line switches
# Allows the user to specify a single IP address
# i.e. -i 192.168.1.7
# or an IP range
# i.e. -i 192.168.1.1-254
# Also allows the user to specify one or multiple ports
# -p 80 or -p '22, 80, 443'
def userInput(argv):
   host = ''
   port = ''
   helpMessage = 'python scan.py -i <host XXX.XX.X.XX-XXX> -p <port>'
   try:
      opts, args = getopt.getopt(argv,"hi:p:",["ip=","port="])
   except getopt.GetoptError:
      print(helpMessage)
      sys.exit(2)
   for opt, arg in opts:
       if opt == '-h':
           print(helpMessage)
           sys.exit()
       elif opt in ("-i", "--ip"):
           host = arg
       elif opt in ("-p", "--port"):
           port = arg.replace(" ", "")

   info = {
       'host': host,
       'port': port
   }

   print('Starting port scan on {} for port(s) {}'.format(host, port))

   return info

# Check if the argument is an ipRange. If so, get the list of IP addresses and then call the scanPorts Function
# If not, call the scan Ports function on the solo IP
# based off code found http://stackoverflow.com/questions/20525330/python-generate-a-list-of-ip-addresses-from-user-input?answertab=votes#answer-20525570
def ip_range(ipRange, port):
    if "-" in ipRange:
        octets = ipRange.split('.')

        chunks = [list(map(int, octet.split('-'))) for octet in octets]
        ranges = [range(c[0], c[1] + 1) if len(c) == 2 else c for c in chunks]

        for address in itertools.product(*ranges):
            ip = '.'.join(map(str, address))
            print()
            print('Scanning {}'.format(ip))
            getPorts(ip, port)

    else:
        ip = ipRange
        getPorts(ip, port)

# Checks if multiple ports were specified and calls the ScanPort function for each port
def getPorts(ip, port):
    if "," in port:
        ports = port.split(',')

        for port in ports:
            scanPort(ip, port)
    else:
        scanPort(ip, port)

# Function to scan the host and ports using socket
def scanPort(ip, port):
    iport = int(port)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    result = s.connect_ex((ip, iport))

    if result == 0:
        print("Port {}: Open".format(port))
    else:
        print("Port {}: Closed".format(port))
    s.close()

def main():
    # Get the ip and port information
    info = userInput(sys.argv[1:])

    # Parse the ip range and call the scan ports function
    ip_range(info['host'], info['port'])

if __name__ == "__main__":
    main()
