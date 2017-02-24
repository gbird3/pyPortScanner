#!/usr/bin/python

import sys, getopt
import socket
import subprocess
import itertools

# Get user input through the use of command line switches
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
            port = arg

   info = {
       'host': host,
       'port': port
   }

   print('Starting port scan on {} for port {}'.format(host, port))

   return info

# based off code found http://stackoverflow.com/questions/20525330/python-generate-a-list-of-ip-addresses-from-user-input?answertab=votes#answer-20525570
def ip_range(ipRange, port):

    if "-" in ipRange:
        octets = ipRange.split('.')

        chunks = [list(map(int, octet.split('-'))) for octet in octets]
        ranges = [range(c[0], c[1] + 1) if len(c) == 2 else c for c in chunks]

        for address in itertools.product(*ranges):
            ip = '.'.join(map(str, address))
            scanPorts(ip, port)

    else:
        ip = ipRange
        scanPorts(ip, port)

# Function to scan the hot and ip address
def scanPorts(ip, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    result = s.connect_ex((ip, int(port)))

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
