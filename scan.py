#!/usr/bin/python

import sys, getopt
import socket
import subprocess

def userInput(argv):
   host = ''
   port = ''
   helpMessage = 'python scan.py -i <host> -p <port>'
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

def scanPorts(ip, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    result = s.connect_ex((ip, int(port)))

    if result == 0:
        print("Port {}: Open".format(port))
    else:
        print("Port {}: Closed".format(port))
    s.close()

def main():
    info = userInput(sys.argv[1:])
    scanPorts(info['host'], info['port'])


if __name__ == "__main__":
    main()
