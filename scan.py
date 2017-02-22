#!/usr/bin/python

import sys, getopt

def main(argv):
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
   print('Host is', host)
   print('Port is', port)

if __name__ == "__main__":
   main(sys.argv[1:])
