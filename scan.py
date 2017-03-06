#!/usr/bin/python

########################################################
##  Author: Greg Bird
##  Github Profile: https://github.com/gbird3
##  Github repo: https://github.com/gbird3/pyPortScanner
########################################################

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
   helpMessage = """
   python scan.py -i <host XXX.XX.X.XX-XXX> -p <port> [-u UDP scan]
    -i - the host ip address or ip range
        XX.XXX.X.XX ot XX.XXX.X.XX-XX
    -p the port
    -u run a UDP scan in addition to the tcp scan
    -o output to html file (only supported with one ip address)
   """
   stype = 'tcp'
   html = "false"
   try:
      opts, args = getopt.getopt(argv,"hi:p:uo",["ip=","port="])
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
       elif opt in ("-u"):
           stype = "udp"
       elif opt in ("-o"):
           html = "true"

   info = {
       'host': host,
       'port': port,
       'stype': stype,
       'html': html
   }

   print('Starting port scan on {} for port(s) {}'.format(host, port))

   return info

# Check if the argument is an ipRange. If so, get the list of IP addresses and then call the scanPorts Function
# If not, call the scan Ports function on the solo IP
# based off code found http://stackoverflow.com/questions/20525330/python-generate-a-list-of-ip-addresses-from-user-input?answertab=votes#answer-20525570
def ip_range(ipRange, port, stype, html):
    if "-" in ipRange:
        octets = ipRange.split('.')

        chunks = [list(map(int, octet.split('-'))) for octet in octets]
        ranges = [range(c[0], c[1] + 1) if len(c) == 2 else c for c in chunks]

        for address in itertools.product(*ranges):
            ip = '.'.join(map(str, address))
            print()
            print('Scanning {}'.format(ip))
            getPorts(ip, port, stype, html)

    else:
        ip = ipRange
        getPorts(ip, port, stype, html)

# Checks if multiple ports were specified and calls the ScanPort function for each port
def getPorts(ip, port, stype, html):
    tcpStatus = []
    udpStatus = []
    print("Starting tcp scan.....")
    print()
    print("Port \t\tStatus")
    print("---- \t\t------")

    if "," in port:
        ports = port.split(',')
        for port in ports:
            status = scantcp(ip, port)
            p = {"port": port + "/tcp",
                 "status": status}
            tcpStatus.append(p)
        if (stype == 'udp'):
            print()
            print("Starting UDP scan.....")
            print()
            print("Port \t\tStatus")
            print("---- \t\t------")
            for port in ports:
                status = scanudp(ip, port)
                p = {"port": port + "/udp",
                     "status": status}
                udpStatus.append(p)
    else:
        status = scantcp(ip, port)
        p = {"port": port + "/tcp",
             "status": status}
        tcpStatus.append(p)

        if (stype == 'udp'):
            print()
            print("Starting UDP scan.....")
            print()
            print("Port \t\tStatus")
            print("---- \t\t------")

            status = scanudp(ip, port)
            p = {"port": port + "/udp",
                 "status": status}
            udpStatus.append(p)

    if (html):
        htmlFile(ip, stype, tcpStatus, udpStatus)

# Function to scan the host and ports using socket
def scantcp(ip, port):
    iport = int(port)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    result = s.connect_ex((ip, iport))
    if result == 0:
        print("%d/tcp \topen" % iport)
        status = 'open'
    else:
        print("%d/tcp \tclosed" % iport)
        status = 'closed'


    s.close()

    return status

def scanudp(ip, port):
    openPorts = []
    closedPorts = []
    iport = int(port)
    try:
        sd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sd.settimeout(0.1)
        sd.sendto("--TEST LINE--", (ip, iport))
        recv, svr = sd.recvfrom(255)
        print ("%d/udp \tclosed" % iport)
        status = 'closed'
    except Exception as e:
        print ("%d/udp \topen" % iport)
        status = 'open'

    return status

def htmlFile(ip, stype, tcpStatus, udpStatus):

    with open('scan.html', 'w') as myFile:
        myFile.write('<html><head><link href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-BVYiiSIFeK1dGmJRAkycuHAHRg32OmUcww7on3RYdg4Va+PmSTsz/K68vbdEjh4u" crossorigin="anonymous"><head>')
        myFile.write('<body>')
        myFile.write('<h3>Port Scan for %s</h3>' % ip)
        myFile.write('<h4>TCP Results</h4>')
        myFile.write('<table class="table table-striped">')
        myFile.write('<tr><th>Port</th><th>Status</th></tr>')
        for port in tcpStatus:
            myFile.write('<tr><td>%s</td><td>%s</td></tr>' % (port['port'], port['status']))
        myFile.write('</table>')
        if (udpStatus):
            myFile.write('<h4>UDP Results</h4>')
            myFile.write('<table class="table table-striped">')
            myFile.write('<tr><th>Port</th><th>Status</th></tr>')
            for port in udpStatus:
                myFile.write('<tr><td>%s</td><td>%s</td></tr>' % (port['port'], port['status']))

        myFile.write('</table>')
        myFile.write('</body></html>')


    myFile.close()

    print ("scan.html file created.")

def main():
    # Get the ip and port information
    info = userInput(sys.argv[1:])
    # Parse the ip range and call the scan ports function
    ip_range(info['host'], info['port'], info['stype'], info['html'])

if __name__ == "__main__":
    main()
