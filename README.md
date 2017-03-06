# pyPortScanner
A port scanner built using python and scapy.

python scan.py -i <host XXX.XX.X.XX-XXX> -p <port> [-u UDP scan]
  -i - the host ip address or ip range
      XX.XXX.X.XX ot XX.XXX.X.XX-XX
  -p the port
  -u run a UDP scan in addition to the tcp scan
  -o output to html file (only supported with one ip address)
