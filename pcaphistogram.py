#!/usr/bin/env python3
import sys
from scapy.all import *

databytes = {}

# Count the number of unique byte values in TCP and UDP payloads
def processpacket(packet):
    global databytes

    data = ''
    if (TCP in packet):
        data = str(packet[TCP].payload)
    elif (UDP in packet):
        data = str(packet[UDP].payload)

    if (data != ''):
        for byte in data:
            databytes[ord(byte)] += 1



if (len(sys.argv) < 2):
    print("pcaphistogram.py: Generate a data file histogram of a libpcap file TCP or UDP payload data.\n")
    print("\nusage: %s filename.dump | gnuplot\n\n" % sys.argv[0])
    print("gnuplot will create a histogram called filename.png\n")
    sys.exit(1)

# Initialize list of unique byte values for counters
for byte in range(0,256):
    databytes[byte] = 0


# This is slower than the original Perl version. TODO: Rewrite using impacket
sniff(offline=sys.argv[1], prn=processpacket)

graphfile = sys.argv[1].split(".")[0] + ".png"
datafile = sys.argv[1].split(".")[0] + ".data"
datafilefp = open(datafile, "w")

for byte, count in databytes.items():
    datafilefp.write("%d\t%d\n"%(byte, count))

datafilefp.close()

# Set some good options for gnuplot
print ("set title \"Packet Payload Histogram for " + sys.argv[1] + "\"")
print ("set xlabel \"Byte Values\"")
print ("set ylabel \"Frequency\"")
print ("set autoscale")
print ("set terminal png")
print ("set output \"" + graphfile + "\"")
print ("set yrange [0:*]")
print ("set xrange [0:255]")
print ("set format x \"%02x\"")
print ("set nokey")
#print ("set size 1,0+5")
print ("plot \"" + datafile + "\" lt 1")
print ("quit")
