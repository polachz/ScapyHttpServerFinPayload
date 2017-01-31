#!/usr/bin/python

# Provides simple HTTP server. Generates HTTP reply content
# in two packets, second packet contains data and FIN
# useful for testing WFP Stream filter special scenario
# related to race condition in WFP engine

# based on # Akaljed code, http://www.akaljed.wordpress.com

from scapy.all import *

import socket
import fcntl
import struct

# define here listening interface and port

interface_name = 'eth0'
listening_port = 80

# DO NOT FORGET to disable generating RST packets by kernel
# to do that run this command from the console:
# replace sport value to your listening_port value

# sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST --sport 80 -j DROP


# This function get IP address of specified interface

def get_interface_ip_address(interface_name_param):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(
        s.fileno(),
        0x8915,  # SIOCGIFADDR
        struct.pack('256s', interface_name_param[:15])
    )[20:24])

# Interacts with a client by going through the three-way handshake.
# Shuts down the connection immediately after the connection has been established.
# Akaljed Dec 2010, http://www.akaljed.wordpress.com

# Resolve local IP address
local_ip = get_interface_ip_address(interface_name)

#prepare page content

# Generate custom http file content.
html_body1 = "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0//EN\"><html><head><title>Testserver</title></head><body><p><h1>Welcome to test server</h1></p>"
html_body2 = "<h2>This is FIN packet content</h2></body></html>"

content_length = len(html_body1) + len(html_body2)
# Build a header with appropriate ContentLength value
html_header = "HTTP/1.1 200 OK\x0d\x0aDate: Wed, 29 Sep 2010 20:19:05 GMT\x0d\x0aServer: Testserver\x0d\x0aConnection: Keep-Alive\x0d\x0aContent-Type: text/html; charset=UTF-8\x0d\x0aContent-Length: %s\x0d\x0a\x0d\x0a" % content_length

# Prepare content of first part of the server reply
html1 = html_header + html_body1

# Wait for client to connect.
print "Waiting for connection on iface:%s (%s:%s)" %(interface_name, local_ip, listening_port)

a = sniff(count=1,filter="tcp and host %s and port %s" %(local_ip,listening_port))
# some variables for later use.
remote_port = a[0].sport
remote_ip = a[0][IP].src
seq_nr = a[0].seq
ack_nr = a[0].seq+1
print "Connection from IP: %s port: %s has been detected" %(remote_ip, remote_port)

# Generating the IP layer:
ip = IP(src=local_ip, dst=remote_ip)
# Generating TCP layer:
syn_ack_pkt = TCP(sport=listening_port, dport=remote_port, flags="SA", seq=seq_nr, ack=ack_nr, options=[('MSS', 1460)])

# send SYN ACK packet to remote and wait for ACK of the SYN
ack_of_syn = sr1(ip/syn_ack_pkt)

# Now wait for HTTP GET request
http_get_request = sniff(filter="tcp and port %s" % listening_port, count=1,prn=lambda x:x.sprintf("{IP:%IP.src%: %TCP.dport%}"))
ack_nr += len(http_get_request[0].load)
seq_nr = a[0].seq + 1

# Print the GET request
# if len(http_get_request[0].load) > 1:
#    print http_get_request[0].load

# Generate TCP data
tcp_packet_1 = TCP(sport=listening_port, dport=remote_port, flags="PA", seq=seq_nr, ack=ack_nr, options=[('MSS', 1460)])

# Construct whole network packet, send it and fetch the returning ack.
ackdata1=sr1(ip/tcp_packet_1/html1)
# Calculate new seq number

seq_nr += len(html1)

# Generate RST-ACK packet
tcp_packet_2 = TCP(sport=listening_port, dport=remote_port, flags="FA", seq=seq_nr, ack=ack_nr, options=[('MSS', 1460)])

# send(ip/Bye/html2)
ack_of_data2 = sr1(ip/tcp_packet_2/html_body2)

seq_nr += len(html_body2)+1
ack_nr = ack_of_data2.seq+1

# ACK fin from other side

ack_of_fin = TCP(sport=listening_port, dport=remote_port, flags="A", seq=seq_nr, ack=ack_nr, options=[('MSS', 1460)])
send(ip/ack_of_fin)

# Http connection finished

