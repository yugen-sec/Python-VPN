import socket
import threading
from struct import *
import os
import time
import os, sys
from fcntl import ioctl
from select import select
import getopt, struct
import sys
import struct
from ctypes import *
import threading
from Crypto.Cipher import AES

TUNSETIFF = 0x400454ca
IFF_TUN   = 0x0001
ight = 0x1000
TUNMODE = IFF_TUN


f = os.open("/dev/net/tun", os.O_RDWR) #Open the file descriptor
ifr = struct.pack('16sH',bytes('asa0','utf-8'),IFF_TUN | ight )
ifs = ioctl(f,TUNSETIFF,ifr)

sock = socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(0x0800)) #Capture ethernet frame
sock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1) #Prevent the error "Address already in use"
sock.bind(('ens33',0))

socksend=socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
socksend.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
socksend.setsockopt(socket.IPPROTO_IP,socket.IP_HDRINCL,1)


class IP(Structure):   #Class for IP header
    _fields_= [
        ("ihl", c_ubyte,4), 	#IHL is captured before the version
        ("version", c_ubyte,4),
        ("tos", c_ubyte),
        ("len", c_ushort),
        ("id", c_ushort),
        ("offset", c_ushort),
        ("ttl", c_ubyte),
        ("protocol_num", c_ubyte),
        ("sum", c_ushort),
        ("src", c_uint32),
        ("dst", c_uint32)
        ]

    def __new__(self, socket_buffer=None):
        return self.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer=None):
        self.src_address = socket.inet_ntoa(struct.pack("@I",self.src)) #Converting source and destination IP to dotted decimal structure
        self.dst_address = socket.inet_ntoa(struct.pack("@I",self.dst))

enAES = AES.new('This is a key123', AES.MODE_CBC, 'This is an IV456')
enAES1 = AES.new('This is a key123', AES.MODE_CBC, 'This is an IV456')

#IP Header
ip_ihl= 5
ip_ver= 4
ip_tos= 0
ip_tot_len= 0
ip_id= 7777
ip_frag_off= 0
ip_ttl= 127
ip_protocol = 50
ip_checksum= 0
source_ip= '192.168.100.5'
dest_ip= '192.168.100.1'

ip_src = socket.inet_aton(source_ip)
ip_dst = socket.inet_aton(dest_ip)

ip_ihl_ver = (ip_ver << 4) + ip_ihl
ip_header = pack('!BBHHHBBH4s4s',ip_ihl_ver,ip_tos,ip_tot_len,ip_id,ip_frag_off,ip_ttl,ip_protocol,ip_checksum,ip_src,ip_dst)

#ESP header
esp_spi=0
#esp_seq_num=0
esp_pad_len = 0
esp_nheader = 0


print('Client VPN Program started\n')


def recv():
    while True:
        d=''
        reqd_packet=''
        d= sock.recvfrom(65565)[0]
        initialp=d[14:34]
        packetesp=IP(initialp)
        if packetesp.src_address == '192.168.100.1':  
            if packetesp.protocol_num == 50:
                readdata = d[42:]
                decreaddata=enAES.decrypt(readdata)
                reqd_packet=decreaddata[:-12]
                os.write(f,reqd_packet)
                print('Writing request packets to tunnel')
        else:
            continue
                
def send():
    esp_seq_num = 0
    while True:
        k= os.read(f,1600)
        data = k[0:28]
        packetasa=IP(data)
        if packetasa.src_address == '10.0.0.2':
            if packetasa.protocol_num == 1:
                datalen = len(k)%16 + 4
                if datalen !=0:
                    m = k + bytes(16-datalen)
                esp_trailer = pack ('!HH',16-datalen,esp_nheader)
                v=enAES1.encrypt(m + esp_trailer)
                esp_seq_num = esp_seq_num + 1
                esp_header = pack('!LL', esp_spi, esp_seq_num)
                packetback = ip_header + esp_header + v
                socksend.sendto(packetback, (dest_ip,0))
                print('Sending Packets through the real interface')
                k=''

v = threading.Thread(target=recv)
h = threading.Thread(target=send)


v.start()
h.start()


