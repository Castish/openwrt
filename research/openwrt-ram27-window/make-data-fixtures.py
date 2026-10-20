#!/usr/bin/env python3
"""Independent RFC826/RFC791/RFC792 synthetic wire fixtures, SPDX-License-Identifier: MIT."""
from pathlib import Path
import struct,socket,json,hashlib
r=Path(__file__).resolve().parent;peer=bytes.fromhex('027122334455');own=(r/'stock-synthetic-eeprom.bin').read_bytes()[4:10]
ip1=socket.inet_aton('192.168.2.1');ip2=socket.inet_aton('192.168.2.2')
def checksum(data):
 data+=bytes(len(data)%2);s=sum(struct.unpack('!%dH'%(len(data)//2),data))
 while s>65535:s=(s&65535)+(s>>16)
 return (~s)&65535
def rawframe(payload,ethertype,seq):
 return struct.pack('<HH',0x0208,304)+peer+own+own+struct.pack('<H',seq<<4)+bytes.fromhex('aaaa03000000')+struct.pack('!H',ethertype)+payload
arp=struct.pack('!HHBBH',1,0x800,6,4,1)+peer+ip2+bytes(6)+ip1
reply=struct.pack('!HHBBH',1,0x800,6,4,2)+own+ip1+peer+ip2
records=[('ARP-request',bytes([255])*6+peer+bytes.fromhex('0806')+arp),('ARP-response',rawframe(reply,0x806,2))]
for size in (0,1,32,64):
 payload=bytes(range(size));req=struct.pack('!BBHHH',8,0,0,0x1234,1)+payload;req=req[:2]+struct.pack('!H',checksum(req))+req[4:]
 answer=struct.pack('!BBHHH',0,0,0,0x1234,1)+payload;answer=answer[:2]+struct.pack('!H',checksum(answer))+answer[4:]
 def ip(p,src,dst,ident):
  h=struct.pack('!BBHHHBBH4s4s',0x45,0,20+len(p),ident,0,64,1,0,src,dst)
  return h[:10]+struct.pack('!H',checksum(h))+h[12:]+p
 records.append((f'ICMP-request-payload{size}',own+peer+bytes.fromhex('0800')+ip(req,ip2,ip1,0x5678)))
 records.append((f'ICMP-response-payload{size}',rawframe(ip(answer,ip1,ip2,1),0x800,3)))
(r/'data-protocol-fixtures.bin').write_bytes(b''.join(struct.pack('<I',len(v))+v for _,v in records))
(r/'evidence/data-protocol-fixtures.json').write_text(json.dumps({'scope':__doc__,'source_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'records':[{'name':k,'bytes':len(v),'hex':v.hex()} for k,v in records],'addresses_synthetic':True,'not_hardware_evidence':True},indent=2)+'\n')
print('RFC wire fixtures: ARP and ICMP payload0/1/32/64')
