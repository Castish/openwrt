#!/usr/bin/env python3
"""Execute exact OEM ARM beacon TXD/helper, offload wrapper and sync builders.
Synthetic adapter/caps/device/packet/OS services; no physical MCU/RF emulation.
Own analysis code: SPDX-License-Identifier: MIT.
"""
from pathlib import Path
import json,struct
from unicorn import UC_HOOK_CODE
from unicorn.arm_const import *
ROOT=Path(__file__).resolve().parent
BASE=ROOT.parent/'radio-init/trace-stock-radio.py'
if not BASE.exists():BASE=ROOT/'trace-stock-radio.py'
ns={'__file__':str(BASE)};exec(compile(BASE.read_text().split('\ncases=[]')[0],str(BASE),'exec'),ns)
RadioModel=ns['RadioModel'];A,H,MSG,SKB,DATA,STACK=(ns[x] for x in ('A','H','MSG','SKB','DATA','STACK'))
RETURN=ns['RETURN'];WDEV=0x41c1b800;OUT=0x41c18000;PHY=0x41c1a800;ARG=0x41c1b000;CFG=0x41c1b100
MAC=bytes.fromhex('525400123456');SSID=b'C80-RAM16'
class BeaconModel(RadioModel):
 def __init__(self):
  super().__init__();self.txd_args=[];self.copies=[]
  self.put(H+0x810+0x60,128) # synthetic host WCID-range capability
  self.put(WDEV+8,A);self.cpu.mem_write(WDEV+14,b'\x00');self.cpu.mem_write(WDEV+41,b'\x00')
 def code(self,uc,pc,size,opaque):
  r0,r1,r2,r3=[uc.reg_read(x) for x in ns['ns']['ns']['REGS']]
  if pc==0x4033c0b8 and r2==6:
   assert 0x41e00000<=r0<r0+6<=0x41e10000 and r1==ARG+4
   uc.mem_write(r0,bytes(uc.mem_read(r1,r2)));self.finish(r0)
  elif pc==0x404f9cc0:
   assert 0<r2<=512 and ((0x41e00000<=r0<r0+r2<=0x41e10000 and r1==OUT) or (r0==DATA and 0x41e00000<=r1<r1+r2<=0x41e10000))
   uc.mem_write(r1,bytes(uc.mem_read(r0,r2)));self.copies.append((r0,r1,r2));self.finish(r1)
  elif pc==0x40563fa4 and 0x41e00000<=r0<r0+r2<=0x41e10000:
   assert r2==516 and 0x41e00000<=r1<r1+r2<=0x41e10000
   uc.mem_write(r0,bytes(uc.mem_read(r1,r2)));self.finish(r0)
  elif pc==0x403199fc:
   self.txd_args.append({'info_hex':bytes(uc.mem_read(r2,44)).hex(),'phy_hex':bytes(uc.mem_read(r3,2)).hex()})
  elif pc==0x402aaf44:
   super().code(uc,pc,size,opaque);self.calls[-1]['attributes_hex']=bytes(uc.mem_read(MSG,24)).hex()
  else:super().code(uc,pc,size,opaque)
def frame(mac=MAC):
 f=bytearray(struct.pack('<HH',0x80,0)+b'\xff'*6+mac+mac+bytes(2)+bytes(8)+struct.pack('<HH',100,1))
 assert len(f)==36
 f+=bytes([0,len(SSID)])+SSID+bytes([1,4,0x82,0x84,0x8b,0x96,3,1,6])
 tim=len(f);f+=bytes([5,4,0,1,0,0]);return bytes(f),tim

def txd(m,n):
 m.put(STACK,n);m.cpu.mem_write(PHY,bytes(2));m.invoke(0x4031a734,A,WDEV,OUT,PHY)
 assert len(m.txd_args)==1 and len(m.copies)==1
 return bytes(m.cpu.mem_read(OUT,32))
def offload(m,enable,data,tim):
 b=bytearray(528);b[1]=enable;struct.pack_into('<HH',b,8,len(data),tim);b[12:12+len(data)]=data
 # actual API passes528B by value,first12B via r1/r2/r3,rest on stack.
 m.cpu.mem_write(STACK,bytes(b[12:]));assert m.invoke(0x403131e8,A,*struct.unpack('<III',b[:12]))==0
 return bytes(b)
def packet(m,name,seq):
 assert len(m.calls)==1;c=m.calls[0];at=bytes.fromhex(c['attributes_hex'])
 m.cpu.mem_write(MSG+22,bytes([seq]));m.invoke(0x4026249c,MSG,SKB)
 p=bytes(m.cpu.mem_read(m.get(SKB+12),m.get(SKB+8)))
 return dict(c,name=name,sequence=seq,packet_hex=p.hex())
cases=[];packets=[]

f,tim=frame();m=BeaconModel();d=txd(m,len(f));template=d+f
assert len(f)==62 and tim==56 and len(template)==94
expected_txd=bytes.fromhex('5e00004800cc0000000400a001f8000000000000000000000400000000c00800')
assert d==expected_txd
cases.append({'case':'actual-factory-beacon-helper-and-TXD','helper':'4031a734','TXD_builder':'403199fc','TXD_hex':d.hex(),'info':m.txd_args[0],'frame_bytes':len(f),'rate':'syntheticPHYword0000/CCK1Mbps'})
for size in (36,62,128,480):
 m=BeaconModel();x=txd(m,size);assert x[2:]==d[2:] and int.from_bytes(x[:2],'little')==size+32
 cases.append({'case':f'actual-TXD-length-{size}','bytes_including_TXD':size+32})
for enable,name in ((1,'beacon-on'),(0,'beacon-off')):
 m=BeaconModel();expected=offload(m,enable,template,32+tim);p=packet(m,name,8)
 assert bytes.fromhex(p['body_hex'])==expected
 at=bytes.fromhex(p['attributes_hex']);assert at[3]==0x49 and at[4]==15 and int.from_bytes(at[6:8],'little')==65535
 w=bytes.fromhex(p['packet_hex']);assert len(w)==592 and w[38]==1 and w[41]==0x49 and w[43]==1
 packets.append(p);cases.append({'case':'actual-beacon-builder-header-'+name,'body_bytes':528,'expected_response':'ffff/ignorelength'})
 # Execute actual worker, including template/header/TimOffset marshalling and
 # by-value API invocation. Packet/skb/device context are synthetic only.
 m=BeaconModel();m.put(A+24,WDEV);m.put(ARG+8,CFG);m.put(WDEV+0x834,SKB);m.put(SKB+12,DATA)
 m.cpu.mem_write(DATA,template);m.put(CFG+4,len(template));m.cpu.mem_write(CFG+8,bytes([enable,0]));m.put(CFG+12,32+tim)
 assert m.invoke(0x402f5a68,A,ARG)==0 and len(m.calls)==1
 assert bytes.fromhex(m.calls[0]['body_hex'])==expected
 cases.append({'case':'actual-HwCtrl-beacon-worker-'+name,'template_bytes':94,'Tim_offset_includes_TXD':88,'WLAN_index':0})
for enable,name in ((1,'sync-on'),(0,'sync-off')):
 m=BeaconModel();b=bytearray(144);b[1]=2 if enable else 1;struct.pack_into('<I',b,48,0x200);struct.pack_into('<H',b,76,100);b[78]=1
 m.cpu.mem_write(ARG,bytes(b));assert m.invoke(0x402ee440,A,ARG)==0
 p=packet(m,name,9);want=bytearray(struct.pack('<BBHB3xHH',0,0,1,1,9,16)+bytes(12))
 if enable:struct.pack_into('<HBB',want,12,100,1,1)
 assert bytes.fromhex(p['body_hex'])==want
 at=bytes.fromhex(p['attributes_hex']);w=bytes.fromhex(p['packet_hex'])
 assert at[3]==0x26 and at[4]==0x27 and int.from_bytes(at[6:8],'little')==16
 assert len(w)==88 and w[38]==0 and w[41]==0x26 and w[43]==1
 packets.append(p);cases.append({'case':'actual-sync-handler-builder-header-'+name,'handler':'402ec78c','body_bytes':24,'feature_mask':'200'})
# Actual offload flags0f use expectedffff,so dispatcher skips length checks.
# Linux still requires the8-byte status base and bounds the entire DMA event.
for ext in (0,0x49):
 for size in (0,7,8,12,16,1508):
  m=BeaconModel();m.put(SKB+12,DATA);m.put(MSG+16,0x402ec530);m.cpu.mem_write(MSG+4,b'\x0f');m.cpu.mem_write(MSG+6,b'\xff\xff')
  m.cpu.mem_write(DATA,struct.pack('<HHBBBBB3x',size+12,0xe000,0xed,8,0,0,ext)+bytes(size));seen=[]
  def dispatch(uc,pc,n,opaque):
   if pc==0x402ec530:seen.append((uc.reg_read(UC_ARM_REG_R1),uc.reg_read(UC_ARM_REG_R2)))
   if pc==0x40264120:uc.reg_write(UC_ARM_REG_PC,RETURN)
  m.cpu.hook_add(UC_HOOK_CODE,dispatch)
  for reg,value in ((UC_ARM_REG_R5,MSG),(UC_ARM_REG_R6,DATA),(UC_ARM_REG_R10,SKB)):m.cpu.reg_write(reg,value)
  m.invoke(0x402637b4);assert seen==[(DATA+12,size)]
  cases.append({'case':f'actual-offload-ignorelength-ext{ext:02x}-body{size}','callback_NOP':True,'host_requires_at_least8':True})
for name,entry in (('beacon',0x403131e8),('sync',0x402ee440)):
 m=BeaconModel();m.alloc_fail=True
 if name=='beacon':
  m.cpu.mem_write(STACK,bytes(516));rc=m.invoke(entry,A,0,0,0)
 else:
  m.cpu.mem_write(ARG,bytes(144));rc=m.invoke(entry,A,ARG)
 assert rc==3 and not m.calls;cases.append({'case':'actual-allocation-refused-'+name})
# Independently decode all IEs with their own bounds and no duplicateSSID/TIM.
ies=[];off=36
while off<len(f):
 assert off+2<=len(f);eid,n=f[off:off+2];off+=2;assert off+n<=len(f);ies.append((eid,f[off:off+n]));off+=n
assert ies==[(0,SSID),(1,bytes.fromhex('82848b96')),(3,b'\x06'),(5,bytes.fromhex('00010000'))]
assert f[:2]==b'\x80\x00' and f[4:10]==b'\xff'*6 and f[10:16]==f[16:22]==MAC
assert f[24:32]==bytes(8) and struct.unpack('<HH',f[32:36])==(100,1)
cases.append({'case':'independent-80211-beacon-IE-bounds-and-fields','SSID':SSID.decode(),'TIM_frame_offset':tim,'TIM_template_offset':tim+32,'FCS_appended_by_hardware_unproven':True})
report={'scope':__doc__,'source_sha256':ns['ns']['ns']['SHA'],'cases_passed':len(cases),'cases':cases,'packets':packets,
 'SSID':SSID.decode(),'beacon_frame_hex':f.hex(),'TXD_hex':d.hex(),'template_hex':template.hex(),'frame_bytes':len(f),'template_bytes':len(template),'TIM_frame_offset':tim,'TIM_template_offset':tim+32,
 'offload_builder':'403131e8','offload_worker':'402f5a68','TXD_beacon_helper':'4031a734','TXD_builder':'403199fc','sync_handler':'402ec78c',
 'limits':['All adapter/capability/device/OS services/packets/events synthetic;no physical MCU/RF','Normal beacon template only,not authentication/association or data path','Timestamp insertion,FCS/actual RF TX and appearance of SSID remain unproven','No STA record/new TX-data ring/IRQ/config80211/mac80211','Offload expectedffff bypassesOEMlengthcheck;Linux adds8B minimum/full32status/echo validation']}
(ROOT/'stock-beacon-traces.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({'cases_passed':len(cases),'packet_sizes':[len(bytes.fromhex(p['packet_hex'])) for p in packets],'frame':len(f),'template':len(template),'TXD':d.hex()}))
