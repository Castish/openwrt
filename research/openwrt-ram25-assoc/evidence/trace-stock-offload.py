#!/usr/bin/env python3
"""Execute OEM MT7626 beacon-mode capability/init and mode-dependent TXD.
All OS allocation/copy/send/adapter contexts are synthetic; no MCU or RF.
Own analysis code SPDX-License-Identifier: MIT.
"""
from pathlib import Path
import json,struct
from unicorn import UC_HOOK_CODE
from unicorn.arm_const import *
ROOT=Path(__file__).resolve().parent
BASE=ROOT.parent/'beacon-init/trace-stock-beacon.py'
if not BASE.exists():BASE=ROOT/'trace-stock-beacon.py'
ns={'__file__':str(BASE)};exec(compile(BASE.read_text().split('\ncases=[]')[0],str(BASE),'exec'),ns)
BeaconModel=ns['BeaconModel'];A,H,WDEV,STACK,RETURN=(ns[x] for x in ('A','H','WDEV','STACK','RETURN'))
CAP=H+0x810
cases=[];packets=[]
class OffloadModel(BeaconModel):
 def code(self,uc,pc,size,opaque):
  if pc==0x404fba44:
   assert uc.reg_read(UC_ARM_REG_R0)==13
   self.finish(0x41c1c300)
  else:super().code(uc,pc,size,opaque)
# Execute the exact MT7626 capability tail from an instruction boundary.
# r8=hc_get_chip_cap() and r6=zero are established earlier in actual init.
m=OffloadModel();m.cpu.reg_write(UC_ARM_REG_R8,CAP);m.cpu.reg_write(UC_ARM_REG_R6,0);m.cpu.reg_write(UC_ARM_REG_R9,2)
def cap_stop(uc,pc,size,opaque):
 if pc==0x4030a1e0:uc.reg_write(UC_ARM_REG_PC,RETURN)
m.cpu.hook_add(UC_HOOK_CODE,cap_stop);m.invoke(0x4030a1a4)
assert m.cpu.mem_read(CAP+0x15e,1)==b'\x01'
cases.append({'case':'actual-MT7626-capability-prefix','entry':'4030a1a4','end_exclusive':'4030a1e0','cap_beacon_offload_offset':'15e','value':1,'register_context_synthetic':True})
# Whole beacon buffer initializer with an existing synthetic skb avoids a new
# OS packet allocation; a 13-byte OS lock allocation remains intercepted.
for cap,expected in ((0,1),(1,2)):
 m=OffloadModel();m.cpu.mem_write(CAP+0x15e,bytes([cap]));m.put(WDEV+0x834,ns['SKB'])
 assert m.invoke(0x4029592c,A,WDEV)==0
 actual=m.cpu.mem_read(WDEV+0x86c,1)[0];assert actual==expected
 cases.append({'case':f'actual-beacon-buffer-init-cap{cap}','entry':'4029592c','WDEV_method_offset':'86c','method':actual,'HIF_type_actual_getter':2})
old=bytes.fromhex('5e00004800cc0000000400a001f8000000000000000000000400000000c00800')
new=bytes.fromhex('5e00004800cc0003080400a001f8000000000000000000000400000000c00800')
for method in (0,1,2,3):
 for size in (36,62,128,480):
  m=OffloadModel();m.cpu.mem_write(WDEV+0x86c,bytes([method]));d=ns['txd'](m,size)
  expected=bytearray(new if method==2 else old);struct.pack_into('<H',expected,0,size+32)
  assert d==expected,(method,size,d.hex())
  info=bytes.fromhex(m.txd_args[0]['info_hex']);assert info[40]==int(method==2)
  cases.append({'case':f'actual-TXD-method{method}-length{size}','method':method,'IsOffloadPkt':info[40],'TXD_hex':d.hex(),'packet_format':d[7]&3,'subtype':d[8]&15,'frame_type':(d[8]>>4)&3})
# Actual initialized MT7626 context, then actual helper, offload builder, header
# and worker. The raw frame and complete surrounding command bytes stay fixed.
f,tim=ns['frame']();m=OffloadModel();m.cpu.mem_write(CAP+0x15e,b'\x01');m.put(WDEV+0x834,ns['SKB']);m.invoke(0x4029592c,A,WDEV)
d=ns['txd'](m,len(f));assert d==new;template=d+f
for enable,name in ((1,'beacon-on'),(0,'beacon-off')):
 m=OffloadModel();expected=ns['offload'](m,enable,template,tim+32);p=ns['packet'](m,name,8)
 assert bytes.fromhex(p['body_hex'])==expected;packets.append(p)
 cases.append({'case':f'actual-offload-builder-and-header-{name}','packet_bytes':len(bytes.fromhex(p['packet_hex']))})
 m=OffloadModel();m.put(A+24,WDEV);m.put(ns['ARG']+8,ns['CFG']);m.put(WDEV+0x834,ns['SKB']);m.put(ns['SKB']+12,ns['DATA']);m.cpu.mem_write(ns['DATA'],template)
 m.put(ns['CFG']+4,len(template));m.cpu.mem_write(ns['CFG']+8,bytes([enable,0]));m.put(ns['CFG']+12,tim+32)
 assert m.invoke(0x402f5a68,A,ns['ARG'])==0 and len(m.calls)==1 and bytes.fromhex(m.calls[0]['body_hex'])==expected
 cases.append({'case':f'actual-worker-{name}','template_bytes':94,'WLAN_index':0,'TIM_offset':88})
changes=[{'offset':i,'old':a,'new':b} for i,(a,b) in enumerate(zip(old,new)) if a!=b]
assert changes==[{'offset':7,'old':0,'new':3},{'offset':8,'old':0,'new':8}]
assert (new[7]&3)==3 and new[8]&0x3f==8
cases.append({'case':'independent-TXD-offload-format-and-management-beacon-decode','packet_format':3,'management_type':0,'beacon_subtype':8,'only_two_changed_bytes':changes})
report={'scope':__doc__,'source_sha256':ns['ns']['ns']['ns']['SHA'],'cases_passed':len(cases),'cases':cases,'packets':packets,'old_TXD_hex':old.hex(),'TXD_hex':new.hex(),'TXD_changes':changes,'template_hex':template.hex(),'beacon_frame_hex':f.hex(),'SSID':'C80-RAM16','template_bytes':len(template),'frame_bytes':len(f),'TIM_template_offset':tim+32,'actual_MT7626_beacon_method':2,'limits':['OS services/caps/adapter are synthetic; no physical MCU/RF or external receiver','RAM16..18 old proof used WDEV method0, not factory-initialized method2','Two descriptor field corrections are proven against OEM; RF transmission/SSID visibility still unproven','No surrounding RF register initialization, STA/BMC record, mac80211 or client stack added']}
(ROOT/'stock-offload-traces.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({'cases_passed':len(cases),'TXD_hex':new.hex(),'changes':changes}))
