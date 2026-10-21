#!/usr/bin/env python3
"""Run actual OEM ARM channel/path builders with channel1 and channel6 arguments.
Synthetic OS and surrounding RF helpers; no physical firmware/radio execution.
"""
from pathlib import Path
import hashlib,json,struct
from unicorn import UC_HOOK_CODE
R=Path(__file__).resolve().parent
p=R.parent/'wifi-bringup/radio-init/trace-stock-radio.py'
n={'__file__':str(p),'__name__':'channel_oracle'}
exec(compile(p.read_text().split('\ncases=[];packets=[]')[0],str(p),'exec'),n)
rows=[];checks=[]
for channel in [1,6]:
 pair=[]
 for name,entry,ext in [('channel',0x40310114,8),('path',0x403103d0,0x4e)]:
  m=n['RadioModel']();m.cpu.mem_write(n['A']+0x1e2324,b'\x64')
  assert n['invoke_cfg'](m,entry,n['cfg'](channel=channel))==0
  row=n['packet'](m,name+str(channel),4);body=bytes.fromhex(row['body_hex'])
  expected=bytearray(76);expected[:5]=bytes([channel,channel,0,1,1])
  if ext==8:expected[20:69]=bytes([63])*49
  assert body==expected and bytes.fromhex(row['packet_hex'])[41]==ext
  rows.append(dict(row,channel=channel));pair.append(body)
  checks.append('actual-ARM-'+name+'-channel'+str(channel))
 m=n['RadioModel']();m.cpu.mem_write(n['A']+0x1e2324,b'\x64');helpers=[]
 def wrapper(uc,pc,size,opaque):
  if pc in (0x40348f14,0x40307b9c):helpers.append(hex(pc));m.finish(0)
 m.cpu.hook_add(UC_HOOK_CODE,wrapper)
 assert n['invoke_cfg'](m,0x4030931c,n['cfg'](channel=channel))==0
 assert [bytes.fromhex(c['body_hex']) for c in m.calls]==pair
 assert helpers
 checks.append('actual-ARM-wrapper-channel'+str(channel))
for name in ['channel','path']:
 a=bytes.fromhex(next(r for r in rows if r['name']==name+'1')['packet_hex'])
 b=bytes.fromhex(next(r for r in rows if r['name']==name+'6')['packet_hex'])
 assert [(i,a[i],b[i]) for i in range(len(a)) if a[i]!=b[i]]==[(64,1,6),(65,1,6)]
result={'passed':True,'cases_passed':len(checks),'cases':checks,'source_sha256':n['ns']['ns']['SHA'],
 'verification_source_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
 'packets':rows,'hardware_tested':False,'firmware_or_RF_emulated':False,
 'channel_vs_path_changed_packet_offsets':[64,65],'power_fields_unchanged':True}
(R/'evidence/stock-channel-traces.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps({'passed':True,'OEM_ARM_channel_cases':len(checks)}))
