#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Create this user's persistent RAM-boot SSH identity and root/openwrt overlay.
Private host keys are generated once and reused; never publish/reuse this
configuration for other devices. The root password was explicitly user-chosen.
"""
from pathlib import Path
import base64,hashlib,importlib.util,json,os,stat,subprocess,zlib
R=Path(__file__).resolve().parent
assert not (R/'c80-ram-auth-v1.zip').exists(),'Issued release is immutable.'
os.umask(0o077)
private=R/'private/identity';private.mkdir(parents=True,exist_ok=True)
# Rebuilding an extracted personal bundle must retain its identity rather than
# silently rotating keys merely because the private build cache is absent.
if (R/'c80-auth.cpio').exists():
 spec=importlib.util.spec_from_file_location('auth_cpio_readonly',R.parent/'openwrt-ram31-scheduler/cpio_tools.py')
 reader=importlib.util.module_from_spec(spec);spec.loader.exec_module(reader)
 saved=reader.entries((R/'c80-auth.cpio').read_bytes())
 for name in ['dropbear_ed25519_host_key','dropbear_ecdsa_host_key','dropbear_rsa_host_key','shadow']:
  key='etc/shadow' if name=='shadow' else 'etc/dropbear/'+name
  path=private/name
  if not path.exists():
   assert key in saved and saved[key][0]==stat.S_IFREG|0o600
   path.write_bytes(saved[key][5]);path.chmod(0o600)
tools=R/'tools/dropbear'
env=dict(os.environ)
env['LD_LIBRARY_PATH']=str(tools/'usr/lib/x86_64-linux-gnu')+':'+env.get('LD_LIBRARY_PATH','')
keygen=tools/'usr/bin/dropbearkey'
entries=[];public=[]
for keytype in ['ed25519','ecdsa','rsa']:
 name='dropbear_'+keytype+'_host_key';path=private/name
 if not path.exists():
  subprocess.run([str(keygen),'-t',keytype,'-f',str(path)],env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=True)
 path.chmod(0o600)
 result=subprocess.run([str(keygen),'-y','-f',str(path)],env=env,capture_output=True,text=True,check=True)
 line=next(x for x in result.stdout.splitlines() if x.startswith(('ssh-ed25519 ','ecdsa-sha2-','ssh-rsa ')))
 fields=line.split();blob=base64.b64decode(fields[1]);fp='SHA256:'+base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip('=')
 public.append({'type':keytype,'algorithm':fields[0],'public_key':fields[0]+' '+fields[1],'fingerprint':fp})
 entries.append(('etc/dropbear/'+name,stat.S_IFREG|0o600,path.read_bytes()))
# Preserve every other field/account from the actual rootfs.
shadow=private/'shadow'
if not shadow.exists():
 password_hash=subprocess.run(['openssl','passwd','-6','-stdin'],input='openwrt\n',capture_output=True,text=True,check=True).stdout.strip()
 assert password_hash.startswith('$6$')
 lines=(R.parent/'openwrt-ram31-scheduler/rootfs/etc/shadow').read_text().splitlines()
 for i,line in enumerate(lines):
  fields=line.split(':')
  if fields[0]=='root':fields[1]=password_hash;lines[i]=':'.join(fields)
 shadow.write_text('\n'.join(lines)+'\n');shadow.chmod(0o600)
entries.append(('etc/shadow',stat.S_IFREG|0o600,shadow.read_bytes()))

def record(ino,name,mode,data):
 name=name.encode()+b'\0'
 fields=[ino,mode,0,0,2 if stat.S_ISDIR(mode) else 1,0,len(data),0,0,0,0,len(name),0]
 out=b'070701'+''.join(f'{v:08x}' for v in fields).encode()+name
 out+=bytes((-len(out))%4);out+=data;out+=bytes((-len(out))%4);return out
parts=[]
for i,(name,mode,data) in enumerate([('etc',stat.S_IFDIR|0o755,b''),('etc/dropbear',stat.S_IFDIR|0o700,b'')]+entries,1):parts.append(record(i,name,mode,data))
parts.append(record(len(parts)+1,'TRAILER!!!',0,b''))
cpio=b''.join(parts);assert len(cpio)<=4096
cpio+=bytes(4096-len(cpio));(R/'c80-auth.cpio').write_bytes(cpio)
(R/'ssh-host-public.json').write_text(json.dumps({'host_keys':public},indent=2)+'\n')
ed=next(x for x in public if x['type']=='ed25519')
(R/'c80-host-ed25519.pub').write_text(ed['public_key']+' c80-openwrt\n')
report={'passed':True,'root_user':'root','user_selected_password':'openwrt','password_hash_algorithm':'sha512crypt',
 'individual_server_keys_generated_once_and_reused':True,'client_key_required':False,'external_initramfs_bytes':len(cpio),
 'external_initramfs_address':'40c00000','external_initramfs_end':'40c01000','external_initramfs_sha256':hashlib.sha256(cpio).hexdigest(),
 'external_initramfs_crc32':f'{zlib.crc32(cpio):08x}','server_ED25519_fingerprint':ed['fingerprint'],
 'files':[{'name':n,'mode':oct(m),'bytes':len(d)} for n,m,d in entries],
 'private_file_intended_only_for_this_users_router':True,'flash_writes':0}
(R/'evidence/auth-image.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({k:v for k,v in report.items() if k!='files'},indent=2))
