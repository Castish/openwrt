#!/usr/bin/env python3
"""Exercise partial-archive recovery, repeatability and preservation of edits."""
from pathlib import Path
import hashlib,json,os,shutil,subprocess,tempfile
r=Path(__file__).resolve().parent
def describe(p):
 return {str(f.relative_to(p)):('link',os.readlink(f)) if f.is_symlink() else ('dir',f.stat().st_mode&0o777) if f.is_dir() else ('file',f.stat().st_mode&0o777,hashlib.sha256(f.read_bytes()).hexdigest()) for f in p.rglob('*')}
def fixture(p):
 for n in ['restore-rootfs.py','rootfs-inputs.json','rootfs.cpio.gz','cpio_tools.py']:shutil.copy2(r/n,p/n)
 for n in ['usr/sbin/c80-wifi','etc/config/network']:
  f=p/'rootfs'/n;f.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(r/'rootfs'/n,f)
with tempfile.TemporaryDirectory(prefix='c80-rootfs-recovery-') as t:
 p=Path(t);fixture(p)
 q=subprocess.run(['python3',str(p/'restore-rootfs.py')],text=True,capture_output=True);assert q.returncode==0,q.stderr
 expected=describe(r/'rootfs');assert describe(p/'rootfs')==expected
 q=subprocess.run(['python3',str(p/'restore-rootfs.py')],text=True,capture_output=True);assert q.returncode==0,q.stderr
 assert describe(p/'rootfs')==expected
with tempfile.TemporaryDirectory(prefix='c80-rootfs-edit-') as t:
 p=Path(t);fixture(p);f=p/'rootfs/etc/config/network';f.write_text(f.read_text()+'\n# existing user edit\n');before=describe(p/'rootfs')
 q=subprocess.run(['python3',str(p/'restore-rootfs.py')],text=True,capture_output=True)
 assert q.returncode!=0 and 'Existing rootfs edit preserved' in q.stderr
 assert describe(p/'rootfs')==before
result={'passed':True,'cases_passed':3,'partial_issue_rootfs_restored_exactly':True,'second_run_idempotent':True,'existing_user_edit_refused_before_mutation':True,'entries_compared':len(expected),'script_sha256':hashlib.sha256((r/'restore-rootfs.py').read_bytes()).hexdigest(),'verification_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
(r/'evidence/rootfs-recovery-result.json').write_text(json.dumps(result,indent=2)+'\n')
print('PASS rootfs recovery:3 cases; partial archive restored, idempotent, conflicting edits preserved; exact release entries.')
