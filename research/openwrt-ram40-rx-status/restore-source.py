#!/usr/bin/env python3
"""Restore the independent RAM40 source cache from verified Linux + issued patch.
The independent cache lives outside the release; /tmp has insufficient space.
"""
from pathlib import Path
import argparse,filecmp,hashlib,json,shutil,subprocess,tarfile,tempfile
R=Path(__file__).resolve().parent
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--source-archive',type=Path,default=R.parent/'linux-bringup/downloads/linux-6.12.113.tar.xz');p.add_argument('--verify-rebuild',action='store_true');a=p.parse_args()
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
assert sha(a.source_archive)=='e09b6727e5c521253f0d41694900b9c38fb7604db7d35238a8197aa9f7de2428'
patch=R/'linux-mt7626-bringup.patch';assert patch.is_file()
if (R/'package-manifest.json').exists():
 row=next(x for x in json.loads((R/'package-manifest.json').read_text())['files'] if x['file']==patch.name);assert sha(patch)==row['sha256']
link=R/'linux-6.12.113';destination=R.parent.parent/'caches/c80-ram40-source/linux-6.12.113'
if not a.verify_rebuild and destination.is_dir():
 assert link.is_symlink() and link.resolve()==destination
 print('Independent source cache already present; no changes.');raise SystemExit
with tempfile.TemporaryDirectory(prefix='c80-ram40-restore-',dir=R/'private') as t:
 t=Path(t)
 with tarfile.open(a.source_archive,'r:xz') as archive:archive.extractall(t,filter='data')
 fresh=t/'linux-6.12.113'
 q=subprocess.run(['patch','--batch','--fuzz=0','-p1','-i',str(patch)],cwd=fresh,text=True,capture_output=True,check=True)
 assert not q.stderr and 'offset' not in q.stdout and 'fuzz' not in q.stdout
 if a.verify_rebuild:
  current={str(f.relative_to(link)):f for f in link.rglob('*') if f.is_symlink() or not f.is_dir()}
  restored={str(f.relative_to(fresh)):f for f in fresh.rglob('*') if f.is_symlink() or not f.is_dir()}
  assert current.keys()==restored.keys();count=0
  for name,old in current.items():
   new=restored[name]
   if old.is_symlink():assert new.is_symlink() and old.readlink()==new.readlink()
   else:assert not new.is_symlink() and filecmp.cmp(old,new,shallow=False),name
   count+=1
  result={'passed':True,'full_source_entries_compared':count,'verified_archive_sha256':sha(a.source_archive),'patch_sha256':sha(patch),'verification_source_sha256':sha(Path(__file__)),'temporary_source_cache_reproducible':True}
  (R/'evidence/source-restore-result.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result))
 else:
  assert not destination.exists();destination.parent.mkdir(parents=True,exist_ok=True);shutil.move(str(fresh),destination)
  if link.is_symlink():assert link.resolve()==destination
  else:assert not link.exists();link.symlink_to(destination,target_is_directory=True)
  print('Restored independent source cache from verified Linux archive + issued patch.')
