#!/usr/bin/env python3
"""Execute actual DSA control helper and unchanged Linux RTL8_4 packet code with independent oracles."""
from pathlib import Path
import hashlib,json,os,shlex,subprocess,tarfile
r=Path(__file__).resolve().parent
t=r/'dsa-tests';t.mkdir(exist_ok=True)
k=r/'linux-6.12.113'
assert (r/'c80_rtl8367s.h').read_bytes()==(k/'drivers/net/dsa/realtek/c80_rtl8367s.h').read_bytes()
assert (r/'rtl8365mb-patched.c').read_bytes()==(k/'drivers/net/dsa/realtek/rtl8365mb.c').read_bytes()
source=k/'net/dsa/tag_rtl8_4.c';helpers=k/'net/dsa/tag.h'
# Pin upstream packet code to the signed source archive, not local assumptions.
archive=r.parent/'linux-bringup/downloads/linux-6.12.113.tar.xz'
if archive.exists():
    assert hashlib.sha256(archive.read_bytes()).hexdigest()=='e09b6727e5c521253f0d41694900b9c38fb7604db7d35238a8197aa9f7de2428'
    with tarfile.open(archive) as a:
        for p in (source,helpers): assert p.read_bytes()==a.extractfile('linux-6.12.113/'+str(p.relative_to(k))).read()
# Strip only includes and module registration metadata; all packet functions retained.
code=source.read_text().split('/* Ethertype version */')[0]
(t/'tagger-under-test.inc').write_text(''.join(x for x in code.splitlines(True) if not x.startswith('#include')))
code=helpers.read_text()
a=code.index('static inline void dsa_strip_etype_header(');b=code.index('/* Create 2 modaliases',a)
(t/'etype-helpers.inc').write_text(code[a:b])
runs=[]
for name in ('control','tag'):
    binary=t/('test-'+name)
    cmd=shlex.split(os.environ.get('HOSTCC','gcc'))+['-O1','-g','-std=gnu11','-Wall','-Wextra','-Werror','-Wno-unused-function','-Wno-unused-parameter','-Wno-misleading-indentation','-fsanitize=address,undefined','-fno-omit-frame-pointer','-I',str(r),'-I',str(t),str(r/('test-dsa-'+name+'.c')),'-o',str(binary)]
    subprocess.run(cmd,check=True)
    p=subprocess.run([str(binary)],capture_output=True,text=True)
    if p.returncode: print(p.stderr,end='')
    p.check_returncode();assert not p.stderr;assert p.stdout.startswith('PASS: ')
    runs.append(p.stdout.strip());print(p.stdout,end='')
result={'status':'pass','scope':__doc__,'runs':runs,'sanitizers':['address','undefined'],'hardware_tested_ram9':False,
 'control_sha256':hashlib.sha256((r/'c80_rtl8367s.h').read_bytes()).hexdigest(),
 'dsa_driver_sha256':hashlib.sha256((r/'rtl8365mb-patched.c').read_bytes()).hexdigest(),
 'upstream_tagger_sha256':hashlib.sha256(source.read_bytes()).hexdigest(),
 'upstream_helpers_sha256':hashlib.sha256(helpers.read_bytes()).hexdigest(),
 'limitations':'API/register models, not a boot of DSA or switch hardware; electrical timing, isolation and throughput remain untested.'}
(r/'artifacts/dsa-verification.json').write_text(json.dumps(result,indent=2)+'\n')
