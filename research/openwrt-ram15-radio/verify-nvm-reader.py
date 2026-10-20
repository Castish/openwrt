#!/usr/bin/env python3
"""Compile the actual Linux ROM-MTD callback with synthetic MTD/allocation.
Synthetic EEPROM bytes and a deliberately constructed CRC32 fixture; this is
not device calibration and CRC32 is not an authenticity mechanism.
"""
from pathlib import Path
import hashlib,json,subprocess,os,zlib
r=Path(__file__).resolve().parent
raw=bytes.fromhex(json.loads((r/'evidence/stock-nvm-traces.json').read_text())['synthetic_EEPROM_hex'])
fixture=bytearray(raw+b'\xa5'*(4092-len(raw))+bytes(4))
initial=zlib.crc32(fixture);columns=[]
for bit in range(32):
    sample=bytearray(fixture);sample[4092+bit//8]^=1<<(bit%8)
    columns.append(zlib.crc32(sample)^initial)
basis={}
for bit,value in enumerate(columns):
    combination=1<<bit
    while value:
        pivot=value.bit_length()-1
        if pivot not in basis: basis[pivot]=(value,combination);break
        other,mask=basis[pivot];value^=other;combination^=mask
assert len(basis)==32
value=initial^0x5c6536a7;combination=0
while value:
    pivot=value.bit_length()-1;other,mask=basis[pivot]
    value^=other;combination^=mask
fixture[-4:]=combination.to_bytes(4,'little')
assert zlib.crc32(fixture)==0x5c6536a7 and fixture[:1024]==raw
(r/'synthetic-radio-fixture.bin').write_bytes(fixture)
source=(r/'c80_mcu_transport.c').read_text()
callback=source[source.index('static c80_u32 c80_linux_nvm_read'):source.index('static irqreturn_t c80_mcu_irq')]
prefix=r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "c80_mcu_core.h"
#define MTD_ROM 2
#define MTD_WRITEABLE 0x400
#define GFP_KERNEL 0
#define IS_ERR(p) ((intptr_t)(p)<0 && (intptr_t)(p)>=-4095)
#define PTR_ERR(p) ((int)(intptr_t)(p))
struct mtd_info { unsigned type,flags; unsigned long long size; };
struct c80_linux { int nvm_error; };
static struct mtd_info mtd;
static unsigned mode,gets,puts_,allocs,frees,reads,wipes;
static unsigned char fixture[4096];
static struct mtd_info *get_mtd_device_nm(const char *name)
{
    assert(!strcmp(name,"30000000.flash"));++gets;
    return mode==1?(void *)(intptr_t)-ENODEV:&mtd;
}
static void put_mtd_device(struct mtd_info *p) { assert(p==&mtd);++puts_; }
static void *kmalloc(size_t bytes,int flags)
{ assert(bytes==4096 && !flags);++allocs;return mode==5?NULL:malloc(bytes); }
static void memzero_explicit(void *p,size_t bytes) { memset(p,0,bytes);++wipes; }
static void kfree(void *p)
{
    size_t i;assert(p);
    for(i=0;i<4096;++i) assert(!((unsigned char *)p)[i]);
    free(p);++frees;
}
static int mtd_read(struct mtd_info *p,unsigned long long offset,size_t size,size_t *done,unsigned char *out)
{
    assert(p==&mtd && offset==0x3ff000 && size==4096);++reads;
    memcpy(out,fixture,4096);*done=mode==7?4095:4096;
    if(mode==8) out[4090]^=1;
    if(mode==10) memset(out,0xff,4096);
    if(mode==11) out[512]^=1;
    return mode==6?-EIO:mode==12?-EUCLEAN:0;
}
'''
suffix=r'''
int main(int argc,char **argv)
{
    FILE *file;
    (void)c80_run;(void)c80_irq_prepare;(void)c80_irq_unmask;(void)c80_irq_event;(void)c80_irq_stop;
    assert(argc==2);file=fopen(argv[1],"rb");assert(file);
    assert(fread(fixture,1,4096,file)==4096 && fgetc(file)==EOF);fclose(file);
    assert(c80_crc(fixture,4096)==C80_RADIO_CRC);
    for(mode=0;mode<13;++mode) {
        struct c80_linux c={0};unsigned char out[1024];c80_u32 crc=0,rc;unsigned i;
        memset(out,0xcc,sizeof(out));gets=puts_=allocs=frees=reads=wipes=0;
        mtd=(struct mtd_info){.type=mode==2?3:MTD_ROM,.flags=mode==3?MTD_WRITEABLE:0,.size=mode==4?0x800000:0x400000};
        rc=c80_linux_nvm_read(&c,out,mode==9?1023:1024,&crc);
        assert(rc==(mode?C80_NVM_BAD_SOURCE:0));
        if(!mode) { assert(!c.nvm_error && crc==C80_RADIO_CRC && !memcmp(out,fixture,1024)); }
        else { assert(c.nvm_error<0);for(i=0;i<1024;++i) assert(out[i]==0xcc); }
        assert(puts_==gets-(mode==1?1u:0u));
        assert(frees==reads && wipes==reads);
        if(mode==2 || mode==3 || mode==4 || mode==9 || mode==1) assert(!reads && !allocs);
        printf("PASS ROM-MTD callback case%u rc%u errno%d reads%u allocations%u frees%u\n",mode,rc,c.nvm_error,reads,allocs,frees);
    }
    return 0;
}
'''
p=r/'nvm-reader-generated.c';p.write_text(prefix+callback+suffix)
subprocess.run(['gcc','-std=c11','-O1','-g','-Wall','-Wextra','-Werror','-fsanitize=address,undefined',
                '-fno-omit-frame-pointer',str(p),'-o',str(r/'verify-nvm-reader')],check=True)
run=subprocess.run([str(r/'verify-nvm-reader'),str(r/'synthetic-radio-fixture.bin')],check=True,capture_output=True,text=True,
                   env={**os.environ,'ASAN_OPTIONS':'detect_leaks=1'})
assert run.stdout.count('PASS ROM-MTD callback')==13 and not run.stderr
(r/'nvm-reader-verification.log').write_text(run.stdout)
(r/'evidence/nvm-reader-result.json').write_text(json.dumps({
 'passed':True,'cases_passed':13,'actual_callback_source_sha256':hashlib.sha256(callback.encode()).hexdigest(),
 'synthetic_fixture_sha256':hashlib.sha256(fixture).hexdigest(),'private_calibration_included':False,
 'scope':__doc__},indent=2)+'\n')
print('PASS:13 actual Linux ROM-MTD callback cases, synthetic MTD/allocation; ASan/UBSan.')
