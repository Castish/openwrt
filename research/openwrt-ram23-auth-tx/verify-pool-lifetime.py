#!/usr/bin/env python3
"""Compile the actual Linux run_store callback with synthetic OS/firmware services.
Checks allocation/zero/free/retention outcomes independently of the shared core.
"""
from pathlib import Path
import hashlib,json,os,subprocess,tempfile
r=Path(__file__).resolve().parent;s=(r/'c80_mcu_transport.c').read_text();body=s[s.index('static ssize_t run_store('):s.index('static struct kobj_attribute reply_attr=')]
prefix=r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <limits.h>
#include <errno.h>
#include <sys/types.h>
#define c80_run c80_unused_original_run
#include "c80_mcu_core.h"
#undef c80_run
struct kobject { int dummy; }; struct kobj_attribute { int dummy; };
struct firmware { size_t size; const unsigned char *data; };
struct c80_linux { void *dev; int lock,rc; bool ran,finished,retained; struct c80_dma_pool *pool; unsigned long long dma; struct c80_io io; struct c80_result result; };
static struct c80_linux *c80_live;
static const char *c80_filenames[6]={"a","b","c","d","e","f"};
static unsigned scenario,requests,releases,allocs,frees,zeros,runs;static int expect_pin;static unsigned char *allocated;static struct firmware fixture_fw;
#define GFP_KERNEL 0
#define upper_32_bits(x) ((unsigned)((x)>>32))
static int sysfs_streq(const char *a,const char *b) { return (!strcmp(a,b) || (!strcmp(a,"1\n") && !strcmp(b,"1"))); }
static int mutex_trylock(int *lock) { assert(!*lock);if(scenario==15) return 0;*lock=1;return 1; }
static void mutex_unlock(int *lock) { assert(*lock);*lock=0; }
static int request_firmware_direct(const struct firmware **out,const char *name,void *dev)
{ (void)name;(void)dev;++requests;if(scenario==9 && requests==3) return -ENOENT;fixture_fw.size=scenario==14?(size_t)UINT_MAX+1:4;fixture_fw.data=(void *)"test";*out=&fixture_fw;return 0; }
static void release_firmware(const struct firmware *f) { (void)f;++releases; }
static void *dma_alloc_coherent(void *dev,size_t bytes,unsigned long long *dma,int flags)
{ (void)dev;(void)flags;++allocs;if(scenario==10) return NULL;assert(bytes==sizeof(struct c80_dma_pool));allocated=malloc(bytes);assert(allocated);*dma=scenario==11?0x141000000ull:scenario==12?0x40000000:scenario==13?0x41000001:0x41000000;return allocated; }
static void memzero_explicit(void *p,size_t n) { assert(!expect_pin && p==allocated);++zeros;memset(p,0,n); }
static void dma_free_coherent(void *dev,size_t n,void *p,unsigned long long dma)
{ (void)dev;(void)dma;assert(!expect_pin && p==allocated);for(size_t i=0;i<n;++i) assert(!allocated[i]);++frees;free(p);allocated=NULL; }
static int c80_run(struct c80_io *io,const struct c80_blob *blobs,struct c80_result *res)
{ (void)blobs;++runs;assert(io->pool==(void *)allocated);memset(allocated,0x5a,sizeof(struct c80_dma_pool));
  res->dma_started=scenario!=0 && scenario!=8;res->dma_idle=scenario==1 || scenario==5;res->mcu_stopped=scenario==1 || scenario==5;
  res->critical=scenario==3 || scenario==7?80:scenario==4?81:0;res->auth_submitted=scenario>=5 && scenario<=8;return res->critical; }
#define dev_info(...) ((void)0)
'''
suffix=r'''
int main(void)
{
 for(scenario=0;scenario<19;++scenario) {
  struct c80_linux c={0};c80_live=scenario==18?NULL:&c;c.ran=scenario==16;
  requests=releases=allocs=frees=zeros=runs=0;allocated=NULL;
  /* Independent lifetime contract: in-flight/critical or ANY posted TXP
   * retains unchanged allocation until full reset; never reclaim at DDONE. */
  expect_pin=scenario>=2 && scenario<=8;
  ssize_t ret=run_store(NULL,NULL,scenario==17?"0":"1\n",2);
  if(scenario>=15) { assert(ret==(scenario==15?-EBUSY:scenario==16?-EALREADY:-EINVAL));assert(!requests && !allocs && !c.finished && !c.lock); }
  else {
   assert(ret==2 && c.ran && c.finished && !c.lock && releases==6);
   if(scenario<=8) assert(runs==1 && requests==6 && allocs==1);
   if(expect_pin) {
    assert(c.retained && c.pool==(void *)allocated && !frees && !zeros);
    for(size_t i=0;i<sizeof(struct c80_dma_pool);++i) assert(allocated[i]==0x5a);
    /* Simulated system-reset teardown, outside the callback being tested. */
    free(allocated);allocated=NULL;
   } else {
    assert(!c.retained && !c.pool && !allocated);
    assert(frees==((scenario==0 || scenario==1 || scenario==11 || scenario==12 || scenario==13)?1u:0u));assert(zeros==frees);
   }
   if(scenario==9) assert(c.rc==-ENOENT && !allocs && !runs);
   if(scenario==10) assert(c.rc==-ENOMEM && !runs);
   if(scenario>=11 && scenario<=13) assert(c.rc==-ERANGE && !runs);
   if(scenario==14) assert(c.rc==-EFBIG && !allocs && !runs);
  }
  printf("PASS LIFETIME-case%u pin%d free%u zero%u run%u\n",scenario,expect_pin,frees,zeros,runs);
 }
 puts("PASS:19 actual Linux run_store lifetime cases; synthetic OS/core results; ASan/UBSan.");return 0;
}
'''
with tempfile.TemporaryDirectory(prefix='c80-pool-lifetime-') as tmp:
 p=Path(tmp);(p/'check.c').write_text(prefix+body+suffix)
 subprocess.run(['gcc','-std=c11','-O1','-g','-Wall','-Wextra','-Werror','-Wno-unused-function','-Wno-unused-parameter','-fsanitize=address,undefined','-fno-omit-frame-pointer','-I',str(r),str(p/'check.c'),'-o',str(p/'check')],check=True)
 result=subprocess.run([str(p/'check')],text=True,capture_output=True,env={**os.environ,'ASAN_OPTIONS':'detect_leaks=1'})
 (r/'verification-pool-lifetime.log').write_text(result.stdout+result.stderr);assert result.returncode==0,result.stdout+result.stderr
 rows=[x for x in result.stdout.splitlines() if x.startswith('PASS LIFETIME-')];assert len(rows)==19
(r/'evidence/pool-lifetime-result.json').write_text(json.dumps({'passed':True,'cases_passed':19,'actual_callback_source_sha256':hashlib.sha256(body.encode()).hexdigest(),'verification_source_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'native_ASan_UBSan':True,'cases':rows,'services_synthetic':True,'actual_firmware_DMA_payload_drain_proven':False},indent=2)+'\n');print(result.stdout.splitlines()[-1])
