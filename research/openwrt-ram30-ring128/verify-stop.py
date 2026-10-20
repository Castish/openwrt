#!/usr/bin/env python3
"""Actual stop/shutdown callbacks with synthetic OS services and real threads."""
from pathlib import Path
import hashlib,json,subprocess,tempfile
r=Path(__file__).resolve().parent;s=(r/'c80_mcu_transport.c').read_text()
stop=s[s.index('static ssize_t stop_store('):s.index('static struct kobj_attribute stop_attr=')]
shutdown=s[s.index('static void c80_mcu_shutdown('):s.index('static const struct of_device_id c80_mcu_match')]
prefix=r'''
#include <assert.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <pthread.h>
#include <sched.h>
#include <time.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
struct kobject {int unused;};struct kobj_attribute {int unused;};
struct c80_linux {atomic_bool net_stop_requested;pthread_mutex_t lock;};
struct platform_device {struct c80_linux *context;};
static struct c80_linux *c80_live;
#define WRITE_ONCE(x,v) atomic_store(&(x),(v))
static int sysfs_streq(const char *a,const char *b){return !strcmp(a,b)||(!strcmp(a,"1\n")&&!strcmp(b,"1"));}
static void mutex_lock(pthread_mutex_t *p){assert(!pthread_mutex_lock(p));}
static void mutex_unlock(pthread_mutex_t *p){assert(!pthread_mutex_unlock(p));}
static struct c80_linux *platform_get_drvdata(struct platform_device *p){return p->context;}
'''
suffix=r'''
static atomic_bool entered,cleanup_allowed,finished;
static void *worker(void *p){struct c80_linux *c=p;mutex_lock(&c->lock);atomic_store(&entered,true);while(!atomic_load(&c->net_stop_requested))sched_yield();while(!atomic_load(&cleanup_allowed))sched_yield();mutex_unlock(&c->lock);return NULL;}
static void *shutdown_thread(void *p){c80_mcu_shutdown(p);atomic_store(&finished,true);return NULL;}
static void until(atomic_bool *p){struct timespec start,now;assert(!clock_gettime(CLOCK_MONOTONIC,&start));while(!atomic_load(p)){assert(!clock_gettime(CLOCK_MONOTONIC,&now));assert(now.tv_sec-start.tv_sec<5);sched_yield();}}
int main(void){struct c80_linux c={0};assert(!pthread_mutex_init(&c.lock,NULL));struct platform_device p={&c};
c80_live=NULL;assert(stop_store(NULL,NULL,"1\n",2)==-EINVAL);puts("PASS STOP no live device");
c80_live=&c;assert(stop_store(NULL,NULL,"0\n",2)==-EINVAL&&!atomic_load(&c.net_stop_requested));puts("PASS STOP invalid request has no effect");
mutex_lock(&c.lock);assert(stop_store(NULL,NULL,"1\n",2)==2&&atomic_load(&c.net_stop_requested));mutex_unlock(&c.lock);puts("PASS STOP remains nonblocking with run mutex held");
assert(stop_store(NULL,NULL,"1\n",2)==2&&atomic_load(&c.net_stop_requested));puts("PASS STOP repeated request idempotent");
atomic_store(&c.net_stop_requested,false);c80_mcu_shutdown(&p);assert(atomic_load(&c.net_stop_requested));puts("PASS STOP idle shutdown returns");
atomic_store(&c.net_stop_requested,false);pthread_t w,t;assert(!pthread_create(&w,NULL,worker,&c));until(&entered);assert(!pthread_create(&t,NULL,shutdown_thread,&p));until(&c.net_stop_requested);assert(!atomic_load(&finished));atomic_store(&cleanup_allowed,true);assert(!pthread_join(w,NULL));assert(!pthread_join(t,NULL));assert(atomic_load(&finished));puts("PASS STOP shutdown delivers stop before waiting for cleanup");
assert(!pthread_mutex_trylock(&c.lock));mutex_unlock(&c.lock);assert(!pthread_mutex_destroy(&c.lock));puts("PASS: 6 actual Linux stop/shutdown callback cases; real pthread ordering, synthetic OS context.");return 0;}
'''
with tempfile.TemporaryDirectory(prefix='c80-stop-') as t:
 t=Path(t);src=t/'stop.c';src.write_text(prefix+stop+shutdown+suffix)
 subprocess.run(['gcc','-D_GNU_SOURCE','-std=c11','-O1','-g','-Wall','-Wextra','-Werror','-Wno-unused-parameter','-fsanitize=address,undefined','-fno-omit-frame-pointer','-pthread',str(src),'-o',str(t/'stop')],check=True)
 result=subprocess.run([str(t/'stop')],text=True,capture_output=True,timeout=15,check=True)
(r/'verification-stop.log').write_text(result.stdout+result.stderr)
assert result.stdout.count('PASS STOP ')==6
sha=lambda data:hashlib.sha256(data).hexdigest()
(r/'evidence/stop-result.json').write_text(json.dumps({'passed':True,'cases_passed':6,'callback_source_sha256':sha((stop+shutdown).encode()),'verification_source_sha256':sha(Path(__file__).read_bytes()),'ASan_UBSan':True,'pthread_mutex_ordering_executed':True,'actual_hardware_restart_or_DMA_not_emulated':True},indent=2)+'\n')
print(result.stdout.splitlines()[-1])
