/* SPDX-License-Identifier: GPL-2.0-only */
/* Read ordinary Linux clock resolution and sample 64 one-millisecond sleeps.
 * No peripheral access, CPU affinity changes, real-time priority or busy wait.
 * ARM EABI syscalls avoid introducing another target libc dependency. */
typedef unsigned long long u64;
struct time32 { int sec, nsec; };
static int syscall3(unsigned nr, unsigned a, unsigned b, unsigned c)
{
    register unsigned r0 __asm__("r0")=a, r1 __asm__("r1")=b;
    register unsigned r2 __asm__("r2")=c, r7 __asm__("r7")=nr;
    __asm__ volatile("svc 0" : "+r"(r0) : "r"(r1),"r"(r2),"r"(r7) : "memory","cc");
    return (int)r0;
}
static int text(const char *s)
{
    unsigned n=0,done=0;int rc;
    while(s[n])++n;
    while(done<n) {
        rc=syscall3(4,1,(unsigned)(s+done),n-done);
        if(rc==-4)continue;
        if(rc<=0)return 1;
        done+=(unsigned)rc;
    }
    return 0;
}
static int number(u64 value)
{
    char buf[21];unsigned count=0;
    buf[20]=0;
    do { buf[19-count]=(char)('0'+value%10);value/=10;++count; } while(value);
    return text(buf+20-count);
}
static int field(const char *name,u64 value)
{ return text(name)||number(value); }
static int time_value(unsigned clock,struct time32 *t,unsigned nr)
{
    int rc=syscall3(nr,clock,(unsigned)t,0);
    return rc || t->sec<0 || t->nsec<0 || t->nsec>=1000000000;
}
static u64 ns(const struct time32 *t)
{ return (u64)(unsigned)t->sec*1000000000ull+(unsigned)t->nsec; }
static int fail(const char *why)
{ text("FAIL C80 TIMER ");text(why);text("\n");return 1; }
/* The freestanding libgcc division helper otherwise calls libc raise(). */
__attribute__((noreturn)) long long __aeabi_ldiv0(long long unused)
{
    (void)unused;fail("division by zero");syscall3(1,1,0,0);
    for(;;) { }
}
int main(void)
{
    struct time32 mono,real,before,after,request,remaining;
    u64 minimum=~0ull,maximum=0,total=0,delta;
    unsigned samples=64,interruptions=0;int rc;
    if(time_value(1,&mono,264)||time_value(0,&real,264))return fail("clock_getres");
    if(!ns(&mono)||!ns(&real))return fail("zero clock resolution");
    for(unsigned i=0;i<samples;++i) {
        request.sec=0;request.nsec=1000000;
        if(time_value(1,&before,263))return fail("clock_gettime before");
        for(;;) {
            rc=syscall3(162,(unsigned)&request,(unsigned)&remaining,0);
            if(!rc)break;
            if(rc!=-4||++interruptions>64)return fail("nanosleep");
            if(remaining.sec<0||remaining.nsec<0||remaining.nsec>=1000000000)return fail("remaining interval");
            request=remaining;
        }
        if(time_value(1,&after,263)||ns(&after)<ns(&before))return fail("monotonic clock");
        delta=ns(&after)-ns(&before);
        if(delta<1000000)return fail("early sleep return");
        total+=delta;
        if(delta<minimum)minimum=delta;
        if(delta>maximum)maximum=delta;
    }
    if(text("C80 timers v1 ")||field("monotonic_res_ns=",ns(&mono))||
       field(" realtime_res_ns=",ns(&real))||field(" requested_sleep_ns=",1000000)||
       field(" samples=",samples)||field(" min_ns=",minimum)||
       field(" mean_ns=",total/samples)||field(" max_ns=",maximum)||
       field(" interrupted=",interruptions)||text(" peripheral_access=0\n"))return 1;
    return 0;
}
__attribute__((naked,noreturn)) void _start(void)
{ __asm__ volatile("bl main\nmov r7,#1\nsvc 0\nb ."); }
