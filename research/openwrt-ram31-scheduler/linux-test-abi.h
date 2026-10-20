/* SPDX-License-Identifier: GPL-2.0-only */
/* Minimal freestanding ARM EABI support for the QEMU-only packet peer.
 * No target libc dependency; these are ordinary Linux userspace syscalls. */
typedef unsigned int uint32_t;
typedef unsigned long long uint64_t;
typedef unsigned int size_t;
typedef int ssize_t;
struct timespec { long tv_sec,tv_nsec; };
#define NULL ((void *)0)
#define O_RDONLY 0
#define O_WRONLY 1
#define W_OK 2
#define CLOCK_MONOTONIC 1
static int call3(unsigned nr,unsigned a,unsigned b,unsigned c)
{
    register unsigned r0 __asm__("r0")=a,r1 __asm__("r1")=b,r2 __asm__("r2")=c,r7 __asm__("r7")=nr;
    __asm__ volatile("svc 0" : "+r"(r0) : "r"(r1),"r"(r2),"r"(r7) : "memory","cc");
    return r0;
}
static size_t strlen(const char *s){size_t n=0;while(s[n])++n;return n;}
static void *memcpy(void *d,const void *s,size_t n){unsigned char *a=d;const unsigned char *b=s;while(n--)*a++=*b++;return d;}
static void *memset(void *d,int c,size_t n){unsigned char *a=d;while(n--)*a++=c;return d;}
static int memcmp(const void *a,const void *b,size_t n){const unsigned char *x=a,*y=b;while(n--){if(*x!=*y)return *x-*y;++x;++y;}return 0;}
static int open(const char *s,int flags){return call3(5,(unsigned)s,flags,0);}
static ssize_t read(int fd,void *p,size_t n){return call3(3,fd,(unsigned)p,n);}
static ssize_t write(int fd,const void *p,size_t n){return call3(4,fd,(unsigned)p,n);}
static int close(int fd){return call3(6,fd,0,0);}
static int access(const char *s,int mode){return call3(33,(unsigned)s,mode,0);}
static int clock_gettime(int clock,struct timespec *ts){return call3(263,clock,(unsigned)ts,0);}
static void usleep(unsigned us){struct timespec ts={us/1000000u,(us%1000000u)*1000u};(void)call3(162,(unsigned)&ts,0,0);}
static void output(const char *s){(void)write(1,s,strlen(s));}
static void number(unsigned n){char b[12];unsigned i=0;do{b[i++]='0'+n%10;n/=10;}while(n);while(i)(void)write(1,&b[--i],1);}
static void printf(const char *format,...)
{
    __builtin_va_list args;__builtin_va_start(args,format);
    while(*format){if(format[0]=='%' && format[1]=='u'){number(__builtin_va_arg(args,unsigned));format+=2;}else{(void)write(1,format,1);++format;}}
    __builtin_va_end(args);
}
static void puts(const char *s){output(s);output("\n");}
static __attribute__((noreturn)) void failed(const char *s,unsigned line)
{output("FAIL LINUX-PEER line");number(line);output(": ");output(s);output("\n");(void)call3(1,1,0,0);for(;;){} }
#define assert(expr) do { if(!(expr)) failed(#expr,__LINE__); } while(0)
#define setbuf(a,b) ((void)0)
int main(void);
__attribute__((naked,noreturn)) void _start(void)
{__asm__ volatile("bl main\nmov r7,#1\nsvc 0\nb .");}
