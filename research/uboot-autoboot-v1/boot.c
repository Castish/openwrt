/* SPDX-License-Identifier: MIT
 * C80 normal-BOOT wrapper; exact factory U-Boot build only. No flash writes.
 * Runs the unchanged hardware-proven RAM runner; fallback is a tail call to
 * factory jmpaddr so decompression may overwrite this wrapper safely.
 */
typedef unsigned int u32;
typedef unsigned char u8;
typedef int (*command_fn)(void *,int,int,char *const []);
typedef void (*flush_fn)(u32,u32);
typedef char *(*getenv_fn)(const char *);
extern const u8 runner_begin[],runner_end[];
#define ENTRY 0x41c00000u
#define RUNNER 0x40280000u
#define PLAN 0x40270000u
#define ORIGINAL_BOOT 0x30025080u
#define SAVED_BOOT 0x303d0000u
#define ORIGINAL_BYTES 64370u
#define ORIGINAL_CRC 0x969b0bf3u
#define LOADER_BYTES 185636u
struct plan {u32 fn,table;char *argv[2];char command[8],address[9];};
static u32 read32(u32 a){return *(volatile u32 *)a;}
static u32 crc32(const u8 *p,u32 n)
{
    u32 c=~0u,j;while(n--){c^=*p++;for(j=0;j<8;++j)c=(c>>1)^(0xedb88320u&(0u-(c&1)));}return ~c;
}
static int fingerprint(u32 b,u32 off,u32 n,u32 crc)
{return crc32((const u8 *)(b+off),n)==crc;}
static int eq(const char *a,const char *b)
{while(*a&&*a==*b){++a;++b;}return *a==*b;}
static void hex_string(u32 v,char *p)
{u32 i;for(i=0;i<8;++i){p[i]="0123456789abcdef"[v>>28];v<<=4;}p[8]=0;}
static void out(const char *s)
{
    u32 n;while(*s){for(n=0;n<1000000;++n)if(read32(0x11002014)&0x20)break;
        if(n==1000000)return;
        *(volatile u32 *)0x11002000=(u8)*s++;}
}
static int command_profile(u32 b,u32 off,u32 name,u32 max,u32 repeat,u32 fn,const char *s)
{
    const u32 *t=(const u32 *)(b+off);return t[0]==b+name&&t[1]==max&&t[2]==repeat&&t[3]==b+fn&&eq((const char *)(b+name),s);
}
static int profile(u32 b)
{
    return fingerprint(b,0x271c,16,0x12c2ca49)&&fingerprint(b,0x272c,32,0x08c88ba2)&&
        fingerprint(b,0x37ec,32,0x8dcc7333)&&fingerprint(b,0x41e0,32,0xdd7368a2)&&
        fingerprint(b,0x4624,32,0xa0c420f0)&&fingerprint(b,0x2650,32,0x3f5946c8)&&
        fingerprint(b,0x0508,16,0xc8100bdb)&&
        command_profile(b,0x29f58,0x23858,8,1,0x272c,"go")&&
        command_profile(b,0x29ff8,0x23fc5,8,0,0x41e0,"setenv")&&
        command_profile(b,0x29f94,0x2383b,8,1,0x2650,"jmpaddr")&&
        command_profile(b,0x2a020,0x23d2b,3,1,0x37ec,"tftpboot");
}
static int set(u32 b,const char *name,const char *value)
{
    char *a[]={"setenv",(char *)name,(char *)value};char *v;u32 p;
    if(((command_fn)(b+0x41e0))((void *)(b+0x29ff8),0,3,a))return 0;
    v=((getenv_fn)(b+0x4624))(name);p=(u32)v;
    if(p<ENTRY||p>0x41ffffc0u)return 0;
    return eq(v,value);
}
static int valid_original(u32 a)
{
    /* Both locations are inside the identified4MiB mapped NOR. Full original
     * uImage CRC prevents executing an unrecognized fallback or padding. */
    return read32(a)==0x56190527u&&crc32((const u8 *)a,ORIGINAL_BYTES)==ORIGINAL_CRC;
}
static void fallback_plan(u32 b,u32 address)
{
    volatile struct plan *p=(volatile struct plan *)PLAN;u32 i;
    const char *s="jmpaddr";p->fn=b+0x2650;p->table=b+0x29f94;
    p->argv[0]=(char *)p->command;p->argv[1]=(char *)p->address;
    for(i=0;i<8;++i)p->command[i]=s[i];
    hex_string(address,(char *)p->address);
}
int boot_main(u32 caller,u32 original_sp)
{
    u32 b=caller-0x2774u,gd,cpsr,midr,fallback,i;int rc;
    if(b&0xfffu)b=caller-0x2700u;
    __asm__ volatile("mov %0,r9":"=r"(gd));
    __asm__ volatile("mrs %0,cpsr":"=r"(cpsr));
    __asm__ volatile("mrc p15,0,%0,c0,c0,0":"=r"(midr));
    if((b&0xfffu)||b<0x41e00000u||b>0x42000000u-LOADER_BYTES||
       (gd&3)||gd<0x41e00000u||gd>0x41fffe00u||
       (original_sp&3)||original_sp<0x41e10000u||original_sp>=0x42000000u||
       (cpsr&0x3ffu)!=0x1d3u||midr!=0x410fc073u)return 10;
    if(!profile(b))return 11;
    out("\r\nC80 automatic TFTP boot v1\r\n");
    if(valid_original(ORIGINAL_BOOT))fallback=ORIGINAL_BOOT;
    else if(valid_original(SAVED_BOOT))fallback=SAVED_BOOT;
    else{out("STOP: no verified stock fallback\r\n");return 12;}
    if(!set(b,"autostart","no")||!set(b,"ipaddr","192.168.0.1")||
       !set(b,"serverip","192.168.0.3")||!set(b,"netretry","no")||
       !set(b,"tftptimeout","1000")){
        out("Configuration failed; stock fallback\r\n");fallback_plan(b,fallback);return 1;
    }
    /* Embedded copy avoids another network dependency. The unchanged runner
     * uses native do_go's return address to identify the relocated loader. */
    for(i=0;i<(u32)(runner_end-runner_begin);++i)((volatile u8 *)RUNNER)[i]=runner_begin[i];
    if(crc32((const u8 *)RUNNER,(u32)(runner_end-runner_begin))!=0x7b0e207au){
        out("Runner CRC failed; stock fallback\r\n");fallback_plan(b,fallback);return 1;
    }
    ((flush_fn)(b+0x0508))(RUNNER,(u32)(runner_end-runner_begin));
    {
        char *a[]={"go","40280000"};
        rc=((command_fn)(b+0x272c))((void *)(b+0x29f58),0,2,a);
    }
    out(rc?"TFTP scenario failed; stock fallback\r\n":"Scenario returned; stock fallback\r\n");
    /* Recreate this state AFTER a returned scenario, which can legitimately
     * have used40270000 for a short RAM probe. Never return into overwritten
     * wrapper code after jmpaddr has decompressed stock U-Boot over ENTRY. */
    fallback_plan(b,fallback);return 1;
}
