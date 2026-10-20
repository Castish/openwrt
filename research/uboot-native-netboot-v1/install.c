/* SPDX-License-Identifier: MIT
 * One-time installer for this exact C80 backup/normal U-Boot patch.
 * Uses the stock NOR driver's bounded4KiB services. i=install,r=rollback;
 * no argument performs the complete preflight with ZERO erase/write calls.
 */
typedef unsigned int u32;
typedef unsigned char u8;
#include "install-profile.h"
#define SOURCE 0x41000000u
#define BUFFER 0x40b00000u
#define SECTOR 4096u
#define RAM_END 0x42000000u
typedef int (*read_fn)(u32,u32,u32 *,u8 *);
typedef int (*write_fn)(u32,u32,u32 *,const u8 *);
typedef int (*erase_fn)(u32,u32);
static u32 read32(u32 p){return *(volatile u32 *)p;}
static void out(const char *s)
{
    u32 i;while(*s){for(i=0;i<1000000;++i)if(read32(0x11002014)&0x20)break;
    if(i==1000000)return;
    *(volatile u32 *)0x11002000=(u8)*s++;}
}
static void hex(u32 v)
{
    char x[9];u32 i;for(i=0;i<8;++i){x[i]="0123456789abcdef"[v>>28];v<<=4;}x[8]=0;out(x);
}
static u32 crc_part(u32 crc,const u8 *p,u32 n)
{
    static const u32 table[16]={0,0x1db71064,0x3b6e20c8,0x26d930ac,0x76dc4190,0x6b6b51f4,0x4db26158,0x5005713c,
    0xedb88320,0xf00f9344,0xd6d6a3e8,0xcb61b38c,0x9b64c2b0,0x86d3d2d4,0xa00ae278,0xbdbdf21c};
    while(n--){crc^=*p++;crc=(crc>>4)^table[crc&15];crc=(crc>>4)^table[crc&15];}return crc;
}
static u32 crc32(const u8 *p,u32 n){return ~crc_part(~0u,p,n);}
static int same(const u8 *a,const u8 *b,u32 n){while(n--)if(*a++!=*b++)return 0;return 1;}
static int fingerprint(u32 b,u32 off,u32 n,u32 crc){return crc32((const u8 *)(b+off),n)==crc;}
static int read_sector(u32 b,u32 offset)
{
    /* The native4KiB read uses its direct mapped path. Discard clean NOR
     * cache lines before every read, so post-program verification cannot
     * observe an earlier cached sector. No CPU stores target the NOR alias.
     * 32-byte stride also covers Cortex-A7 implementations with64B lines.
     */
    u32 n=0,a; int rc;
    for(a=0x30000000u+offset;a<0x30000000u+offset+SECTOR;a+=32u)
        __asm__ volatile("mcr p15,0,%0,c7,c6,1"::"r"(a):"memory");
    __asm__ volatile("dsb sy":::"memory");
    rc=((read_fn)(b+0x60e4))(offset,SECTOR,&n,(u8 *)BUFFER);
    return !rc&&n==SECTOR;
}
static int flash_crc(u32 b,u32 start,u32 end,u32 *result)
{
    u32 c=~0u,a;for(a=start;a<end;a+=SECTOR){if(!read_sector(b,a))return 0;c=crc_part(c,(const u8 *)BUFFER,SECTOR);}
    *result=~c;return 1;
}
static int fail(u32 code,u32 address)
{out("STOP code=");hex(code);out(" offset=");hex(address);out("; keep power on, preserve log\r\n");return (int)code;}
int install_main(u32 argc,char **argv,u32 caller,u32 original_sp)
{
    u32 b=caller-0x2774u,gd,cpsr,midr,source_crc,current_crc,factory_crc,tail_crc,after_crc,after_tail;
    u32 a,n,changed=0,writes=0,sh,nor;int rollback=0,commit=0;
    __asm__ volatile("mov %0,r9":"=r"(gd));__asm__ volatile("mrs %0,cpsr":"=r"(cpsr));
    __asm__ volatile("mrc p15,0,%0,c0,c0,0":"=r"(midr));
    if((b&0xfffu)||b<0x41e00000u||b>RAM_END-185636u||
       (gd&3)||gd<0x41e00000u||gd>=RAM_END-256u||
       (original_sp&3)||original_sp<0x41e10000u||original_sp>=RAM_END||
       (cpsr&0x3ffu)!=0x1d3u||midr!=0x410fc073u)return 10;
    if(!fingerprint(b,0x271c,16,0x12c2ca49)||!fingerprint(b,0x272c,32,0x08c88ba2)||
       !fingerprint(b,0x60e4,32,0x83bc3c52)||!fingerprint(b,0x6288,32,0x70e33930)||
       !fingerprint(b,0x63b0,32,0x8f5e1dba))return 11;
    out("\r\nC80 native U-Boot installer v1\r\n");
    if(argc>2)return fail(12,0);
    if(argc==2){
        if(argv[1][0]=='i'&&!argv[1][1])commit=1;
        else if(argv[1][0]=='r'&&!argv[1][1]){commit=1;rollback=1;}
        else return fail(12,0);
    }
    sh=read32(b+0x2a914);
    if((sh&3)||sh<0x41e00000u||sh>RAM_END-16)return fail(13,0);
    nor=read32(sh);if((nor&3)||nor<0x41e00000u||nor>RAM_END-32||read32(nor+16)!=0x400000u)return fail(13,0);
    source_crc=crc32((const u8 *)SOURCE,FW_LENGTH);
    out("SOURCE_CRC=");hex(source_crc);out("\r\n");
    if(source_crc!=(rollback?OLD_CRC:NEW_CRC))return fail(14,0);
    if(!flash_crc(b,0,FW_START,&factory_crc)||factory_crc!=FACTORY_CRC)return fail(15,0);
    if(!flash_crc(b,FW_END,0x400000u,&tail_crc))return fail(16,FW_END);
    if(!flash_crc(b,FW_START,FW_END,&current_crc))return fail(17,FW_START);
    out("CURRENT_CRC=");hex(current_crc);out("\r\n");
    if(current_crc==source_crc){out("ALREADY_MATCHES; zero writes\r\n");return 0;}
    if(!rollback&&current_crc!=OLD_CRC)return fail(18,FW_START);
    for(a=FW_START;a<FW_END;a+=SECTOR){
        if(!read_sector(b,a))return fail(19,a);
        if(!same((const u8 *)BUFFER,(const u8 *)(SOURCE+a-FW_START),SECTOR))++changed;
    }
    out("CHANGED_SECTORS=");hex(changed);out("\r\n");
    if(!commit){out("DRY_RUN_OK; ZERO flash writes. Use i only to install, r only with stock rollback payload.\r\n");return 0;}
    out(rollback?"ROLLBACK_BEGIN\r\n":"INSTALL_BEGIN\r\n");
    /* Header sector LAST: until all body sectors verify, its canonical MD5
     * is invalid and the preserved factory recovery can reject partial data.
     * This is recoverable through recovery, not an atomic NOR transaction.
     */
    for(n=0;n<FW_LENGTH/SECTOR;++n){
        a=n+1<FW_LENGTH/SECTOR?FW_START+(n+1)*SECTOR:FW_START;
        if(!read_sector(b,a))return fail(20,a);
        if(same((const u8 *)BUFFER,(const u8 *)(SOURCE+a-FW_START),SECTOR))continue;
        if(a<FW_START||a>FW_END-SECTOR)return fail(21,a);
        if(((erase_fn)(b+0x63b0))(a,SECTOR))return fail(22,a);
        u32 written=0;
        if(((write_fn)(b+0x6288))(a,SECTOR,&written,(const u8 *)(SOURCE+a-FW_START))||written!=SECTOR)return fail(23,a);
        if(!read_sector(b,a)||!same((const u8 *)BUFFER,(const u8 *)(SOURCE+a-FW_START),SECTOR))return fail(24,a);
        ++writes;if(!(writes&63)){out("VERIFIED_SECTORS=");hex(writes);out("\r\n");}
    }
    if(!flash_crc(b,FW_START,FW_END,&after_crc)||after_crc!=source_crc)return fail(25,FW_START);
    if(!flash_crc(b,0,FW_START,&factory_crc)||factory_crc!=FACTORY_CRC)return fail(26,0);
    if(!flash_crc(b,FW_END,0x400000u,&after_tail)||after_tail!=tail_crc)return fail(27,FW_END);
    out(rollback?"ROLLBACK_OK ":"INSTALL_OK ");out("readback CRC=");hex(after_crc);
    out("; factory and board data unchanged. Type reset.\r\n");return 0;
}
