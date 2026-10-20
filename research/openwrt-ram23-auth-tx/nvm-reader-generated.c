
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
static c80_u32 c80_linux_nvm_read(void *context,c80_u8 *out,c80_u32 bytes,c80_u32 *crc)
{
    struct c80_linux *c=context; struct mtd_info *mtd;
    c80_u8 *sector; size_t done=0; int rc;
    if(bytes!=C80_NVM_BYTES) { c->nvm_error=-EINVAL; return C80_NVM_BAD_SOURCE; }
    mtd=get_mtd_device_nm("30000000.flash");
    if(IS_ERR(mtd)) { c->nvm_error=PTR_ERR(mtd); return C80_NVM_BAD_SOURCE; }
    if(mtd->type!=MTD_ROM || mtd->size!=0x400000 || (mtd->flags&MTD_WRITEABLE)) {
        c->nvm_error=-EINVAL; put_mtd_device(mtd); return C80_NVM_BAD_SOURCE;
    }
    sector=kmalloc(4096,GFP_KERNEL);
    if(!sector) { c->nvm_error=-ENOMEM; put_mtd_device(mtd); return C80_NVM_BAD_SOURCE; }
    rc=mtd_read(mtd,0x3ff000,4096,&done,sector);
    if(rc || done!=4096) c->nvm_error=rc?rc:-EIO;
    else {
        *crc=c80_crc(sector,4096);
        if(*crc!=C80_RADIO_CRC) c->nvm_error=-EBADMSG;
        else memcpy(out,sector,C80_NVM_BYTES);
    }
    memzero_explicit(sector,4096); kfree(sector); put_mtd_device(mtd);
    return c->nvm_error?C80_NVM_BAD_SOURCE:0;
}

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
