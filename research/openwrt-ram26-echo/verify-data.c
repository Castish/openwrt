/* SPDX-License-Identifier: GPL-2.0-only */
#define C80_ASSOC_LIBRARY
#include "verify-association.c"
static c80_u8 data_txd[32],wire[10][200];static unsigned wire_size[10],data_cases;
struct data_model {
    struct association_model parent;
    unsigned fault,request[2],pub[2],notify[2],wmb[2],early,dup,jumped;
    c80_u8 header[2][64],frame[2][160];
};
static struct model *data_model_base(struct data_model *x) { return &x->parent.base.auth.em.m; }
static void data_pinned(struct data_model *x)
{
    association_pinned(&x->parent);struct model *m=data_model_base(x);
    for(unsigned k=0;k<2;++k) if(x->pub[k]) {
        assert(!memcmp(x->header[k],m->pool.diag_header[k],64));assert(!memcmp(x->frame[k],m->pool.diag_frame[k],160));
    }
}
static unsigned data_packet(c80_u8 *v,unsigned kind,unsigned translated,unsigned group,unsigned pad,unsigned qos,unsigned fixture)
{
    unsigned o=16+16*!!(group&8)+16*!!(group&1)+8*!!(group&2)+24*!!(group&4)+2*pad;
    const c80_u8 *eth=wire[kind?2+2*fixture:0];unsigned n=wire_size[kind?2+2*fixture:0],bytes;
    memset(v,0,512);c80_put32(v+4,(translated<<23)|(pad<<22)|2);v[8]=1;
    if(group&8) { c80_put16(v+16,qos?0x0188:0x0108);memcpy(v+18,peer,6);c80_put16(v+24,0x540); }
    if(translated) { memcpy(v+o,eth,n);bytes=o+n; }
    else {
        c80_u8 *p=v+o;unsigned h=qos?26:24;c80_put16(p,qos?0x0188:0x0108);memcpy(p+4,synthetic_nvm+4,6);memcpy(p+10,peer,6);memcpy(p+16,eth,6);c80_put16(p+22,0x540);
        memcpy(p+h,(c80_u8[]){0xaa,0xaa,3,0,0,0},6);memcpy(p+h+6,eth+12,n-12);bytes=o+h+8+n-14;
    }
    c80_put32(v,(2u<<29)|(group<<25)|bytes);return bytes;
}
static c80_u32 data_read(void *opaque,c80_u32 a)
{
    struct data_model *x=opaque;struct model *m=data_model_base(x);data_pinned(x);
    if(m->phase==37 && m->result.diag_captured[0] && !x->pub[0] && !x->pub[1]) {
        if(x->fault==15 && a==C80_AUTH_RING) return 0x41430000;
        if(x->fault==16 && a==C80_AUTH_RING+4) return 31;
        if(x->fault==17 && a==C80_AUTH_RING+8) return 1;
        if(x->fault==18 && a==C80_AUTH_RING+12) return 1;
    }
    return association_read(opaque,a);
}
static void data_write(void *opaque,c80_u32 a,c80_u32 val)
{
    struct data_model *x=opaque;struct model *m=data_model_base(x);struct c80_result *r=&m->result;data_pinned(x);
    if(a==C80_AUTH_RING+8 && (val==3 || val==4) && m->phase==37) {
        unsigned slot=val-1,k=r->diag_submitted[0] && !x->pub[0]?0:1;struct c80_desc *d=&m->pool.auth_tx[slot];
        assert(k<2 && !x->pub[k] && r->diag_submitted[k] && r->diag_slot[k]==slot && r->assoc_token_returned && r->sta_valid[0]);
        assert(x->wmb[k]==1 && d->addr==c80_dma_address(&m->io,m->pool.diag_header[k]) && d->addr1==c80_dma_address(&m->io,m->pool.diag_frame[k]) && !d->info && d->ctrl==0x40400000);
        c80_u8 h[64]={0};memcpy(h,data_txd,32);c80_put16(h,32+r->diag_bytes[k]);c80_put16(h+32,0x8002+k);c80_put32(h+40,d->addr1);c80_put16(h+44,0x8000|r->diag_bytes[k]);assert(!memcmp(h,m->pool.diag_header[k],64));
        unsigned fixture=x->fault==31?3:x->fault==32?1:x->fault==33?0:2,idx=k?3+2*fixture:1;
        assert(r->diag_bytes[k]==wire_size[idx] && !memcmp(m->pool.diag_frame[k],wire[idx],wire_size[idx]));
        for(unsigned j=wire_size[idx];j<160;++j) assert(!m->pool.diag_frame[k][j]);
        memcpy(x->header[k],m->pool.diag_header[k],64);memcpy(x->frame[k],m->pool.diag_frame[k],160);++x->pub[k];
        if(x->fault!=11) *regptr(m,a)=val;
        if(x->fault!=12) d->ctrl|=C80_DONE;
        if(x->fault!=13) *regptr(m,C80_AUTH_RING+12)=val;
        if(x->fault==14) d->addr^=16;
        return;
    }
    association_write(opaque,a,val);
}
static void data_barrier(void *opaque,int publish)
{
    struct data_model *x=opaque;struct model *m=data_model_base(x);data_pinned(x);association_barrier(opaque,publish);
    if(publish && m->phase==37) for(unsigned k=0;k<2;++k) if(m->result.diag_captured[k] && !m->result.diag_submitted[k]) {
        if(!x->jumped && (x->fault==23 || x->fault==25)) { m->us=x->fault==23?m->result.assoc_window_start_us-1:m->us+30000000;++x->jumped; }
        for(unsigned j=2;j<4;++j) if(m->pool.auth_tx[j].ctrl==0x40400000 && m->pool.auth_tx[j].addr1==c80_dma_address(&m->io,m->pool.diag_frame[k])) ++x->wmb[k];
    }
}
static void data_input(struct data_model *x,unsigned k)
{
    struct model *m=data_model_base(x);unsigned i=m->result.rx_next[0];c80_u8 *v=m->pool.data[0][i];assert(!(m->pool.rx[0][i].ctrl&C80_DONE));
    unsigned t=x->fault==1 || (x->fault==2 && k),group=t?15:0,pad=t,qos=x->fault==2;
    unsigned fixture=x->fault==31?3:x->fault==32?1:x->fault==33?0:2;
    unsigned n=data_packet(v,k,t,group,pad,qos,fixture);
    if(x->fault==7) v[10]|=2;
    if(x->fault==8) v[8]=2;
    if((x->fault==34 || x->fault==35) && k) {
        unsigned ip=16+24+8;v[ip+(x->fault==34?10:22)]^=1;
    }
    m->pool.rx[0][i].ctrl=C80_DONE|C80_LS0|(n<<16);++x->request[k];
}
static void data_notification(struct data_model *x,unsigned token,unsigned count)
{
    struct model *m=data_model_base(x);unsigned i=x->parent.base.auth.em.producer;struct c80_desc *d=&m->pool.rx[1][i];assert(!(d->ctrl&C80_DONE));
    unsigned n=notification(m->pool.data[1][i],1,count,token);d->ctrl=C80_DONE|C80_LS0|(n<<16);x->parent.base.auth.em.producer=(i+1)%64;m->rx_next[1]=x->parent.base.auth.em.producer;
}
static void data_delay(void *opaque,c80_u32 us)
{
    struct data_model *x=opaque;struct model *m=data_model_base(x);data_pinned(x);association_delay(opaque,us);
    if(m->phase!=37 || !m->result.assoc_dma_done) return;
    if(x->fault==27 && !x->early) { data_notification(x,2,1);++x->early;return; }
    for(unsigned k=0;k<2;++k) if(x->pub[k] && !x->notify[k] && x->fault!=10 && x->fault!=12 && x->fault!=13) {
        data_notification(x,x->fault==20?4096:2+k,x->fault==28?2:1);++x->notify[k];
    }
    if(x->fault==6) return;
    if(x->fault==24 && m->us-m->watch_start<28500000) return;
    if(x->fault==25 && (m->result.diag_captured[0] || m->result.diag_captured[1])) m->us+=30000000;
    if(x->fault==23 && m->result.diag_captured[0]) m->us=m->result.assoc_window_start_us-1;
    if(x->fault==3 || x->fault==5) {
        if(!x->request[1]) data_input(x,1);
        else if(x->fault==3 && m->result.diag_token_returned[1] && !x->request[0]) data_input(x,0);
    } else {
        if(!x->request[0]) data_input(x,0);
        else if(x->fault!=4 && m->result.diag_token_returned[0] && !x->request[1]) data_input(x,1);
    }
    if(x->fault==26 && m->result.diag_token_returned[1] && !x->dup) { data_input(x,0);++x->dup; }
}
static struct data_model *data_new(unsigned fault)
{
    struct association_model *p=association_new(0);struct data_model *x=calloc(1,sizeof(*x));assert(x);memcpy(&x->parent,p,sizeof(*p));free(p);struct model *m=data_model_base(x);
    x->fault=fault;m->io.context=x;m->io.pool=&m->pool;m->io.data_echo_test=1;m->io.read=data_read;m->io.write=data_write;m->io.dma_order=data_barrier;m->io.delay_us=data_delay;
    if(fault==19) x->parent.fault=21;
    if(fault==21) m->fault=BSS_RESET_STUCK;
    if(fault==22) m->fault=BSS_DMA_BUSY;
    return x;
}
static void data_full(unsigned fault,unsigned expected)
{
    struct data_model *x=data_new(fault);struct model *m=data_model_base(x);unsigned rc=c80_run(&m->io,firmware,&m->result);struct c80_result *r=&m->result;
    if(rc!=expected) fprintf(stderr,"data full%u rc%u expected%u phase%u cap%u/%u pub%u/%u done%u/%u free%u/%u\n",fault,rc,expected,r->phase,r->diag_captured[0],r->diag_captured[1],x->pub[0],x->pub[1],r->diag_dma_done[0],r->diag_dma_done[1],r->diag_token_returned[0],r->diag_token_returned[1]);
    assert(rc==expected);data_pinned(x);
    if(!expected) {
        unsigned responses=fault==4 || fault==5 || fault==34 || fault==35?1:fault==6 || fault==7 || fault==8 || fault==24?0:2;
        assert(r->diag_submissions==responses && x->pub[0]+x->pub[1]==responses && r->watch[1].complete && r->sta_valid[1]);
        for(unsigned k=0;k<2;++k) if(x->pub[k]) assert(r->diag_dma_done[k] && r->diag_token_returned[k]);
    }
    if(expected==80 || expected==81) assert(r->critical==expected && !r->dma_idle);
    else assert(!r->critical && !r->cleanup && r->mcu_stopped && r->dma_idle && !r->auth_ring_restore_bad);
    if(fault==27) assert(r->diag_early[0]==1);
    if(fault==28) assert(r->diag_dup_free[0]==1 && r->diag_dup_free[1]==1);
    printf("PASS DATA-full fault%u rc%u responses%u\n",fault,rc,r->diag_submissions);++data_cases;free(x);
}
static void data_unit(unsigned kind,unsigned translated,unsigned group,unsigned pad,unsigned qos,unsigned fixture)
{
    struct data_model *x=data_new(0);struct model *m=data_model_base(x);struct c80_result *r=&m->result;c80_u8 input[512];
    memcpy(m->pool.nvm_payload+8,synthetic_nvm+4,6);memcpy(m->pool.auth_frame+4,peer,6);r->phase=37;r->assoc_submitted=r->assoc_dma_done=r->sta_valid[0]=1;r->assoc_window_start_us=m->us;
    unsigned bytes=data_packet(input,kind,translated,group,pad,qos,fixture),o=16+16*!!(group&8)+16*!!(group&1)+8*!!(group&2)+24*!!(group&4)+2*pad;
    c80_data_receive(&m->io,r,input,bytes,o);assert(r->diag_captured[kind]);unsigned idx=kind?3+2*fixture:1;
    assert(r->diag_bytes[kind]==wire_size[idx] && !memcmp(m->pool.diag_frame[kind],wire[idx],wire_size[idx]));
    assert(!m->writes && !r->diag_submissions);
    printf("PASS DATA-unit kind%u trans%u group%x pad%u qos%u fixture%u\n",kind,translated,group,pad,qos,fixture);++data_cases;free(x);
}
static void data_fault(unsigned f)
{
    struct data_model *x=data_new(0);struct model *m=data_model_base(x);struct c80_result *r=&m->result;c80_u8 input[512];
    memcpy(m->pool.nvm_payload+8,synthetic_nvm+4,6);memcpy(m->pool.auth_frame+4,peer,6);r->phase=37;r->assoc_submitted=r->assoc_dma_done=r->sta_valid[0]=1;r->assoc_window_start_us=m->us;
    unsigned n=data_packet(input,1,0,0,0,0,2),o=16;c80_u8 *p=input+o,*ip=p+32;
    switch(f) {
    case 0:input[10]|=2;break;case 1:input[10]|=16;break;case 2:input[9]=0x10;break;case 3:input[8]=2;break;case 4:p[4]^=2;break;case 5:p[10]^=2;break;case 6:p[16]^=2;break;
    case 7:p[0]|=1;break;case 8:p[1]|=0x40;break;case 9:p[1]|=0x80;break;case 10:p[1]|=2;break;case 11:p[1]|=4;break;case 12:p[22]=1;break;case 13:p[24]=0xab;break;
    case 14:ip[0]=0x46;break;case 15:ip[2]=8;break;case 16:ip[6]=0x20;break;case 17:ip[8]=0;break;case 18:ip[10]^=1;break;case 19:ip[12]^=1;break;case 20:ip[16]^=1;break;
    case 21:ip[20]=0;break;case 22:ip[21]=1;break;case 23:ip[22]^=1;break;case 24:r->phase=38;break;case 25:r->assoc_submitted=0;break;case 26:r->assoc_dma_done=0;break;case 27:r->sta_valid[0]=0;break;case 28:r->sta_status[0]=1;break;case 29:r->sta_attempted[1]=1;break;case 30:m->io.data_echo_test=0;break;case 31:m->us+=28000001;break;case 32:r->assoc_window_start_us=m->us+1;break;
    case 33:input[7]=1;break;case 34:input[10]|=128;break;case 35:input[11]=1;break;case 36:input[11]=2;break;default:assert(0);
    }
    c80_data_receive(&m->io,r,input,n,o);assert(!r->diag_captured[0] && !r->diag_captured[1] && !m->writes);
    printf("PASS DATA-refuse case%u\n",f);++data_cases;free(x);
}
static void data_guard(unsigned bytes,unsigned translated)
{
    struct data_model *x=data_new(0);struct model *m=data_model_base(x);struct c80_result *r=&m->result;c80_u8 tmp[512];
    memcpy(m->pool.nvm_payload+8,synthetic_nvm+4,6);memcpy(m->pool.auth_frame+4,peer,6);r->phase=37;r->assoc_submitted=r->assoc_dma_done=r->sta_valid[0]=1;r->assoc_window_start_us=m->us;
    unsigned n=data_packet(tmp,1,translated,translated?8:0,0,0,2),offset=translated?32:16;(void)n;
    long pg=sysconf(_SC_PAGESIZE);c80_u8 *a=mmap(NULL,2*pg,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);assert(a!=MAP_FAILED && !mprotect(a+pg,pg,PROT_NONE));c80_u8 *v=a+pg-bytes;
    if(bytes) memcpy(v,tmp,bytes);
    c80_data_receive(&m->io,r,v,bytes,offset);assert(!m->writes && r->diag_captured[1]==(bytes>=n));assert(!munmap(a,2*pg));
    printf("PASS DATA-guard bytes%u trans%u captured%u\n",bytes,translated,r->diag_captured[1]);++data_cases;free(x);
}
int main(int argc,char **argv)
{
    assert(argc==9);FILE *f;
    f=fopen(argv[4],"rb");assert(f && fread(auth_oracle,1,32,f)==32 && fgetc(f)==EOF);fclose(f);
    f=fopen(argv[3],"rb");assert(f && fread(synthetic_nvm,1,1024,f)==1024 && fgetc(f)==EOF);fclose(f);
    f=fopen(argv[2],"rb");assert(f);for(unsigned i=0;i<59;++i) { c80_u8 b[4];assert(fread(b,1,4,f)==4);stock_sizes[i]=c80_get32(b);assert(stock_sizes[i]<=1152 && fread(stock_packets[i],1,stock_sizes[i],f)==stock_sizes[i]); }assert(fgetc(f)==EOF);fclose(f);
    f=fopen(argv[5],"rb");assert(f);for(unsigned i=0;i<2;++i) { c80_u8 b[4];assert(fread(b,1,4,f)==4);sta_size[i]=c80_get32(b);assert(sta_size[i]<=308 && fread(sta_oracle[i],1,sta_size[i],f)==sta_size[i]); }assert(fgetc(f)==EOF);fclose(f);
    f=fopen(argv[6],"rb");assert(f && fread(assoc_txd,1,32,f)==32 && fgetc(f)==EOF);fclose(f);
    f=fopen(argv[7],"rb");assert(f && fread(data_txd,1,32,f)==32 && fgetc(f)==EOF);fclose(f);
    f=fopen(argv[8],"rb");assert(f);for(unsigned i=0;i<10;++i) { c80_u8 b[4];assert(fread(b,1,4,f)==4);wire_size[i]=c80_get32(b);assert(wire_size[i]<=200 && fread(wire[i],1,wire_size[i],f)==wire_size[i]); }assert(fgetc(f)==EOF);fclose(f);
    const char *names[]={"test_mcu.bin","test_wifi.bin","WIFI_RAM_CODE_iemi.bin","WIFI_RAM_CODE_demi.bin","mt7626_patch_e1_hdr.bin","WIFI_RAM_CODE_7626.bin"};for(unsigned i=0;i<6;++i) { char path[4096];snprintf(path,sizeof(path),"%s/%s",argv[1],names[i]);f=fopen(path,"rb");assert(f);firmware[i].bytes=c80_blob_sizes[i];firmware[i].data=malloc(firmware[i].bytes);assert(fread((void *)firmware[i].data,1,firmware[i].bytes,f)==firmware[i].bytes && fgetc(f)==EOF);fclose(f); }
    const unsigned e[]={0,0,0,0,0,0,0,0,0,0,68,66,68,68,67,67,67,67,67,68,58,80,81,5,0,68,0,0,0,0,0,0,0,0,0,0};
    for(unsigned i=0;i<sizeof(e)/sizeof(e[0]);++i) if(i!=9 && i!=29 && i!=30) data_full(i,e[i]);
    for(unsigned kind=0;kind<2;++kind) for(unsigned group=0;group<16;++group) for(unsigned pad=0;pad<2;++pad) for(unsigned qos=0;qos<2;++qos) for(unsigned t=0;t<2;++t) if(!t || (group&8)) data_unit(kind,t,group,pad,qos,2);
    for(unsigned fi=0;fi<4;++fi) data_unit(1,1,8,0,0,fi);
    for(unsigned i=0;i<37;++i) data_fault(i);
    for(unsigned t=0;t<2;++t) for(unsigned n=0;n<=160;++n) data_guard(n,t);
    struct data_model *x=data_new(0);struct model *m=data_model_base(x);m->io.assoc_reply_test=0;assert(c80_run(&m->io,firmware,&m->result)==65 && !m->writes);free(x);++data_cases;puts("PASS DATA-feature-guard noMMIO");
    for(unsigned i=0;i<6;++i) free((void *)firmware[i].data);
    printf("PASS: %u actual-core bounded ARP/ICMP cases; ASan/UBSan; synthetic host/device/client effects.\n",data_cases);return 0;
}
