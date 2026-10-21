/* SPDX-License-Identifier: GPL-2.0-only */
#define C80_COMPLETE_LIBRARY
#include "verify-tx-free.c"
static c80_u8 sta_oracle[2][308],assoc_txd[32];static unsigned sta_size[2],assoc_cases;
struct association_model {
    struct complete_model base;
    unsigned fault,requests,submits,notices,data_stage,tx_sta,late_jump,early;
    c80_u8 header[64],frame[48];
};
static void association_pinned(struct association_model *x)
{
    auth_pinned(&x->base.auth);
    if(x->submits) {
        assert(!memcmp(x->header,x->base.auth.em.m.pool.assoc_header,64));
        assert(!memcmp(x->frame,x->base.auth.em.m.pool.assoc_frame,48));
    }
}
static c80_u32 association_read(void *opaque,c80_u32 address)
{
    struct association_model *x=opaque;struct model *m=&x->base.auth.em.m;association_pinned(x);
    if(m->phase==37 && m->result.sta_valid[0] && !x->submits) {
        if(x->fault==16 && address==C80_AUTH_RING) return 0x41430000;
        if(x->fault==17 && address==C80_AUTH_RING+4) return 31;
        if(x->fault==18 && address==C80_AUTH_RING+8) return 0;
        if(x->fault==19 && address==C80_AUTH_RING+12) return 2;
    }
    return auth_read(opaque,address);
}
static void association_write(void *opaque,c80_u32 address,c80_u32 value)
{
    struct association_model *x=opaque;struct model *m=&x->base.auth.em.m;struct c80_result *r=&m->result;association_pinned(x);
    if(address==C80_AUTH_RING+8 && value==2 && m->phase==37) {
        assert(!x->submits && r->assoc_submitted && r->sta_valid[0] && !r->sta_status[0] && r->auth_token_returned);
        struct c80_desc *d=&m->pool.auth_tx[1];assert(d->addr==c80_dma_address(&m->io,m->pool.assoc_header) && d->addr1==c80_dma_address(&m->io,m->pool.assoc_frame));
        assert(d->ctrl==0x40400000 && !d->info && !memcmp(assoc_txd,m->pool.assoc_header,32));
        c80_u8 txp[32]={0};c80_put16(txp,0x8001);c80_put32(txp+8,d->addr1);c80_put16(txp+12,0x8024);assert(!memcmp(txp,m->pool.assoc_header+32,32));
        c80_u8 frame[48]={0};c80_put16(frame,0x10);c80_put16(frame+2,304);c80_put16(frame+22,16);memcpy(frame+4,peer,6);memcpy(frame+10,synthetic_nvm+4,6);memcpy(frame+16,synthetic_nvm+4,6);
        c80_put16(frame+24,1);c80_put16(frame+28,0xc001);memcpy(frame+30,(c80_u8[]){1,4,0x82,0x84,0x8b,0x96},6);assert(!memcmp(frame,m->pool.assoc_frame,48));
        memcpy(x->header,m->pool.assoc_header,64);memcpy(x->frame,m->pool.assoc_frame,48);++x->submits;
        if(x->fault!=11) *regptr(m,address)=2;
        if(x->fault!=12 && x->fault!=13) d->ctrl|=C80_DONE;
        if(x->fault!=12 && x->fault!=14) *regptr(m,C80_AUTH_RING+12)=2;
        if(x->fault==15) d->addr^=16;
        return;
    }
    if(address==0x180043f8 && r->sta_waiting) {
        unsigned off=r->sta_waiting-1,slot=value-1,i=x->base.auth.em.producer;
        struct c80_desc *d=&m->pool.tx[slot];c80_u8 *p=m->pool.command[slot],expected[308];
        assert(off<2 && value==m->tx_seen+1 && slot<29 && r->phase==37);
        assert(d->addr==c80_dma_address(&m->io,p) && !d->addr1 && !d->info && d->ctrl==(C80_LS0|(sta_size[off]<<16)));
        memcpy(expected,sta_oracle[off],sta_size[off]);expected[39]=(m->tx_seen+m->fwdl_seen)%15+1;assert(!memcmp(p,expected,sta_size[off]));
        assert(p[41]==0x25 && p[43]==1 && *regptr(m,C80_MASK)==0 && !(*regptr(m,C80_GLO)&C80_DOWNLOAD_MODE));
        ++m->tx_seen;++m->writes;++x->tx_sta;
        if(x->fault!=7 || off) { d->ctrl|=C80_DONE;*regptr(m,0x180043fc)=value; }
        *regptr(m,address)=value;
        if(x->fault==8 && !off) return;
        struct c80_desc *rx=&m->pool.rx[1][i];c80_u8 *v=m->pool.data[1][i];assert(!(rx->ctrl&C80_DONE));
        unsigned bytes=x->fault==4?56:44;if((x->fault==2 && !off)||(x->fault==10 && off)) bytes=43;
        memset(v,0,64);c80_put32(v,(7u<<29)|bytes);c80_put16(v+16,bytes-16);c80_put16(v+18,0xe000);v[20]=0xed;v[21]=p[39];v[24]=0x25;v[28]=0x25;v[37]=1;c80_put16(v+38,off?1:2);
        if((x->fault==1 && !off)||(x->fault==9 && off)) c80_put32(v+32,1);
        if(x->fault==3 && !off) v[28]=0x26;
        if(x->fault==5 && !off) v[24]=0x26;
        if(x->fault==6 && !off) v[21]^=1;
        rx->ctrl=C80_DONE|C80_LS0|(bytes<<16);x->base.auth.em.producer=(i+1)%64;m->rx_next[1]=x->base.auth.em.producer;
        return;
    }
    auth_write(opaque,address,value);
}
static void association_barrier(void *opaque,int publish)
{
    struct association_model *x=opaque;struct model *m=&x->base.auth.em.m;association_pinned(x);complete_barrier(opaque,publish);
    if(x->fault==28 && m->result.sta_valid[0] && !x->late_jump) { m->us+=1500000;x->late_jump=1; }
}
static void association_rx(struct association_model *x,unsigned type)
{
    struct model *m=&x->base.auth.em.m;unsigned i=m->result.rx_next[0];c80_u8 *v=m->pool.data[0][i],*p=v+16;unsigned n=type==0?45:type==1?28:26;
    assert(!(m->pool.rx[0][i].ctrl&C80_DONE));memset(v,0,128);frame(p,m->pool.nvm_payload+8,0);
    if(!type) {
        c80_put16(p+24,1);c80_put16(p+26,10);p[28]=0;p[29]=9;memcpy(p+30,"C80-RAM16",9);memcpy(p+39,(c80_u8[]){1,4,0x82,0x84,0x8b,0x96},6);
        if(x->fault==29) p[44]=12;
        if(x->fault==31) p[10]^=2;
    } else { c80_put16(p,type==1?0x0108:0x01c8);memset(p+24,0,n-24); }
    c80_put32(v,(2u<<29)|(16+n));m->pool.rx[0][i].ctrl=C80_DONE|C80_LS0|((16+n)<<16);
}
static void association_delay(void *opaque,c80_u32 us)
{
    struct association_model *x=opaque;struct model *m=&x->base.auth.em.m;association_pinned(x);complete_delay(opaque,us);
    if(m->phase!=37) return;
    unsigned ready=x->fault==27?m->us-m->watch_start>=28500000:x->fault==28?m->us-m->watch_start>=28000000:1;
    if(x->base.auth.pubs && !x->requests && ready) { association_rx(x,0);++x->requests; }
    if(x->fault==22 && x->base.auth.pubs && !x->early) {
        unsigned i=x->base.auth.em.producer;struct c80_desc *d=&m->pool.rx[1][i];assert(!(d->ctrl&C80_DONE));
        unsigned bytes=notification(m->pool.data[1][i],1,1,1);d->ctrl=C80_DONE|C80_LS0|(bytes<<16);x->base.auth.em.producer=(i+1)%64;m->rx_next[1]=x->base.auth.em.producer;++x->early;
    }
    if(x->submits && !x->notices && x->fault!=21 && x->fault!=12 && x->fault!=13 && x->fault!=14) {
        unsigned i=x->base.auth.em.producer;struct c80_desc *d=&m->pool.rx[1][i];assert(!(d->ctrl&C80_DONE));
        unsigned bytes=notification(m->pool.data[1][i],1,x->fault==23?2:1,x->fault==24?4096:1);d->ctrl=C80_DONE|C80_LS0|(bytes<<16);
        x->base.auth.em.producer=(i+1)%64;m->rx_next[1]=x->base.auth.em.producer;++x->notices;
    }
    if(x->fault==30 && x->submits && x->data_stage<2) { association_rx(x,x->data_stage?2:1);++x->data_stage; }
}
static struct association_model *association_new(unsigned fault)
{
    struct auth_model *old=auth_new(0);struct association_model *x=calloc(1,sizeof(*x));assert(x);memcpy(&x->base.auth,old,sizeof(*old));free(old);struct model *m=&x->base.auth.em.m;
    x->fault=fault;m->io.context=x;m->io.pool=&m->pool;m->io.read=association_read;m->io.write=association_write;m->io.dma_order=association_barrier;m->io.delay_us=association_delay;
    m->io.rx1_packet_test=m->io.assoc_reply_test=1;
    if(fault==20) x->base.scenario=3;
    if(fault==25) m->fault=BSS_RESET_STUCK;
    if(fault==26) m->fault=BSS_DMA_BUSY;
    return x;
}
static void association_full(unsigned fault,unsigned expected)
{
    struct association_model *x=association_new(fault);struct model *m=&x->base.auth.em.m;struct c80_result *r=&m->result;
    unsigned rc=c80_run(&m->io,firmware,r);if(rc!=expected) fprintf(stderr,"association fault%u got%u expected%u phase%u sta%u/%u/%u\n",fault,rc,expected,r->phase,r->sta_valid[0],r->sta_status[0],x->tx_sta);assert(rc==expected);association_pinned(x);
    assert(x->base.auth.pubs==1 && r->auth_dma_done && x->requests==1);
    if(!expected && fault!=27 && fault!=29 && fault!=31) {
        assert(r->assoc_complete && r->assoc_captured && r->assoc_dma_done && r->assoc_token_returned && r->assoc_cpu_readback==2 && r->assoc_dma_index==2);
        assert(r->sta_valid[0] && r->sta_valid[1] && !r->sta_status[0] && !r->sta_status[1] && x->tx_sta==2 && x->submits==1);
        assert(r->tx_submitted==60 && r->tx_completed==60 && r->sequence==15 && r->watch[1].complete);
    }
    if(fault==27 || fault==29 || fault==31) assert(!r->assoc_captured && !x->tx_sta && !x->submits && r->watch[1].complete);
    if(fault==27) assert(r->assoc_late==1);
    if(fault==29) assert(r->assoc_request_bad==1);
    if(fault==20) assert(r->assoc_captured && !x->tx_sta && !x->submits && !r->auth_token_returned);
    if(fault==28) assert(x->late_jump && r->sta_valid[0] && !x->submits);
    if(fault==30) assert(r->assoc_data_candidates==1 && r->assoc_null_candidates==1);
    if(fault==22) assert(x->early && r->assoc_free_before==1 && r->assoc_token_returned);
    if(fault==23) assert(r->assoc_free_duplicate==1 && r->assoc_token_returned);
    if(expected==80 || expected==81) assert(r->critical==expected && !r->dma_idle);
    else assert(!r->critical && !r->cleanup && r->mcu_stopped && r->dma_idle && !r->auth_ring_restore_bad);
    printf("PASS ASSOC-full fault%u rc%u submitted%u STA_commands%u\n",fault,rc,x->submits,x->tx_sta);++assoc_cases;free(x);
}
static void association_capture_unit(unsigned variant)
{
    struct association_model *x=association_new(0);struct model *m=&x->base.auth.em.m;struct c80_result *r=&m->result;c80_u8 req[96];frame(req,synthetic_nvm+4,0);
    memcpy(m->pool.nvm_payload+8,synthetic_nvm+4,6);memcpy(m->pool.auth_frame+4,peer,6);r->auth_submitted=r->auth_dma_done=1;r->phase=m->phase=37;
    r->auth_ring_programmed=r->nvm_equal=r->devinfo_mac_valid=r->bss_valid[0]=r->radio_valid[3]=r->beacon_valid[1]=1;r->assoc_window_start_us=m->us;
    c80_put16(req+24,1);c80_put16(req+26,10);req[28]=0;req[29]=9;memcpy(req+30,"C80-RAM16",9);memcpy(req+39,(c80_u8[]){1,4,0x82,0x84,0x8b,0x96},6);
    unsigned size=45;
    switch(variant) {
    case 0:break;case 1:req[0]=1;break;case 2:req[1]|=0x40;break;case 3:req[1]|=0x80;break;case 4:req[1]|=1;break;case 5:req[1]|=4;break;case 6:req[22]=1;break;
    case 7:req[4]^=2;break;case 8:req[16]^=2;break;case 9:req[10]^=2;break;case 10:c80_put16(req+24,0x11);break;case 11:c80_put16(req+24,3);break;case 12:c80_put16(req+26,0);break;
    case 13:req[29]=32;break;case 14:req[28]=1;break;case 15:req[38]^=1;break;case 16:req[39]=2;break;case 17:req[40]=9;break;case 18:req[40]=0;break;case 19:req[44]=12;break;case 20:size=44;break;
    case 21:r->phase=38;break;case 22:r->auth_dma_done=0;break;case 23:r->bss_status[0]=1;break;case 24:m->us+=28000001;break;case 25:m->io.assoc_reply_test=0;break;
    case 26:size=49;memset(req+45,0xa5,4);break;case 27:r->beacon_valid[1]=0;break;case 28:r->auth_submitted=0;break;case 29:r->assoc_window_start_us=m->us+1;break;default:assert(0);
    }
    c80_assoc_capture(&m->io,r,req,size);assert(r->assoc_captured==(variant==0 || variant==26));assert(!m->writes && !x->submits && !r->sta_waiting);
    printf("PASS ASSOC-capture variant%u captured%u\n",variant,r->assoc_captured);++assoc_cases;free(x);
}
static void association_reply_unit(unsigned variant)
{
    struct association_model *x=association_new(0);struct model *m=&x->base.auth.em.m;struct c80_result *r=&m->result;c80_u8 data[96]={0};c80_u32 status=~0u;r->phase=37;r->sta_waiting=1;
    c80_put16(data+16,28);c80_put16(data+18,0xe000);data[20]=0xed;data[21]=8;data[24]=data[28]=0x25;data[37]=1;c80_put16(data+38,2);unsigned size=44,expected=0;
    switch(variant) {
    case 0:break;case 1:size=43;c80_put16(data+16,27);expected=60;break;case 2:data[28]=0x26;expected=60;break;case 3:data[24]=0x26;expected=13;break;case 4:data[21]=7;expected=13;break;case 5:data[19]=0xd0;expected=13;break;
    case 6:c80_put32(data+32,0x80000000);break;case 7:data[24]=0;break;case 8:size=72;c80_put16(data+16,56);break;case 9:r->sta_waiting=2;break;case 10:data[36]=3;data[37]=7;c80_put16(data+38,0);data[40]=5;break;case 11:r->sta_waiting=3;expected=60;break;default:assert(0);
    }
    assert(c80_parse_event(&m->io,r,data,size,8,0xed,&status)==expected);
    if(!expected) { unsigned k=r->sta_waiting-1;assert(r->sta_valid[k] && r->sta_status[k]==(variant==6?0x80000000:0)); }
    printf("PASS ASSOC-reply variant%u rc%u\n",variant,expected);++assoc_cases;free(x);
}
static void association_guard_pages(unsigned bytes)
{
    struct association_model *x=association_new(0);struct model *m=&x->base.auth.em.m;struct c80_result *r=&m->result;c80_u8 req[80];frame(req,synthetic_nvm+4,0);
    memcpy(m->pool.nvm_payload+8,synthetic_nvm+4,6);memcpy(m->pool.auth_frame+4,peer,6);r->auth_submitted=r->auth_dma_done=1;r->phase=m->phase=37;
    r->auth_ring_programmed=r->nvm_equal=r->devinfo_mac_valid=r->bss_valid[0]=r->radio_valid[3]=r->beacon_valid[1]=1;r->assoc_window_start_us=m->us;
    c80_put16(req+24,1);c80_put16(req+26,10);req[28]=0;req[29]=9;memcpy(req+30,"C80-RAM16",9);memcpy(req+39,(c80_u8[]){1,4,0x82,0x84,0x8b,0x96},6);
    long page=sysconf(_SC_PAGESIZE);c80_u8 *area=mmap(NULL,2*page,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);assert(area!=MAP_FAILED);assert(!mprotect(area+page,page,PROT_NONE));c80_u8 *p=area+page-bytes;
    if(bytes) { memcpy(p,req,bytes); }
    c80_assoc_capture(&m->io,r,p,bytes);assert(r->assoc_captured==(bytes>=45));assert(!munmap(area,2*page));
    printf("PASS ASSOC-guard-page bytes%u captured%u\n",bytes,r->assoc_captured);++assoc_cases;free(x);
}
static void association_feature_guard(unsigned which)
{
    struct association_model *x=association_new(0);struct model *m=&x->base.auth.em.m;
    if(which) m->io.rx1_packet_test=0;else m->io.auth_reply_test=0;
    assert(c80_run(&m->io,firmware,&m->result)==59 && m->result.primary==59 && !m->writes && !x->submits);
    printf("PASS ASSOC-feature-guard %u noMMIO\n",which);++assoc_cases;free(x);
}
#ifdef C80_ASSOC_LIBRARY
int c80_association_test_entry(int argc,char **argv)
#else
int main(int argc,char **argv)
#endif
{
    assert(argc==7);FILE *f=fopen(argv[4],"rb");assert(f && fread(auth_oracle,1,32,f)==32 && fgetc(f)==EOF);fclose(f);
    f=fopen(argv[3],"rb");assert(f && fread(synthetic_nvm,1,1024,f)==1024 && fgetc(f)==EOF);fclose(f);
    f=fopen(argv[2],"rb");assert(f);for(unsigned i=0;i<59;++i) { c80_u8 b[4];assert(fread(b,1,4,f)==4);stock_sizes[i]=c80_get32(b);assert(stock_sizes[i]<=1152 && fread(stock_packets[i],1,stock_sizes[i],f)==stock_sizes[i]); }assert(fgetc(f)==EOF);fclose(f);
    f=fopen(argv[5],"rb");assert(f);for(unsigned i=0;i<2;++i) { c80_u8 b[4];assert(fread(b,1,4,f)==4);sta_size[i]=c80_get32(b);assert(sta_size[i]<=308 && fread(sta_oracle[i],1,sta_size[i],f)==sta_size[i]); }assert(fgetc(f)==EOF);fclose(f);
    f=fopen(argv[6],"rb");assert(f && fread(assoc_txd,1,32,f)==32 && fgetc(f)==EOF);fclose(f);
    const char *names[]={"test_mcu.bin","test_wifi.bin","WIFI_RAM_CODE_iemi.bin","WIFI_RAM_CODE_demi.bin","mt7626_patch_e1_hdr.bin","WIFI_RAM_CODE_7626.bin"};for(unsigned i=0;i<6;++i) { char path[4096];snprintf(path,sizeof(path),"%s/%s",argv[1],names[i]);f=fopen(path,"rb");assert(f);firmware[i].bytes=c80_blob_sizes[i];firmware[i].data=malloc(firmware[i].bytes);assert(fread((void *)firmware[i].data,1,firmware[i].bytes,f)==firmware[i].bytes && fgetc(f)==EOF);fclose(f); }
    unsigned expected[]={0,61,60,60,0,13,13,12,13,61,60,62,63,63,63,64,64,64,64,64,63,63,0,0,58,80,81,0,63,0,0,0};
    for(unsigned i=0;i<sizeof(expected)/sizeof(expected[0]);++i) association_full(i,expected[i]);
    for(unsigned i=0;i<30;++i) association_capture_unit(i);
    for(unsigned i=0;i<12;++i) association_reply_unit(i);
    for(unsigned i=0;i<=46;++i) association_guard_pages(i);
    association_feature_guard(0);association_feature_guard(1);
    for(unsigned i=0;i<6;++i) free((void *)firmware[i].data);
    printf("PASS: %u actual-core single association/STA cases; ASan/UBSan; synthetic host/device/client effects.\n",assoc_cases);return 0;
}
