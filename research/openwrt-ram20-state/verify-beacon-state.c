/* SPDX-License-Identifier: GPL-2.0-only */
/* Actual shared core, independent synthetic TSF events and register values. */
#define main c80_inherited_main
#include "verify-core.c"
#undef main
struct state_model {
    struct model m;
    unsigned fault,which,reads,queries;
    c80_u64 values[2],tsf_start;
};
static c80_u32 state_read(void *opaque,c80_u32 a)
{
    struct state_model *x=opaque;struct model *m=&x->m;
    /* Inherited fixture returned ready state6 only during stage18; the
     * real RAM18/19 trace retains it through MAC/state snapshots. */
    if(a==C80_SYNC && m->phase>=20 && m->phase<90) return 6;
    if(x->fault==20 && a==C80_GLO && m->phase==33 && m->result.beacon_valid[0])
        return *regptr(m,a)&~1u;
    for(unsigned i=0;i<12;++i) if(a==c80_state_regs[i]) {
        unsigned sample=x->reads/12;
        assert(m->io.beacon_state_test && sample<5 && i==x->reads%12);
        assert(m->result.radio_valid[3] && !m->result.radio_status[3]);
        assert((m->phase==(unsigned[]){30,33,34,37,36}[sample]));
        ++x->reads;
        return x->fault==21?~0u:0x10000000u|(sample<<8)|i;
    }
    return read_reg(opaque,a);
}
static void state_write(void *opaque,c80_u32 a,c80_u32 value)
{
    struct state_model *x=opaque;struct model *m=&x->m;
    for(unsigned i=0;i<12;++i) assert(a!=c80_state_regs[i]);
    if(a!=0x180043f8 || (m->phase!=39 && m->phase!=40)) { write_reg(opaque,a,value);return; }
    unsigned k=m->phase-39,f=k==x->which?x->fault:0,slot=value-1;
    struct c80_desc *d=&m->pool.tx[slot];c80_u8 *p=m->pool.command[slot];
    assert(value==m->tx_seen+1 && slot<27 && d->ctrl==(C80_LS0|(168u<<16)));
    assert(d->addr==c80_dma_address(&m->io,p) && !d->addr1 && !d->info);
    check_packet(m,p,168);++m->tx_seen;++m->writes;++x->queries;*regptr(m,a)=value;
    x->tsf_start=m->us;
    if(f!=13) { d->ctrl|=C80_DONE;*regptr(m,0x180043fc)=value; }
    if(f==14 || f==15 || f==16) return;
    unsigned index=m->rx_next[1]++;assert(index<63);
    struct c80_desc *rx=&m->pool.rx[1][index];c80_u8 *v=m->pool.data[1][index];
    assert(rx->addr==c80_dma_address(&m->io,v) && rx->ctrl==1536u<<16);
    memset(v,0,64);c80_put16(v+16,24);c80_put16(v+18,0xe000);
    v[20]=0xed;v[21]=p[39];v[24]=0x3c;c80_put16(v+28,2);
    c80_put32(v+32,(c80_u32)x->values[k]);c80_put32(v+36,(c80_u32)(x->values[k]>>32));
    unsigned bytes=40;
    if(f==5) c80_put16(v+28,5);
    if(f==6) { c80_put16(v+16,23);bytes=39; }
    if(f==7) { c80_put16(v+16,25);bytes=41; }
    if(f==8) bytes=39;
    if(f==9) v[24]=0x3d;
    if(f==10) v[21]^=1;
    if(f==11) v[19]=0xd0;
    if(f==12) v[20]=1;
    rx->ctrl=C80_DONE|C80_LS0|(bytes<<16);
    if(f==17 || f==18) {
        m->deferred_rx=rx;m->deferred_ctrl=rx->ctrl;
        m->deferred_due=m->us+6000000u-(f==17?1000u:0);rx->ctrl=1536u<<16;
    } else *regptr(m,C80_SOURCE)|=2;
}
static void state_delay(void *opaque,c80_u32 us)
{
    struct state_model *x=opaque;struct model *m=&x->m;
    if((m->phase==39 || m->phase==40) && m->phase-39==x->which) {
        if(x->fault==15) return;
        if(x->fault==16) { m->us=0;return; }
    }
    delay(opaque,us);
}
static struct state_model *state_new(unsigned fault,unsigned which)
{
    struct state_model *x=calloc(1,sizeof(*x));assert(x);struct model *m=&x->m;
    x->fault=fault;x->which=which;m->us=100;m->fault=BSS_GOOD;
    x->values[0]=0x1234567889abcdefull;x->values[1]=x->values[0]+30000000;
    if(fault==1) x->values[0]=x->values[1]=0;
    if(fault==2) { x->values[0]=0x1fffffff0ull;x->values[1]=x->values[0]+30000000; }
    if(fault==3) x->values[0]=x->values[1]=~0ull;
    if(fault==4) x->values[1]=x->values[0]-1;
    for(unsigned i=0;i<10;++i) *regptr(m,c80_aon_regs[i])=(c80_u32[]){0,0xe0800022,0,0xffffff20,0x11040,1,0x269f0000,0x0700b644,0x0700b644,0x9000}[i];
    *regptr(m,c80_controls[0])=0x40100000;*regptr(m,c80_controls[1])=0xf0000000;
    *regptr(m,0x180b1010)=0x10040101;*regptr(m,0x18002000)=*regptr(m,0x18002004)=0x8a00;
    *regptr(m,C80_OWN)=0x30001;*regptr(m,C80_GLO)=0x10001870;*regptr(m,C80_SYNC)=2;
    m->io=(struct c80_io){.context=x,.read=state_read,.write=state_write,.time_us=model_time,.delay_us=state_delay,
        .dma_order=barrier,.copy_emi=copy_emi,.crc_emi=crc_emi,.stage=stage,.pool=&m->pool,.dma_base=0x41000000,
        .irq_arm=model_irq_arm,.irq_disarm=model_irq_disarm,.nvm_read=model_nvm_read,.devinfo_test=1,.bss_test=1,
        .radio_test=1,.beacon_test=1,.watch_test=1,.rx0_rearm_test=1,.beacon_state_test=1};
    return x;
}
static unsigned cases;
static void state_case(unsigned fault,unsigned which,unsigned expected)
{
    struct state_model *x=state_new(fault,which);struct model *m=&x->m;
    if(fault==22) m->fault=BSS_RESET_STUCK;
    if(fault==23) m->fault=BSS_DMA_BUSY;
    if(fault==24) { m->bfault=4;m->bstep=1; }
    if(fault==25) m->io.beacon_test=0;
    if(fault==26) m->io.watch_test=0;
    if(fault==27) m->io.rx0_rearm_test=0;
    unsigned rc=c80_run(&m->io,firmware,&m->result);
    if(rc!=expected) fprintf(stderr,"state f%u k%u got%u want%u phase%u reads%u\n",fault,which,rc,expected,m->phase,x->reads);
    assert(rc==expected && m->result.primary==(expected<80?expected:0));
    if(fault>=25) assert(!m->writes && !x->reads && !x->queries);
    else {
        assert(m->result.mcu_stopped==(fault!=22) && m->result.dma_idle==(fault!=22 && fault!=23));
        assert(m->result.critical==(expected>=80?expected:0));
        if(!m->result.critical) assert(!m->result.cleanup);
    }
    if(!rc || fault==22 || fault==23) {
        assert(m->result.state_mask==31 && x->reads==60 && x->queries==2);
        assert(m->result.tsf_valid[0] && m->result.tsf_valid[1]);
        assert(m->result.command_submitted==27 && m->result.command_completed==27);
        assert(m->result.tx_completed==58 && m->result.rx_next[1]==27 && m->result.sequence==13);
        assert(m->result.beacon_complete && m->result.radio_complete);
        for(unsigned k=0;k<2;++k) assert((((c80_u64)m->result.tsf_high[k]<<32)|m->result.tsf_low[k])==x->values[k]);
        assert(m->result.tsf_delta_valid==(fault!=4));
        assert(m->result.tsf_delta_us==(fault==0 || fault==2 || fault>=17?30000000u:0u));
        for(unsigned k=0;k<5;++k) for(unsigned i=0;i<12;++i) {
            assert(m->result.state_regs[k][i]==(fault==21?~0u:0x10000000u|(k<<8)|i));
            assert(m->result.state_allones[k]==(fault==21?4095u:0u));
        }
    } else if(fault>=5 && fault<=18) {
        assert(m->result.tsf_attempted[which]);
        assert(m->result.state_mask==(which?15u:7u));
        assert(!m->result.beacon_attempted[2] && !m->result.radio_attempted[4]);
        assert(x->queries==which+1);
        if(fault==13) assert(m->result.tsf_valid[which]);
        else assert(!m->result.tsf_valid[which]);
    }
    if(fault==20) assert(m->result.state_guard_fault==1 && m->result.state_mask==1 && !x->queries && !m->result.beacon_attempted[1]);
    if(fault==24) assert(m->result.state_mask==3 && !x->queries);
    printf("PASS STATE-f%u-k%u rc=%u mask=%x reads=%u queries=%u\n",fault,which,rc,m->result.state_mask,x->reads,x->queries);
    ++cases;free(x);
}
int main(int argc,char **argv)
{
    assert(argc==4);const char *names[6]={"test_mcu.bin","test_wifi.bin","WIFI_RAM_CODE_iemi.bin","WIFI_RAM_CODE_demi.bin","mt7626_patch_e1_hdr.bin","WIFI_RAM_CODE_7626.bin"};
    for(unsigned i=0;i<6;++i) { char path[1024];snprintf(path,sizeof(path),"%s/%s",argv[1],names[i]);FILE *f=fopen(path,"rb");assert(f);firmware[i].bytes=c80_blob_sizes[i];firmware[i].data=malloc(firmware[i].bytes);assert(fread((void *)firmware[i].data,1,firmware[i].bytes,f)==firmware[i].bytes);assert(fgetc(f)==EOF);fclose(f); }
    FILE *f=fopen(argv[2],"rb");assert(f);
    for(unsigned i=0;i<57;++i) { c80_u8 n[4];assert(fread(n,1,4,f)==4);stock_sizes[i]=c80_get32(n);assert(stock_sizes[i]<=1152 && fread(stock_packets[i],1,stock_sizes[i],f)==stock_sizes[i]); }
    assert(fgetc(f)==EOF);fclose(f);f=fopen(argv[3],"rb");assert(f && fread(synthetic_nvm,1,1024,f)==1024);fclose(f);
    for(unsigned i=0;i<5;++i) state_case(i,0,0);
    for(unsigned i=5;i<=18;++i) for(unsigned k=0;k<2;++k) state_case(i,k,i==17?0:i==13?12:i==8?14:i<=7?46:13);
    state_case(20,0,44);state_case(21,0,0);state_case(22,0,80);state_case(23,0,81);state_case(24,0,42);
    for(unsigned i=25;i<=27;++i) state_case(i,0,47);
    struct state_model *x=state_new(0,0);assert(c80_state_capture(&x->m.io,&x->m.result,5)==47);assert(c80_state_tsf(&x->m.io,&x->m.result,2)==47);assert(!x->reads && !x->m.writes);free(x);++cases;puts("PASS STATE-out-of-range-indices-before-MMIO");
    for(unsigned i=0;i<6;++i) free((void *)firmware[i].data);
    printf("PASS: %u actual-core beacon-state/TSF scenarios; all effects synthetic.\n",cases);
}
