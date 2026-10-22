/* SPDX-License-Identifier: GPL-2.0-only */
/* Reuse the actual-core fixture, replacing only its two OEM channel oracles. */
#define main c80_previous_core_cases
#include "verify-core.c"
#undef main
int main(int argc,char **argv)
{
    static const char *names[]={"test_mcu.bin","test_wifi.bin","WIFI_RAM_CODE_iemi.bin","WIFI_RAM_CODE_demi.bin","mt7626_patch_e1_hdr.bin","WIFI_RAM_CODE_7626.bin"};
    unsigned cases=0;FILE *f;char path[4096];c80_u8 saved[2][1152];
    assert(argc==5);setvbuf(stdout,NULL,_IOLBF,0);
    f=fopen(argv[3],"rb");assert(f && fread(synthetic_nvm,1,1024,f)==1024 && fgetc(f)==EOF);fclose(f);
    f=fopen(argv[2],"rb");assert(f);
    for(unsigned i=0;i<59;++i) {
        c80_u8 size[4];assert(fread(size,1,4,f)==4);stock_sizes[i]=c80_get32(size);
        assert(stock_sizes[i]<=1152 && fread(stock_packets[i],1,stock_sizes[i],f)==stock_sizes[i]);
    }
    assert(fgetc(f)==EOF);fclose(f);
    for(unsigned i=0;i<6;++i) {
        snprintf(path,sizeof(path),"%s/%s",argv[1],names[i]);f=fopen(path,"rb");assert(f);
        firmware[i].bytes=c80_blob_sizes[i];firmware[i].data=malloc(firmware[i].bytes);assert(firmware[i].data);
        assert(fread((void *)firmware[i].data,1,firmware[i].bytes,f)==firmware[i].bytes && fgetc(f)==EOF);fclose(f);
    }
    memcpy(saved,stock_packets+47,sizeof(saved));
    for(unsigned channel=1;channel<=6;channel+=5) {
        if(channel==1) {
            f=fopen(argv[4],"rb");assert(f);
            for(unsigned i=0;i<2;++i) {
                c80_u8 size[4];assert(fread(size,1,4,f)==4 && c80_get32(size)==stock_sizes[47+i]);
                assert(fread(stock_packets[47+i],1,stock_sizes[47+i],f)==stock_sizes[47+i]);
            }
            assert(fgetc(f)==EOF);fclose(f);
        } else memcpy(stock_packets+47,saved,sizeof(saved));
        test_radio_channel(0,0,0,channel);test_radio_channel(29,0,0,channel);test_radio_channel(30,0,0,channel);cases+=3;
        for(unsigned k=1;k<=2;++k)for(unsigned fault=1;fault<=15;++fault) {
            unsigned rc=fault<=2?38:fault==3||fault==5||fault==6?39:fault==7?14:fault==10?12:13;
            if(fault==12)rc=0;
            test_radio_channel(fault,k,rc,channel);++cases;
        }
        struct c80_dma_pool *pool=calloc(1,sizeof(*pool));assert(pool);
        struct c80_io io={.pool=pool,.radio_channel=channel};c80_u8 body[528];
        assert(!c80_beacon_payload(&io,body,1) && body[44+53]==3 && body[44+54]==1 && body[44+55]==channel);++cases;
        assert(c80_radio_frequency(&io)==(channel==1?2412u:2437u));++cases;free(pool);
    }
    const unsigned bad[]={2,11,14,36,255,~0u};
    for(unsigned i=0;i<sizeof(bad)/sizeof(*bad);++i) {
        struct c80_io io={.radio_channel=bad[i]};struct c80_result result={0};
        assert(c80_run(&io,NULL,&result)==C80_RADIO_BAD_STATE && result.phase==1 && result.primary==C80_RADIO_BAD_STATE);++cases;
    }
    for(unsigned i=0;i<6;++i)free((void *)firmware[i].data);
    assert(cases==76);printf("PASS: %u selected-channel full-core/OEM-oracle/beacon/refusal cases; ASan/UBSan; synthetic hardware.\n",cases);
    return 0;
}
