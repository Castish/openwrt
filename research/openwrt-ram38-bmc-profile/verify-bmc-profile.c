/* SPDX-License-Identifier: GPL-2.0-only */
/* Actual BMC producer, independent OEM oracle and guard pages. */
#define _GNU_SOURCE
#include "private/bmc-profile-fixture.h"
#include <sys/mman.h>
#include <unistd.h>
int main(int argc,char **argv)
{
    unsigned cases=0;assert(argc==2);load_security(argv[1]);
    struct secure_model *s=secure_fixture();c80_u8 body[252];
    c80_security_bmc_payload(&s->m.io,body,0);
    assert(!memcmp(body,sta_security[0],252));
    assert(c80_get16(body+2)==3 && c80_get16(body+28)==8 && c80_get16(body+30)==8 && c80_get32(body+32)==1 && c80_get16(body+36)==13);
    ++cases;free(s);
    long page=sysconf(_SC_PAGESIZE);assert(page>=4096);
    c80_u8 *p=mmap(NULL,page*2,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);assert(p!=MAP_FAILED);
    assert(!mprotect(p+page,page,PROT_NONE));
    for(unsigned off=0;off<2;++off) {
        unsigned bytes=off?28:252;s=secure_fixture();c80_u8 *b=p+page-bytes;
        c80_security_bmc_payload(&s->m.io,b,off);
        assert(!memcmp(b,sta_security[off],bytes));++cases;free(s);
    }
    assert(!munmap(p,page*2));
    for(unsigned fault=1;fault<=10;++fault) {
        if(fault==8)continue;
        s=secure_fixture();s->fault=fault;
        assert(request(s,C80_KEY_ADD,0) && s->done==1 && s->result && !s->m.r.security.bmc_live && !s->m.r.security.gtk && s->posts==1);
        for(unsigned i=0;i<16;++i)assert(!s->m.r.security.gtk_key[i]);
        ++cases;free(s);
    }
    assert(cases==12);printf("PASS: %u BMC normal-profile/OEM/guard/refusal cases; ASan/UBSan; synthetic hardware.\n",cases);
    return 0;
}
