/* SPDX-License-Identifier: GPL-2.0-only */
/* A synthetic Ethernet peer for the QEMU-only callback test device. It checks
 * actual Linux ARP/IP/ICMP/TCP and the official userspace dnsmasq/dropbear.
 * It does not emulate the C80 MCU, WLAN association, radio or DMA engine. */
#include "linux-test-abi.h"
static const unsigned char own[6]={2,0xc0,0x80,0x28,0,1},peer[6]={2,0xc0,0x80,0x28,0,2};
static const unsigned char server[4]={192,168,2,1},client[4]={192,168,2,2};
static unsigned char packet[2048],reply[2048];static unsigned cases;
static unsigned be16(const unsigned char *p){return ((unsigned)p[0]<<8)|p[1];}
static uint32_t be32(const unsigned char *p){return ((uint32_t)be16(p)<<16)|be16(p+2);}
static void put16(unsigned char *p,unsigned v){p[0]=v>>8;p[1]=v;}
static void put32(unsigned char *p,uint32_t v){put16(p,v>>16);put16(p+2,v);}
static unsigned sum(const unsigned char *p,unsigned n,unsigned seed)
{while(n>=2){seed+=be16(p);p+=2;n-=2;}if(n)seed+=(unsigned)p[0]<<8;while(seed>>16)seed=(seed&65535)+(seed>>16);return (~seed)&65535;}
static uint64_t milliseconds(void)
{struct timespec ts;assert(!clock_gettime(CLOCK_MONOTONIC,&ts));return (uint64_t)ts.tv_sec*1000+ts.tv_nsec/1000000;}
static int captured(void)
{int fd=open("/sys/kernel/c80_net_selftest/capture",O_RDONLY);assert(fd>=0);ssize_t n=read(fd,reply,sizeof(reply));close(fd);assert(n>=0);return n;}
static void drain(void){for(unsigned i=0;i<128 && captured();++i){} }
static void inject(unsigned n)
{int fd=open("/sys/kernel/c80_net_selftest/inject",O_WRONLY);assert(fd>=0);assert(write(fd,packet,n)==(ssize_t)n);close(fd);}
static void ethernet(unsigned type,int broadcast)
{memset(packet,0,sizeof(packet));memcpy(packet,own,6);if(broadcast)memset(packet,255,6);memcpy(packet+6,peer,6);put16(packet+12,type);}
static void ip(unsigned proto,unsigned length,int dhcp)
{unsigned char *p=packet+14;p[0]=0x45;put16(p+2,length);put16(p+4,0x2800+cases);put16(p+6,0x4000);p[8]=64;p[9]=proto;if(!dhcp)memcpy(p+12,client,4);memcpy(p+16,server,4);if(dhcp)memset(p+16,255,4);put16(p+10,sum(p,20,0));}
static unsigned dhcp(unsigned type)
{
    ethernet(0x800,1);ip(17,328,1);unsigned char *udp=packet+34,*b=udp+8;
    put16(udp,68);put16(udp+2,67);put16(udp+4,308);b[0]=1;b[1]=1;b[2]=6;put32(b+4,0x76262801);put16(b+10,0x8000);memcpy(b+28,peer,6);put32(b+236,0x63825363);
    unsigned k=240;b[k++]=53;b[k++]=1;b[k++]=type;b[k++]=61;b[k++]=7;b[k++]=1;memcpy(b+k,peer,6);k+=6;
    if(type==3){b[k++]=50;b[k++]=4;memcpy(b+k,client,4);k+=4;b[k++]=54;b[k++]=4;memcpy(b+k,server,4);k+=4;}
    b[k++]=55;b[k++]=4;b[k++]=1;b[k++]=3;b[k++]=6;b[k++]=51;b[k++]=255;assert(k<=300);return 342;
}
static int dhcp_match(int bytes,unsigned wanted)
{
    if(bytes<14+20+8+240 || be16(reply+12)!=0x800)return 0;unsigned ihl=(reply[14]&15)*4;
    if(ihl<20 || 14+ihl+8+240>(unsigned)bytes || reply[23]!=17)return 0;
    unsigned char *udp=reply+14+ihl,*b=udp+8;if(be16(udp)!=67 || be16(udp+2)!=68 || b[0]!=2 || be32(b+4)!=0x76262801)return 0;
    assert(!memcmp(b+16,client,4) && !memcmp(b+28,peer,6) && be32(b+236)==0x63825363);
    unsigned len=be16(udp+4);assert(len>=248 && 14+ihl+len<=(unsigned)bytes);unsigned k=240,type=0,mask=0,router=0,dns=0,lease=0,srv=0;
    while(k<len-8){unsigned code=b[k++];if(!code)continue;if(code==255)break;assert(k<len-8);unsigned n=b[k++];assert(n<=len-8-k);if(code==53){assert(n==1);type=b[k];}if(code==1){assert(n==4 && be32(b+k)==0xffffff00);mask=1;}if(code==3)router=1;if(code==6)dns=1;if(code==51){assert(n==4 && be32(b+k)>=60);lease=1;}if(code==54){assert(n==4 && !memcmp(b+k,server,4));srv=1;}k+=n;}
    if(type!=wanted)return 0;assert(mask && lease && srv && !router && !dns);return 1;
}
static void wait_dhcp(unsigned type)
{uint64_t end=milliseconds()+15000;for(;;){int n=captured();if(n && dhcp_match(n,type))return;assert(milliseconds()<end);usleep(10000);}}
static void arp(void)
{
    ethernet(0x806,1);unsigned char *p=packet+14;put16(p,1);put16(p+2,0x800);p[4]=6;p[5]=4;put16(p+6,1);memcpy(p+8,peer,6);memcpy(p+14,client,4);memcpy(p+24,server,4);inject(42);
    uint64_t end=milliseconds()+5000;for(;;){int n=captured();if(n>=42 && be16(reply+12)==0x806 && be16(reply+20)==2){assert(!memcmp(reply,peer,6) && !memcmp(reply+6,own,6) && !memcmp(reply+22,own,6) && !memcmp(reply+28,server,4) && !memcmp(reply+32,peer,6) && !memcmp(reply+38,client,4));return;}assert(milliseconds()<end);usleep(10000);}
}
static unsigned echo(unsigned payload,unsigned id)
{ethernet(0x800,0);ip(1,28+payload,0);unsigned char *p=packet+34;p[0]=8;put16(p+4,id);put16(p+6,1);for(unsigned i=0;i<payload;++i)p[8+i]=(i*13+7)&255;put16(p+2,sum(p,8+payload,0));return 42+payload;}
static int echo_match(unsigned n,unsigned id,unsigned payload)
{
    if(n<42+payload || be16(reply+12)!=0x800 || reply[23]!=1 || reply[34]!=0 || be16(reply+38)!=id)return 0;
    assert(!memcmp(reply,peer,6) && !memcmp(reply+6,own,6) && !memcmp(reply+26,server,4) && !memcmp(reply+30,client,4));assert(be16(reply+16)==28+payload && !sum(reply+14,20,0) && !sum(reply+34,8+payload,0));for(unsigned i=0;i<payload;++i)assert(reply[42+i]==((i*13+7)&255));return 1;
}
static void wait_echo(unsigned id,unsigned payload,int expect)
{uint64_t end=milliseconds()+(expect?5000:400);int found=0;do{int n=captured();if(n && echo_match(n,id,payload)){found=1;break;}usleep(10000);}while(milliseconds()<end);assert(found==expect);}
static unsigned tcp(uint32_t seq,uint32_t ack,unsigned flags)
{
    ethernet(0x800,0);ip(6,40,0);unsigned char *p=packet+34;put16(p,40028);put16(p+2,22);put32(p+4,seq);put32(p+8,ack);p[12]=0x50;p[13]=flags;put16(p+14,65535);
    unsigned pseudo=be16(client)+be16(client+2)+be16(server)+be16(server+2)+6+20;put16(p+16,sum(p,20,pseudo));return 54;
}
static unsigned tcp_match(int n)
{
    if(n<54 || be16(reply+12)!=0x800 || reply[23]!=6 || be16(reply+34)!=22 || be16(reply+36)!=40028)return 0;
    unsigned len=be16(reply+16)-20;assert(14+20+len<=(unsigned)n && !memcmp(reply+26,server,4) && !memcmp(reply+30,client,4));unsigned pseudo=be16(server)+be16(server+2)+be16(client)+be16(client+2)+6+len;assert(!sum(reply+34,len,pseudo));return len;
}
static void tcp_test(void)
{
    const uint32_t seq=0x12345678;inject(tcp(seq,0,2));uint64_t end=milliseconds()+5000;uint32_t ss=0;int seen=0;
    do{int n=captured();unsigned len=tcp_match(n);if(len && (reply[47]&0x12)==0x12){assert(be32(reply+42)==seq+1);ss=be32(reply+38);seen=1;break;}usleep(10000);}while(milliseconds()<end);assert(seen);
    ++cases;puts("PASS LINUX-TCP-SYNACK from actual kernel");inject(tcp(seq+1,ss+1,0x10));end=milliseconds()+8000;seen=0;
    do{int n=captured();unsigned len=tcp_match(n);if(len){unsigned h=(reply[46]>>4)*4;assert(h>=20 && h<=len);if(len>h){assert(len-h>=8 && !memcmp(reply+34+h,"SSH-2.0-",8));inject(tcp(seq+1,ss+1+len-h,0x14));seen=1;break;}}usleep(10000);}while(milliseconds()<end);assert(seen);
    ++cases;puts("PASS LINUX-TCP-SSH-BANNER from actual OpenWrt dropbear");
}
int main(void)
{
    setbuf(stdout,NULL);assert(access("/sys/kernel/c80_net_selftest/inject",W_OK)==0);drain();
    inject(dhcp(1));wait_dhcp(2);++cases;puts("PASS LINUX-DHCP-OFFER actual dnsmasq no gateway/DNS");
    inject(dhcp(3));wait_dhcp(5);++cases;puts("PASS LINUX-DHCP-ACK actual dnsmasq lease192.168.2.2");
    drain();arp();++cases;puts("PASS LINUX-ARP actual kernel response");
    const unsigned sizes[]={0,1,32,64,512,1372};for(unsigned i=0;i<sizeof(sizes)/sizeof(sizes[0]);++i){drain();inject(echo(sizes[i],0x2800+i));wait_echo(0x2800+i,sizes[i],1);++cases;printf("PASS LINUX-ICMP actual kernel payload%u\n",sizes[i]);}
    drain();unsigned n=echo(32,0x2900);packet[24]^=1;inject(n);wait_echo(0x2900,32,0);++cases;puts("PASS LINUX-IP-BAD-CHECKSUM rejected by actual kernel");
    drain();n=echo(32,0x2901);packet[36]^=1;inject(n);wait_echo(0x2901,32,0);++cases;puts("PASS LINUX-ICMP-BAD-CHECKSUM rejected by actual kernel");
    drain();tcp_test();printf("PASS LINUX-NETWORK %u actual Linux callback/IPv4/ARP/ICMP/TCP and dnsmasq/dropbear checks; software peer only, no C80 radio/DMA.\n",cases);return 0;
}
