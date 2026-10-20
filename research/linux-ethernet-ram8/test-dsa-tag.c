/* SPDX-License-Identifier: MIT
 * Models skb APIs. Includes unchanged Linux RTL8_4 tagger and header helpers.
 */
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
typedef uint16_t __be16;
typedef uint16_t u16;
typedef uint8_t u8;
#define BIT(n) (1U << (n))
#define GENMASK(h,l) (((~0U) >> (31-(h))) & (~0U << (l)))
#define FIELD_PREP(mask,val) (((val) << __builtin_ctz(mask)) & (mask))
#define FIELD_GET(mask,val) (((val) & (mask)) >> __builtin_ctz(mask))
#define ETH_P_REALTEK 0x8899
#define ETH_ALEN 6
#define ETH_HLEN 14
#define CHECKSUM_PARTIAL 1
#define unlikely(x) (x)
#define dev_warn_ratelimited(...) ((void)0)
struct dsa_port { unsigned index; };
struct net_device { unsigned index; struct dsa_port port; };
struct sk_buff { unsigned char storage[2200], *data; unsigned len, ip_summed; struct net_device *dev; bool marked; };
static struct net_device ports[5], conduit;
static struct dsa_port *dsa_user_to_port(struct net_device *d) { return &d->port; }
static struct net_device *dsa_conduit_find_user(struct net_device *d, int sw, unsigned port)
{ assert(d == &conduit && sw == 0); return port < 5 ? &ports[port] : NULL; }
static void dsa_default_offload_fwd_mark(struct sk_buff *s) { s->marked = true; }
static void *skb_push(struct sk_buff *s, unsigned n) { assert(s->data-s->storage >= (int)n); s->data-=n;s->len+=n;return s->data; }
static void *skb_put(struct sk_buff *s, unsigned n) { void *p=s->data+s->len;s->len+=n;assert(s->data+s->len<=s->storage+sizeof(s->storage));return p; }
static bool pskb_may_pull(struct sk_buff *s, unsigned n) { return s->len>=n; }
static void skb_pull_rcsum(struct sk_buff *s, unsigned n) { assert(n<=s->len);s->data+=n;s->len-=n; }
static int skb_checksum_help(struct sk_buff *s) { (void)s;return 0; }
static int skb_linearize(struct sk_buff *s) { (void)s;return 0; }
static void *skb_tail_pointer(struct sk_buff *s) { return s->data+s->len; }
static int pskb_trim_rcsum(struct sk_buff *s, unsigned n) { assert(n<=s->len);s->len=n;return 0; }
#include "etype-helpers.inc"
#include "tagger-under-test.inc"
static unsigned checks;
#define CHECK(x) do { assert(x); checks++; } while (0)
static void frame(struct sk_buff *s, unsigned size)
{
    memset(s,0,sizeof(*s));s->data=s->storage+64;s->len=size;
    for(unsigned i=0;i<size;i++)s->data[i]=(unsigned char)(i*7+3);
    s->data[12]=8;s->data[13]=0;
}
int main(void)
{
    for(unsigned p=0;p<5;p++){ports[p].index=p;ports[p].port.index=p;}
    unsigned sizes[]={42,60,1514,1518};
    for(unsigned p=0;p<5;p++) for(unsigned n=0;n<4;n++) for(unsigned trap=0;trap<2;trap++) {
        struct sk_buff s;frame(&s,sizes[n]);unsigned char original[1518];memcpy(original,s.data,s.len);
        CHECK(rtl8_4_tag_xmit(&s,&ports[p])==&s && s.len==sizes[n]+8);
        unsigned char expected[]={0x88,0x99,4,0,0,0x20,0,(unsigned char)(1U<<p)};
        CHECK(!memcmp(s.data,original,12));CHECK(!memcmp(s.data+12,expected,8));
        CHECK(!memcmp(s.data+20,original+12,sizes[n]-12));
        /* Independent switch RX oracle: source port number, not TX bitmap. */
        s.data[15]=trap?80:0;s.data[18]=0;s.data[19]=p;s.dev=&conduit;
        skb_pull_rcsum(&s,14); /* Linux eth_type_trans before tagger */
        CHECK(rtl8_4_tag_rcv(&s,&conduit)==&s && s.dev==&ports[p]);
        CHECK(s.len==sizes[n]-14 && !memcmp(s.data-14,original,sizes[n]));
        CHECK(s.marked==!trap);
    }
    for(unsigned bad=0;bad<4;bad++) {
        struct sk_buff s;frame(&s,60);rtl8_4_tag_xmit(&s,&ports[1]);
        s.data[19]=1;
        if(bad==0)s.data[12]^=1;if(bad==1)s.data[14]=5;if(bad==2)s.data[19]=6;
        skb_pull_rcsum(&s,14);if(bad==3)s.len=7;
        CHECK(!rtl8_4_tag_rcv(&s,&conduit));
    }
    printf("PASS: %u checks; Linux rtl8_4 tagger, all five ports, short and MTU1500 frames, rejection paths\n",checks);
    return 0;
}
