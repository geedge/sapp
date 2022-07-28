#include "stream.h"
#include <stdio.h>
#include <pthread.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <sys/types.h>
#include <linux/if_tun.h>
#include <linux/limits.h>
#include <assert.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <dirent.h>
#include "dpdk_rte_hash_crc.h"

#include "stream_inc/stream_base.h"
#include "stream_internal.h"

#ifdef __cplusplus
extern "C" { 
#endif 

/*
	本函数copy自dpdk源码中的rte_hash_crc.h, 用于计算ip二元组hash,
	用来保证pcap模式下收包, 与marsio的分流算法一样, 便于测试.
	详见: marsio源码: ldbc.c -> hash_sym_crc()函数.
*/
unsigned int dpdk_rte_crc_hash(const char *sipaddr, const char *dipaddr, int addrlen, unsigned int orin_hash)
{
	unsigned int sip_hash, dip_hash;
	
	sip_hash = rte_hash_crc(sipaddr, addrlen, orin_hash);
	dip_hash = rte_hash_crc(dipaddr, addrlen, orin_hash);
	
	return sip_hash ^ dip_hash;
}

unsigned int tuple4_v4_make_crc_hash(const struct stream_tuple4_v4 *tuple4_v4)
{
  const char *a, *b;
  unsigned short c, d;
  unsigned int hash0, hash1;

  a = (const char *)&tuple4_v4->saddr;
  b = (const char *)&tuple4_v4->daddr;
  c = tuple4_v4->source;
  d = tuple4_v4->dest;

  hash0 = rte_hash_crc(a, sizeof(tuple4_v4->saddr), 0);
  hash0 = rte_hash_crc(&c, sizeof(tuple4_v4->source), hash0);

  hash1 = rte_hash_crc(b, sizeof(tuple4_v4->daddr), 0);
  hash1 = rte_hash_crc(&d, sizeof(tuple4_v4->dest), hash1);

  return hash0 ^ hash1;
}

unsigned int tuple4_v6_make_crc_hash(const struct stream_tuple4_v6 *tuple4_v6)
{
    const char *a, *b;
    unsigned short c, d;
    unsigned int hash0, hash1;

    a = (const char *)(tuple4_v6->saddr);
    b = (const char *)(tuple4_v6->daddr);
    c = tuple4_v6->source;
    d = tuple4_v6->dest;

    hash0 = rte_hash_crc(a, 12, 0);
    hash0 = rte_hash_crc(&c, sizeof(tuple4_v6->source), hash0);
    hash1 = rte_hash_crc(b, 12, 0);
    hash1 = rte_hash_crc(&d, sizeof(tuple4_v6->source), hash1);
    return hash0 ^ hash1;
}

int stream_make_rte_crchash(struct streaminfo_private *stream_pr, unsigned int maxsize)
{
    unsigned int hash_val;
    const struct layer_addr *addr = &stream_pr->stream_public.addr;

    if (ADDR_TYPE_IPV4 == addr->addrtype)
    {
        const struct stream_tuple4_v4 *tuple4_v4 = addr->tuple4_v4;
        hash_val = tuple4_v4_make_crc_hash(tuple4_v4);
    }
    else if (ADDR_TYPE_IPV6 == addr->addrtype)
    {
        const struct stream_tuple4_v6 *tuple4_v6 = addr->tuple4_v6;
        hash_val = tuple4_v6_make_crc_hash(tuple4_v6);
    }
    else
    {
        printf("stream_make_hash() error, addr type is not IPv4 or IPv6!\n");
        abort();
    }
    return hash_val % maxsize;
}

#ifdef __cplusplus
}
#endif 


