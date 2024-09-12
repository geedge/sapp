#ifndef _DEAL_IPV4_H_
#define _DEAL_IPV4_H_

#include "stream_internal.h" 
#include <netinet/ip.h>
#include "ip_reassembly.h"

#define IPV4_DEBUG						(0)

#if IPV4_DEBUG
#define IPV4_PRINT(fmt, args...) printf(fmt, ##args)
#else
#define IPV4_PRINT(fmt, args...) 
#endif

//#define IPV4_FRAG_TIMEOUT				(30)

#define IPV4_FRAG_TIMEOUT				(6)

#define IPV4_FRAG_RESERVED_HDR_LEN		(20) 

#define IPV4_FRAG_NUM_PER_IPQ			(100)

#define IPV4_FRAG_MEM_HIGH_THRESH		(64 * 1024 * 1024)
#define IPV4_FRAG_MEM_FREE_ONCE		(512 * 1024)

#define IPv4_FRAG_CE					0x8000    /* Flag: "Congestion" */
#define IPv4_FRAG_DF					0x4000    /* Flag: "Don't Fragment" */
#define IPv4_FRAG_MF					0x2000    /* Flag: "More Fragments" */
#define IPv4_FRAG_OFFSET				0x1FFF    /* "Fragment Offset" part */

#define IPv4_HDR_MAX_LEN				(60)	

struct ipv4_frag_key{
	unsigned int ip_src;	/* source address, network order */
	unsigned int ip_dst; 	/* dest address, network order */
	unsigned short identification; /* network order */
	unsigned char protocol;
	char __pad__[5];	
#if USE_MESA_STREAM_HASH
	struct streaminfo_private *pstream_pr; 
#endif
};

struct ipv4_frag_private{
	int raw_ip_hdr_len; 
};

#ifdef __cplusplus
extern "C" {
#endif

static inline int is_private_addr_v4(u_int ip_add)
{
/* 10/8 */
#define IPV4_LOCAL_CLASS_A(_add) (((_add&0xFF000000)==0x0A000000)?1:0) 
/* 172.16/12 */
#define IPV4_LOCAL_CLASS_B(_add) (((_add&0xFFF00000)==0xAC100000)?1:0) 
/* 192.168/16 */
#define IPV4_LOCAL_CLASS_C(_add) (((_add&0xFFFF0000)==0xC0A80000)?1:0) 

    if((int)IPV4_LOCAL_CLASS_A(ip_add) 
      || (int)IPV4_LOCAL_CLASS_B(ip_add) 
      || (int)IPV4_LOCAL_CLASS_C(ip_add))
    {
        return 1;
    }

    return 0;
}

static inline int is_multicast_addr_v4(u_int ip_add)
{
/* 224~239 */
#define IPV4_MULTICAST_ADDR(_add) (((_add&0xF0000000)==0xE0000000)?1:0) 

    if(IPV4_MULTICAST_ADDR(ip_add))
    {
        return 1;
    }

    return 0;
}

#ifdef __cplusplus
}
#endif

#endif

