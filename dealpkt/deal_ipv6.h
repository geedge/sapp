#ifndef __DEAL_IPV6_H_
#define __DEAL_IPV6_H_

#include "stream_internal.h" 
#include <netinet/ip6.h>

#define IPV6_DEBUG						(0)

#define IPV6_FRAG_DUMP				(1 && IPV6_DEBUG)

#define IPV6_MAXPLEN					(65535)

#define IPV6_FRAG_RESERVED_HDR_LEN		(40) /* 预留第一个IPv6分片头部长度 */

//#define IPV6_FRAG_TIMEOUT				(60)			/* 重组超时时间 */
/* 
	2015-12-02 lijia modify, 
	虽然RFC规定, 60秒内所有分片重组完成就是合法的,
	针对实际情况, IPv6分片如果在10秒内还未重组完成, 则认为是攻击行为或丢包, 直接free.
*/
#define IPV6_FRAG_TIMEOUT				(10)			/* 重组超时时间 */


#define IPV6_FRAG_MEM_FREE_ONCE		(512*1024)		/* 每次释放内存数量 */
#define IPV6_FRAG_MEM_HIGH_THRESH		(16*1024*1024)	/* 内存上限 */

#define IPV6_FRAG_NUM_PER_IPQ			(100)			/* 同一IPQ最大分片包数 */

#if IPV6_DEBUG
#define IPV6_PRINT(fmt, args...) printf(fmt, ##args)
#else
#define IPV6_PRINT(fmt, args...) 
#endif


struct simple_ip6_hdr
{
    unsigned char ip6_flags[4]; 	/* version, traffic-class, flow-label */
    u_int16_t ip6_payload_len;  	/* payload length, not contain header */
    unsigned char ip6_nxt_hdr;      /* next header, same as protocol in IPv4 */
    unsigned char ip6_hop;          /* hop limit, same as TTL in IPv4 */
    struct in6_addr ip6_src;		/* source address */
    struct in6_addr ip6_dst; 		/* dest address */
};


/*
 *	NextHeader field of IPv6 header
 */
#define NEXTHDR_HOP			0	/* Hop-by-hop option header. */
#define NEXTHDR_IPIP			4	/* IPIP header. */
#define NEXTHDR_TCP			6	/* TCP segment. */
#define NEXTHDR_UDP			17	/* UDP message. */
#define NEXTHDR_IPV6			41	/* IPv6 in IPv6 */
#define NEXTHDR_ROUTING		43	/* Routing header. */
#define NEXTHDR_FRAGMENT		44	/* Fragmentation/reassembly header. */
#define NEXTHDR_ESP			50	/* Encapsulating security payload. */
#define NEXTHDR_AUTH			51	/* Authentication header. */
#define NEXTHDR_ICMP			58	/* ICMP for IPv6. */
#define NEXTHDR_NONE			59	/* No next header */
#define NEXTHDR_DEST			60	/* Destination options header. */
#define NEXTHDR_MOBILITY		135	/* Mobility header. */

struct ipv6_opt_hdr{
	unsigned char	nexthdr;
	unsigned char	hdrlen;
	/* 
	 * TLV encoded option data follows.
	 */
} __attribute__((packed));	/* required for some archs */



/*
 *	Hop-By-Hop header
 */
struct ipv6_hop_hdr{
	unsigned char	nexthdr;
	unsigned char	hdrlen;
};


/*
 *	fragmentation header
 */

#define IPv6_FRAG_ISF			(1) /* 本包是一个分片包 */
#define IPv6_FRAG_NEW			(2) /* 已收到所有分片包，重组成的新包 */

#define	IP6_MF					(0x0001)

struct ipv6_frag_hdr{
	unsigned char	nexthdr;
	unsigned char	reserved;
	unsigned short	frag_off;
	unsigned int	identification;
};

struct ipv6_frag_key{
	unsigned int identification;	/* 最有可能不同的值放在结构体前面，比较时会快一些 */
	int __pad__; /* 整体结构8字节对齐 */
	struct in6_addr ip6_src;	/* source address */
	struct in6_addr ip6_dst; 	/* dest address */
	struct streaminfo_private *pfstream_pr;
};

struct ipv6_frag_private{
	unsigned char raw_next_hdr; /* 原始IP包的第一个可分片部分头部类型 */
	int unfragmentable_len; 	/* 原始IP包的不可分片部分长度 */
};


#endif

