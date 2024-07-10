#ifndef __DEAL_IPV6_H_
#define __DEAL_IPV6_H_

#include "stream_internal.h" 
#include <netinet/ip6.h>

#define IPV6_DEBUG						(0)

#define IPV6_FRAG_DUMP				(1 && IPV6_DEBUG)

#define IPV6_MAXPLEN					(65535)

#define IPV6_FRAG_RESERVED_HDR_LEN		(40) /* Ԥ����һ��IPv6��Ƭͷ������ */

//#define IPV6_FRAG_TIMEOUT				(60)			/* ���鳬ʱʱ�� */
/* 
	2015-12-02 lijia modify, 
	��ȻRFC�涨, 60�������з�Ƭ������ɾ��ǺϷ���,
	���ʵ�����, IPv6��Ƭ�����10���ڻ�δ�������, ����Ϊ�ǹ�����Ϊ�򶪰�, ֱ��free.
*/
#define IPV6_FRAG_TIMEOUT				(10)			/* ���鳬ʱʱ�� */


#define IPV6_FRAG_MEM_FREE_ONCE		(512*1024)		/* ÿ���ͷ��ڴ����� */
#define IPV6_FRAG_MEM_HIGH_THRESH		(16*1024*1024)	/* �ڴ����� */

#define IPV6_FRAG_NUM_PER_IPQ			(100)			/* ͬһIPQ����Ƭ���� */

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
#define NEXTHDR_GRE		47	/* Generic Routing Encapsulation */
#define NEXTHDR_ESP			50	/* Encapsulating security payload. */
#define NEXTHDR_AUTH			51	/* Authentication header. */
#define NEXTHDR_ICMP			58	/* ICMP for IPv6. */
#define NEXTHDR_NONE			59	/* No next header */
#define NEXTHDR_DEST			60	/* Destination options header. */
#define NEXTHDR_OSPF_IGP			89	/* Destination options header. */
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

#define IPv6_FRAG_ISF			(1) /* ������һ����Ƭ�� */
#define IPv6_FRAG_NEW			(2) /* ���յ����з�Ƭ��������ɵ��°� */

#define	IP6_MF					(0x0001)

struct ipv6_frag_hdr{
	unsigned char	nexthdr;
	unsigned char	reserved;
	unsigned short	frag_off;
	unsigned int	identification;
};

struct ipv6_frag_key{
	unsigned int identification;	/* ���п��ܲ�ͬ��ֵ���ڽṹ��ǰ�棬�Ƚ�ʱ���һЩ */
	int __pad__; /* ����ṹ8�ֽڶ��� */
	struct in6_addr ip6_src;	/* source address */
	struct in6_addr ip6_dst; 	/* dest address */
	struct streaminfo_private *pfstream_pr;
};

struct ipv6_frag_private{
	unsigned char raw_next_hdr; /* ԭʼIP���ĵ�һ���ɷ�Ƭ����ͷ������ */
	int unfragmentable_len; 	/* ԭʼIP���Ĳ��ɷ�Ƭ���ֳ��� */
};


#endif

