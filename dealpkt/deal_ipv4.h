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
/* 
	2015-12-02 lijia modify, 
	虽然RFC规定, 30秒内所有分片重组完成就是合法的,
	针对实际情况, IPv4分片如果在6秒内还未重组完成, 则认为是攻击行为或丢包, 直接free.
*/
#define IPV4_FRAG_TIMEOUT				(6)

#define IPV4_FRAG_RESERVED_HDR_LEN		(20) /* 预留第一个IP分片头部长度 */

#define IPV4_FRAG_NUM_PER_IPQ			(100)

#define IPV4_FRAG_MEM_HIGH_THRESH		(64 * 1024 * 1024)
#define IPV4_FRAG_MEM_FREE_ONCE		(512 * 1024)

#define IPv4_FRAG_CE					0x8000    /* Flag: "Congestion" */
#define IPv4_FRAG_DF					0x4000    /* Flag: "Don't Fragment" */
#define IPv4_FRAG_MF					0x2000    /* Flag: "More Fragments" */
#define IPv4_FRAG_OFFSET				0x1FFF    /* "Fragment Offset" part */

#define IPv4_HDR_MAX_LEN				(60)	/* IPv4最大头部长度 */

struct ipv4_frag_key{
	unsigned int ip_src;	/* source address, network order */
	unsigned int ip_dst; 	/* dest address, network order */
	unsigned short identification;
	unsigned char protocol;
	char __pad__[5];	/* 整体结构8字节对齐 */
#if USE_MESA_STREAM_HASH
	struct streaminfo_private *pstream_pr; /* 仅用于比较地址, 实际不参与HASH运算 */
#endif
};

struct ipv4_frag_private{
	/* 
		原始IP包的第一个分片头部长度, 初始化时设为init_len = 20, 即标准IP头部长度, 以保证大部分情况下是正确的.
		如果收到第一个分片后, 原始包头实际长度actual_len = 40, 大于init_len, 
		需要再realloc内存, 然后将实际数据部分向后memmove(actual_len - init_len).
	*/
	int raw_ip_hdr_len; 
};

#ifdef __cplusplus
extern "C" {
#endif

/* 是否为IPv4私有地址 */
static inline int is_private_addr_v4(u_int ip_add)
{
/* 10/8 */
#define IPV4_LOCAL_CLASS_A(_add) (((_add&0xFF000000)==0x0A000000)?1:0) 
/* 172.16/12 */
#define IPV4_LOCAL_CLASS_B(_add) (((_add&0xFFF00000)==0xAC100000)?1:0) 
/* 192.168/16 */
#define IPV4_LOCAL_CLASS_C(_add) (((_add&0xFFFFFF00)==0xC0A80000)?1:0) 

    if((int)IPV4_LOCAL_CLASS_A(ip_add) 
      || (int)IPV4_LOCAL_CLASS_B(ip_add) 
      || (int)IPV4_LOCAL_CLASS_C(ip_add))
    {
        return 1;
    }

    return 0;
}

/* 是否为IPv4组播地址 */
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

