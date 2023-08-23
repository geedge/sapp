#ifndef __duplicate_pkt_distinguish_h
#define __duplicate_pkt_distinguish_h 
#include <netinet/ip6.h>
#include "mesa_net.h"
#include "stream_internal.h" 

#define SAPP_DUP_FIRST_PKT_NUM		(3) /* 通过前N个包识别是否有重复流量 */

/* 网络序,  network order */

/* ipv4和ipv6分别定义, 因为ipv6地址巨大, 比例也相对较少, 
   统一使用union定义, 都会按最大长度计算, 影响性能. 
*/
struct sapp_dup_key_ip4_tuple{
	unsigned int sip;
	unsigned int dip;
};

struct sapp_dup_key_ip6_tuple{
	struct in6_addr sip;
	struct in6_addr dip;
};

struct __sapp_dup_pkt_key_l4{
	unsigned int tcp_seq;
	unsigned int tcp_ack;	
	unsigned short sport;
	unsigned short dport;
	unsigned short checksum; /* tcp or udp */
}__attribute__((packed, aligned(1)));

struct __sapp_dup_pkt_key_v4{
	struct __sapp_dup_pkt_key_l4 l4;
	unsigned short ip_id; /* TCP层SYN重传时, 或者应用层重传数据, ipid是不一样的, 其实不能算为重复包, 所以ipid也作为Key */
	struct sapp_dup_key_ip4_tuple ip_addr;
}__attribute__((packed, aligned(1)));


struct __sapp_dup_pkt_key_v6{
	struct __sapp_dup_pkt_key_l4 l4;
	struct sapp_dup_key_ip6_tuple ip_addr;
}__attribute__((packed, aligned(1)));

typedef struct __sapp_dup_pkt_key_v4 sapp_dup_pkt_key_v4_t;
typedef struct __sapp_dup_pkt_key_v6 sapp_dup_pkt_key_v6_t;


int sapp_dup_pkt_init(void);
void sapp_dup_pkt_destroy(void);

void sapp_dup_pkt_mark_l4(struct streaminfo *a_stream, const void *ip_hdr, const void *l4_hdr);
void sendpkt_dup_pkt_mark_stream(struct streaminfo *top_stream, const char *ip_hdr);


int sapp_dup_pkt_identify(int tid, struct streaminfo_private *pstream_pr, 
		const void *ip_hdr, const void *l4_hdr, int need_add_bloom_filter);


#endif

