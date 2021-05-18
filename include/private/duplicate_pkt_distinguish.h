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

struct __sapp_dup_pkt_key_v4{
	struct sapp_dup_key_ip4_tuple ip_addr;
	unsigned int tcp_seq;
	unsigned int tcp_ack;	
	unsigned short sport;
	unsigned short dport;
	unsigned short ip_id; /* TCP层SYN重传时, 或者应用层重传数据, ipid是不一样的, 其实不能算为重复包, 所以ipid也作为Key */
	unsigned short checksum; /* tcp or udp */
}__attribute__((packed, aligned(1)));


struct __sapp_dup_pkt_key_v6{
	struct sapp_dup_key_ip6_tuple ip_addr;
	unsigned int tcp_seq;
	unsigned int tcp_ack;	
	unsigned short sport;
	unsigned short dport;
	unsigned short checksum; /* tcp or udp */
}__attribute__((packed, aligned(1)));

typedef struct __sapp_dup_pkt_key_v4 sapp_dup_pkt_key_v4_t;
typedef struct __sapp_dup_pkt_key_v6 sapp_dup_pkt_key_v6_t;


int sapp_dup_pkt_init(void);

void sapp_dup_pkt_mark_tcp(int tid, unsigned char addr_type, const void *ip_hdr, const struct mesa_tcp_hdr *tcp_h);
void sapp_dup_pkt_mark_udp(int tid, unsigned char addrtype, const void *ip_hdr, const struct mesa_udp_hdr *udp_h);
void sendpkt_dup_pkt_mark_stream(const struct streaminfo *top_stream, const char *ip_hdr);


int sapp_dup_pkt_identify_tcp(int tid, struct streaminfo_private *pstream_pr, 
		const void *ip_hdr, const struct mesa_tcp_hdr *tcp_h, int add_filter);
int sapp_dup_pkt_identify_udp_v4(int tid, struct streaminfo_private *pstream_pr,  
		const struct mesa_ip4_hdr *ipv4_hdr, const struct mesa_udp_hdr *udp_h, int add_filter);		
int sapp_dup_pkt_identify_udp_v6(int tid, struct streaminfo_private *pstream_pr,  
		const struct mesa_ip6_hdr *ipv6_hdr, const struct mesa_udp_hdr *udp_h);


#endif

