#ifdef __cplusplus
extern "C" {
#endif

#ifndef __FAVOR_BSD
#define __FAVOR_BSD 1
#endif

#include "stream_base.h"
#include "stream_internal.h"
#include "stream_manage.h"
#include "mesa_net.h"
#include "project_requirement.h"
#include "terminal_tag.h"
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>


#define TERMINAL_TAG_SIZE_MAX		(48)
extern int project_req_terminal_tag_id;
unsigned char terminal_tag_checksum_hash(unsigned char rand_num, 
						unsigned int ip_addr, unsigned short dev_id)
{
	unsigned char checksum_key = 0x5A;
	unsigned char *p;

	checksum_key += rand_num;
	p = (unsigned char *)&ip_addr;	
	checksum_key += p[0];
	checksum_key += p[1];
	checksum_key += p[2];
	checksum_key += p[3];
	p = (unsigned char *)&dev_id;
	checksum_key += p[0];
	checksum_key += p[1];

	return checksum_key;
}

unsigned char terminal_tag_checksum(struct terminal_tag_t *terminal_tag,
								 unsigned char checksum_key)
{
	unsigned char checksum = 0x77;
	unsigned char *p = (unsigned char *)terminal_tag;

	terminal_tag->check_sum = 0;

	checksum += p[0]; 
	checksum += p[1]; 
	checksum += p[2];
	checksum += p[3];
	checksum += p[4];
	checksum += p[5];
	checksum += p[6];
	checksum += p[7];	
	checksum += p[8];	
	checksum += p[9];
	checksum += checksum_key;
	
	return checksum;
}

unsigned char terminal_tag_encrypt_hash(unsigned char rand_num, unsigned int ip_addr)
{
	unsigned char encrypt_key = 0xA5;
	unsigned char *p;

	encrypt_key ^= rand_num;
	p = (unsigned char *)&ip_addr;	
	encrypt_key ^= p[0];
	encrypt_key ^= p[1];
	encrypt_key ^= p[2];
	encrypt_key ^= p[3];

	return encrypt_key;
}

static void *terminal_tag_create_struct(int thread_num)
{
	void *info = dictator_malloc(thread_num, TERMINAL_TAG_SIZE_MAX);
	memset(info, 0, TERMINAL_TAG_SIZE_MAX);

	return info;
}

static void terminal_tag_transform(struct terminal_tag_t *terminal_tag, 
								struct streaminfo *stream, unsigned char *stack_tag_string)
{
	char ip_str[16];
	unsigned char *mac;
	struct stream_tuple4_v4 *st4;
	int sip_addr;
	void *stream_tag_value;

	if(ADDR_TYPE_IPV4 == stream->addr.addrtype){
		st4 = (struct stream_tuple4_v4 *)stream->addr.tuple4_v4;
		sip_addr = st4->saddr;
	}else{
		return; /* 不支持ipv6 */
	}

	switch(terminal_tag->type)
	{
		case TERMINAL_ADDR_TYPE_MAC:
			mac = (unsigned char *)terminal_tag->local_addr.local_mac;
			snprintf((char *)stack_tag_string, TERMINAL_TAG_SIZE_MAX, "%s:%05u:%02x%02x-%02x%02x-%02x%02x",
					 "M",ntohs(terminal_tag->dev_id), mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
		break;
		
		case TERMINAL_ADDR_TYPE_IP:
			inet_ntop(AF_INET, &terminal_tag->local_addr.local_ip.ipaddr, ip_str, 16);
			snprintf((char *)stack_tag_string, TERMINAL_TAG_SIZE_MAX, "%s:%05u:%s",
					 "I", ntohs(terminal_tag->dev_id), ip_str);
		break;

		case TERMINAL_ADDR_TYPE_TRACE:
			// to do!
		break;

		case TERMINAL_ADDR_TYPE_GLOBAL_SIP:
		default:
			inet_ntop(AF_INET, &sip_addr, ip_str, 16);
			snprintf((char *)stack_tag_string, TERMINAL_TAG_SIZE_MAX, "%s:%s", "G:00000", ip_str);
		break;
	}
	
#if 0
	if(terminal_tag->type < 2)
	{
		printf("Tagv4 is: %s\n", stream->terminal_tag);
	}
	//mac = (unsigned char *)terminal_tag;
	//printf("Clear-bin is: %02x-%02x-%02x-%02x-%02x-%02x-%02x-%02x-%02x-%02x\n",
			//mac[0],mac[1],mac[2],mac[3],mac[4],mac[5],mac[6],mac[7],mac[8],mac[9]);
#endif	

	stream_tag_value = terminal_tag_create_struct(stream->threadnum);
	strncpy((char *)stream_tag_value, (const char *)stack_tag_string, TERMINAL_TAG_SIZE_MAX);
	project_req_add_struct(stream, project_req_terminal_tag_id, stream_tag_value);

	return;
}

static int terminal_tag_checksum_check(struct terminal_tag_t *terminal_tag_clear,
							struct streaminfo *stream, unsigned char *stack_tag_string)
{
	unsigned char checksum_key;
	unsigned char raw_checksum, new_checksum;
	struct stream_tuple4_v4 *st4 = (struct stream_tuple4_v4 *)stream->addr.tuple4_v4;
	int dip_addr;

	if(ADDR_TYPE_IPV4 == stream->addr.addrtype){
		st4 = (struct stream_tuple4_v4 *)stream->addr.tuple4_v4;
		dip_addr = st4->daddr;
	}else{
		return -1; /* 不支持ipv6 */
	}
	
	checksum_key = terminal_tag_checksum_hash(terminal_tag_clear->random,
											  dip_addr,
											  ntohs(terminal_tag_clear->dev_id));

	raw_checksum = terminal_tag_clear->check_sum;

	new_checksum = terminal_tag_checksum(terminal_tag_clear, checksum_key);

	if(raw_checksum != new_checksum)
	{
		//printf("Checksum error!\n");
		goto err; /* 校验和不对，可能传输错误、或被篡改、或恶意伪造包 */
	}

	switch(terminal_tag_clear->type)
	{	
		case TERMINAL_ADDR_TYPE_MAC:
		break;
		
		case TERMINAL_ADDR_TYPE_IP:  /* IP类型,空余两个字节用于完整性校验 */
			if(IP_STRUCT_MAGIC != terminal_tag_clear->local_addr.local_ip.ip_magic_num)
			{
				goto err;
			}
		break;

		default: /* 用户标签设备添加的标志只能是MAC或IP */
			return -1;
		break;
	}

	terminal_tag_transform(terminal_tag_clear, stream, stack_tag_string);
	return 0;
	
err:
	return -1;	
}

/* 用户标签解密 */
static int terminal_tag_decrypt(struct terminal_tag_t *terminal_tag_enc, 
							  struct streaminfo *stream, unsigned char *stack_tag_string)
{
	struct terminal_tag_t terminal_tag;
	unsigned char rand_num, encrypt_key;
	unsigned char *clear, *encrypt;
	struct stream_tuple4_v4 *st4 = (struct stream_tuple4_v4 *)stream->addr.tuple4_v4;
	int dip_addr;

	if(ADDR_TYPE_IPV4 == stream->addr.addrtype){
		st4 = (struct stream_tuple4_v4 *)stream->addr.tuple4_v4;
		dip_addr = st4->daddr;
	}else{
		return -1; /* 不支持ipv6 */
	}
	
	/* copy到一个临时空间，不修改原始数据包 */
	memcpy(&terminal_tag, terminal_tag_enc, sizeof(struct terminal_tag_t));

#if 0
	unsigned char *	mac = (unsigned char *)&terminal_tag;
	printf("Encrypt-bin is: %02x-%02x-%02x-%02x-%02x-%02x-%02x-%02x-%02x-%02x\n",
			mac[0],mac[1],mac[2],mac[3],mac[4],mac[5],mac[6],mac[7],mac[8],mac[9]);
#endif

	clear = (unsigned char *)&terminal_tag;
	encrypt = (unsigned char *)terminal_tag_enc;

	clear[0] = ror(encrypt[0], 4);
	rand_num  = terminal_tag.random;

	encrypt_key = terminal_tag_encrypt_hash(rand_num, dip_addr);

	/* 跳过第一个字节，type和random字段不参与此方式解密 */

	clear[1] = encrypt[1] ^ encrypt_key;
	clear[2] = encrypt[2] ^ encrypt_key;
	clear[3] = encrypt[3] ^ encrypt_key;
	clear[4] = encrypt[4] ^ encrypt_key;
	clear[5] = encrypt[5] ^ encrypt_key;
	clear[6] = encrypt[6] ^ encrypt_key;
	clear[7] = encrypt[7] ^ encrypt_key;
	clear[8] = encrypt[8] ^ encrypt_key;
	clear[9] = encrypt[9] ^ encrypt_key;

	return terminal_tag_checksum_check(&terminal_tag, stream, stack_tag_string);
}


static int terminal_tag_trace(struct streaminfo *stream, unsigned char *stack_tag_string)
{
	struct terminal_tag_t terminal_tag;
	/* 溯源系统查询 */
	/* to do:
		terminal_tag_trace(); 
		if(err)
		{
			goto def_tag;
		}
		terminal_tag_clear->type = TERMINAL_ADDR_TYPE_TRACE;
	*/
	terminal_tag.type = TERMINAL_ADDR_TYPE_GLOBAL_SIP;
	terminal_tag_transform(&terminal_tag, stream, stack_tag_string);
	return 0;
}




static int terminal_tag_set_ipv6(struct streaminfo *stream, unsigned char *stack_tag_string, const void *rawippkt)
{
	void *stream_tag_value;
	const struct mesa_ip6_hdr *ip6h = (struct mesa_ip6_hdr *)rawippkt;

	/* 暂时使用IPv6的源地址做为v6_tag */
	if(NULL == inet_ntop(AF_INET6, &ip6h->ip6_src, (char *)stack_tag_string, TERMINAL_TAG_SIZE_MAX))
	{
		return -1;
	}

	stream_tag_value = terminal_tag_create_struct(stream->threadnum);
	strncpy((char *)stream_tag_value, (const char *)stack_tag_string, TERMINAL_TAG_SIZE_MAX);
	project_req_add_struct(stream, project_req_terminal_tag_id, stream_tag_value);

	return 0;
}


/* 设备获取用户TAG, 判断是否正确，解密后存于stream结构中 */
static int terminal_tag_probe(struct streaminfo *stream, struct tcphdr *api_tcp_hdr,
							const void *rawippkt)
{
	struct mesa_tcp_hdr *this_tcphdr;
	unsigned char *stream_tag_string = NULL;
	unsigned char stack_tag_string[TERMINAL_TAG_SIZE_MAX];
	u_int8_t *option;
	int tcp_hdr_len;
	u_int16_t option_len;
	int ret = 0;

	if(likely(-1 == project_req_terminal_tag_id)){
		return -1;
	}
	
	this_tcphdr = (struct mesa_tcp_hdr *)api_tcp_hdr;
	option = (u_int8_t *)this_tcphdr + 20; /* TCP标准头部长度=20 */
	tcp_hdr_len = 4 * this_tcphdr->th_off;

	stream_tag_string = (unsigned char *)project_req_get_struct(stream, project_req_terminal_tag_id);
	if((NULL != stream_tag_string) && (stream_tag_string[0] != '\0')){ /* 已经获取到标签 */
		return 0;
	}
	
	if(ADDR_TYPE_IPV6 == stream->addr.addrtype)
	{
		return terminal_tag_set_ipv6(stream, stack_tag_string, rawippkt);
	}else if(ADDR_TYPE_IPV4 != stream->addr.addrtype){
		return -1;
	}

	if(this_tcphdr->th_flags != TH_SYN)
	{
		ret = -2;
		goto trace_tag;
	}
	tcp_hdr_len -= 20;
	if(tcp_hdr_len < TCP_SYN_TAG_LEN)
	{
		ret = -3;
		goto trace_tag;
	}

	while(tcp_hdr_len > 0)
	{
		switch(*option)
		{
			case 0: /* type=0原意是选项结束，因追加了新选项，所以要继续往后检查 */			
			case 1:
				option_len = 1;
			break;

			case TCP_SYN_TAG_TYPE:
				option_len = *(option+1);
				if(TCP_SYN_TAG_LEN == option_len)
				{
					ret = terminal_tag_decrypt((struct terminal_tag_t *)(option+2), stream, stack_tag_string);
					if(0 == ret)
					{
						return 0;
					}
				}
			break;

			default:
				option_len = *(option+1);
		}
		if(0 == option_len)
		{
			goto trace_tag;
		}
		if(option_len > tcp_hdr_len)
		{
			goto trace_tag;
		}
		option += option_len;
		tcp_hdr_len -= option_len;
	}

trace_tag:
	return terminal_tag_trace(stream, stack_tag_string);	
	//return -1;
}


char terminal_tag_tcp_all_entry(struct streaminfo *a_tcp,  void **pme, int thread_seq,void *a_packet)
{
	const struct mesa_ip4_hdr *ip4h = (const struct mesa_ip4_hdr *)a_packet;

	if(OP_STATE_PENDING == a_tcp->pktstate){
		terminal_tag_probe(a_tcp,  (struct tcphdr *)((char *)a_packet + ip4h->ip_hl*4), a_packet);		
	}

	return APP_STATE_DROPME;
}

int terminal_tag_init(void)
{
	return 0;
}

#ifdef __cplusplus
}
#endif

