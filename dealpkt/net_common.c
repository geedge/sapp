
#include "packet_io_internal.h"
#include "packet_io.h"
#include "mesa_net.h"
#include "stream_internal.h"
#include "deal_ipv6.h"
#include <MESA/MESA_handle_logger.h>
#include <linux/if_ether.h>
#include <net/if_arp.h>
#include <arpa/inet.h>
#include <netinet/ip6.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <assert.h>
#include <ctype.h>


#ifdef __cplusplus
extern "C" {
#endif

static int eth_jump_to_layer(const char *raw_data,  int raw_layer_type, int expect_layer_type);
static int vlan8021q_jump_to_layer(const char *raw_data,  int raw_layer_type, int expect_layer_type);
static int ipv4_jump_to_layer(const char *raw_data,  int raw_layer_type, int expect_layer_type);
static int ipv6_jump_to_layer(const char *raw_data,  int raw_layer_type, int expect_layer_type);

/* 
	地址链转换函数, 类似标准库<arpa/inet.h>中的inet_ntop, inet_pton,
	为了方便应用打印日志的需求, 同时支持'由内向外'及'由外向内'遍历两种类型;
	地址层与层之间, 根据方向的不同使用'<'或'>'分割;
	地址有双向特性的, 如IP、PORT等, 用'-'分割源和目的地址, 格式:"源-目的";
	字符串地址使用固定4字节的前缀, 用于标识本层地址类型;
	字符串格式举例:
		从内层向外层遍历, 即outward:
			T4T:6005-1673<IP4:61.147.112.53-11.215.62.23<MAC:0000ea60040d-0200000003b6
		从外层向内层遍历, 即inward:
			MAC:0000ea600608-020000000299>IP4:95.49.136.204-125.118.233.38>T4T:52694-46786
*/
const char *stream_addr_list_ntop_outward(const struct streaminfo *pstream);
const char *stream_addr_list_ntop_inward(const struct streaminfo *pstream);
const struct streaminfo *stream_addr_list_pton_outward(const char *addr_list_str, int thread_index);
const struct streaminfo *stream_addr_list_pton_inward(const char *addr_list_str, int thread_index);
const char *addr_type_to_prefix(enum addr_type_t layer_type);
extern void reverse_addr(void *addr, int addrtype);
extern const addr_convert_t G_ADDR_CONVERT_HANDLE[];


/* ascii字符转16进制 */
char MESA_ascii_to_hex(char ascii)
{
	char c = 0;
	
	switch(ascii)
	{
		case '0':
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
		case '8':
		case '9':
			c = ascii - 0x30;
		break;

		case 'a':
		case 'b':
		case 'c':
		case 'd':
		case 'e':
		case 'f':
			c = 10 + ascii - 0x61;
		break;

		case 'A':
		case 'B':
		case 'C':
		case 'D':
		case 'E':
		case 'F':
			c = 10 + ascii - 0x41;
		break;
	}

	return c;
}




const char *addr_type_to_string(enum addr_type_t layer_type)
{
	int i;
	
	if(layer_type <=  __ADDR_TYPE_INIT || layer_type >= __ADDR_TYPE_MAX){
		return NULL;
	}

	for(i = __ADDR_TYPE_INIT+1; G_ADDR_CONVERT_HANDLE[i].addr_type_bin != __ADDR_TYPE_MAX; i++){
		if(G_ADDR_CONVERT_HANDLE[i].addr_type_bin == layer_type){
			return G_ADDR_CONVERT_HANDLE[i].addr_type_str;
		}
	}

	return NULL;	
}


static inline int check_layer_type(int layer_type)
{
	if(NULL == addr_type_to_prefix((enum addr_type_t)layer_type)){
		return -1;
	}

	return 0;
}

static int arp_jump_to_layer(const char *raw_data,  int raw_layer_type, int expect_layer_type)
{
	/* arp协议不承载任何上层其他协议 */
	return -1;
}


static int ipv4_jump_to_layer(const char *raw_data,  int raw_layer_type, int expect_layer_type)
{
	struct ip *p_ip_hdr = (struct ip *)raw_data;
	int skip_len = 0;
	int ip_hdr_len = p_ip_hdr->ip_hl * 4;
	//const char *next_layer_data = raw_data + ip_hdr_len;

	if(raw_layer_type == expect_layer_type){
		return 0;
	}
	
	switch(p_ip_hdr->ip_p){
		case IPPROTO_TCP:
			if(ADDR_TYPE_TCP == expect_layer_type){
				skip_len = 0;
				break;
			}else{
				skip_len = -1; /* tcp 层之上不承载其他协议 */
			}
		break;

		case IPPROTO_UDP:
			if(ADDR_TYPE_UDP == expect_layer_type){
				skip_len = 0;
				break;
			}else{
				/* TODO: teredo隧道模式 */
				skip_len = -1; 
			}
		break;

		case IPPROTO_IPV6:
			if(__ADDR_TYPE_IP_PAIR_V4 == expect_layer_type){
				skip_len = 0;
				break;
			}else{
				skip_len = ipv6_jump_to_layer(raw_data+ip_hdr_len, __ADDR_TYPE_IP_PAIR_V6, expect_layer_type);
			}
		break;
		
		default:
			skip_len = -1;
		break;
	}

	if(skip_len < 0){
		return -1;
	}

	return skip_len + sizeof(struct ip);
}

static int ipv6_jump_to_layer(const char *raw_data,  int raw_layer_type, int expect_layer_type)
{
	const struct mesa_ip6_hdr *a_packet = (const struct mesa_ip6_hdr *)raw_data;
	UINT8 next_hdr_type = a_packet->ip6_nxt_hdr;
	UINT8 *next_hdr_ptr = (UINT8 *)a_packet + sizeof(struct mesa_ip6_hdr);	
	int skip_len = 0;
	int offset_to_ip6 = 0;
	
	if(raw_layer_type == expect_layer_type){
		return 0;
	}

	while(1){
		offset_to_ip6 = 0;
		switch(next_hdr_type)
		{
			case NEXTHDR_HOP:
			case NEXTHDR_ROUTING:
			case NEXTHDR_AUTH:
			case NEXTHDR_DEST:
				offset_to_ip6 = (*(next_hdr_ptr + 1))*8 + 8; /* 选项长度以8字节为单位 */				
			break;

			case NEXTHDR_IPIP:
				if(__ADDR_TYPE_IP_PAIR_V4 == expect_layer_type){
					skip_len = next_hdr_ptr - (UINT8 *)raw_data;
				}else{
					skip_len = ipv4_jump_to_layer((const char *)next_hdr_ptr, __ADDR_TYPE_IP_PAIR_V4, expect_layer_type);
					if(skip_len < 0){
						return -1;
					}else{
						return skip_len + next_hdr_ptr - (UINT8 *)raw_data;
					}
				}
				goto done;
			break;

			case NEXTHDR_NONE:
				skip_len = -1;
				goto done;					
			break;

			case NEXTHDR_ICMP: /* IMCP不再承载其他协议 */
				skip_len = -1;
				goto done;
			break;
			
			case NEXTHDR_TCP:
				if(ADDR_TYPE_TCP == expect_layer_type){
					skip_len = next_hdr_ptr - (UINT8 *)raw_data;
				}else{
					skip_len = -1;
				}
				goto done;
			break;
				
			case NEXTHDR_UDP:
				if(ADDR_TYPE_UDP == expect_layer_type){
					skip_len = next_hdr_ptr - (UINT8 *)raw_data;
				}else{
					skip_len = -1;
				}
				goto done;
			break;

			case NEXTHDR_FRAGMENT:		
				offset_to_ip6 = sizeof(struct ipv6_frag_hdr);
			break;

			case NEXTHDR_ESP:
				skip_len = -1;
				goto done;

			default:
				printf("TODO:jmp Unknown IPv6 header type:0x%x!\n", next_hdr_type);		
				skip_len = -1;
				goto done;
			break;
		}

		next_hdr_type = *next_hdr_ptr;
		next_hdr_ptr += offset_to_ip6;
	}	

done:
	if(skip_len < 0){
		return -1;
	}
	
	return skip_len;
}

static int ppp_jump_to_layer(const char *raw_data,  int raw_layer_type, int expect_layer_type)
{
	int skip_len = 0;
	struct mesa_pppoe_session_hdr *pppoe_ses_hdr;
	char *next_hdr;
	
	if(raw_layer_type == expect_layer_type){
		return 0;
	}
	pppoe_ses_hdr = (struct mesa_pppoe_session_hdr *)raw_data;
	next_hdr = (char *)raw_data + sizeof(struct mesa_pppoe_session_hdr);

	switch(ntohs(pppoe_ses_hdr->ppp_protocol)){
		case PPP_PROTOCOL_IPv4:
			if(__ADDR_TYPE_IP_PAIR_V4 == expect_layer_type){
				break;
			}else{
				skip_len = ipv4_jump_to_layer(next_hdr, __ADDR_TYPE_IP_PAIR_V4, expect_layer_type);
			}
		break;

		case PPP_IPV6:
			if(__ADDR_TYPE_IP_PAIR_V6 == expect_layer_type){
				break;
			}else{
				skip_len = ipv6_jump_to_layer(next_hdr, __ADDR_TYPE_IP_PAIR_V4, expect_layer_type);
			}		
		break;

		case PPP_COMP:
		case PPP_CCP:
		case PPP_IPCP:
		case PPP_PAP:
		case PPP_CHAP:
		case PPP_LQR:
		case PPP_PROTOCOL_LCP: 
		
			/* 不承载应用层协议 */
			skip_len = -1;
		break;

		default:
			printf("TODO: jmp unsupport ppp pro:0x%x!\n", ntohs(pppoe_ses_hdr->ppp_protocol));
		break;
		
	}

	if(skip_len < 0){
		return -1;
	}
	
	return skip_len + sizeof(struct mesa_pppoe_session_hdr);
}

static int __common_eth_type_dispatch(UINT16 eth_type, const char *next_layer_data, int raw_layer_type, int expect_layer_type)
{
	int skip_len = 0;
	
	switch(eth_type){
		case ETH_P_ARP:
			if(ADDR_TYPE_ARP == expect_layer_type){
				break;
			}else{
				skip_len = arp_jump_to_layer(next_layer_data, ADDR_TYPE_ARP, expect_layer_type);
			}
		break;

		case ETH_P_8021Q:
			if(ADDR_TYPE_VLAN == expect_layer_type){
				break;
			}else{
				skip_len = vlan8021q_jump_to_layer(next_layer_data, ADDR_TYPE_VLAN, expect_layer_type);
			}
		break;
		
		case ETH_P_IP:
			if(__ADDR_TYPE_IP_PAIR_V4 == expect_layer_type){
				break;
			}else{
				skip_len = ipv4_jump_to_layer(next_layer_data, __ADDR_TYPE_IP_PAIR_V4, expect_layer_type);
			}
		break;

		case ETH_P_IPV6:
			if(__ADDR_TYPE_IP_PAIR_V6 == expect_layer_type){
				break;
			}else{
				skip_len = ipv6_jump_to_layer(next_layer_data, __ADDR_TYPE_IP_PAIR_V6, expect_layer_type);
			}
		break;

		case ETH_P_PPP_SES:
			if(ADDR_TYPE_PPPOE_SES == expect_layer_type){
				break;
			}else{
				skip_len = ppp_jump_to_layer(next_layer_data, ADDR_TYPE_PPPOE_SES, expect_layer_type);
			}
		break;		
		
		default:
			skip_len = -1;
		break;
	}

	return skip_len;
}

static int vlan8021q_jump_to_layer(const char *raw_data,  int raw_layer_type, int expect_layer_type)
{
	int skip_len = 0;
	const struct mesa_vlan_hdr *vlan_hdr = (const struct mesa_vlan_hdr *)raw_data;
	const char *next_layer_data = raw_data + sizeof(struct mesa_vlan_hdr);

	if(raw_layer_type == expect_layer_type){
		return 0;
	}
	
	switch(ntohs(vlan_hdr->type)){
		case ETH_P_ARP:
			if(ADDR_TYPE_ARP == expect_layer_type){
				break;
			}else{
				skip_len = arp_jump_to_layer(next_layer_data, ADDR_TYPE_ARP, expect_layer_type);
			}
		break;
		
		case ETH_P_IP:
			if(__ADDR_TYPE_IP_PAIR_V4 == expect_layer_type){
				break;
			}else{
				skip_len = ipv4_jump_to_layer(next_layer_data, __ADDR_TYPE_IP_PAIR_V4, expect_layer_type);
			}
		break;

		case ETH_P_IPV6:
			if(__ADDR_TYPE_IP_PAIR_V6 == expect_layer_type){
				break;
			}else{
				skip_len = ipv6_jump_to_layer(next_layer_data, __ADDR_TYPE_IP_PAIR_V6, expect_layer_type);
			}
		break;

		case ETH_P_PPP_SES:
			if(ADDR_TYPE_PPPOE_SES == expect_layer_type){
				break;
			}else{
				skip_len = ppp_jump_to_layer(next_layer_data, ADDR_TYPE_PPPOE_SES, expect_layer_type);
			}
		break;		

		case ETH_P_PPP_DISC: /* pppoe发现阶段 */
			skip_len = -1;
		break;

		case 0x8200: /* TODO: XinJing捕包发现此类型, 未知什么包 */
			skip_len = -1;
		break;
		
		default:
			printf("TODO: jmp unsupport type in vlan8021q, 0x%x!\n", ntohs(vlan_hdr->type));
			skip_len = -1;
	}

	if(skip_len < 0){
		return -1;
	}

	return skip_len + sizeof(struct mesa_vlan_hdr);
}

static int eth_jump_to_layer(const char *raw_data,  int raw_layer_type, int expect_layer_type)
{
	struct ethhdr *p_eth_hdr = (struct ethhdr *)raw_data;
	unsigned short eth_type = ntohs(p_eth_hdr->h_proto);
	//int skip_len = -1;
	const char *next_layer_data = raw_data + sizeof(struct ethhdr);
	int layer_skip_len;

	if(raw_layer_type == expect_layer_type){
		return 0;
	}
	
	layer_skip_len =  __common_eth_type_dispatch(eth_type, next_layer_data, raw_layer_type, expect_layer_type);
	if(layer_skip_len < 0){
		return -1;
	}

	return layer_skip_len + sizeof(struct ethhdr);
}


static int mac_in_mac_jump_to_layer(const char *raw_data,  int raw_layer_type, int expect_layer_type)
{
	struct ethhdr *inner_eth_hdr = (struct ethhdr *)(raw_data + sizeof(struct ethhdr ));
	unsigned short inner_eth_type = ntohs(inner_eth_hdr->h_proto);
	//int skip_len = -1;
	const char *next_layer_data = raw_data + sizeof(struct ethhdr);
	int layer_skip_len;

	if(raw_layer_type == expect_layer_type){
		return 0;
	}
	
	layer_skip_len =  __common_eth_type_dispatch(inner_eth_type, next_layer_data, raw_layer_type, expect_layer_type);
	if(layer_skip_len < 0){
		return -1;
	}

	return layer_skip_len + sizeof(struct ethhdr) * 2;
}
/*
	return value:
		Non-NULL: the pointer to expect layer;
		NULL: not found expect layer.
*/
const void *MESA_net_jump_to_layer(const void *raw_data,  int raw_layer_type, int expect_layer_type)
{
	int  ret;

	if(check_layer_type(raw_layer_type) < 0){
		return NULL;
	}

	if(check_layer_type(expect_layer_type) < 0){
		return NULL;
	}

	if(ADDR_TYPE_IPV4 == expect_layer_type){
		/* 转成纯IPv4地址类型 */
		expect_layer_type = __ADDR_TYPE_IP_PAIR_V4;
	}

	if(ADDR_TYPE_IPV6 == expect_layer_type){
		/* 转成纯IPv6地址类型 */
		expect_layer_type = __ADDR_TYPE_IP_PAIR_V6;
	}

	if(raw_layer_type == expect_layer_type){
		return raw_data;
	}
	
	switch(raw_layer_type){
		case ADDR_TYPE_MAC:
			ret = eth_jump_to_layer((const char *)raw_data, raw_layer_type, expect_layer_type);
		break;
		
		case ADDR_TYPE_ARP:
			ret = arp_jump_to_layer((const char *)raw_data, raw_layer_type, expect_layer_type);
		break;
		case ADDR_TYPE_VLAN:
			ret = vlan8021q_jump_to_layer((const char *)raw_data, raw_layer_type, expect_layer_type);
		break;
		
		case __ADDR_TYPE_IP_PAIR_V4:
			ret = ipv4_jump_to_layer((const char *)raw_data, raw_layer_type, expect_layer_type);
		break;

		case __ADDR_TYPE_IP_PAIR_V6:
			ret = ipv6_jump_to_layer((const char *)raw_data, raw_layer_type, expect_layer_type);
		break;

		case ADDR_TYPE_MAC_IN_MAC:
			ret = mac_in_mac_jump_to_layer((const char *)raw_data, raw_layer_type, expect_layer_type);
		break;
				
		case ADDR_TYPE_PPPOE_SES:
		case ADDR_TYPE_MPLS:		
		case ADDR_TYPE_GRE:
		/* TODO */
		default:
			printf("TODO: jmp unsupport raw_layer_type:%d in MESA_net_jump_to_layer()!\n", raw_layer_type);
			return NULL;
	}

	if(ret < 0){
		return NULL;
	}

	return ((const char *)raw_data + ret);
}

UINT8 net_layer_to_ipv4_protocol(int addr_type)
{
	UINT8 proto = 0;

	switch(addr_type){
		case __ADDR_TYPE_IP_PAIR_V4:
			proto = IPPROTO_IPIP;
		break;

		case __ADDR_TYPE_IP_PAIR_V6:
			proto = IPPROTO_IPV6;
		break;

		case ADDR_TYPE_TCP:
			proto = IPPROTO_TCP;
		break;

		case ADDR_TYPE_UDP:
			proto = IPPROTO_UDP;
		break;

		case ADDR_TYPE_GRE:
			proto = IPPROTO_GRE;
		break;

		default:
			printf("unknown ip4 protocolr:%d\n", addr_type);
			proto = 0xFF;
		break;
	}

	return proto;
}

UINT8 net_layer_to_ipv6_protocol(int addr_type)
{
	UINT8 proto = 0;

	switch(addr_type){
		case ADDR_TYPE_TCP:
			proto = NEXTHDR_TCP;
		break;

		case ADDR_TYPE_UDP:
			proto = NEXTHDR_UDP;
		break;

		case __ADDR_TYPE_IP_PAIR_V4:
			proto = NEXTHDR_IPIP;
		break;

		default:
			printf("unknown ip6 next-hdr:%d\n", addr_type);
			return 0xFF;
		break;
	}

	return proto;
}

/*
	将MESA地址类型转换为标准Ethernet类型;
	
	return value:
		ethernet type, host order.
*/
UINT16 net_layer_to_ethernet_protocol(int addr_type)
{
	UINT16 ether_type = 0;

	switch(addr_type){
		case __ADDR_TYPE_IP_PAIR_V4:
			ether_type = ETH_P_IP;
		break;

		case __ADDR_TYPE_IP_PAIR_V6:
			ether_type = ETH_P_IPV6;
		break;

		case ADDR_TYPE_VLAN:
			ether_type = ETHERTYPE_VLAN;
		break;

		case ADDR_TYPE_TCP:
		case ADDR_TYPE_UDP:
			sapp_runtime_log(RLOG_LV_FATAL, "%s:%d: Ethernet can't carry addr type:%d directly!\n", __FILE__, __LINE__,addr_type);
			//assert(0);
			ether_type = -1;
		break;

		case ADDR_TYPE_PPPOE_SES:
			ether_type = ETH_P_PPP_SES;
		break;

		case ADDR_TYPE_MPLS:
			ether_type = ETH_P_MPLS_UC;
		break;

		case ADDR_TYPE_ARP:
			ether_type = ETH_P_ARP;
		break;
		
		default:
			/* to do, unknown type */
			sapp_runtime_log(RLOG_LV_FATAL, "%s:%d: Ethernet addr type:%d!\n", __FILE__, __LINE__, addr_type);
			ether_type = -1;
		break;
	}

	return ether_type;
}

/* 串联模式下, 将收到的包正常转发 */
int packet_io_forward_pkt(int thread_num, int top_mode)
{
	if(0 == (top_mode & __NET_CONN_SERIAL)){
		return -1;
	}

	/* to do!! */
	/* G模式下与双网卡串联模式处理不一样, G相当于新造了一个包, 双网卡模式可以直接透传, 如DPDK和PFRING下都支持 */
	
	return 0;
}

int net_common_adjust_forward_mac(struct mesa_ethernet_hdr *raw_eth_hdr,int net_topology_mode)
{
	u_int8_t  tmp_addr[ETHER_ADDR_LEN];
	
	if(NET_CONN_SERIAL_GDEV == net_topology_mode){
		memcpy(tmp_addr, raw_eth_hdr->ether_shost, ETHER_ADDR_LEN);
		memcpy(raw_eth_hdr->ether_shost, raw_eth_hdr->ether_dhost, ETHER_ADDR_LEN);
		memcpy(raw_eth_hdr->ether_dhost, tmp_addr, ETHER_ADDR_LEN);
	}
	return 0;
}

int net_common_build_send_mac(UINT8 *buf, const struct mesa_ethernet_hdr *raw_eth_hdr,
						int upper_layer_addr_type, int dir_reverse, int net_topology_mode)
{
	struct mesa_ethernet_hdr *send_eth_hdr = (struct mesa_ethernet_hdr *)buf;

	if(NET_CONN_SERIAL_GDEV == net_topology_mode){
		/* 如果是同向, 简单颠倒顺序即可 */
		memcpy(send_eth_hdr->ether_dhost, raw_eth_hdr->ether_shost, ETHER_ADDR_LEN);
		memcpy(send_eth_hdr->ether_shost, raw_eth_hdr->ether_dhost, ETHER_ADDR_LEN);

		if(1 == dir_reverse){
			/* MAC地址最低位取反 */
			if(send_eth_hdr->ether_dhost[5] & 0x01){
				send_eth_hdr->ether_dhost[5] &= 0xFE; /* 最后一位清零 */
			}else{
				send_eth_hdr->ether_dhost[5] |= 0x01; /* 最后一位设为1 */
			}
		}
	}else{
		if(0 == dir_reverse){
			memcpy(send_eth_hdr->ether_dhost, raw_eth_hdr->ether_dhost, ETHER_ADDR_LEN);
			memcpy(send_eth_hdr->ether_shost, raw_eth_hdr->ether_shost, ETHER_ADDR_LEN);
		}else{
			memcpy(send_eth_hdr->ether_dhost, raw_eth_hdr->ether_shost, ETHER_ADDR_LEN);
			memcpy(send_eth_hdr->ether_shost, raw_eth_hdr->ether_dhost, ETHER_ADDR_LEN);
		}
	}

	send_eth_hdr->ether_type = htons(net_layer_to_ethernet_protocol(upper_layer_addr_type));

	return 0;
}


void MESA_stream_list_free(struct streaminfo_private *pstream_pr)
{
	struct streaminfo_private *pfather_pr;
	struct streaminfo *pstream = &pstream_pr->stream_public;

	if(NULL == pstream_pr){
		return;
	}
	/* 先将pfather保存到临时变量 */
	pfather_pr = (struct streaminfo_private *)pstream_pr->stream_public.pfather;

	dictator_free(pstream->threadnum, pstream->addr.paddr);
	dictator_free(pstream->threadnum, pstream_pr);

	return MESA_stream_list_free(pfather_pr);
}

struct streaminfo_private *MESA_stream_list_dup(struct streaminfo_private *stack_stream_pr, int reverse)
{
	struct streaminfo_private *heap_stream_pr = NULL;
	struct streaminfo *heap_stream;
	void *heap_addr;
	struct streaminfo *stack_stream;

	if(NULL == stack_stream_pr){
		return NULL;
	}
	stack_stream = &stack_stream_pr->stream_public;

	heap_stream_pr = (struct streaminfo_private *)dictator_malloc(stack_stream->threadnum, sizeof(struct streaminfo_private));
	memcpy(heap_stream_pr, stack_stream_pr, sizeof(struct streaminfo_private));
	heap_stream = &heap_stream_pr->stream_public;
	
	heap_addr = dictator_malloc(stack_stream->threadnum, stack_stream->addr.addrlen);
	memcpy(heap_addr, stack_stream->addr.paddr, stack_stream->addr.addrlen);

	if(reverse){
		heap_stream_pr->dirreverse=1;
		heap_stream_pr->stream_dir = 1 ^ heap_stream_pr->layer_dir; /* lijia comment, 与"src>=dst"默认规则不一致 */
		reverse_addr(heap_addr, heap_stream->addr.addrtype);
	}else{
		heap_stream_pr->stream_dir = heap_stream_pr->layer_dir;
	}

	heap_stream->addr.paddr = heap_addr;
	heap_stream->addr.addrlen = stack_stream->addr.addrlen;

	heap_stream->pfather = (struct streaminfo *)MESA_stream_list_dup((struct streaminfo_private *)(stack_stream->pfather), reverse);

	return (struct streaminfo_private *)heap_stream;
}

int MESA_stream_list_cmp(struct streaminfo_private *stream1_pr, struct streaminfo_private *stream2_pr)
{
	int ret = 0;
	//int isreverse = 0;
	struct streaminfo *stream1 = &stream1_pr->stream_public;
	struct streaminfo *stream2 = &stream2_pr->stream_public;
	
	if(NULL == stream1_pr){
		if(stream2_pr != NULL){		
			return -1;
		}else{	
			return 0;
		}
	}else{
		if(NULL == stream2_pr){			
			return 1;
		}	
	}

	if(stream1->type != stream2->type){
		return (stream1->type > stream2->type) ? 1:-1;
	}
	
	if(stream1->addr.addrtype != stream2->addr.addrtype){
		return (stream1->addr.addrtype > stream2->addr.addrtype)?1:-1;
	}
	
	//if(stream1_pr->dirreverse != stream2_pr->dirreverse){ /* lijia comment, 新流的dirreverse=0; */
		//isreverse = 1; 
	//}
	
	/* 2014-04-01 lijia add, 本层无需比较, 直接跳过 */
	if((0 == stream1_pr->addr_use_as_hash) && (0 == stream2_pr->addr_use_as_hash)){
		return MESA_stream_list_cmp((struct streaminfo_private *)(stream1->pfather), (struct streaminfo_private *)(stream2->pfather));
	}

#if IP_PORT_UNION_VERSION
	/* IPPORT_UNION版本只有一个streaminfo, 直接比较地址即可, 不用跳转到pfather */
#else
	/* TCP或UDP的地址信息都存于IP层, 本层无需比较 */
	if((ADDR_TYPE_IPV4 == stream1->addr.addrtype)
	||(ADDR_TYPE_IPV6 == stream1->addr.addrtype)){
		return MESA_stream_list_cmp((struct streaminfo_private *)(stream1->pfather), (struct streaminfo_private *)(stream2->pfather));
	}
#endif

	/* TODO, to do: 
		if(isreverse), 反转地址比较, 或调用反向地址比较函数 
	*/

	ret = memcmp(stream1->addr.paddr, stream2->addr.paddr, stream2->addr.addrlen);
	if(ret != 0){
		return ret;
	}

	ret = MESA_stream_list_cmp((struct streaminfo_private *)(stream1->pfather), (struct streaminfo_private *)(stream2->pfather));
	
	return ret;
}


/* 获取本层流对应的原始包头起始地址 */
const void *get_this_layer_header(const struct streaminfo *pstream)
{
	const void *this_layer_hdr = NULL;
	const struct streaminfo_private *pstream_pr = (const struct streaminfo_private *)pstream;

	if(OP_STATE_CLOSE == pstream->opstate){
		if(STREAM_TYPE_TCP == pstream->type){ 
			const struct tcpdetail_private *pr_tcpdetail=(struct tcpdetail_private *)pstream->pdetail;
			if((STREAM_LINK_TIMEOUT == pr_tcpdetail->link_state) || (STREAM_LINK_LRU_OUT == pr_tcpdetail->link_state)){
				this_layer_hdr = NULL;
			}
		}else if(STREAM_TYPE_UDP == pstream->type){
			this_layer_hdr = NULL; /* UDP全是靠时间淘汰, 当前包肯定为NULL */
		}else{
			this_layer_hdr = (const void *)
					 ((const char *)(pstream_pr->raw_pkt->raw_pkt_data) + pstream_pr->offset_to_raw_pkt_hdr);
		}
	}else{
		this_layer_hdr = (const void *)
					 ((const char *)(pstream_pr->raw_pkt->raw_pkt_data) + pstream_pr->offset_to_raw_pkt_hdr);
	}
	
	return this_layer_hdr;
}

/* 删除末尾的换行符"\r\n" */
void del_last_rn(char *data, int max_len)
{
    int i;
    for(i = 0; i < max_len; i++){
        if(('\r' == data[i]) || ('\n' == data[i])){
            data[i] = '\0';
            return;
        }
    }

    return;
}

/*	
	返回值:
		ethernet长度, 包括eth头部.
*/
int get_pkt_len_from_eth_hdr(const struct mesa_ethernet_hdr *ehdr)
{
	int raw_pkt_len = -1;

	switch(ntohs(ehdr->ether_type)){
		case ETHERTYPE_IP:
		{
			struct mesa_ip4_hdr *ip4hdr = (struct mesa_ip4_hdr *)((char *)ehdr + sizeof(struct mesa_ethernet_hdr));
			raw_pkt_len = ntohs(ip4hdr->ip_len) + sizeof(mesa_ethernet_hdr);
		}
		break;

		case ETHERTYPE_IPv6:
		{
			struct mesa_ip6_hdr *ip6hdr = (struct mesa_ip6_hdr *)((char *)ehdr + sizeof(struct mesa_ethernet_hdr));
			raw_pkt_len = ntohs(ip6hdr->ip6_payload_len) + sizeof(struct mesa_ip6_hdr) + sizeof(struct mesa_ethernet_hdr);	
		}
		break;

		default:
		break;
	}

	return raw_pkt_len;
}


#ifdef __cplusplus
}
#endif

