#include "sapp_api.h"
#include "sapp_private_api.h"
#include "sapp_declaration.h"


#ifdef __cplusplus
extern "C" {
#endif

static int eth_jump_to_layer(const char *raw_data,  int raw_layer_type, int expect_layer_type);
static int vlan8021q_jump_to_layer(const char *raw_data,  int raw_layer_type, int expect_layer_type);
static int ipv4_jump_to_layer(const char *raw_data,  int raw_layer_type, int expect_layer_type);
static int ipv6_jump_to_layer(const char *raw_data,  int raw_layer_type, int expect_layer_type);
static int ppp_jump_to_layer(const char *raw_data,  int raw_layer_type, int expect_layer_type);

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

		default:
			c = 0; //todo , what error number return?
		break;
	}

	return c;
}

typedef struct{
	enum addr_type_t addrtype;
	const void *layer_header;
}sapp_net_layer_header_t;

/*
	遍历当前包能解析的所有协议层, 通过layer_info数组输出每个协议层的地址类型和起始头部, 最大层数为layer_info_max_num.

	返回值:
		>=0 : 从raw_data开始, 能正确解析的层数, 为了数组遍历方便, 从0开始计数, 具体值为: MIN(layer_info_max_num-1, 实际可以解析的层数);
		-1  : 错误.
*/
int MESA_net_iterate_layer(const void *raw_data,  int raw_layer_type, sapp_net_layer_header_t layer_info[], int layer_info_max_num)
{
	//TODO
	return 0;
}


UINT8 net_layer_to_ipv4_protocol(int addr_type)
{
	UINT8 proto = 0;

	switch(addr_type){
		case __ADDR_TYPE_IP_PAIR_V4:
			proto = IPPROTO_IPIP;
		break;

		case ADDR_TYPE_IPV6: //6over4 tunnel
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
			sapp_runtime_log(RLOG_LV_INFO, "net_layer_to_ipv4_protocol(): unknown ip4 protocol:%d\n", addr_type);
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

		case ADDR_TYPE_IPV4: //4over6 tunnel
		case __ADDR_TYPE_IP_PAIR_V4:
			proto = NEXTHDR_IPIP;
		break;

		default:
			sapp_runtime_log(RLOG_LV_INFO, "net_layer_to_ipv6_protocol(): unknown ip6 next-hdr:%d\n", addr_type);
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
		case ADDR_TYPE_IPV4:
			ether_type = ETH_P_IP;
		break;

		case __ADDR_TYPE_IP_PAIR_V6:
		case ADDR_TYPE_IPV6:
			ether_type = ETH_P_IPV6;
		break;

		case ADDR_TYPE_VLAN:
			ether_type = ETHERTYPE_VLAN;
		break;

		case ADDR_TYPE_TCP:
		case ADDR_TYPE_UDP:
			sapp_runtime_log(RLOG_LV_INFO, "net_layer_to_ethernet_protocol(): Ethernet can't carry addr type:%d directly!\n", addr_type);
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
			sapp_runtime_log(RLOG_LV_INFO, "net_layer_to_ethernet_protocol(): unknown ethernet carry addr type:%d!\n", addr_type);
			ether_type = -1;
		break;
	}

	return ether_type;
}

/*
	将MESA地址类型转换为标准Ethernet类型;
	
	return value:
		ethernet type, host order.
*/
UINT16 net_layer_to_ethernet_protocol_by_stream(const struct streaminfo *pstream)
{
	UINT16 ether_type = 0;
	int addr_type = pstream->addr.addrtype;

	switch(addr_type){
		case __ADDR_TYPE_IP_PAIR_V4:
		case ADDR_TYPE_IPV4:
			ether_type = ETH_P_IP;
		break;

		case __ADDR_TYPE_IP_PAIR_V6:
		case ADDR_TYPE_IPV6:
			ether_type = ETH_P_IPV6;
		break;

		case ADDR_TYPE_VLAN:
			if(ADDR_TYPE_8021Q_ABBR == pstream->addr.pkttype){
				ether_type = ETH_P_8021Q;
			}else{
				ether_type = ETH_P_8021AD;
			}
		break;

		case ADDR_TYPE_TCP:
		case ADDR_TYPE_UDP:
			sapp_runtime_log(RLOG_LV_INFO, "net_layer_to_ethernet_protocol_by_stream(): Ethernet can't carry addr type:%d directly!\n", addr_type);
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
			sapp_runtime_log(RLOG_LV_INFO, "net_layer_to_ethernet_protocol_by_stream(): unknown ethernet carry addr type:%d!\n", addr_type);
			ether_type = -1;
		break;
	}

	return ether_type;
}


/*
	将标准Ethernet类型转换为MESA地址类型;
*/
enum addr_type_t ethernet_protocol_to_net_layer(UINT16 ether_type_host)
{
	enum addr_type_t addrtype = __ADDR_TYPE_INIT;

	switch(ether_type_host){
		case ETH_P_IP:
			addrtype = __ADDR_TYPE_IP_PAIR_V4;
		break;

		case ETH_P_IPV6:
			addrtype = __ADDR_TYPE_IP_PAIR_V6;
		break;

		case ETH_P_8021Q:
		case ETH_P_8021AD:
			addrtype = ADDR_TYPE_VLAN;
		break;

		case ETH_P_PPP_SES:
			addrtype =  ADDR_TYPE_PPPOE_SES;
		break;

		case ETH_P_MPLS_UC :
			addrtype = ADDR_TYPE_MPLS;
		break;

		case ETH_P_ARP:
			addrtype = ADDR_TYPE_ARP;
		break;
		default:
			/* to do, unknown type */
			sapp_runtime_log(RLOG_LV_INFO, "ethernet_protocol_to_net_layer(): unknown ethernet carry addr type:0x%x\n", ether_type_host);
		break;
	}

	return addrtype;
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


void MESA_stream_list_free(int mem_used_type, struct streaminfo_private *pstream_pr)
{
	struct streaminfo_private *pfather_pr;
	struct streaminfo *pstream = &pstream_pr->stream_public;

	if(NULL == pstream_pr){
		return;
	}
	/* 先将pfather保存到临时变量 */
	pfather_pr = (struct streaminfo_private *)pstream_pr->stream_public.pfather; /* 2021-01-11, 仅用于ip分片确定地址, 此处使用内存四元组,使用pfather而不是pfather_pr */

	sapp_mem_free((sapp_mem_type_t)mem_used_type,pstream->threadnum, pstream->addr.paddr);
	sapp_mem_free((sapp_mem_type_t)mem_used_type,pstream->threadnum, pstream_pr);

	return MESA_stream_list_free(mem_used_type, pfather_pr);
}

struct streaminfo_private *MESA_stream_list_dup(int mem_used_type, struct streaminfo_private *stack_stream_pr, int reverse)
{
	struct streaminfo_private *heap_stream_pr = NULL;
	struct streaminfo *heap_stream;
	void *heap_addr;
	struct streaminfo *stack_stream;

	if(NULL == stack_stream_pr){
		return NULL;
	}
	stack_stream = &stack_stream_pr->stream_public;

	heap_stream_pr = (struct streaminfo_private *)sapp_mem_malloc((sapp_mem_type_t)mem_used_type, stack_stream->threadnum, sizeof(struct streaminfo_private));
	memcpy(heap_stream_pr, stack_stream_pr, sizeof(struct streaminfo_private));
	heap_stream = &heap_stream_pr->stream_public;
	
	heap_addr = sapp_mem_malloc((sapp_mem_type_t)mem_used_type, stack_stream->threadnum, stack_stream->addr.addrlen);
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

	/* 2021-01-11, 仅用于ip分片确定地址, 此处使用内存四元组,使用pfather而不是pfather_pr */
	heap_stream->pfather = (struct streaminfo *)MESA_stream_list_dup(mem_used_type, (struct streaminfo_private *)(stack_stream->pfather), reverse);

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

	/* TODO 2, to do:
		if(isreverse), 反转地址比较, 或调用反向地址比较函数 
	*/

	ret = memcmp(stream1->addr.paddr, stream2->addr.paddr, stream2->addr.addrlen);
	if(ret != 0){
		return ret;
	}

	ret = MESA_stream_list_cmp((struct streaminfo_private *)(stream1->pfather), (struct streaminfo_private *)(stream2->pfather));
	
	return ret;
}




const void *get_current_layer3_header(const struct streaminfo *pstream)
{
	if(STREAM_TYPE_UDP != pstream->type && STREAM_TYPE_TCP != pstream->type)
	{
		return NULL;
	}
	const void *this_layer_hdr = NULL;
	const struct streaminfo_private *pstream_pr = (const struct streaminfo_private *)pstream;	
	if(pstream_pr->raw_pkt)
	{
		this_layer_hdr = (const void *)
					 ((const char *)(pstream_pr->raw_pkt->raw_pkt_data) + pstream_pr->offset_to_raw_pkt_hdr);
	}
	return this_layer_hdr;
}

const void *get_this_layer_header(const struct streaminfo *pstream)
{
	return get_current_layer3_header(pstream);
}

const void *get_current_layer4_header(const struct streaminfo *pstream)
{
	if(STREAM_TYPE_UDP != pstream->type && STREAM_TYPE_TCP != pstream->type)
	{
		return NULL;
	}
	const void *this_layer_hdr = NULL;
	const struct streaminfo_private *pstream_pr = (const struct streaminfo_private *)pstream;	
	if(pstream_pr->raw_pkt)
	{
		this_layer_hdr = (const void *)
					 ((const char *)(pstream_pr->raw_pkt->raw_pkt_data) + pstream_pr->raw_pkt->offset_to_raw_pkt_hdr);
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

int sapp_del_last_char(char *data, int max_len, char del_char)
{
    int i, actual_len = 0;

	actual_len = strlen(data);
	
    for(i = actual_len-1; i >= 0; i--){
        if(del_char == data[i]){
            data[i] = '\0';
        }else{
			return 0;
        }
    }

    return 0;
}


/* 跳过配置文件前面的空格 \t符号, 方便解析, 但是不处理字符串中间的空格\t */
char *sapp_memmove_for_blank_table(char *data, int max_len)
{
	if(NULL == data){
		return NULL;
	}
	
	while(('\t' == data[0]) || (' ' ==data[0])){
		memmove(data, data+1, max_len-1);
	}
	return data;
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
			raw_pkt_len = ntohs(ip4hdr->ip_len) + sizeof(struct mesa_ethernet_hdr);
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

/* 模拟tcpdump格式:   192.168.40.137.22 > 192.168.36.40.49429  */
const char *sapp_raw_ipv4_ntop(const struct mesa_ip4_hdr *ip4_hdr, char *out_buf, int buf_len )
{
	unsigned char inner_ip_proto;
	const struct mesa_tcp_hdr *inner_thdr = NULL;
	const struct mesa_udp_hdr *inner_uhdr = NULL;
	unsigned short sport, dport;
	char ipsrc_str[INET6_ADDRSTRLEN];
	char ipdst_str[INET6_ADDRSTRLEN];

	inner_ip_proto = ip4_hdr->ip_p;		
	if(IPPROTO_TCP == inner_ip_proto){
		inner_thdr = (struct mesa_tcp_hdr *)((char *)ip4_hdr + ip4_hdr->ip_hl*4);
		sport = ntohs(inner_thdr->th_sport);
		dport = ntohs(inner_thdr->th_dport);
	}else if(IPPROTO_UDP){
		inner_uhdr = (struct mesa_udp_hdr *)((char *)ip4_hdr + ip4_hdr->ip_hl*4);
		sport = ntohs(inner_uhdr->uh_sport);
		dport = ntohs(inner_uhdr->uh_dport);				
	}else{
		sapp_runtime_log(RLOG_LV_INFO, "sapp_raw_ipv4_ntop() error, unsupport ip protocol:%d", inner_ip_proto);
		return NULL;
	}
	
	inet_ntop(AF_INET, &ip4_hdr->ip_src.s_addr, ipsrc_str, sizeof(ipsrc_str));
	inet_ntop(AF_INET, &ip4_hdr->ip_dst.s_addr, ipdst_str, sizeof(ipdst_str));

	snprintf(out_buf, buf_len, "%s.%u > %s.%u", ipsrc_str, sport, ipdst_str, dport);

	return out_buf;
}


const char *sapp_raw_ipv6_ntop(const struct mesa_ip6_hdr *ip6_hdr, char *out_buf, int buf_len)
{
	unsigned char inner_ip_proto;
	const struct tcphdr *inner_thdr = NULL;
	const struct udphdr *inner_uhdr = NULL;
	unsigned short sport, dport;
	char ipsrc_str[INET6_ADDRSTRLEN];
	char ipdst_str[INET6_ADDRSTRLEN];
	

	/* TODO: 此处有可能包含选项或碎片, 不能直接获取下一层的协议类型, 如此处理并不严谨! */
	inner_ip_proto = ip6_hdr->ip6_nxt_hdr;	
	if(IPPROTO_TCP == inner_ip_proto){
		inner_thdr = (struct tcphdr *)((char *)ip6_hdr + sizeof(struct ip6_hdr));
		sport = inner_thdr->source;
		dport = inner_thdr->dest;				
	}else if(IPPROTO_UDP){
		inner_uhdr = (struct udphdr *)((char *)ip6_hdr + sizeof(struct ip6_hdr));
		sport = inner_uhdr->source;
		dport = inner_uhdr->dest;					
	}else{
		sapp_runtime_log(RLOG_LV_INFO, "sapp_raw_ipv6_ntop() error, unsupport ip6_nxt_hdr:%d", inner_ip_proto);
		return NULL;
	}	
	
	inet_ntop(AF_INET6, &ip6_hdr->ip6_src, ipsrc_str, sizeof(ipsrc_str));
	inet_ntop(AF_INET6, &ip6_hdr->ip6_dst, ipdst_str, sizeof(ipdst_str));

	snprintf(out_buf, buf_len, "%s.%u > %s.%u", ipsrc_str, sport, ipdst_str, dport);


	return out_buf;
}

const char *sapp_rawpkt_ntop(const raw_pkt_t *raw_pkt, int greedy_inner_layer, char *out_buf, int buf_len)
{
	const struct mesa_ip4_hdr *ip4hdr;
	const struct mesa_ip6_hdr *ip6hdr;
	const struct mesa_tcp_hdr *thdr;
	const struct mesa_udp_hdr *uhdr;
	char ipsrc_str[64], ipdst_str[64];
	unsigned short sport, dport, ipid=0, transport_checksum;
	unsigned char ip_pro;

	if(greedy_inner_layer){
		ip4hdr = (struct mesa_ip4_hdr *)MESA_jump_layer_greedy(raw_pkt->raw_pkt_data, (int)raw_pkt->low_layer_type, (int)ADDR_TYPE_IPV4);
	}else{
		ip4hdr = (struct mesa_ip4_hdr *)MESA_jump_layer(raw_pkt->raw_pkt_data, (int)raw_pkt->low_layer_type, (int)ADDR_TYPE_IPV4);
	}
	if(ip4hdr){
		inet_ntop(AF_INET, &ip4hdr->ip_src.s_addr, ipsrc_str, 64);
		inet_ntop(AF_INET, &ip4hdr->ip_dst.s_addr, ipdst_str, 64);
		ipid = ntohs(ip4hdr->ip_id);
		ip_pro = ip4hdr->ip_p;

		if(IPPROTO_TCP == ip_pro){
			thdr = (const struct mesa_tcp_hdr *)((char *)ip4hdr + ip4hdr->ip_hl * 4);
			sport = ntohs(thdr->th_sport);
			dport = ntohs(thdr->th_dport);
			transport_checksum = ntohs(thdr->th_sum);

			snprintf(out_buf, buf_len, "IPv4: %s.%u > %s.%u, IPID:%u, PROTO:TCP, TCP-Checksum:0x%x",
					ipsrc_str, sport, ipdst_str, dport, ipid, transport_checksum);		
		}else if(IPPROTO_UDP == ip_pro){
			uhdr = (const struct mesa_udp_hdr *)((char *)ip4hdr + ip4hdr->ip_hl * 4);
			sport = ntohs(uhdr->uh_sport);
			dport = ntohs(uhdr->uh_dport);
			transport_checksum = ntohs(uhdr->uh_sum);
			snprintf(out_buf, buf_len, "IPv4: %s.%u > %s.%u, IPID:%u, PROTO:UDP, UDP-Checksum:0x%x",
					ipsrc_str, sport, ipdst_str, dport, ipid, transport_checksum);	

		}else{
			snprintf(out_buf, buf_len, "IPv4: %s > %s, IPID:%u, IPPROTO:%u",ipsrc_str, ipdst_str, ipid, ip_pro);				
		}
		
		return out_buf;
	}

	if(greedy_inner_layer){
		ip6hdr = (struct mesa_ip6_hdr *)MESA_jump_layer_greedy(raw_pkt->raw_pkt_data, (int)raw_pkt->low_layer_type, (int)ADDR_TYPE_IPV6);
	}else{
		ip6hdr = (struct mesa_ip6_hdr *)MESA_jump_layer(raw_pkt->raw_pkt_data, (int)raw_pkt->low_layer_type, (int)ADDR_TYPE_IPV6);
	}
	if(NULL == ip6hdr){
		return ""; /* 此次返回一个空字符串, 而不是NULL, 防止调用者不判断返回值而崩溃, 返回空串只是什么都不打印 */
	}
	
	{
		inet_ntop(AF_INET6, &ip6hdr->ip6_src, ipsrc_str, 64);
		inet_ntop(AF_INET6, &ip6hdr->ip6_dst, ipdst_str, 64);
		ip_pro = ip6hdr->ip6_nxt_hdr;

		if(IPPROTO_TCP == ip_pro){
			thdr = (const struct mesa_tcp_hdr *)((char *)ip6hdr + sizeof(struct mesa_ip6_hdr));
			sport = ntohs(thdr->th_sport);
			dport = ntohs(thdr->th_dport);
			transport_checksum = ntohs(thdr->th_sum);

			snprintf(out_buf, buf_len, "IPv6: %s.%u > %s.%u, IPID:%u, PROTO:TCP, TCP-Checksum:0x%x",
					ipsrc_str, sport, ipdst_str, dport, ipid, transport_checksum);		
		}else if(IPPROTO_UDP == ip_pro){
			uhdr = (const struct mesa_udp_hdr *)((char *)ip6hdr + sizeof(struct mesa_ip6_hdr));
			sport = ntohs(uhdr->uh_sport);
			dport = ntohs(uhdr->uh_dport);
			transport_checksum = ntohs(uhdr->uh_sum);
			snprintf(out_buf, buf_len, "IPv6: %s.%u > %s.%u, IPID:%u, PROTO:UDP, UDP-Checksum:0x%x",
					ipsrc_str, sport, ipdst_str, dport, ipid, transport_checksum);	

		}else{
			snprintf(out_buf, buf_len, "IPv6: %s > %s, IPPROTO:%u",ipsrc_str, ipdst_str, ip_pro);				
		}
	}
	return out_buf;
}


static const unsigned long long TO_KB = 1024;
static const unsigned long long TO_MB = 0x100000ULL;
static const unsigned long long TO_GB = 0x40000000ULL;
static const unsigned long long TO_TB = 0x10000000000ULL;

/* 转换成人容易读的网络流量字符串, 如123bps, 34.5Mbps */
char *byte_convert_human(unsigned long long bytes, int interval, int multiple, char * byte_str)
{
    bytes *= multiple; /* to network pattern, or human pattern */

    bytes /= interval; /* per second */

    if(bytes < TO_KB){
        snprintf(byte_str,STATS_STR_LEN,"%llu", bytes);
    }else if(bytes < TO_MB){
        snprintf(byte_str,STATS_STR_LEN,"%.2fK", (float)bytes/TO_KB);
    }else if(bytes < TO_GB){
        snprintf(byte_str,STATS_STR_LEN,"%.2fM", (float)bytes/TO_MB);
    }else if(bytes < TO_TB){
        snprintf(byte_str,STATS_STR_LEN,"%.2fG", (float)bytes/TO_GB);
    }else{
        snprintf(byte_str,STATS_STR_LEN,"%.2fT", (double)bytes/TO_TB);	
    }

    return byte_str;
}



#ifdef __cplusplus
}
#endif

