/*
	2015-02-26 lijia create.
	地址转换函数, 类似标准库<arpa/inet.h>中的inet_ntop, inet_pton.
	同时用于前端和二级, 所以将此部分函数单独提取存于一个文件, 方便移植到其它模块.

	update log:
		2016-01-19, 平台将IP和PORT合并到一层, 修改ntop和pton的实现.
*/
#include "sapp_api.h"
#include "sapp_private_api.h"

#ifdef __cplusplus
extern "C" {
#endif

#define ADDR_LIST_OUTWARD_DELIM		"|"
#define ADDR_LIST_INWARD_DELIM		">"


static char __stream_list_string[MAX_THREAD_NUM][MAX_ADDR_LIST_STRING_LEN];
static char __addr_ntop_string[MAX_THREAD_NUM][MAX_ADDR_TYPE_STRING_LEN];
//static char __addr_pton_value[MAX_THREAD_NUM][MAX_ADDR_BIN_VALUE_LEN];
static addr_continuous_bin_t __stream_list_bin_value[MAX_THREAD_NUM][MAX_ADDR_EMBED_LAYER_NUM];


static int __addr_ip4_n2p_fun(const struct layer_addr *paddr, char *buf, int buf_len);
static int __addr_pure_tcp_n2p_fun(const struct layer_addr *paddr, char *buf, int buf_len);
static int __addr_tcp_n2p_fun(const struct layer_addr *paddr, char *buf, int buf_len);
static int __addr_pure_udp_n2p_fun(const struct layer_addr *paddr, char *buf, int buf_len);
static int __addr_udp_n2p_fun(const struct layer_addr *paddr, char *buf, int buf_len);
static int __addr_ip6_n2p_fun(const struct layer_addr *paddr, char *buf, int buf_len);
static int __addr_vlan_n2p_fun(const struct layer_addr *paddr, char *buf, int buf_len);
static int __addr_mac_n2p_fun(const struct layer_addr *paddr, char *buf, int buf_len);
static int __addr_gre_n2p_fun(const struct layer_addr *paddr, char *buf, int buf_len);
static int __addr_mpls_n2p_fun(const struct layer_addr *paddr, char *buf, int buf_len);
static int __addr_pppoe_n2p_fun(const struct layer_addr *paddr, char *buf, int buf_len);
static int __addr_l2tp_n2p_fun(const struct layer_addr *paddr, char *buf, int buf_len);
static int __addr_arp_n2p_fun(const struct layer_addr *paddr, char *buf, int buf_len);
static int __addr_ppp_n2p_fun(const struct layer_addr *paddr, char *buf, int buf_len);
static int __addr_pptp_n2p_fun(const struct layer_addr *paddr, char *buf, int buf_len);
static int __addr_socks_n2p_fun(const struct layer_addr *paddr, char *buf, int buf_len);
static int __addr_http_proxy_n2p_fun(const struct layer_addr *paddr, char *buf, int buf_len);
static int __addr_openvpn_n2p_fun(const struct layer_addr *paddr, char *buf, int buf_len);
static int __addr_mac_in_mac_n2p_fun(const struct layer_addr *paddr, char *buf, int buf_len);
static int __addr_gtp_n2p_fun(const struct layer_addr *paddr, char *buf, int buf_len);
static int __addr_vxlan_n2p_fun(const struct layer_addr *paddr, char *buf, int buf_len);


static int __addr_ipv4_pton(char *addr_str, addr_continuous_bin_t *addr_bin_val);
static int __addr_ipv6_pton(char *addr_str, addr_continuous_bin_t *addr_bin_val);
static int __addr_pure_tcp_pton(char *addr_str, addr_continuous_bin_t *addr_bin_val);
static int __addr_tcpv4_pton(char *addr_str, addr_continuous_bin_t *addr_bin_val);
static int __addr_tcpv6_pton(char *addr_str, addr_continuous_bin_t *addr_bin_val);
static int __addr_pure_udp_pton(char *addr_str, addr_continuous_bin_t *addr_bin_val);
static int __addr_udpv4_pton(char *addr_str, addr_continuous_bin_t *addr_bin_val);
static int __addr_udpv6_pton(char *addr_str, addr_continuous_bin_t *addr_bin_val);
static int __addr_vlan_pton(char *addr_str, addr_continuous_bin_t *addr_bin_val);
static int __addr_mac_pton(char *addr_str, addr_continuous_bin_t *addr_bin_val);
static int __addr_arp_pton(char *addr_str, addr_continuous_bin_t *addr_bin_val);
static int __addr_gre_pton(char *addr_str, addr_continuous_bin_t *addr_bin_val);
static int __addr_mpls_pton(char *addr_str, addr_continuous_bin_t *addr_bin_val);
static int __addr_pppoe_pton(char *addr_str, addr_continuous_bin_t *addr_bin_val);
static int __addr_l2tp_pton(char *addr_str, addr_continuous_bin_t *addr_bin_val);
static int __addr_ppp_pton(char *addr_str, addr_continuous_bin_t *addr_bin_val);
static int __addr_pptp_pton(char *addr_str, addr_continuous_bin_t *addr_bin_val);
static int __addr_sockv4_pton(char *addr_str, addr_continuous_bin_t *addr_bin_val);
static int __addr_openvpn_pton(char *addr_str, addr_continuous_bin_t *addr_bin_val);
static int __addr_http_proxy_pton(char *addr_str, addr_continuous_bin_t *addr_bin_val);
static int __addr_mac_in_mac_pton(char *addr_str, addr_continuous_bin_t *addr_bin_val);
static const char *__layer_addr_ntop (const struct streaminfo *stream, int thread_index);
static int __addr_gtp_pton(char *addr_str, addr_continuous_bin_t *addr_bin_val);
static int __addr_vxlan_pton(char *addr_str, addr_continuous_bin_t *addr_bin_val);



static const addr_convert_t G_ADDR_CONVERT_HANDLE[] = 
{
	{__ADDR_TYPE_INIT,			STREAM_TYPE_NON,NULL, 	NULL,	NULL,	NULL},
#if (0 == IP_PORT_UNION_VERSION) /* 在IP-PORT合并的版本里, 没有纯IP地址层 */
	{ADDR_TYPE_IPV4,			STREAM_TYPE_TCP,"ADDR_TYPE_TUPLE4V4",	"IPv4_TCP",	"IPv4_TCP<",__addr_tcp_n2p_fun, __addr_tcpv4_pton, "tuple4v4"}, /* 1, 基于IPv4地址的四元组信息 */
	{ADDR_TYPE_IPV4,			STREAM_TYPE_UDP,"ADDR_TYPE_TUPLE4V4",	"IPv4_UDP",	"IPv4_UDP<",__addr_udp_n2p_fun, __addr_udpv4_pton, "tuple4v4"}, /* 1, 基于IPv4地址的四元组信息 */
	{ADDR_TYPE_IPV6,			STREAM_TYPE_TCP,"ADDR_TYPE_TUPLE4V6",	"IPv6_TCP",	"IPv6_TCP<",__addr_tcp_n2p_fun, __addr_tcpv6_pton, "tuple4v6"},	/* 2, 基于IPv6地址的四元组信息 */
	{ADDR_TYPE_IPV6,			STREAM_TYPE_UDP,"ADDR_TYPE_TUPLE4V6",	"IPv6_UDP",	"IPv6_UDP<",__addr_udp_n2p_fun, __addr_udpv6_pton, "tuple4v6"},	/* 2, 基于IPv6地址的四元组信息 */
#else /* 将四元组prefix改名, 用UNION字母U与老版区别开 */
	{ADDR_TYPE_IPV4,			STREAM_TYPE_TCP,"ADDR_TYPE_TUPLE4V4",	"IPv4_TCP",	"IPv4_TCP<",__addr_tcp_n2p_fun, __addr_tcpv4_pton, "tuple4v4"}, /* 1, 基于IPv4地址的四元组信息 */
	{ADDR_TYPE_IPV4,			STREAM_TYPE_UDP,"ADDR_TYPE_TUPLE4V4",	"IPv4_UDP",	"IPv4_UDP<",__addr_udp_n2p_fun, __addr_udpv4_pton, "tuple4v4"}, /* 1, 基于IPv4地址的四元组信息 */
	{ADDR_TYPE_IPV6,			STREAM_TYPE_TCP,"ADDR_TYPE_TUPLE4V6",	"IPv6_TCP",	"IPv6_TCP<",__addr_tcp_n2p_fun, __addr_tcpv6_pton, "tuple4v6"},	/* 2, 基于IPv6地址的四元组信息 */
	{ADDR_TYPE_IPV6,			STREAM_TYPE_UDP,"ADDR_TYPE_TUPLE4V6",	"IPv6_UDP",	"IPv6_UDP<",__addr_udp_n2p_fun, __addr_udpv6_pton, "tuple4v6"},	/* 2, 基于IPv6地址的四元组信息 */
#endif
	{ADDR_TYPE_VLAN,			STREAM_TYPE_NON,"ADDR_TYPE_VLAN",		"VLAN",		"VLAN<",__addr_vlan_n2p_fun,__addr_vlan_pton, "vlan"},	/* 3 */
	{ADDR_TYPE_MAC,				STREAM_TYPE_NON,"ADDR_TYPE_MAC",		"MAC",		"MAC<",__addr_mac_n2p_fun,__addr_mac_pton, "ethernet"}, /* 4 */
	{ADDR_TYPE_ARP,				STREAM_TYPE_NON,"ADDR_TYPE_ARP",		"ARP",		"ARP<",__addr_arp_n2p_fun,__addr_arp_pton, "arp"},				/* 5 */
	{ADDR_TYPE_GRE,				STREAM_TYPE_NON,"ADDR_TYPE_GRE",		"GRE",		"GRE<",__addr_gre_n2p_fun,__addr_gre_pton, "gre"},		/* 6 */
	{ADDR_TYPE_MPLS,			STREAM_TYPE_NON,"ADDR_TYPE_MPLS",		"MPLS",		"MPLS<",__addr_mpls_n2p_fun,__addr_mpls_pton, "mpls"},/* 7 */
	{ADDR_TYPE_PPPOE_SES,		STREAM_TYPE_PPPOE,"ADDR_TYPE_PPPOE",	"PPPOE",		"PPPOE<",__addr_pppoe_n2p_fun,__addr_pppoe_pton, "pppoe"},/* 8 */
	{ADDR_TYPE_TCP,				STREAM_TYPE_NON,"ADDR_TYPE_TCP",		"TCP",		"TCP<",__addr_pure_tcp_n2p_fun, __addr_pure_tcp_pton, "tcp"},		/* 9 */
	{ADDR_TYPE_UDP,				STREAM_TYPE_NON,"ADDR_TYPE_UDP",		"UDP",		"UDP<",__addr_pure_udp_n2p_fun,__addr_pure_udp_pton, "udp"},		/* 10 */
	{ADDR_TYPE_L2TP,			STREAM_TYPE_L2TP,"ADDR_TYPE_L2TP",		"L2TP",		"L2TP<",__addr_l2tp_n2p_fun,__addr_l2tp_pton, "l2tp"},	/* 11 */
	{__ADDR_TYPE_IP_PAIR_V4,	STREAM_TYPE_NON,"ADDR_TYPE_IPPAIR_V4",	"IPv4",		"IPv4<",__addr_ip4_n2p_fun,__addr_ipv4_pton, "ipv4"},/* 12, 纯IPv4地址对 */
	{__ADDR_TYPE_IP_PAIR_V6,	STREAM_TYPE_NON,"ADDR_TYPE_IPPAIR_V6",	"IPv6",		"IPv6<",__addr_ip6_n2p_fun,__addr_ipv6_pton, "ipv6"},/* 13, 纯IPv6地址对 */
	{ADDR_TYPE_PPP,				STREAM_TYPE_NON,"ADDR_TYPE_PPP",		"PPP",		"PPP<",__addr_ppp_n2p_fun,__addr_ppp_pton, "ppp"},/* 14 */
	{ADDR_TYPE_IPV4,			STREAM_TYPE_SOCKS4,"ADDR_TYPE_SOCKS",	"SOCKS",		"SOCKS<",__addr_socks_n2p_fun,__addr_sockv4_pton, "socks"},/* 14 */
	{ADDR_TYPE_IPV4,			STREAM_TYPE_SOCKS5,"ADDR_TYPE_SOCKS",	"SOCKS",		"SOCKS<",__addr_socks_n2p_fun,__addr_sockv4_pton, "socks"},/* 14 */
	{ADDR_TYPE_IPV4,			STREAM_TYPE_HTTP_PROXY,"ADDR_TYPE_HTTP_PROXY",	"HTTP_PROXY",		"HTTP_PROXY<",__addr_http_proxy_n2p_fun,__addr_http_proxy_pton, "http_proxy"},
	{ADDR_TYPE_IPV6,			STREAM_TYPE_HTTP_PROXY,"ADDR_TYPE_HTTP_PROXY",	"HTTP_PROXY",		"HTTP_PROXY<",__addr_http_proxy_n2p_fun,__addr_http_proxy_pton, "http_proxy"},
	{ADDR_TYPE_PPTP,			STREAM_TYPE_PPTP,"ADDR_TYPE_PPPTP",		"PPTP", 		"PPTP<",__addr_pptp_n2p_fun, __addr_pptp_pton, "pptp"}, /* 15 */
	{ADDR_TYPE_MAC_IN_MAC,		STREAM_TYPE_NON, "ADDR_TYPE_MAC_IN_MAC",	"MAC_IN_MAC",	"MAC_IN_MAC<",__addr_mac_in_mac_n2p_fun,__addr_mac_in_mac_pton, "mac_in_mac"}, /* 4 */
	{ADDR_TYPE_IPV4,			STREAM_TYPE_OPENVPN,"ADDR_TYPE_OPENVPN",	"OpenVPN",	"OpenVPN<",__addr_openvpn_n2p_fun,__addr_openvpn_pton, "openvpn"},/* 2017-02-10 lijia add */
	{ADDR_TYPE_IPV6,			STREAM_TYPE_OPENVPN,"ADDR_TYPE_OPENVPN",	"OpenVPN",	"OpenVPN<",__addr_openvpn_n2p_fun,__addr_openvpn_pton, "openvpn"},/* 2017-02-10 lijia add */
    {ADDR_TYPE_GPRS_TUNNEL,		STREAM_TYPE_NON,"ADDR_TYPE_GTP",			"GTP",		"GTP<",__addr_gtp_n2p_fun,__addr_gtp_pton, "gtp"},	/*  */
    {ADDR_TYPE_VXLAN,			STREAM_TYPE_NON,"ADDR_TYPE_VXLAN",		"VXLAN",		"VXLAN<", __addr_vxlan_n2p_fun,__addr_vxlan_pton, "vxlan"},  
    {__ADDR_TYPE_MAX,			STREAM_TYPE_NON,NULL, 	NULL,	NULL,	NULL, NULL} /* EOF */
};


static inline enum addr_type_t addr_prefix_to_type(const char *prefix)
{
	int i;

	for(i = __ADDR_TYPE_INIT+1; G_ADDR_CONVERT_HANDLE[i].addr_type_bin!= __ADDR_TYPE_MAX; i++){
		if(strncasecmp(prefix, G_ADDR_CONVERT_HANDLE[i].addr_type_prefix, strlen(G_ADDR_CONVERT_HANDLE[i].addr_type_prefix)) == 0){
			return G_ADDR_CONVERT_HANDLE[i].addr_type_bin;
		}
	}

	return __ADDR_TYPE_INIT;
}

const char *addr_type_to_prefix(enum addr_type_t layer_type)
{
	int i;
	if(layer_type <=  __ADDR_TYPE_INIT || layer_type >= __ADDR_TYPE_MAX){
		return NULL;
	}

	for(i = __ADDR_TYPE_INIT+1; G_ADDR_CONVERT_HANDLE[i].addr_type_bin!= __ADDR_TYPE_MAX; i++){
		if(G_ADDR_CONVERT_HANDLE[i].addr_type_bin == layer_type){
			return G_ADDR_CONVERT_HANDLE[i].addr_type_prefix;
		}
	}

	return NULL;
}

static int __addr_ipv4_pton(char *addr_str, addr_continuous_bin_t *addr_bin_val)
{
	char *save_ptr;
	char *item;
	struct stream_tuple4_v4 *tuple4_v4 = (struct stream_tuple4_v4 *)addr_bin_val->addr_value;
	
	addr_bin_val->stream.addr.addrtype = __ADDR_TYPE_IP_PAIR_V4;
	addr_bin_val->stream.addr.addrlen = sizeof(struct stream_tuple4_v4);

	item = strtok_r(addr_str, "-", &save_ptr);
	if(NULL == item){
		goto err;
	}
	if(inet_pton(AF_INET, item, &tuple4_v4->saddr) < 0){
		goto err;
	}

	item = strtok_r(NULL, "-", &save_ptr);
	if(NULL == item){
		goto err;
	}
	if(inet_pton(AF_INET, item, &tuple4_v4->daddr) < 0){
		goto err;
	}	

	addr_bin_val->stream.addr.paddr = tuple4_v4;

	return 0;
err:
	while(strtok_r(NULL, "-", &save_ptr)); /* clear buf */ 
	return -1;	
}

static int __addr_ipv6_pton(char *addr_str, addr_continuous_bin_t *addr_bin_val)
{
	char *save_ptr;
	char *item;
	struct stream_tuple4_v6 *tuple4_v6 = (struct stream_tuple4_v6 *)addr_bin_val->addr_value;
	
	addr_bin_val->stream.addr.addrtype = __ADDR_TYPE_IP_PAIR_V6;
	addr_bin_val->stream.addr.addrlen = sizeof(struct stream_tuple4_v6);

	item = strtok_r(addr_str, "-", &save_ptr);
	if(NULL == item){
		goto err;
	}
	if(inet_pton(AF_INET6, item, tuple4_v6->saddr) < 0){
		goto err;
	}

	item = strtok_r(NULL, "-", &save_ptr);
	if(NULL == item){
		goto err;
	}
	if(inet_pton(AF_INET6, item, tuple4_v6->daddr) < 0){
		goto err;
	}	

	addr_bin_val->stream.addr.paddr = tuple4_v6;

	return 0;

err:
	while(strtok_r(NULL, "-", &save_ptr)); /* clear buf */ 
	return -1;	
}


static int __addr_pure_tcp_pton(char *addr_str, addr_continuous_bin_t *addr_bin_val)
{
	char *save_ptr;
	char *item;
	int temp;
	struct layer_addr_tcp *tcp_addr_val = (struct layer_addr_tcp *)addr_bin_val->addr_value;
	
	addr_bin_val->stream.addr.addrtype = ADDR_TYPE_TCP; /* TCP层使用四元组地址类型 */
	addr_bin_val->stream.type = STREAM_TYPE_TCP;
	addr_bin_val->stream.addr.addrlen = sizeof(struct stream_tuple4_v4);
	item = strtok_r(addr_str, "-", &save_ptr);
	if(NULL == item){
		goto err;
	}
	temp = strtol(item, NULL, 10);
	if(temp < 0 || temp > 65535){
		goto err;
	}
	tcp_addr_val->source = (UINT16)temp;
	tcp_addr_val->source = htons(tcp_addr_val->source);
	item = strtok_r(NULL, "-", &save_ptr);
	if(NULL == item){
		goto err;
	}
	temp = strtol(item, NULL, 10);
	if(temp < 0 || temp > 65535){
		goto err;
	}
	tcp_addr_val->dest = (UINT16)temp;
	tcp_addr_val->dest = htons(tcp_addr_val->dest);

	addr_bin_val->stream.addr.paddr = tcp_addr_val;

	return 0;

err:
	while(strtok_r(NULL, "-", &save_ptr)); /* clear buf */ 
	return -1;		
}

static int __addr_tcpv4_pton(char *addr_str, addr_continuous_bin_t *addr_bin_val)
{
	char *save_ptr;
	char *item;
	int temp;
	struct stream_tuple4_v4 *tuple4_v4 = (struct stream_tuple4_v4 *)addr_bin_val->addr_value;
	
	addr_bin_val->stream.addr.addrtype = ADDR_TYPE_IPV4; /* TCP层使用四元组地址类型 */
	addr_bin_val->stream.type = STREAM_TYPE_TCP;
	addr_bin_val->stream.addr.addrlen = sizeof(struct stream_tuple4_v4);
	item = strtok_r(addr_str, "-", &save_ptr);
	if(NULL == item){
		goto err;
	}
	temp = strtol(item, NULL, 10);
	if(temp < 0 || temp > 65535){
		goto err;
	}
	tuple4_v4->source = (UINT16)temp;
	tuple4_v4->source = htons(tuple4_v4->source);
	item = strtok_r(NULL, "-", &save_ptr);
	if(NULL == item){
		goto err;
	}
	temp = strtol(item, NULL, 10);
	if(temp < 0 || temp > 65535){
		goto err;
	}
	tuple4_v4->dest = (UINT16)temp;
	tuple4_v4->dest = htons(tuple4_v4->dest);

#if IP_PORT_UNION_VERSION
	item = strtok_r(NULL, "-", &save_ptr);
	if(NULL == item){
		goto err;
	}	
	if(inet_pton(AF_INET, item, &tuple4_v4->saddr) <= 0){
		goto err;
	}

	item = strtok_r(NULL, "-", &save_ptr);
	if(NULL == item){
		goto err;
	}	
	if(inet_pton(AF_INET, item, &tuple4_v4->daddr) <= 0){
		goto err;
	}	
#endif

	addr_bin_val->stream.addr.paddr = tuple4_v4;

	return 0;

err:
	while(strtok_r(NULL, "-", &save_ptr)); /* clear buf */ 
	return -1;
}

static int __addr_tcpv6_pton(char *addr_str, addr_continuous_bin_t *addr_bin_val)
{
	char *save_ptr;
	char *item;
	int temp;
	struct stream_tuple4_v6 *tuple4_v6 = (struct stream_tuple4_v6 *)addr_bin_val->addr_value;
	
	addr_bin_val->stream.addr.addrtype = ADDR_TYPE_IPV6; /* TCP层使用四元组地址类型 */
	addr_bin_val->stream.type = STREAM_TYPE_TCP;
	addr_bin_val->stream.addr.addrlen = sizeof(struct stream_tuple4_v6);
	item = strtok_r(addr_str, "-", &save_ptr);
	if(NULL == item){
		goto err;
	}
	temp = strtol(item, NULL, 10);
	if(temp < 0 || temp > 65535){
		goto err;
	}
	tuple4_v6->source = (UINT16)temp;
	tuple4_v6->source = htons(tuple4_v6->source);
	item = strtok_r(NULL, "-", &save_ptr);
	if(NULL == item){
		goto err;
	}
	temp = strtol(item, NULL, 10);
	if(temp < 0 || temp > 65535){
		goto err;
	}
	tuple4_v6->dest = (UINT16)temp;
	tuple4_v6->dest = htons(tuple4_v6->dest);

#if IP_PORT_UNION_VERSION
	item = strtok_r(NULL, "-", &save_ptr);
	if(NULL == item){
		goto err;
	}	
	if(inet_pton(AF_INET6, item, tuple4_v6->saddr) <= 0){
		goto err;
	}

	item = strtok_r(NULL, "-", &save_ptr);
	if(NULL == item){
		goto err;
	}	
	if(inet_pton(AF_INET6, item, tuple4_v6->daddr) <= 0){
		goto err;
	}	
#endif

	addr_bin_val->stream.addr.paddr = tuple4_v6;

	return 0;

err:
	while(strtok_r(NULL, "-", &save_ptr)); /* clear buf */ 
	return -1;		
}

static int __addr_pure_udp_pton(char *addr_str, addr_continuous_bin_t *addr_bin_val)
{
	char *save_ptr;
	char *item;
	int temp;
	struct layer_addr_udp *udp_addr_val = (struct layer_addr_udp *)addr_bin_val->addr_value;
	
	addr_bin_val->stream.addr.addrtype = ADDR_TYPE_UDP; /* TCP层使用四元组地址类型 */
	addr_bin_val->stream.type = STREAM_TYPE_UDP;
	addr_bin_val->stream.addr.addrlen = sizeof(struct stream_tuple4_v4);
	item = strtok_r(addr_str, "-", &save_ptr);
	if(NULL == item){
		goto err;
	}
	temp = strtol(item, NULL, 10);
	if(temp < 0 || temp > 65535){
		goto err;
	}
	udp_addr_val->source = (UINT16)temp;
	udp_addr_val->source = htons(udp_addr_val->source);
	item = strtok_r(NULL, "-", &save_ptr);
	if(NULL == item){
		goto err;
	}
	temp = strtol(item, NULL, 10);
	if(temp < 0 || temp > 65535){
		goto err;
	}
	udp_addr_val->dest = (UINT16)temp;
	udp_addr_val->dest = htons(udp_addr_val->dest);

	addr_bin_val->stream.addr.paddr = udp_addr_val;

	return 0;

err:
	while(strtok_r(NULL, "-", &save_ptr)); /* clear buf */ 
	return -1;		
}

static int __addr_udpv4_pton(char *addr_str, addr_continuous_bin_t *addr_bin_val)
{
	char *save_ptr;
	char *item;
	int temp;
	struct stream_tuple4_v4 *tuple4_v4 = (struct stream_tuple4_v4 *)addr_bin_val->addr_value;
	
	addr_bin_val->stream.addr.addrtype = ADDR_TYPE_IPV4; /* TCP层使用四元组地址类型 */
	addr_bin_val->stream.type = STREAM_TYPE_UDP;
	addr_bin_val->stream.addr.addrlen = sizeof(struct stream_tuple4_v4);
	item = strtok_r(addr_str, "-", &save_ptr);
	if(NULL == item){
		goto err;
	}
	temp = strtol(item, NULL, 10);
	if(temp < 0 || temp > 65535){
		goto err;
	}
	tuple4_v4->source = (UINT16)temp;
	tuple4_v4->source = htons(tuple4_v4->source);
	item = strtok_r(NULL, "-", &save_ptr);
	if(NULL == item){
		goto err;
	}
	temp = strtol(item, NULL, 10);
	if(temp < 0 || temp > 65535){
		goto err;
	}
	tuple4_v4->dest = (UINT16)temp;
	tuple4_v4->dest = htons(tuple4_v4->dest);

#if IP_PORT_UNION_VERSION
	item = strtok_r(NULL, "-", &save_ptr);
	if(NULL == item){
		goto err;
	}	
	if(inet_pton(AF_INET, item, &tuple4_v4->saddr) <= 0){
		goto err;
	}

	item = strtok_r(NULL, "-", &save_ptr);
	if(NULL == item){
		goto err;
	}	
	if(inet_pton(AF_INET, item, &tuple4_v4->daddr) <= 0){
		goto err;
	}	
#endif

	addr_bin_val->stream.addr.paddr = tuple4_v4;

	return 0;

err:
	while(strtok_r(NULL, "-", &save_ptr)); /* clear buf */ 
	return -1;		
}

static int __addr_udpv6_pton(char *addr_str, addr_continuous_bin_t *addr_bin_val)
{
	char *save_ptr;
	char *item;
	int temp;
	struct stream_tuple4_v6 *tuple4_v6 = (struct stream_tuple4_v6 *)addr_bin_val->addr_value;
	
	addr_bin_val->stream.addr.addrtype = ADDR_TYPE_IPV6; /* TCP层使用四元组地址类型 */
	addr_bin_val->stream.type = STREAM_TYPE_UDP;
	addr_bin_val->stream.addr.addrlen = sizeof(struct stream_tuple4_v6);
	item = strtok_r(addr_str, "-", &save_ptr);
	if(NULL == item){
		goto err;
	}
	temp = strtol(item, NULL, 10);
	if(temp < 0 || temp > 65535){
		goto err;
	}
	tuple4_v6->source = (UINT16)temp;
	tuple4_v6->source = htons(tuple4_v6->source);
	item = strtok_r(NULL, "-", &save_ptr);
	if(NULL == item){
		goto err;
	}
	temp = strtol(item, NULL, 10);
	if(temp < 0 || temp > 65535){
		goto err;
	}
	tuple4_v6->dest = (UINT16)temp;
	tuple4_v6->dest = htons(tuple4_v6->dest);

#if IP_PORT_UNION_VERSION
	item = strtok_r(NULL, "-", &save_ptr);
	if(NULL == item){
		goto err;
	}	
	if(inet_pton(AF_INET6, item, tuple4_v6->saddr) <= 0){
		goto err;
	}

	item = strtok_r(NULL, "-", &save_ptr);
	if(NULL == item){
		goto err;
	}	
	if(inet_pton(AF_INET6, item, tuple4_v6->daddr) <= 0){
		goto err;
	}	
#endif
	addr_bin_val->stream.addr.paddr = tuple4_v6;

	return 0;

err:
	while(strtok_r(NULL, "-", &save_ptr)); /* clear buf */ 
	return -1;	
}

static int __addr_vlan_pton(char *addr_str, addr_continuous_bin_t *addr_bin_val)
{
	addr_bin_val->stream.addr.addrtype = ADDR_TYPE_VLAN; 
	addr_bin_val->stream.type = STREAM_TYPE_NON;
	addr_bin_val->stream.addr.addrlen = sizeof(struct layer_addr_vlan);

	addr_bin_val->stream.addr.paddr = addr_bin_val->addr_value;

	return 0;
}

static int __addr_mac_pton(char *addr_str, addr_continuous_bin_t *addr_bin_val)
{
	int i;
	char *str_val = addr_str;
	//char *bin_val = addr_bin_val->addr_value;
	unsigned char tmp_bin_val;
	struct layer_addr_mac *macaddr = (struct layer_addr_mac *)addr_bin_val->addr_value;
	addr_bin_val->stream.addr.addrtype = ADDR_TYPE_MAC;
	addr_bin_val->stream.type = STREAM_TYPE_NON;
	addr_bin_val->stream.addr.addrlen = sizeof(struct layer_addr_mac);

	for(i = 0; i < MAC_ADDR_LEN; i++){
		tmp_bin_val = 0; /* 先清零, 后续赋值语句都是或操作 */
		if(isxdigit(*str_val)==0){
			sapp_runtime_log(20, "MAC string type error!\n");
			return -1;
		}
		tmp_bin_val |= MESA_ascii_to_hex(*str_val) << 4;
		str_val++;
		
		if(isxdigit(*str_val)==0)	{
			sapp_runtime_log(20, "MAC string type error!\n");
			return -1;
		}
		tmp_bin_val |= MESA_ascii_to_hex(*str_val);
		str_val++;
		macaddr->src_addr.h_source[i] = tmp_bin_val;
	}

	if(*str_val != '-'){
		sapp_runtime_log(20, "MAC string type error!\n");
		return -1;		
	}
	str_val++;
	
	for(i = 0; i < MAC_ADDR_LEN; i++){
		tmp_bin_val = 0; /* 先清零, 后续赋值语句都是或操作 */
		if(isxdigit(*str_val)==0){
			sapp_runtime_log(20, "MAC string type error!\n");
			return -1;
		}
		tmp_bin_val |= MESA_ascii_to_hex(*str_val) << 4;
		str_val++;
		
		if(isxdigit(*str_val)==0)	{
			sapp_runtime_log(20, "MAC string type error!\n");
			return -1;
		}
		tmp_bin_val |= MESA_ascii_to_hex(*str_val);
		str_val++;
		macaddr->src_addr.h_dest[i] = tmp_bin_val;
	}
	
	addr_bin_val->stream.addr.paddr = addr_bin_val->addr_value;

	return 0;
}	

/*MAC_IN_MAC<000100032202-00e0fc030007,000100032202-00e0fc030007>*/
static int __addr_mac_in_mac_pton(char *addr_str, addr_continuous_bin_t *addr_bin_val)
{
	int i;
	char *str_val = addr_str;
	//char *bin_val = addr_bin_val->addr_value;
	unsigned char tmp_bin_val;
	struct layer_addr_mac_in_mac *macaddr = (struct layer_addr_mac_in_mac *)addr_bin_val->addr_value;
	addr_bin_val->stream.addr.addrtype = ADDR_TYPE_MAC_IN_MAC;
	addr_bin_val->stream.type = STREAM_TYPE_NON;
	addr_bin_val->stream.addr.addrlen = sizeof(struct layer_addr_mac_in_mac);

	for(i = 0; i < MAC_ADDR_LEN; i++){
		tmp_bin_val = 0; /* 先清零, 后续赋值语句都是或操作 */
		if(isxdigit(*str_val)==0){
			printf("MAC string type error!\n");
			return -1;
		}
		tmp_bin_val |= MESA_ascii_to_hex(*str_val) << 4;
		str_val++;
		
		if(isxdigit(*str_val)==0)	{
			printf("MAC string type error!\n");
			return -1;
		}
		tmp_bin_val |= MESA_ascii_to_hex(*str_val);
		str_val++;
		macaddr->inner_src_mac[i] = tmp_bin_val;
	}

	if(*str_val != '-'){
		printf("MAC string type error!\n");
		return -1;		
	}
	str_val++;
	
	for(i = 0; i < MAC_ADDR_LEN; i++){
		tmp_bin_val = 0; /* 先清零, 后续赋值语句都是或操作 */
		if(isxdigit(*str_val)==0){
			printf("MAC string type error!\n");
			return -1;
		}
		tmp_bin_val |= MESA_ascii_to_hex(*str_val) << 4;
		str_val++;
		
		if(isxdigit(*str_val)==0)	{
			printf("MAC string type error!\n");
			return -1;
		}
		tmp_bin_val |= MESA_ascii_to_hex(*str_val);
		str_val++;
		macaddr->inner_dst_mac[i] = tmp_bin_val;
	}

	if(*str_val != ','){
		printf("MAC_IN_MAC string type error!\n");
		return -1;		
	}
	str_val++;
	
	for(i = 0; i < MAC_ADDR_LEN; i++){
		tmp_bin_val = 0; /* 先清零, 后续赋值语句都是或操作 */
		if(isxdigit(*str_val)==0){
			printf("MAC string type error!\n");
			return -1;
		}
		tmp_bin_val |= MESA_ascii_to_hex(*str_val) << 4;
		str_val++;
		
		if(isxdigit(*str_val)==0)	{
			printf("MAC string type error!\n");
			return -1;
		}
		tmp_bin_val |= MESA_ascii_to_hex(*str_val);
		str_val++;
		macaddr->outer_src_mac[i] = tmp_bin_val;
	}

	if(*str_val != '-'){
		printf("MAC_IN_MAC string type error!\n");
		return -1;		
	}
	str_val++;
	
	for(i = 0; i < MAC_ADDR_LEN; i++){
		tmp_bin_val = 0; /* 先清零, 后续赋值语句都是或操作 */
		if(isxdigit(*str_val)==0){
			printf("MAC string type error!\n");
			return -1;
		}
		tmp_bin_val |= MESA_ascii_to_hex(*str_val) << 4;
		str_val++;
		
		if(isxdigit(*str_val)==0)	{
			printf("MAC string type error!\n");
			return -1;
		}
		tmp_bin_val |= MESA_ascii_to_hex(*str_val);
		str_val++;
		macaddr->outer_dst_mac[i] = tmp_bin_val;
	}
	
	addr_bin_val->stream.addr.paddr = addr_bin_val->addr_value;

	return 0;
}

static int __addr_arp_pton(char *addr_str, addr_continuous_bin_t *addr_bin_val)
{
	addr_bin_val->stream.addr.addrtype = ADDR_TYPE_ARP;
	addr_bin_val->stream.type = STREAM_TYPE_NON;
	addr_bin_val->stream.addr.paddr = addr_bin_val->addr_value;
	
	return 0;
}	

static int __addr_gre_pton(char *addr_str, addr_continuous_bin_t *addr_bin_val)
{
	addr_bin_val->stream.addr.addrtype = ADDR_TYPE_GRE;
	addr_bin_val->stream.type = STREAM_TYPE_NON;
	addr_bin_val->stream.addr.paddr = addr_bin_val->addr_value;

	return 0;
}	

static int __addr_mpls_pton(char *addr_str, addr_continuous_bin_t *addr_bin_val)
{
	addr_bin_val->stream.addr.addrtype = ADDR_TYPE_MPLS;
	addr_bin_val->stream.type = STREAM_TYPE_NON;
	addr_bin_val->stream.addr.paddr = addr_bin_val->addr_value;

	return 0;
}	

static int __addr_pppoe_pton(char *addr_str, addr_continuous_bin_t *addr_bin_val)
{
	addr_bin_val->stream.addr.addrtype = ADDR_TYPE_PPPOE_SES;
	addr_bin_val->stream.type = STREAM_TYPE_PPPOE;
	addr_bin_val->stream.addr.paddr = addr_bin_val->addr_value;

	return 0;
}	

static int __addr_ppp_pton(char *addr_str, addr_continuous_bin_t *addr_bin_val)
{
	addr_bin_val->stream.addr.addrtype = ADDR_TYPE_PPP;
	addr_bin_val->stream.type = STREAM_TYPE_NON;
	addr_bin_val->stream.addr.paddr = addr_bin_val->addr_value;

	return 0;
}	

static int __addr_pptp_pton(char *addr_str, addr_continuous_bin_t *addr_bin_val)
{
	struct layer_addr_pptp *pptpaddr = (struct layer_addr_pptp *)&addr_bin_val->addr_value[0];
	char *save_ptr;
	char *item;
	int temp;

	item = strtok_r(addr_str, "-", &save_ptr);
	if(NULL == item){
		goto err;
	}
	temp = strtol(item, NULL, 10);
	if(temp < 0 || temp > 65535){
		goto err;
	}
	pptpaddr->C2S_call_id = htons((UINT16)temp);

	item = strtok_r(NULL, "-", &save_ptr);
	if(NULL == item){
		goto err;
	}
	temp = strtol(item, NULL, 10);
	if(temp < 0 || temp > 65535){
		goto err;
	}
	pptpaddr->S2C_call_id = htons((UINT16)temp);
	
	addr_bin_val->stream.addr.addrtype = ADDR_TYPE_PPTP;
	addr_bin_val->stream.type = STREAM_TYPE_PPTP;
	addr_bin_val->stream.addr.paddr = addr_bin_val->addr_value;
	addr_bin_val->stream.addr.addrlen = sizeof(struct layer_addr_pptp);
	
	return 0;

err:
	while(strtok_r(NULL, "-", &save_ptr)); /* clear buf */ 
	return -1;
}	


static int __addr_l2tp_pton(char *addr_str, addr_continuous_bin_t *addr_bin_val)
{
	addr_bin_val->stream.addr.addrtype = ADDR_TYPE_L2TP;
	addr_bin_val->stream.type = STREAM_TYPE_L2TP;
	addr_bin_val->stream.addr.paddr = addr_bin_val->addr_value;

	return 0;
}

static int __addr_gtp_pton(char *addr_str, addr_continuous_bin_t *addr_bin_val)
{
	struct layer_addr_gtp *gtpaddr = (struct layer_addr_gtp *)&addr_bin_val->addr_value[0];
	char *save_ptr;
	char *item;
	int temp;

	item = strtok_r(addr_str, "-", &save_ptr);
	if(NULL == item){
		goto err;
	}
	temp = strtol(item, NULL, 10);
	gtpaddr->teid_c2s = htonl(temp);

	item = strtok_r(NULL, "-", &save_ptr);
	if(NULL == item){
		goto err;
	}
	temp = strtol(item, NULL, 10);
	gtpaddr->teid_s2c = htonl(temp);	

    addr_bin_val->stream.addr.addrtype = ADDR_TYPE_GPRS_TUNNEL;
    addr_bin_val->stream.type = STREAM_TYPE_NON;
    addr_bin_val->stream.addr.paddr = addr_bin_val->addr_value;

    return 0;

err:
	while(strtok_r(NULL, "-", &save_ptr)); /* clear buf */ 
	return -1;    
}

/* vxlan地址格式:  vlan_id-dir-link_id-link_type*/
static int __addr_vxlan_pton(char *addr_str, addr_continuous_bin_t *addr_bin_val)
{
	char *vxlan_struct_item;
	const char *delim = "-";
	char *save_ptr;
	struct layer_addr_vxlan *vxlan_bin_addr = (struct layer_addr_vxlan *)addr_bin_val->addr_value;
	addr_bin_val->stream.addr.addrtype = ADDR_TYPE_VXLAN;
	addr_bin_val->stream.type = STREAM_TYPE_NON;
	addr_bin_val->stream.addr.addrlen = sizeof(struct layer_addr_vxlan);	
	addr_bin_val->stream.addr.paddr = addr_bin_val->addr_value;

	vxlan_struct_item = strtok_r(addr_str, delim, &save_ptr);
	if(NULL == vxlan_struct_item){
		return -1;
	}
	vxlan_bin_addr->vlan_id = strtol(vxlan_struct_item, NULL, 10);

	vxlan_struct_item = strtok_r(NULL, delim, &save_ptr);
	if(NULL == vxlan_struct_item){
		return -1;
	}
	vxlan_bin_addr->dir = strtol(vxlan_struct_item, NULL, 10);


	vxlan_struct_item = strtok_r(NULL, delim, &save_ptr);
	if(NULL == vxlan_struct_item){
		return -1;
	}
	vxlan_bin_addr->link_id = strtol(vxlan_struct_item, NULL, 10);

	vxlan_struct_item = strtok_r(NULL, delim, &save_ptr);
	if(NULL == vxlan_struct_item){
		return -1;
	}
	vxlan_bin_addr->link_type = strtol(vxlan_struct_item, NULL, 10);


	return 0;
}
static int __addr_sockv4_pton(char *addr_str, addr_continuous_bin_t *addr_bin_val)
{
	char *save_ptr;
	char *item;
	int temp;
	struct stream_tuple4_v4 *tuple4_v4 = (struct stream_tuple4_v4 *)addr_bin_val->addr_value;
	
	addr_bin_val->stream.addr.addrtype = ADDR_TYPE_IPV4; /* TCP层使用四元组地址类型 */
	addr_bin_val->stream.type = STREAM_TYPE_SOCKS4;
	addr_bin_val->stream.addr.addrlen = sizeof(struct stream_tuple4_v4);
	item = strtok_r(addr_str, "-", &save_ptr);
	if(NULL == item){
		goto err;
	}
	temp = strtol(item, NULL, 10);
	if(temp < 0 || temp > 65535){
		goto err;
	}
	tuple4_v4->source = (UINT16)temp;
	tuple4_v4->source = htons(tuple4_v4->source);
	item = strtok_r(NULL, "-", &save_ptr);
	if(NULL == item){
		goto err;
	}
	temp = strtol(item, NULL, 10);
	if(temp < 0 || temp > 65535){
		goto err;
	}
	tuple4_v4->dest = (UINT16)temp;
	tuple4_v4->dest = htons(tuple4_v4->dest);

#if IP_PORT_UNION_VERSION
	item = strtok_r(NULL, "-", &save_ptr);
	if(NULL == item){
		goto err;
	}	
	if(inet_pton(AF_INET, item, &tuple4_v4->saddr) <= 0){
		goto err;
	}

	item = strtok_r(NULL, "-", &save_ptr);
	if(NULL == item){
		goto err;
	}	
	if(inet_pton(AF_INET, item, &tuple4_v4->daddr) <= 0){
		goto err;
	}	
#endif

	addr_bin_val->stream.addr.paddr = tuple4_v4;

	return 0;

err:
	while(strtok_r(NULL, "-", &save_ptr)); /* clear buf */ 
	return -1;
}

/* How TODO 2, 基于IPv6的openvpn协议如何? */
static int __addr_openvpn_pton(char *addr_str, addr_continuous_bin_t *addr_bin_val)
{
	addr_bin_val->stream.addr.addrtype = ADDR_TYPE_IPV4; 
	addr_bin_val->stream.type = STREAM_TYPE_OPENVPN;
	addr_bin_val->stream.addr.addrlen = sizeof(struct layer_addr_ipv4);

	addr_bin_val->stream.addr.paddr = addr_bin_val->addr_value;

	return 0;
}

static int __addr_http_proxy_pton(char *addr_str, addr_continuous_bin_t *addr_bin_val)
{
	addr_bin_val->stream.addr.addrtype = ADDR_TYPE_IPV4;
	addr_bin_val->stream.type = STREAM_TYPE_HTTP_PROXY;
	addr_bin_val->stream.addr.paddr = addr_bin_val->addr_value;
	
	return 0;
}	


/*
	return val:
		<0 : error;
		>0 : prefix length;
*/
static inline int addr_prefix_to_stream_and_addr_type(const char *prefix, enum addr_type_t *addr_type, UCHAR *stream_type)
{
	int i;

	/* NOTE: 比较前缀时, 需要用addr_type_prefix_with_delim, 带分隔符 */
	for(i = __ADDR_TYPE_INIT+1; G_ADDR_CONVERT_HANDLE[i].addr_type_bin!= __ADDR_TYPE_MAX; i++){
		if(strncasecmp(prefix, G_ADDR_CONVERT_HANDLE[i].addr_type_prefix_with_delim, 
				        strlen(G_ADDR_CONVERT_HANDLE[i].addr_type_prefix_with_delim)) == 0){
			*addr_type = G_ADDR_CONVERT_HANDLE[i].addr_type_bin;
			*stream_type = G_ADDR_CONVERT_HANDLE[i].stream_type;
			return strlen(G_ADDR_CONVERT_HANDLE[i].addr_type_prefix_with_delim);
		}
	}

	return -1;
}

static int __addr_pton(char *single_addr_str, addr_continuous_bin_t *addr_bin_val)
{
	enum addr_type_t addr_type;
	int i, ret = 0, prefix_with_delim_len, single_addr_str_len;

#if 0	
	addr_type = addr_prefix_to_type(single_addr_str);
	if(__ADDR_TYPE_INIT == addr_type){
		return -1;
	}
#else
	prefix_with_delim_len = addr_prefix_to_stream_and_addr_type(single_addr_str, &addr_type, &addr_bin_val->stream.type);
	if(prefix_with_delim_len < 0){
		return -1;
	}
#endif

	single_addr_str_len = strlen(single_addr_str);
	if(single_addr_str[single_addr_str_len-1] != '>'){ /* 地址最后一个字符不是分隔符'>' */
		return -1;
	}
	single_addr_str[single_addr_str_len-1] = '\0';

	for(i = __ADDR_TYPE_INIT+1; G_ADDR_CONVERT_HANDLE[i].addr_type_bin != __ADDR_TYPE_MAX; i++){
		if((G_ADDR_CONVERT_HANDLE[i].addr_type_bin == addr_type)
		 &&(G_ADDR_CONVERT_HANDLE[i].stream_type == addr_bin_val->stream.type)){
			ret = G_ADDR_CONVERT_HANDLE[i].addr_p2n_fun(
							single_addr_str+prefix_with_delim_len, /* 跳过前缀和'<'分隔符 */ 
							addr_bin_val);
			break;
		}
	}

	if(ret < 0){
		return -1;
	}
	
	return 0;
}

static struct streaminfo *create_chain_outward(addr_continuous_bin_t *list_bin_val, int layer_num)
{
	int i;
	struct streaminfo *last_stream = NULL;

	for(i = layer_num-1; i >= 0; i--){
		if(NULL == last_stream){
			last_stream = &list_bin_val[i].stream;
		}else{
			list_bin_val[i].stream.pfather = last_stream;
			last_stream = &list_bin_val[i].stream;
		}
	}

	return &list_bin_val[0].stream;
}



static struct streaminfo *create_chain_inward(addr_continuous_bin_t *list_bin_val, int layer_num)
{
	int i;
	struct streaminfo *last_stream = NULL;

	for(i = 0; i < layer_num; i++){
		if(NULL == last_stream){
			last_stream = &list_bin_val[i].stream;
		}else{
			list_bin_val[i].stream.pfather = last_stream;
			last_stream = &list_bin_val[i].stream;
		}
	}

	return &list_bin_val[layer_num-1].stream;
}

#if (0 == IP_PORT_UNION_VERSION)
static int fix_tuple4_addr(struct streaminfo *raw_stream)
{
	struct streaminfo *stream = raw_stream;
	struct stream_tuple4_v4 *tuple4_v4_this, *tuple4_v4_father;
	struct stream_tuple4_v6 *tuple4_v6_this, *tuple4_v6_father;

if(NULL == raw_stream->pfather){ /* 2015-03-27 lijia add, for bug */
return -1;
}
	
	while(stream){
		if(ADDR_TYPE_IPV4 == stream->addr.addrtype){
			tuple4_v4_this = (struct stream_tuple4_v4 *)stream->addr.paddr;
			tuple4_v4_father = (struct stream_tuple4_v4 *)stream->pfather->addr.paddr;
			tuple4_v4_father->source = tuple4_v4_this->source;
			tuple4_v4_father->dest = tuple4_v4_this->dest;
			stream->addr.paddr = stream->pfather->addr.paddr;
		}else if(ADDR_TYPE_IPV6 == stream->addr.addrtype){
			tuple4_v6_this = (struct stream_tuple4_v6 *)stream->addr.paddr;
			tuple4_v6_father = (struct stream_tuple4_v6 *)stream->pfather->addr.paddr;
			tuple4_v6_father->source = tuple4_v6_this->source;
			tuple4_v6_father->dest = tuple4_v6_this->dest;
			stream->addr.paddr = stream->pfather->addr.paddr;
		}

		stream = stream->pfather;
	}

	return 0;
}
#endif

/* 由内向外(平台默认模式), "TCP<12345-80>|IP4<10.0.6.1-10.0.6.2>|MAC<0x112233445566-0xAABBCCDDEEFF>"*/
const struct streaminfo *stream_addr_list_pton_outward(const char *addr_list_str, int thread_index)
{
	char *tmp_store_str, *stack_addr_list_str;
	int addr_list_str_len;
	addr_continuous_bin_t *list_bin_val = __stream_list_bin_value[thread_index];
	char *save_ptr;
	char *single_addr_str;
	int layer_addr_level = 0, ret;
	struct streaminfo *stream_head = NULL;

	if(NULL == addr_list_str){
		return NULL;
	}

	addr_list_str_len = strlen(addr_list_str);
	if(addr_list_str_len < 4){ /* 4:一个合法地址字符串的最小长度, prefix<实际地址> */
		return NULL;
	}
	/* 需要用strtok分割字符串, copy到临时缓存中 */
	tmp_store_str = (char *)dictator_malloc(thread_index, addr_list_str_len+1);
	memcpy(tmp_store_str, addr_list_str, addr_list_str_len+1); 
	stack_addr_list_str = tmp_store_str;
	
	while((single_addr_str = strtok_r(stack_addr_list_str, ADDR_LIST_OUTWARD_DELIM, &save_ptr)) != NULL){
		memset(&list_bin_val[layer_addr_level], 0, sizeof(addr_continuous_bin_t));
		ret = __addr_pton(single_addr_str, &list_bin_val[layer_addr_level]);
		if(ret < 0){
			goto fun_exit;
		}
		layer_addr_level++;
		if(layer_addr_level >= MAX_ADDR_EMBED_LAYER_NUM){
			printf("addr_list level too many, max is %d!\n", MAX_ADDR_EMBED_LAYER_NUM);
			goto fun_exit;
		}
		stack_addr_list_str = NULL;
	}

	/* 构建pfather的链接关系 */
	stream_head = create_chain_outward(list_bin_val, layer_addr_level);

#if (0 == IP_PORT_UNION_VERSION)
	/* 修正四元组地址关系, 地址信息实际存储于IP层, 将TCP或UDP层的地址改为ADDR_TYPE_IPV4, 或ADDR_TYPE_IPV6 */
	ret = fix_tuple4_addr(stream_head); 
	if(ret < 0){
		printf("stream_addr_list_pton_outward(): '%s' error!\n", addr_list_str);
		goto err_exit;
	}
#endif	

fun_exit:
	dictator_free(thread_index, tmp_store_str);

	return stream_head;

#if (0 == IP_PORT_UNION_VERSION)	
err_exit:
	dictator_free(thread_index, tmp_store_str);
	return NULL;
#endif	
}

/* 向外向内, "MAC:0x112233445566-0xAABBCCDDEEFF,IP4:10.0.6.1-10.0.6.2,TCP:12345-80" */
const struct streaminfo *stream_addr_list_pton_inward(const char *addr_list_str, int thread_index)
{
	char *tmp_store_str, *stack_addr_list_str;
	int addr_list_str_len;
	addr_continuous_bin_t *list_bin_val = __stream_list_bin_value[thread_index];
	char *save_ptr;
	char *single_addr_str;
	int layer_addr_level = 0, ret;
	struct streaminfo *stream_head = NULL;

	if(NULL == addr_list_str){
		return NULL;
	}

	addr_list_str_len = strlen(addr_list_str);
	if(addr_list_str_len < 5){ /* 5:一个合法地址的最小长度 */
		return NULL;
	}
	tmp_store_str = (char *)dictator_malloc(thread_index, addr_list_str_len+1);
	memcpy(tmp_store_str, addr_list_str, addr_list_str_len+1); 
	stack_addr_list_str = tmp_store_str;
	
	while((single_addr_str = strtok_r(stack_addr_list_str, ADDR_LIST_INWARD_DELIM, &save_ptr)) != NULL){
		memset(&list_bin_val[layer_addr_level], 0, sizeof(addr_continuous_bin_t));
		ret = __addr_pton(single_addr_str, &list_bin_val[layer_addr_level]);
		if(ret < 0){
			goto fun_exit;
		}
		layer_addr_level++;
		if(layer_addr_level >= MAX_ADDR_EMBED_LAYER_NUM){
			printf("addr_list level too many, max is %d!\n", MAX_ADDR_EMBED_LAYER_NUM);
			goto fun_exit;
		}
		stack_addr_list_str = NULL;
	}

	/* 构建pfather的链接关系 */
	stream_head = create_chain_inward(list_bin_val, layer_addr_level);

#if (0 == IP_PORT_UNION_VERSION)
	/* 修正四元组地址关系, 地址信息实际存储于IP层, TCP或UDP层的地址改为ADDR_TYPE_IPV4, 或ADDR_TYPE_IPV6 */
	fix_tuple4_addr(stream_head); 
#endif

fun_exit:
	dictator_free(thread_index, tmp_store_str);

	return stream_head;
}

int stream_addr_list_pton(const char *addr_list_str, void *dst, int size, int thread_index)
{
	const struct streaminfo *stream_addr;
	addr_continuous_bin_t *real_stream_item;
	int tot_len = 0;
	char *save_dst = (char *)dst;

	if(NULL == addr_list_str || size <= 0){
		return -2;
	}

	stream_addr = stream_addr_list_pton_outward(addr_list_str, thread_index);
	if(NULL == stream_addr){
		return -3;
	}

	while(stream_addr){
		if(tot_len + (int)sizeof(addr_continuous_bin_t) > size){
			return -1;
		}
		real_stream_item = (addr_continuous_bin_t *)stream_addr;
		real_stream_item->stream.threadnum = thread_index;
		memcpy(save_dst, real_stream_item, sizeof(addr_continuous_bin_t));
		stream_addr = stream_addr->pfather;
		tot_len += sizeof(addr_continuous_bin_t);
		save_dst += sizeof(addr_continuous_bin_t);
	}

	return tot_len;
}


static int __addr_ip4_n2p_fun(const struct layer_addr *paddr, char *buf, int buf_len)
{
	int len;
	const char *res;
	const struct stream_tuple4_v4 *t4v4 = (const struct stream_tuple4_v4 *)paddr->tuple4_v4;

	res = inet_ntop(AF_INET, &t4v4->saddr, buf, buf_len);
	if(NULL == res){
		buf[0] = '\0';
		return -1;
	}

	len = strlen(buf);
	buf[len] = '-';
	len++;

	res = inet_ntop(AF_INET, &t4v4->daddr, buf+len, buf_len-len);
	if(NULL == res){
		buf[0] = '\0';
		return -1;
	}

	return strlen(buf) + 1;
}

static int __addr_ip6_n2p_fun(const struct layer_addr *paddr, char *buf, int buf_len)
{
	int len;
	const char *res;
	const struct stream_tuple4_v6 *t4v6 = (const struct stream_tuple4_v6 *)paddr->tuple4_v6;

	res = inet_ntop(AF_INET6, t4v6->saddr, buf, buf_len);
	if(NULL == res){
		buf[0] = '\0';
		return -1;
	}

	len = strlen(buf);
	buf[len] = '-';
	len++;

	res = inet_ntop(AF_INET6, t4v6->daddr, buf+len, buf_len-len);
	if(NULL == res){
		buf[0] = '\0';
		return -1;
	}

	return strlen(buf) + 1;
}


static int __addr_tcp_n2p_fun(const struct layer_addr *paddr, char *buf, int buf_len)
{
	const struct stream_tuple4_v4 *t4v4;
	const struct stream_tuple4_v6 *t4v6;
#if IP_PORT_UNION_VERSION	
	char ip_src_str[64], ip_dst_str[64]; /* 同时支持IPv4和IPv6地址字符串模式 */
	const char *res;
#endif	

	if(ADDR_TYPE_IPV4 == paddr->addrtype){
		t4v4 = (const struct stream_tuple4_v4 *)paddr->tuple4_v4;
#if IP_PORT_UNION_VERSION			
		res = inet_ntop(AF_INET, &t4v4->saddr, ip_src_str, 64);
		if(res <= 0){
			return -1;
		}
		res = inet_ntop(AF_INET, &t4v4->daddr, ip_dst_str, 64);
		if(res <= 0){
			return -1;
		}
		snprintf(buf, buf_len, "%u-%u-%s-%s", ntohs(t4v4->source),ntohs(t4v4->dest), ip_src_str, ip_dst_str); 
#else
		snprintf(buf, buf_len, "%u-%u", ntohs(t4v4->source),ntohs(t4v4->dest)); 
#endif
	}else if(ADDR_TYPE_IPV6 == paddr->addrtype){
		t4v6 = (const struct stream_tuple4_v6 *)paddr->tuple4_v6;
#if IP_PORT_UNION_VERSION				
		res = inet_ntop(AF_INET6, t4v6->saddr, ip_src_str, 64);
		if(res <= 0){
			return -1;
		}
		res = inet_ntop(AF_INET6, t4v6->daddr, ip_dst_str, 64);
		if(res <= 0){
			return -1;
		}		
		snprintf(buf, buf_len, "%u-%u-%s-%s", ntohs(t4v6->source),ntohs(t4v6->dest), ip_src_str, ip_dst_str);  
#else
		snprintf(buf, buf_len, "%u-%u", ntohs(t4v6->source),ntohs(t4v6->dest));  
#endif
	}else{
		return -1;
	}
	
	return strlen(buf) + 1;
}


static int __addr_udp_n2p_fun(const struct layer_addr *paddr, char *buf, int buf_len)
{
	/* 功能一样, 复用 */
	return __addr_tcp_n2p_fun(paddr, buf, buf_len);
}

static int __addr_pure_tcp_n2p_fun(const struct layer_addr *paddr, char *buf, int buf_len)
{
	struct layer_addr_tcp *tcp_addr_val = (struct layer_addr_tcp *)paddr->paddr;

	snprintf(buf, buf_len, "%u-%u", ntohs(tcp_addr_val->source),ntohs(tcp_addr_val->dest)); 

	
	return strlen(buf) + 1;
}

static int __addr_pure_udp_n2p_fun(const struct layer_addr *paddr, char *buf, int buf_len)
{

	struct layer_addr_udp *udp_addr_val = (struct layer_addr_udp *)paddr->paddr;

	snprintf(buf, buf_len, "%u-%u", ntohs(udp_addr_val->source),ntohs(udp_addr_val->dest)); 

	return strlen(buf) + 1;
}

static int __addr_vlan_n2p_fun(const struct layer_addr *paddr, char *buf, int buf_len)
{
	const struct layer_addr_vlan *vlan_addr = paddr->vlan;
	const struct mesa_vlan_hdr *vhdr;
	int i;
	unsigned short vlan_id;
	char tmp_buf[32] = {};
	char vlan_addr_string[128] = {};
	
	/* 注意: 可能有非对称vlan的情况 */
	int max_layer_num = vlan_addr->c2s_layer_num > vlan_addr->s2c_layer_num ? vlan_addr->c2s_layer_num:vlan_addr->s2c_layer_num;

	for(i = 0; i < max_layer_num; i++){
		if(vlan_addr->c2s_layer_num >= i+1){
			vhdr = (struct mesa_vlan_hdr *)&vlan_addr->c2s_addr_array[i];
			vlan_id = ntohs(vhdr->pri_cfi_id) & VLAN_ID_MASK;
			snprintf(tmp_buf, 32, "%d", vlan_id);
			strcat(vlan_addr_string, tmp_buf);
		}else{
			strcat(vlan_addr_string, "N/A");
		}
		if(vlan_addr->s2c_layer_num >= i+1){
			vhdr = (struct mesa_vlan_hdr *)&vlan_addr->s2c_addr_array[i];
			vlan_id = ntohs(vhdr->pri_cfi_id) & VLAN_ID_MASK;
			snprintf(tmp_buf, 32, "%d", vlan_id);
			strcat(vlan_addr_string, tmp_buf);
		}else{
			strcat(vlan_addr_string, "-N/A");
		}
		if(i < max_layer_num-1){
			strcat(vlan_addr_string, ",");
		}
	}
	
	int addr_len = strlen(vlan_addr_string);
	if(buf_len <= addr_len + 1){
		return -1;
	}
	strncpy(buf, vlan_addr_string, addr_len + 1);

	return addr_len + 1;
}


static int __addr_mac_n2p_fun(const struct layer_addr *paddr, char *buf, int buf_len)
{
#define MAC_ADDR_STR_LEN		(25+1)
	int i;
	//unsigned char *mac_addr = (unsigned char *)stream->addr.paddr;
	const struct layer_addr_mac *macaddr = (const struct layer_addr_mac *)paddr->paddr;

	if(buf_len <= MAC_ADDR_STR_LEN){
		buf[0]= '\0';
		return -1;
	}

	for(i = 0; i < 6; i++,buf+=2){
		sprintf(buf, "%02x", macaddr->src_addr.h_source[i]);
	}
	*buf = '-';
	buf++;
	//mac_addr += MAC_ADDR_LEN;
	for(i = 0; i < 6; i++,buf+=2){
		sprintf(buf, "%02x", macaddr->src_addr.h_dest[i]);
	}
	*buf = '\0';
	buf++;
	
	return MAC_ADDR_STR_LEN;	
}

static int __addr_mac_in_mac_n2p_fun(const struct layer_addr *paddr, char *in_buf, int buf_len)
{
#define MACINMAC_ADDR_STR_LEN		(strlen("00e0fc030007")*4 + 3) /* 四个MAC字符串, 三个分隔符, 最小缓存长度 */
	int i;
	char *buf = in_buf;
	//unsigned char *mac_addr = (unsigned char *)stream->addr.paddr;
	const struct layer_addr_mac_in_mac *macaddr = (const struct layer_addr_mac_in_mac *)paddr->paddr;

	if(buf_len <= (int)MACINMAC_ADDR_STR_LEN){
		buf[0]= '\0';
		return -1;
	}

	/* 里层MAC在左面 */
	for(i = 0; i < 6; i++, buf+=2){
		sprintf(buf, "%02x", macaddr->inner_src_mac[i]);
	}
	*buf = '-';
	buf++;
	//mac_addr += MAC_ADDR_LEN;
	for(i = 0; i < 6; i++,buf+=2){
		sprintf(buf, "%02x", macaddr->inner_dst_mac[i]);
	}
	
	*buf = ','; /* 分隔符 */
	buf++;
	
	for(i = 0; i < 6; i++, buf+=2){
		sprintf(buf, "%02x", macaddr->outer_src_mac[i]);
	}
	*buf = '-';
	buf++;
	//mac_addr += MAC_ADDR_LEN;
	for(i = 0; i < 6; i++,buf+=2){
		sprintf(buf, "%02x", macaddr->outer_dst_mac[i]);
	}	
	*buf = '\0';
	buf++;
	
	return strlen(in_buf) + 1;	
}

static int __addr_gre_n2p_fun(const struct layer_addr *paddr, char *buf, int buf_len)
{
#define __GRE_ADDR_STRING		"NULL"

	int addr_len = strlen(__GRE_ADDR_STRING);
	if(buf_len <= addr_len + 1){
		return -1;
	}
	strncpy(buf, __GRE_ADDR_STRING, addr_len + 1);

	return addr_len + 1;
}

/*
	格式说明:
		每层mpls地址使用src-dst表示, 多层之间的mpls使用,分割, 
		例如:
		<1-2>
		<1-2,3-4,5-6>
*/
static int __addr_mpls_n2p_fun(const struct layer_addr *paddr, char *buf, int buf_len)
{
	const struct layer_addr_mpls *mpls_addr = paddr->mpls;
	const struct mesa_mpls_hdr *net_mpls_hdr;
	int i;
	int mpls_label;
	char tmp_buf[32];
	/* 注意有非对称mpls的情况 */
	int max_layer_num = mpls_addr->c2s_layer_num > mpls_addr->s2c_layer_num ? mpls_addr->c2s_layer_num:mpls_addr->s2c_layer_num;

	char mpls_addr_string[128] = {};

	for(i = 0; i < max_layer_num; i++){
		if(mpls_addr->c2s_layer_num >= i+1){
			//mpls_label = 0;
			//net_mpls_hdr = (struct mesa_mpls_hdr *)&mpls_addr->src_mpls_pkt[i];
			//mpls_label = (net_mpls_hdr->mpls_label_low<<12) | (net_mpls_hdr->mpls_label_mid<<4) | net_mpls_hdr->mpls_label_high; /* network order */
			snprintf(tmp_buf, 32, "%d", ntohl(mpls_addr->c2s_addr_array[i].label));
			strcat(mpls_addr_string, tmp_buf);
		}else{
			strcat(mpls_addr_string, "N/A");
		}
		if(mpls_addr->s2c_layer_num >= i+1){
			//mpls_label = 0;
			//net_mpls_hdr = (struct mesa_mpls_hdr *)&mpls_addr->dest_mpls_pkt[i];
			//mpls_label = (net_mpls_hdr->mpls_label_low<<12) | (net_mpls_hdr->mpls_label_mid<<4) | net_mpls_hdr->mpls_label_high; /* network order */
			snprintf(tmp_buf, 32, "-%d", ntohl(mpls_addr->s2c_addr_array[i].label));
			strcat(mpls_addr_string, tmp_buf);
		}else{
			strcat(mpls_addr_string, "-N/A");
		}
		if(i < max_layer_num-1){
			strcat(mpls_addr_string, ",");
		}
	}
	
	int addr_len = strlen(mpls_addr_string);
	if(buf_len <= addr_len + 1){
		return -1;
	}
	strncpy(buf, mpls_addr_string, addr_len + 1);

	return addr_len + 1;
}

static int __addr_pppoe_n2p_fun(const struct layer_addr *paddr, char *buf, int buf_len)
{
#define __PPPOE_ADDR_STRING		"NULL"

	int addr_len = strlen(__PPPOE_ADDR_STRING);
	if(buf_len <= addr_len + 1){
		return -1;
	}
	strncpy(buf, __PPPOE_ADDR_STRING, addr_len + 1);

	return addr_len + 1;
}

static int __addr_l2tp_n2p_fun(const struct layer_addr *paddr, char *buf, int buf_len)
{
#define __L2TP_ADDR_STRING		"NULL"

	int addr_len = strlen(__L2TP_ADDR_STRING);
	if(buf_len <= addr_len + 1){
		return -1;
	}
	strncpy(buf, __L2TP_ADDR_STRING, addr_len + 1);

	return addr_len + 1;
}

static int __addr_gtp_n2p_fun(const struct layer_addr *paddr, char *buf, int buf_len)
{
	int addr_len;
	//const struct gtp_hdr *src_net_hdr = (struct gtp_hdr *)&paddr->gtp->source;
	//const struct gtp_hdr *dst_net_hdr = (struct gtp_hdr *)&paddr->gtp->dest;
	
	addr_len = snprintf(buf, buf_len, "%u-%u", ntohl(paddr->gtp->teid_c2s), ntohl(paddr->gtp->teid_s2c));

	return addr_len + 1;
}

static int __addr_arp_n2p_fun(const struct layer_addr *paddr, char *buf, int buf_len)
{
#define __ARP_ADDR_STRING		"NULL"

	int addr_len = strlen(__ARP_ADDR_STRING);
	if(buf_len <= addr_len + 1){
		return -1;
	}
	strncpy(buf, __ARP_ADDR_STRING, addr_len + 1);

	return addr_len + 1;
}

static int __addr_ppp_n2p_fun(const struct layer_addr *paddr, char *buf, int buf_len)
{

#define __PPP_ADDR_STRING               "NULL"
	
	int addr_len = strlen(__PPP_ADDR_STRING);
	if(buf_len <= addr_len + 1){
			return -1;
	}
	strncpy(buf, __PPP_ADDR_STRING, addr_len + 1);

	return addr_len + 1;
}

static int __addr_pptp_n2p_fun(const struct layer_addr *paddr, char *buf, int buf_len)
{	
	const struct layer_addr_pptp *pptpaddr = paddr->pptp;
	int addr_len;

	addr_len = snprintf(buf, buf_len, "%u-%u", ntohs(pptpaddr->C2S_call_id), ntohs(pptpaddr->S2C_call_id));
	if(addr_len < 0){
		return -1;
	}
	return addr_len + 1;
}

static int __addr_socks_n2p_fun(const struct layer_addr *paddr, char *buf, int buf_len)
{
	const struct stream_tuple4_v4 *t4v4;
	const struct stream_tuple4_v6 *t4v6;
#if IP_PORT_UNION_VERSION	
	char ip_src_str[64], ip_dst_str[64]; /* 同时支持IPv4和IPv6地址字符串模式 */
	const char *res;
#endif	

	if(ADDR_TYPE_IPV4 == paddr->addrtype){
		t4v4 = (const struct stream_tuple4_v4 *)paddr->tuple4_v4;
#if IP_PORT_UNION_VERSION			
		res = inet_ntop(AF_INET, &t4v4->saddr, ip_src_str, 64);
		if(res <= 0){
			return -1;
		}
		res = inet_ntop(AF_INET, &t4v4->daddr, ip_dst_str, 64);
		if(res <= 0){
			return -1;
		}
		snprintf(buf, buf_len, "%u-%u-%s-%s", ntohs(t4v4->source),ntohs(t4v4->dest), ip_src_str, ip_dst_str); 
#else
		snprintf(buf, buf_len, "%u-%u", ntohs(t4v4->source),ntohs(t4v4->dest)); 
#endif
	}else if(ADDR_TYPE_IPV6 == paddr->addrtype){
		t4v6 = (const struct stream_tuple4_v6 *)paddr->tuple4_v6;
#if IP_PORT_UNION_VERSION				
		res = inet_ntop(AF_INET6, t4v6->saddr, ip_src_str, 64);
		if(res <= 0){
			return -1;
		}
		res = inet_ntop(AF_INET6, t4v6->daddr, ip_dst_str, 64);
		if(res <= 0){
			return -1;
		}		
		snprintf(buf, buf_len, "%u-%u-%s-%s", ntohs(t4v6->source),ntohs(t4v6->dest), ip_src_str, ip_dst_str);  
#else
		snprintf(buf, buf_len, "%u-%u", ntohs(t4v6->source),ntohs(t4v6->dest));  
#endif
	}else{
		return -1;
	}
	
	return strlen(buf) + 1;
}

/* 暂时复用tcp的n2p函数 */
static int __addr_openvpn_n2p_fun(const struct layer_addr *paddr, char *buf, int buf_len)
{
	const struct stream_tuple4_v4 *t4v4;
	const struct stream_tuple4_v6 *t4v6;
#if IP_PORT_UNION_VERSION	
	char ip_src_str[64], ip_dst_str[64]; /* 同时支持IPv4和IPv6地址字符串模式 */
	const char *res;
#endif	

	if(ADDR_TYPE_IPV4 == paddr->addrtype){
		t4v4 = (const struct stream_tuple4_v4 *)paddr->tuple4_v4;
#if IP_PORT_UNION_VERSION			
		res = inet_ntop(AF_INET, &t4v4->saddr, ip_src_str, 64);
		if(res <= 0){
			return -1;
		}
		res = inet_ntop(AF_INET, &t4v4->daddr, ip_dst_str, 64);
		if(res <= 0){
			return -1;
		}
		snprintf(buf, buf_len, "%u-%u-%s-%s", ntohs(t4v4->source),ntohs(t4v4->dest), ip_src_str, ip_dst_str); 
#else
		snprintf(buf, buf_len, "%u-%u", ntohs(t4v4->source),ntohs(t4v4->dest)); 
#endif
	}else if(ADDR_TYPE_IPV6 == paddr->addrtype){
		t4v6 = (const struct stream_tuple4_v6 *)paddr->tuple4_v6;
#if IP_PORT_UNION_VERSION				
		res = inet_ntop(AF_INET6, t4v6->saddr, ip_src_str, 64);
		if(res <= 0){
			return -1;
		}
		res = inet_ntop(AF_INET6, t4v6->daddr, ip_dst_str, 64);
		if(res <= 0){
			return -1;
		}		
		snprintf(buf, buf_len, "%u-%u-%s-%s", ntohs(t4v6->source),ntohs(t4v6->dest), ip_src_str, ip_dst_str);  
#else
		snprintf(buf, buf_len, "%u-%u", ntohs(t4v6->source),ntohs(t4v6->dest));  
#endif
	}else{
		return -1;
	}
	
	return strlen(buf) + 1;
}


static int __addr_vxlan_n2p_fun(const struct layer_addr *paddr, char *buf, int buf_len)
{
	const struct layer_addr_vxlan *vxlan_addr = paddr->vxlan;
	int addr_len;

	/* 按vxlan结构体顺序排列 */
	snprintf(buf, buf_len, "%u-%u-%u-%u", vxlan_addr->vlan_id, vxlan_addr->dir, vxlan_addr->link_id, vxlan_addr->link_type);

	addr_len = strlen(buf) + 1; //add EOF

	return addr_len;
}

static int __addr_http_proxy_n2p_fun(const struct layer_addr *paddr, char *buf, int buf_len)
{
#define __HTTPPRO_ADDR_STRING		"NULL"

	int addr_len = strlen(__HTTPPRO_ADDR_STRING);
	if(buf_len <= addr_len + 1){
		return -1;
	}
	strncpy(buf, __HTTPPRO_ADDR_STRING, addr_len + 1);

	return addr_len + 1;
}


static const char *addr_and_stream_type_to_prefix(UCHAR stream_type, enum addr_type_t layer_type)
{
	int i;
	if(layer_type <=  __ADDR_TYPE_INIT || layer_type >= __ADDR_TYPE_MAX){
		return NULL;
	}

	for(i = __ADDR_TYPE_INIT+1; G_ADDR_CONVERT_HANDLE[i].addr_type_bin!= __ADDR_TYPE_MAX; i++){
		if((G_ADDR_CONVERT_HANDLE[i].addr_type_bin == layer_type)
		 &&(G_ADDR_CONVERT_HANDLE[i].stream_type == stream_type)){
			return G_ADDR_CONVERT_HANDLE[i].addr_type_prefix;
		}
	}

	return NULL;
}

/* 转换后的结果存储每个线程的独立全局变量中, 是线程安全的, 但不可递归使用 */
static const char *__layer_addr_ntop (const struct streaminfo *stream, int thread_index)
{
	/* 像GRE, PPPOE类地址直接打印原始包即可, "0xAABBCC..." */
	//const char *prefix = addr_type_to_prefix((enum addr_type_t)stream->addr.addrtype);
	const char *prefix = addr_and_stream_type_to_prefix(stream->type, (enum addr_type_t)stream->addr.addrtype);
	int i, prefix_len, addr_single_len = -1;
	char *result = __addr_ntop_string[thread_index];
	
	if(NULL == prefix){
		return NULL;
	}
	prefix_len = snprintf(result, MAX_ADDR_TYPE_STRING_LEN, "%s<", prefix);

	for(i = 0; G_ADDR_CONVERT_HANDLE[i].addr_type_bin != __ADDR_TYPE_MAX; i++){
		if((G_ADDR_CONVERT_HANDLE[i].addr_type_bin == stream->addr.addrtype)
		  &&G_ADDR_CONVERT_HANDLE[i].stream_type == stream->type){
			addr_single_len = G_ADDR_CONVERT_HANDLE[i].addr_n2p_fun(
						&stream->addr, result+prefix_len, MAX_ADDR_LIST_STRING_LEN-prefix_len);
			break;			
		}
	}	
			
	if(addr_single_len < 0){
		return NULL;
	}

	/* ntop的地址长度已经包括了'\0', 此处需要先减1 */
	result[prefix_len +  addr_single_len -1 ] = '>'; /* 地址结束标志 */
	result[prefix_len +  addr_single_len] = '\0';
	
	return result;
}

/* 线程安全可重入版本 */
const char *__layer_addr_ntop_r (const struct streaminfo *stream, char *dst, int size, int thread_index)
{
	const char *result = __layer_addr_ntop(stream, thread_index);
	int addr_len = strlen(result) + 1;
	if(addr_len > size){
		return NULL;
	}

	strncpy(dst, result, addr_len);

	return result;
}


/* 由内向外(平台默认模式), "IPv4_TCP<2196-80-222.75.165.42-209.34.91.23>|MAC<000100032101-00e0fc030002>" */
const char *stream_addr_list_ntop_outward(const struct streaminfo *pstream)
{
	const struct streaminfo *ptmp = pstream;;
	const struct streaminfo *pfather;
	char *result = __stream_list_string[pstream->threadnum];
	int addr_tot_len = 0, addr_single_len = 0;
	const char *addr_single_str;
	
	while(ptmp){
		pfather = ptmp->pfather;
		addr_single_str = __layer_addr_ntop(ptmp, pstream->threadnum);
		if(NULL == addr_single_str){
			return NULL;
		}
		addr_single_len = snprintf(result + addr_tot_len, MAX_ADDR_LIST_STRING_LEN-addr_tot_len,
							 "%s", addr_single_str);
		if(addr_single_len >= MAX_ADDR_LIST_STRING_LEN-addr_tot_len){
			sapp_runtime_log(RLOG_LV_INFO, "stream_addr_list_ntop_outward(), no enough space to convert string!\n");
			return NULL;
		}
		addr_tot_len += addr_single_len;		
		result[addr_tot_len] = *(ADDR_LIST_OUTWARD_DELIM); /* 分隔符 */
		addr_tot_len ++;
		ptmp = pfather;
	}

	result[addr_tot_len-1] = '\0'; /* EOF */
	addr_tot_len--;
		
	return result;
}

/* 由内向外(平台默认模式), "TCP:12345-80,IP4:10.0.6.1-10.0.6.2,MAC:0x112233445566-0xAABBCCDDEEFF" */
const char *stream_addr_list_ntop_outward_r(const struct streaminfo *pstream, char *dst, int size)
{
	/* 平台必须先将结果暂存于内部变量, 再copy到dst空间, 其实和调用者自行实现差不多, TODO吧 */
	return NULL;
}


int stream_addr_list_ntop(const struct streaminfo *pstream, char *dst, int size)
{
	const char *addr_str;
	int addr_str_len;

	if(NULL == dst){
		return -2;
	}

	addr_str = stream_addr_list_ntop_outward(pstream);
	if(NULL == addr_str){
		return -3;
	}

	addr_str_len = strlen(addr_str) + 1;
	if(addr_str_len > size){
		return -1;
	}

	memcpy(dst, addr_str, addr_str_len);

	return addr_str_len;
}

/* return value:
	地址字符串长度.
*/
static int stream_addr_list_ntop_inward_recur(const struct streaminfo *pstream, char *result)
{
	const char *addr_single_str;
	int addr_tot_len = 0, addr_single_len = 0;
	
	if(pstream->pfather){
		addr_tot_len = stream_addr_list_ntop_inward_recur(pstream->pfather, result);
		if(addr_tot_len < 0){
			return -1; /* error */
		}
	}

	addr_single_str = __layer_addr_ntop(pstream, pstream->threadnum);
	if(NULL == addr_single_str){
		return -1;
	}

	addr_single_len = snprintf(result + addr_tot_len, MAX_ADDR_LIST_STRING_LEN-addr_tot_len,
						 "%s", addr_single_str);
	result[addr_single_len + addr_tot_len] = *(ADDR_LIST_INWARD_DELIM);
	
	return addr_single_len + addr_tot_len + 1; /* plus delim ">" length */
}


/* 由外向内, "MAC:0x112233445566-0xAABBCCDDEEFF>IP4:10.0.6.1-10.0.6.2>TCP:12345-80"*/
const char *stream_addr_list_ntop_inward(const struct streaminfo *pstream)
{
	/* 平台stream地址链存储是由内向外的, 得用递归 */
	int ret;

	ret = stream_addr_list_ntop_inward_recur(pstream, __stream_list_string[pstream->threadnum]);
	if(ret < 0){
		return NULL;
	}
	__stream_list_string[pstream->threadnum][ret-1] = '\0'; /* del last delim ">" */

	return __stream_list_string[pstream->threadnum];
}

/* 由外向内, "MAC:0x112233445566-0xAABBCCDDEEFF>IP4:10.0.6.1-10.0.6.2>TCP:12345-80"*/
const char *stream_addr_list_ntop_inward_r(const struct streaminfo *pstream, char *dst, int size)
{
	/* 平台必须先将结果暂存于内部变量, 再copy到dst空间, 其实和调用者自行实现差不多, TODO吧 */

	return 0;
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


static char __g_layer_addr_ntop_buf[MAX_THREAD_NUM][MAX_ADDR_LIST_STRING_LEN];
const char *layer_addr_ntop(const struct streaminfo *pstream)
{
	int i, ret;
	if(NULL == pstream){
		return NULL;
	}

	int (*conv_f)(const struct layer_addr *paddr, char *buf, int buf_len) = NULL;

	for(i = __ADDR_TYPE_INIT+1; G_ADDR_CONVERT_HANDLE[i].addr_type_bin!= __ADDR_TYPE_MAX; i++){
		if((G_ADDR_CONVERT_HANDLE[i].addr_type_bin == pstream->addr.addrtype)
		 &&(G_ADDR_CONVERT_HANDLE[i].stream_type == pstream->type)){
			conv_f = G_ADDR_CONVERT_HANDLE[i].addr_n2p_fun;
			break;
		}
	}

	if(conv_f != NULL){
		ret = conv_f(&pstream->addr, __g_layer_addr_ntop_buf[pstream->threadnum], MAX_ADDR_LIST_STRING_LEN);
		if(ret > 0){
			return __g_layer_addr_ntop_buf[pstream->threadnum];
		}
	}
	
	return NULL;
}


char *layer_addr_ntop_r(const struct streaminfo *pstream, char *out_buf, int out_buf_len)
{
	int i, ret, addr_str_len;
	char tmp_buf[MAX_ADDR_LIST_STRING_LEN]=" ";
	
	if((NULL == pstream) || (NULL == out_buf)){
		return NULL;
	}

	int (*conv_f)(const struct layer_addr *paddr, char *buf, int buf_len) = NULL;

	for(i = __ADDR_TYPE_INIT+1; G_ADDR_CONVERT_HANDLE[i].addr_type_bin!= __ADDR_TYPE_MAX; i++){
		if((G_ADDR_CONVERT_HANDLE[i].addr_type_bin == pstream->addr.addrtype)
		 &&(G_ADDR_CONVERT_HANDLE[i].stream_type == pstream->type)){
			conv_f = G_ADDR_CONVERT_HANDLE[i].addr_n2p_fun;
			break;
		}
	}

	if(conv_f != NULL){
		ret = conv_f(&pstream->addr, tmp_buf, MAX_ADDR_LIST_STRING_LEN);
		if(ret > 0){
			addr_str_len = strlen(tmp_buf) + 1; /* with EOF */
			if(addr_str_len <= out_buf_len){
				memcpy(out_buf, tmp_buf, addr_str_len);
				return out_buf;
			}
		}
	}

	return NULL;
}

const char *layer_addr_prefix_ntop(const struct streaminfo *pstream)
{
	int i;
	const char *addr_type_str = NULL;
	
	if(NULL == pstream){
		return NULL;
	}

	for(i = __ADDR_TYPE_INIT+1; G_ADDR_CONVERT_HANDLE[i].addr_type_bin!= __ADDR_TYPE_MAX; i++){
		if((G_ADDR_CONVERT_HANDLE[i].addr_type_bin == pstream->addr.addrtype)
		 &&(G_ADDR_CONVERT_HANDLE[i].stream_type == pstream->type)){
			addr_type_str = G_ADDR_CONVERT_HANDLE[i].addr_type_prefix;
			break;
		}
	}

	if(NULL == addr_type_str){
		return "Unknown";
	}
	
	return addr_type_str;
}

/* ipv4, ipv6, ethernet,vlan, arp, gre, mpls, pppoe, tcp, udp, l2tp, ppp, pptp, gtp */
enum addr_type_t addr_type_abbreviation_pton(const char *addr_type_abbreviation)
{
	int i;
	enum addr_type_t addrtype = __ADDR_TYPE_MAX;

	for(i = __ADDR_TYPE_INIT+1; G_ADDR_CONVERT_HANDLE[i].addr_type_bin!= __ADDR_TYPE_MAX; i++){
		if((strncasecmp(addr_type_abbreviation, G_ADDR_CONVERT_HANDLE[i].addr_type_string_abbreviation, strlen(addr_type_abbreviation)) == 0)
		&& (strncasecmp(addr_type_abbreviation, G_ADDR_CONVERT_HANDLE[i].addr_type_string_abbreviation, strlen(G_ADDR_CONVERT_HANDLE[i].addr_type_string_abbreviation)) == 0)){
			addrtype =  G_ADDR_CONVERT_HANDLE[i].addr_type_bin;
			break;
		}
	}

	return addrtype;	
}

const char *addr_type_abbreviation_ntop(enum addr_type_t addrtype)
{
	int i;
	const char *addr_abbr_str = "unknown";

	for(i = __ADDR_TYPE_INIT+1; G_ADDR_CONVERT_HANDLE[i].addr_type_bin!= __ADDR_TYPE_MAX; i++){
		if(G_ADDR_CONVERT_HANDLE[i].addr_type_bin == addrtype){
			addr_abbr_str =	G_ADDR_CONVERT_HANDLE[i].addr_type_string_abbreviation;
			break;
		}
	}

	return addr_abbr_str;	
}


#ifdef __cplusplus
}
#endif

