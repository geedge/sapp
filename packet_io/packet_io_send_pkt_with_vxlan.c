#include "packet_io.h"
#include "packet_io_internal.h"
#include "stream_manage.h"
#include "stream_internal.h"
#include "mesa_net.h"
#include "sendpacket.h"
#include <MESA_handle_logger.h>
#include <stdio.h>
#include <unistd.h>
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <sched.h>


#ifdef __cplusplus
extern "C" {
#endif


#define SMAC_ROUTE_DIR_MASK	(0x1)		/* 链路方向位 */
#define SMAC_LINK_ID_MASK		(0xE)		/* 链路ID */
#define SMAC_DEV_SEQ_MASK	(0x3F0)		/* 设备编号 */
#define SMAC_REGION_SEQ_MASK	(0x7C00)		/* 局点编号 */
#define SMAC_ENCAP_TYPE_MASK	(0xF0000)	/* 原始二层封装 */

#define SMAC_EXTRACT_ROUTE_DIR(n)  ((unsigned char)(n & SMAC_ROUTE_DIR_MASK))
#define SMAC_EXTRACT_LINK_ID(n)  	((unsigned char)((n & SMAC_LINK_ID_MASK) >> 1))
#define SMAC_EXTRACT_DEV_SEQ(n)  	((unsigned char)((n & SMAC_DEV_SEQ_MASK) >> 4))
#define SMAC_EXTRACT_REGION_SEQ(n)  ((unsigned char)((n & SMAC_REGION_SEQ_MASK) >> 10))
#define SMAC_EXTRACT_ENCAP_TYPE(n)  ((unsigned char)((n & SMAC_ENCAP_TYPE_MASK) >>16))


extern UINT64 MESA_rand_range(UINT64 start, UINT64 end);

/* 8字节大小端转换 */
static inline void sapp_ntoh_8byte(char *out, const char *in)
{
	out[0]	= in[7];
	out[1]	= in[6];
	out[2]	= in[5];
	out[3]	= in[4];
	out[4]	= in[3];
	out[5]	= in[2];
	out[6]	= in[1];
	out[7]	= in[0];
}

void packet_extract_para_from_mac_addr(const struct layer_addr_mac_in_mac *mimac,  struct pangu_mac_in_mac_mem_hdr *mim_mem_hdr)
{
	unsigned long long tmp_num_net = 0;
	unsigned long long tmp_num_host = 0;

	memcpy(&tmp_num_net, mimac->outer_src_mac, MAC_ADDR_LEN);
	tmp_num_net &= 0xFFFFFFFFFFFFUL; /* 清空最高两个字节 */

	sapp_ntoh_8byte((char *)&tmp_num_host, (char *)&tmp_num_net);

	mim_mem_hdr->route_dir = SMAC_EXTRACT_ROUTE_DIR(tmp_num_host);
	mim_mem_hdr->link_id = SMAC_EXTRACT_LINK_ID(tmp_num_host);
	mim_mem_hdr->dev_seq = SMAC_EXTRACT_DEV_SEQ(tmp_num_host);
	mim_mem_hdr->region_seq = SMAC_EXTRACT_REGION_SEQ(tmp_num_host);
	mim_mem_hdr->encap_type = SMAC_EXTRACT_ENCAP_TYPE(tmp_num_host);
}


int packet_io_send_pkt_region_dev_id_cfg_parse(void)
{
	return 0;
}


/*
	data指向真实外网数据包的IP头部;
*/
int packet_io_send_fake_pkt_with_vxlan(MESA_send_handle *send_handle, enum addr_type_t addrtype, 
	char *raw_data, int datalen, int dir_reverse,char *feedback_buf, int *feedback_buf_len)
{
	const struct streaminfo_private *pstrem_pr =  (const struct streaminfo_private *)send_handle->user_arg;
	const struct streaminfo *pstream = (const struct streaminfo *)send_handle->user_arg;
	vxlan_header_t *vxlan_hdr;
	struct pangu_mac_in_mac_mem_hdr mim_mem_hdr;
	struct mesa_ethernet_hdr *inner_eth_hdr;
	struct mesa_udp_hdr *udp_hdr;
	struct mesa_ip4_hdr *ip4_hdr;
	int ret;
	struct sockaddr_in sock_addr_v4;
	char *data = raw_data;

	while(pstream->pfather != NULL){
		pstream = pstream->pfather; /* seek to the lowest layer */
	}

	data -= sizeof(struct mesa_ethernet_hdr);
	inner_eth_hdr = (struct mesa_ethernet_hdr *)data;

	if(dir_reverse){ /* 当前发包方向与流创建时的地址是反向的, 即流结构体的四元组: sip=1.1.1.1, dip=2.2.2.2, 当前想发送的包sip=2.2.2.2, dip=1.1.1.1 */
		memcpy(inner_eth_hdr->ether_shost, pstream->addr.mimac->inner_dst_mac, MAC_ADDR_LEN);
		memcpy(inner_eth_hdr->ether_dhost, pstream->addr.mimac->inner_src_mac, MAC_ADDR_LEN);
	}else{
		memcpy(inner_eth_hdr->ether_shost, pstream->addr.mimac->inner_src_mac, MAC_ADDR_LEN);
		memcpy(inner_eth_hdr->ether_dhost, pstream->addr.mimac->inner_dst_mac, MAC_ADDR_LEN);
	}

	if(ADDR_TYPE_IPV4 == addrtype){
		inner_eth_hdr->ether_type = htons(ETH_P_IP);
	}else if(ADDR_TYPE_IPV6 == addrtype){
		inner_eth_hdr->ether_type = htons(ETH_P_IPV6);
	}else{
		assert(0); /* TODO */
	}
	
	data -= sizeof(vxlan_header_t);

	vxlan_hdr = (vxlan_header_t *)data;

	memset(vxlan_hdr, 0, sizeof(vxlan_header_t));
	packet_extract_para_from_mac_addr(pstream->addr.mimac, &mim_mem_hdr);

	vxlan_hdr->link_id = mim_mem_hdr.link_id;
	vxlan_hdr->link_layer_type = mim_mem_hdr.encap_type;

	/* 发包时, vxlan头部的vlan_id不关心 */

	if(dir_reverse){ /* 当前发包方向与流创建时的地址是反向的, 即流结构体的四元组: sip=1.1.1.1, dip=2.2.2.2, 当前想发送的包sip=2.2.2.2, dip=1.1.1.1 */
		vxlan_hdr->dir = mim_mem_hdr.route_dir ^ 1;
	}else{
		vxlan_hdr->dir = mim_mem_hdr.route_dir;
	}

	data -= sizeof(struct mesa_udp_hdr);
	udp_hdr = (struct mesa_udp_hdr *)data;

	udp_hdr->uh_sport = htons(4789);
	udp_hdr->uh_dport = htons(4789);
	udp_hdr->uh_ulen = htons(datalen + sizeof(vxlan_header_t) + sizeof(struct mesa_udp_hdr));
	udp_hdr->uh_sum = 0;

	data -= sizeof(struct mesa_ip4_hdr);
	ip4_hdr = (struct mesa_ip4_hdr *)data;

	ip4_hdr->ip_v = 4;
	ip4_hdr->ip_hl = 5;
	ip4_hdr->ip_tos = 0;
	ip4_hdr->ip_len = htons(datalen + sizeof(vxlan_header_t) + sizeof(struct mesa_udp_hdr) + sizeof(struct mesa_ip4_hdr));
	ip4_hdr->ip_off = 0;
	ip4_hdr->ip_id = MESA_rand_range(10000, 60000);
	ip4_hdr->ip_ttl = MESA_rand_range(64, 128);
	ip4_hdr->ip_p = IPPROTO_UDP;
	ip4_hdr->ip_dst.s_addr = 0xC906000A;
	ip4_hdr->ip_src.s_addr = 0xE506000A; 

	sock_addr_v4.sin_family = AF_INET;
	sock_addr_v4.sin_addr.s_addr = ip4_hdr->ip_dst.s_addr;

	ret = sendto(send_handle->raw_ipv4_fd, data, datalen + sizeof(vxlan_header_t) + sizeof(struct mesa_udp_hdr) + sizeof(struct mesa_ip4_hdr), 0,
				(struct sockaddr *)&sock_addr_v4, sizeof(struct sockaddr));

	return ret;
}

#ifdef __cplusplus
}
#endif
