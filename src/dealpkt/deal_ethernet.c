#ifdef __cplusplus
extern "C" {
#endif

#include "sapp_api.h"
#include "sapp_private_api.h"


extern int g_skip_ethernet_layer_sw;

static inline void set_mac_addr(struct layer_addr_mac *addr, const struct mesa_ethernet_hdr *p_eth_hdr)
{
	/* 收到包时, 地址都临时存储于src_addr内 */
	memcpy(&(addr->src_addr.h_source), &(p_eth_hdr->ether_shost[0]), ETHER_ADDR_LEN);
	memcpy(&(addr->src_addr.h_dest), &(p_eth_hdr->ether_dhost[0]), ETHER_ADDR_LEN);

	memset(&addr->dst_addr, 0, sizeof(struct ethhdr));
}


static inline int should_create_empty_mpls_layer_for_symmetric(const struct streaminfo *pstream, unsigned short next_eth_type)
{
	const struct streaminfo_private *pstream_pr = (const struct streaminfo_private *)pstream;
	int this_layer_type = (int)ADDR_TYPE_MAC;
	int this_layer_index = pstream_pr->layer_index;
	int next_layer_index = pstream_pr->layer_index + 1;
	int next_layer_addrtype;

	next_layer_addrtype = ethernet_protocol_to_net_layer(next_eth_type);
	if(unlikely(next_layer_addrtype <= __ADDR_TYPE_INIT || next_layer_addrtype >= __ADDR_TYPE_MAX)){
		return 0;
	}

	if(g_asymmetric_presence_layer_set[ADDR_TYPE_MPLS].is_asymmetric_layer != 0){
		if((g_asymmetric_presence_layer_set[ADDR_TYPE_MPLS].under_layer.layer_type_index[this_layer_type][this_layer_index] != 0)
		&& (g_asymmetric_presence_layer_set[ADDR_TYPE_MPLS].upper_layer.layer_type_index[next_layer_addrtype][next_layer_index] != 0)){
			return 1;
		}
	}

	return 0;
}

int eth_entry(struct streaminfo_private *fstream_pr, const void *this_layer_hdr,int thread_num, 
			unsigned char dir, const raw_pkt_t *raw_pkt, int offset_to_raw_pkt_hdr)
{
	int ret = PASS;
	const  unsigned char *next_layer_data = (const unsigned char *)this_layer_hdr + sizeof(struct mesa_ethernet_hdr);
	const struct mesa_ethernet_hdr *p_eth_hdr = (const struct mesa_ethernet_hdr *)this_layer_hdr;
	struct layer_addr_mac addr;
	unsigned short eth_type = ntohs(p_eth_hdr->ether_type); 
	int next_layer_offset;
	struct streamindex tmp_index;
	struct streamindex *ptmp;
	struct streaminfo_private *pstream_pr;
	struct streaminfo *pstream;
	sapp_gval_mthread_sys_stat_t *local_sys_stat = &sapp_global_val->mthread_volatile[thread_num]->sys_stat;

	if(NET_CONN_SERIAL_GDEV == g_topology_mode){
		if(unlikely(sapp_identify_broad_multicast_pkt(this_layer_hdr, raw_pkt) != 0)){
			local_sys_stat->count[SAPP_STAT_DROP_ETHERNET]++;
			local_sys_stat->length[SAPP_STAT_DROP_ETHERNET]+=raw_pkt->raw_pkt_len;
			return DROP;
		}
	}

	if(unlikely(0 == g_skip_ethernet_layer_sw)){
		ptmp = &tmp_index;
		pstream_pr = &ptmp->stream;
		pstream = &pstream_pr->stream_public;
		next_layer_offset = offset_to_raw_pkt_hdr + sizeof(struct mesa_ethernet_hdr);

		memset(ptmp, 0, sizeof(struct streamindex));
		set_mac_addr(&addr, p_eth_hdr);
		pstream->addr.mac = (struct layer_addr_mac *)&addr;
		pstream->addr.addrlen = sizeof(struct layer_addr_mac);
		pstream->addr.addrtype = ADDR_TYPE_MAC;
		pstream_pr->addr_use_as_hash = 0;
		//ptmp->stream.p_layer_header = this_layer_hdr;
		//ptmp->stream.offset_to_raw_pkt_hdr = (char *)this_layer_hdr - (char *)raw_pkt->raw_pkt_data;
		pstream_pr->offset_to_raw_pkt_hdr = offset_to_raw_pkt_hdr;
		pstream_pr->raw_pkt = raw_pkt; /* 2014-12-30 lijia add */

		pstream->pfather = (struct streaminfo *)fstream_pr;
		pstream->type = STREAM_TYPE_NON;
		pstream->routedir = dir;
		pstream->threadnum = thread_num;
		/* LiJia add, 人为定义一个方向, 认为源地址大的作为Client端 */
		if(memcmp(p_eth_hdr->ether_shost, p_eth_hdr->ether_dhost, ETHER_ADDR_LEN) >= 0){
			pstream_pr->layer_dir = 1;
			pstream->curdir = DIR_C2S;
		}else{
			pstream_pr->layer_dir = 0;
			pstream->curdir = DIR_S2C;
		}		

		local_sys_stat->count[SAPP_STAT_RCV_ETHERNET]++;
		local_sys_stat->length[SAPP_STAT_RCV_ETHERNET] += (unsigned long long)raw_pkt->raw_pkt_len;
		if(dir == sapp_global_val->config.packet_io.inbound_route_dir){
			local_sys_stat->count[SAPP_STAT_ETH_INBOUND]++;
			local_sys_stat->length[SAPP_STAT_ETH_INBOUND] += (unsigned long long)raw_pkt->raw_pkt_len;
		}else{
			local_sys_stat->count[SAPP_STAT_ETH_OUTBOUND]++;
			local_sys_stat->length[SAPP_STAT_ETH_OUTBOUND] += (unsigned long long)raw_pkt->raw_pkt_len;
		}

		if(NULL == fstream_pr){
			pstream_pr->layer_index = 0; /* first layer, index start from 0 */
		}else{
			if(unlikely(fstream_pr->layer_index >= SAPP_SUPPORT_LAYER_NUM_MAX)){
				local_sys_stat->count[SAPP_STAT_DROP_ETHERNET]++;
				sapp_runtime_log(RLOG_LV_INFO, "eth_entry: layer index more than:%d", fstream_pr->layer_index);
				return PASS;
			}
			pstream_pr->layer_index = fstream_pr->layer_index + 1;
		}
		if(g_asymmetric_addr_layer_set.layer_type_index[ADDR_TYPE_MAC][pstream_pr->layer_index] != 0){
			pstream_pr->need_update_opposite_addr = 1;//两侧地址不一样，需要更新对侧信息, 一般用于mpls隧道内层的ethernet
		}else{
			pstream_pr->need_update_opposite_addr = 0;
		}	
		
	}else{
		pstream_pr = NULL; /* 使上层承载协议的pfather为NULL */
		next_layer_offset = 0;
		if((int)CAP_LEVEL_MAC == (int)raw_pkt->low_layer_type){
			((raw_pkt_t *)raw_pkt)->raw_pkt_data = (char *)raw_pkt->__lib_raw_pkt_data + sizeof(struct mesa_ethernet_hdr);
			((raw_pkt_t *)raw_pkt)->raw_pkt_len = raw_pkt->__lib_raw_pkt_len - sizeof(struct mesa_ethernet_hdr);
		}
	}
	
	if(should_create_empty_mpls_layer_for_symmetric(pstream, eth_type) != 0){
		((raw_pkt_t *)raw_pkt)->offset_to_raw_pkt_hdr = next_layer_offset;
		ret = mpls_empty_entry(pstream_pr, (const void *)next_layer_data, thread_num, dir, raw_pkt, next_layer_offset);
		return ret;
	}
	/* 2020-09-17 lijia modify, 如果不创建空的mpls层, 此处要继续执行, 不能是else */
	//else
	{
		switch(eth_type){
			case ETH_P_IP:
				if(g_skip_ethernet_layer_sw){
					((raw_pkt_t *)raw_pkt)->low_layer_type = (enum addr_type_t)CAP_LEVEL_IPV4;
				}
				((raw_pkt_t *)raw_pkt)->offset_to_raw_pkt_hdr = next_layer_offset;
				ret = ipv4_entry(pstream_pr, (const void *)next_layer_data, thread_num, dir, raw_pkt, next_layer_offset);
			break;

			case ETH_P_IPV6:
				if(g_skip_ethernet_layer_sw){
					((raw_pkt_t *)raw_pkt)->low_layer_type = (enum addr_type_t)CAP_LEVEL_IPV6;
				}
				((raw_pkt_t *)raw_pkt)->offset_to_raw_pkt_hdr = next_layer_offset;
				ret = ipv6_entry(pstream_pr, (const void *)next_layer_data, thread_num, dir, raw_pkt, next_layer_offset);
			break;

			case ETH_P_8021Q:
			/* 2020-11-23 lijia add, 不再支持2018年pangu一期使用0x88a8作为MAC-IN-MAC格式数据包，使用802.1ad原始格式解析 */
			case ETH_P_8021AD:			
				((raw_pkt_t *)raw_pkt)->offset_to_raw_pkt_hdr = next_layer_offset;
				ret = IEEE_8021_entry(pstream_pr, (const void *)next_layer_data, thread_num, dir, raw_pkt, next_layer_offset, eth_type);
			break;
			

			case ETH_P_PPP_SES:
				((raw_pkt_t *)raw_pkt)->offset_to_raw_pkt_hdr = next_layer_offset;
				ret = pppoe_session_entry(pstream_pr, (const void *)next_layer_data, thread_num, dir, raw_pkt, next_layer_offset);
			break;

			case ETH_P_MPLS_UC: /* 2014-12-08 add */
				((raw_pkt_t *)raw_pkt)->offset_to_raw_pkt_hdr = next_layer_offset;
				ret = mpls_uc_entry(pstream_pr, (const void *)next_layer_data, thread_num, dir, raw_pkt, next_layer_offset);
			break;

			case ETH_P_ARP:
				((raw_pkt_t *)raw_pkt)->offset_to_raw_pkt_hdr = next_layer_offset;
				ret = arp_entry(pstream_pr, (const void *)next_layer_data, thread_num, dir, raw_pkt, next_layer_offset);
			break;

			default:
				/* unknown protocol */

				local_sys_stat->count[SAPP_STAT_RCV_UNKNOWN]++;
				local_sys_stat->length[SAPP_STAT_RCV_UNKNOWN] += (unsigned long long)raw_pkt->raw_pkt_len;				
				if(NET_CONN_SERIAL_GDEV == g_topology_mode){
					if(sapp_identify_tunnel_inner_pkt(raw_pkt) != 0){
						ret = PASS;
					}else{
						/* GDEV模式下, 什么时候都不应该把非隧道内不认识的包再转发出去, 在线发现把SPT生成树协议再注回去, 导致网络故障 */
						local_sys_stat->count[SAPP_STAT_DROP_ETHERNET]++;
						ret = DROP;
						sapp_runtime_log(RLOG_LV_DEBUG, "is not raw inline ethernet pkt, type is:0x%x, drop it.", eth_type); 
					}
				}
				sapp_runtime_log(20, "eth_entry() recv unknown pkt, protocol is:0x%04x, pkt seq:%llu", eth_type, local_sys_stat->count[SAPP_STAT_RCV_RAW]);
			break;
		}
	}

	return ret;
}


#ifdef __cplusplus
}
#endif

