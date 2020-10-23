
#ifdef __cplusplus
extern "C" {
#endif

#include "sapp_api.h"
#include "sapp_private_api.h"

extern int g_skip_ethernet_layer_sw;

static void set_mac_in_mac_addr(const struct mesa_ethernet_hdr *outer_ether_hdr,
    const struct mesa_ethernet_hdr *inner_ether_hdr, struct layer_addr_mac_in_mac *mim_addr)
{
	memcpy(mim_addr->outer_dst_mac, outer_ether_hdr->ether_dhost, ETHER_ADDR_LEN);
	memcpy(mim_addr->outer_src_mac, outer_ether_hdr->ether_shost, ETHER_ADDR_LEN);
	
	memcpy(mim_addr->inner_dst_mac, inner_ether_hdr->ether_dhost, ETHER_ADDR_LEN);
	memcpy(mim_addr->inner_src_mac, inner_ether_hdr->ether_shost, ETHER_ADDR_LEN);
}


static inline int should_create_empty_mpls_layer_for_symmetric(const struct streaminfo *pstream, unsigned short next_eth_type)
{
	const const struct streaminfo_private *pstream_pr = (const struct streaminfo_private *)pstream;
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


/* 2018-08-19 lijia add, for PanGu项目并联回流流量格式, 复用了ETH_P_8021AD字段, 实际是MAC-IN-MAC格式数据包,
	outer_mac--inner_mac--ipv4/6--tcp/udp---layer7.
*/
int mac_in_mac_entry(struct streaminfo_private *fstream_pr, const void *this_layer_hdr,int thread_num, 
			unsigned char dir, const raw_pkt_t *raw_pkt, int offset_to_raw_pkt_hdr)
{
	struct layer_addr_mac_in_mac mim_addr;
	struct streamindex tmp_index;
	struct streamindex *ptmp;
	struct streaminfo_private *pstream_pr;
	struct streaminfo *pstream;
	const struct mesa_ethernet_hdr *outer_ether_hdr;
	const struct mesa_ethernet_hdr *inner_ether_hdr;
	//const struct mesa_vlan_detail_hdr *vlan_hdr;
	const  unsigned char *next_layer_data;
	int next_layer_offset,  ret;
    unsigned short eth_type = 0; 
	sapp_gval_mthread_sys_stat_t *local_sys_stat = &sapp_global_val->mthread_volatile[thread_num]->sys_stat;

	memset(&tmp_index, 0, sizeof(struct streamindex));
	ptmp = &tmp_index;
	pstream_pr = &ptmp->stream;
	pstream = &pstream_pr->stream_public;

	if(unlikely(0 == g_skip_ethernet_layer_sw)){
		outer_ether_hdr = (struct mesa_ethernet_hdr *)raw_pkt->raw_pkt_data;
		inner_ether_hdr = (struct mesa_ethernet_hdr *)((char *)raw_pkt->raw_pkt_data + sizeof(struct mesa_ethernet_hdr));
		////vlan_hdr = (struct mesa_vlan_detail_hdr *)((char *)outer_ether_hdr + sizeof(struct mesa_ethernet_hdr));
		
		next_layer_data = (unsigned char *)inner_ether_hdr + sizeof(struct mesa_ethernet_hdr);
		next_layer_offset = sizeof(struct mesa_ethernet_hdr) + sizeof(struct mesa_ethernet_hdr);
		
		set_mac_in_mac_addr(outer_ether_hdr, inner_ether_hdr, &mim_addr);

		pstream->addr.addrtype = ADDR_TYPE_MAC_IN_MAC;
		pstream->addr.addrlen = sizeof(struct layer_addr_mac_in_mac);
		pstream->addr.paddr = &mim_addr;
		pstream_pr->addr_use_as_hash = 0;
	}else{
		pstream_pr = NULL; /* 使上层承载协议的pfather为NULL */
		next_layer_offset = 0;
		if((int)CAP_LEVEL_MAC == (int)raw_pkt->low_layer_type){
			((raw_pkt_t *)raw_pkt)->raw_pkt_data = (char *)raw_pkt->__lib_raw_pkt_data + sizeof(struct mesa_ethernet_hdr);
			((raw_pkt_t *)raw_pkt)->raw_pkt_len = raw_pkt->__lib_raw_pkt_len - sizeof(struct mesa_ethernet_hdr);
		}
	}
    eth_type = ntohs(inner_ether_hdr->ether_type);
	if(should_create_empty_mpls_layer_for_symmetric(pstream, eth_type) != 0){
		if(eth_type == ETHERTYPE_IP || eth_type == ETHERTYPE_IPv6)
		{
			((raw_pkt_t *)raw_pkt)->offset_to_raw_pkt_hdr = next_layer_offset;
			ret = mpls_empty_entry(pstream_pr, (const void *)next_layer_data, thread_num, dir, raw_pkt, next_layer_offset);
			return ret;
		}
	}
	//else
	{
		switch(eth_type){
			case ETHERTYPE_IP:
				if(g_skip_ethernet_layer_sw){
					((raw_pkt_t *)raw_pkt)->low_layer_type = (enum addr_type_t)CAP_LEVEL_IPV4;
				}
				((raw_pkt_t *)raw_pkt)->offset_to_raw_pkt_hdr = next_layer_offset;
				ret = ipv4_entry(pstream_pr, (const void *)next_layer_data, thread_num, dir, raw_pkt, next_layer_offset);
			break;

			case ETHERTYPE_IPv6:
				if(g_skip_ethernet_layer_sw){
					((raw_pkt_t *)raw_pkt)->low_layer_type = (enum addr_type_t)CAP_LEVEL_IPV6;
				}
				((raw_pkt_t *)raw_pkt)->offset_to_raw_pkt_hdr = next_layer_offset;
				ret = ipv6_entry(pstream_pr, (const void *)next_layer_data, thread_num, dir, raw_pkt, next_layer_offset);
			break;

			case ETH_P_MPLS_UC:
				((raw_pkt_t *)raw_pkt)->offset_to_raw_pkt_hdr = next_layer_offset;
				ret = mpls_uc_entry(pstream_pr, (const void *)next_layer_data, thread_num, dir, raw_pkt, next_layer_offset);
			break;

			default:
				/* unknown protocol */
				local_sys_stat->count[SAPP_STAT_RCV_UNKNOWN]++;
				local_sys_stat->count[SAPP_STAT_RCV_UNKNOWN]+= raw_pkt->raw_pkt_len;	
				((raw_pkt_t *)raw_pkt)->diagnose_to_dump = 1;
				sapp_runtime_log(20, "MAC-IN-MAC unknown protocol: 0x%x\n", eth_type);
				ret = PASS;
			break;
		}
	}

	return ret;
}


#ifdef __cplusplus
}
#endif


