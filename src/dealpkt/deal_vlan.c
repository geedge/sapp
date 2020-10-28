#ifdef __cplusplus
extern "C" {
#endif

#include "sapp_api.h"
#include "sapp_private_api.h"

#define VLAN_ID_MAX		(4096) /* vlan id is 12bit, max is 4096 */

#if DEBUG
static inline void packet_io_vlan_status_update(int thread_seq, const struct layer_addr_vlan *addr, int raw_pkt_len);
#endif

int set_vlan_addr(struct layer_addr_vlan *addr, const unsigned char *vlan_tag)
{
	int i;
	const struct mesa_vlan_hdr *vhdr;
	int vlan_layer_len = 0;

	memset(addr, 0, sizeof(struct layer_addr_vlan));

	addr->vlan_id = ntohs(*(unsigned short *)vlan_tag) & VLAN_ID_MASK; //compat old value

	for(i = 0; i < MAX_VLAN_ADDR_LAYER; i++){
		vhdr = (struct mesa_vlan_hdr *)vlan_tag;
		memcpy(&addr->src_vlan_pkt[i], vlan_tag, sizeof(struct mesa_vlan_hdr));
		vlan_tag += sizeof(struct mesa_vlan_hdr);
		addr->src_vlan_layer_num++;
		vlan_layer_len += sizeof(struct mesa_vlan_hdr);
		if(ETH_P_8021Q != ntohs(vhdr->type)){
			break;
		}
	}
	
	return vlan_layer_len;
}

int vlan_8021q_entry(struct streaminfo_private *pfstream_pr,const void *this_layer_data,int thread_num, 
						unsigned char routedir, const raw_pkt_t *raw_pkt, int offset_to_raw_pkt_hdr)
{
	int ret = PASS;
	struct streamindex tmp_index;
	struct streamindex *ptmp=&tmp_index;
	struct streaminfo_private *pstream_pr = &ptmp->stream;
	struct streaminfo *pstream = &pstream_pr->stream_public;	
	struct layer_addr_vlan addr;
	u_short next_layer_type;
	char *next_layer_hdr;
	int next_layer_offset;
	sapp_gval_mthread_sys_stat_t *local_sys_stat = &sapp_global_val->mthread_volatile[thread_num]->sys_stat;
	int vlan_layer_len;
	const struct mesa_vlan_hdr *vhdr;

	if(likely(0 == G_SKIP_NOT_IP_LAYER)){
		memset(ptmp,0,sizeof(struct streamindex));
		vlan_layer_len = set_vlan_addr(&addr, (unsigned char *)this_layer_data);

		pstream->addr.paddr=&addr;
		pstream->addr.addrtype = ADDR_TYPE_VLAN;
		pstream->addr.addrlen = sizeof(struct layer_addr_vlan);
		pstream_pr->addr_use_as_hash = 0;//地址不参与hash比对，仅算层数
		//ptmp->stream.p_layer_header = this_layer_data;
		//ptmp->stream.offset_to_raw_pkt_hdr = (char *)this_layer_data - (char *)raw_pkt->raw_pkt_data;
		pstream_pr->offset_to_raw_pkt_hdr = offset_to_raw_pkt_hdr;
		pstream_pr->raw_pkt = raw_pkt; /* 2014-12-30 lijia add */
		
		pstream->pfather=&pfstream_pr->stream_public;
		pstream->type=STREAM_TYPE_NON;
		pstream->routedir=routedir;
		pstream->threadnum=thread_num;
		
		pstream_pr->layer_index = pfstream_pr->layer_index + 1;
		if(g_asymmetric_addr_layer_set.layer_type_index[ADDR_TYPE_VLAN][pstream_pr->layer_index] != 0){
			pstream_pr->need_update_opposite_addr = 1;//两侧地址不一样，需要更新对侧信息
		}else{
			pstream_pr->need_update_opposite_addr = 0;
		}

		//pstream_pr->fake_layer_dir_for_asymmetric_cmp = 0; //todo, 根据g_asymmetric_presence_layer_set判断
	}else{
		pstream_pr = pfstream_pr; /* 2015-07-03 lijia add, skip this layer */
	}

	vhdr = (struct mesa_vlan_hdr *)&addr.src_vlan_pkt[addr.src_vlan_layer_num-1];
	next_layer_type = ntohs(vhdr->type);

	next_layer_hdr = (char *)this_layer_data + vlan_layer_len;
	next_layer_offset = offset_to_raw_pkt_hdr + vlan_layer_len;

	switch(next_layer_type)
	{
		case ETH_P_IP:
			((raw_pkt_t *)raw_pkt)->offset_to_raw_pkt_hdr = next_layer_offset;
			ret=ipv4_entry(pstream_pr,next_layer_hdr,thread_num,routedir,raw_pkt, next_layer_offset);
			break;
		case ETH_P_IPV6:
			((raw_pkt_t *)raw_pkt)->offset_to_raw_pkt_hdr = next_layer_offset;
			ret=ipv6_entry(pstream_pr,next_layer_hdr,thread_num,routedir,raw_pkt, next_layer_offset);
			break;

		case ETH_P_8021Q:
			//((raw_pkt_t *)raw_pkt)->offset_to_raw_pkt_hdr = next_layer_offset;
			//ret=vlan_8021q_entry(pstream_pr, next_layer_hdr,thread_num, routedir,raw_pkt, next_layer_offset);
			sapp_runtime_log(30, "vlan_8021q_entry(): VLAN combine to one layer!\n");
			assert(0);
			break;
			
		case ETH_P_PPP_SES:
#if COMPAT_PAPP_FOR_BENCHMARK
			return PASS;
#endif		
			((raw_pkt_t *)raw_pkt)->offset_to_raw_pkt_hdr = next_layer_offset;
			ret=pppoe_session_entry(pstream_pr,next_layer_hdr,thread_num,routedir,raw_pkt, next_layer_offset);
		break;

		case ETH_P_MPLS_UC:
		case ETH_P_MPLS_MC:
			((raw_pkt_t *)raw_pkt)->offset_to_raw_pkt_hdr = next_layer_offset;
			ret = mpls_uc_entry(pstream_pr, (const void *)next_layer_hdr, thread_num, routedir, raw_pkt, next_layer_offset);
			break;

		default:
			/* unknown protocol */	
			local_sys_stat->count[SAPP_STAT_RCV_UNKNOWN]++;
			local_sys_stat->length[SAPP_STAT_RCV_UNKNOWN]+= raw_pkt->raw_pkt_len;

			sapp_runtime_log(20, "VLAN unknown protocol: 0x%x, pkt seq:%llu\n", next_layer_type, local_sys_stat->count[SAPP_STAT_RCV_RAW]);
			
			if(NET_CONN_SERIAL_GDEV == g_topology_mode){
				if(sapp_identify_tunnel_inner_pkt(raw_pkt) != 0){
					ret = PASS;
				}else{			
					/* GDEV模式下, 什么时候都不应该把不认识的包再转发出去, 在线发现把SPT生成树协议再注回去, 导致网络故障 */
					ret = DROP;
				}
			}else{
				ret = PASS;
			}
			break;
	}

	return ret;
}


#ifdef __cplusplus
}
#endif

