#ifdef __cplusplus
extern "C" {
#endif

#include "sapp_api.h"
#include "sapp_private_api.h"


#if IKNOW_ENABLE
#include "iknow.h"
extern packet_io_status_t *g_packet_io_status_pool[MAX_THREAD_NUM];
//extern int g_packet_io_thread_num;
static inline void packet_io_eth_status_update(int thread_seq,  int raw_pkt_len);
#endif

extern int g_skip_ethernet_layer_sw;

static inline void set_mac_addr(struct layer_addr_mac *addr, const struct mesa_ethernet_hdr *p_eth_hdr)
{
	memcpy(&(addr->dst_mac[0]), &(p_eth_hdr->ether_dhost[0]), ETHER_ADDR_LEN);
	memcpy(&(addr->src_mac[0]), &(p_eth_hdr->ether_shost[0]), ETHER_ADDR_LEN);
}


int eth_entry(struct streaminfo_private *fstream_pr, const void *this_layer_hdr,int thread_num, 
			unsigned char dir, const raw_pkt_t *raw_pkt, int offset_to_raw_pkt_hdr)
{
	int ret = PASS;
	const  unsigned char *next_layer_data = (const unsigned char *)this_layer_hdr + sizeof(struct mesa_ethernet_hdr);
	const struct mesa_ethernet_hdr *p_eth_hdr = (const struct mesa_ethernet_hdr *)this_layer_hdr;
	//unsigned short eth_type = ntohs(p_eth_hdr->ether_type);
	unsigned short eth_type = ntohs(p_eth_hdr->ether_type); 
	int next_layer_offset;
	struct streamindex tmp_index;
	struct streamindex *ptmp;
	struct streaminfo_private *pstream_pr;
	struct streaminfo *pstream;
	sapp_gval_mthread_sys_stat_t *local_sys_stat = &sapp_global_val->mthread_volatile[thread_num]->sys_stat;

	if(NET_CONN_SERIAL_GDEV == g_topology_mode){
		if(unlikely(sapp_identify_broad_multicast_pkt(this_layer_hdr, raw_pkt) != 0)){
			//g_SysInputInfo[thread_num][SAPP_STAT_DROP]++;
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

#if IKNOW_ENABLE
		packet_io_eth_status_update(thread_num, raw_pkt->raw_pkt_len);
#endif
		memset(ptmp, 0, sizeof(struct streamindex));
		//set_mac_addr(&addr, p_eth_hdr);
		pstream->addr.mac = (struct layer_addr_mac *)this_layer_hdr;
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

		//g_SysInputInfo[thread_num][PKT_ETHERNET]++;
		//g_SysInputInfo[thread_num][PKT_ETHERNET_LEN] += (unsigned long long)raw_pkt->raw_pkt_len;	
		local_sys_stat->count[SAPP_STAT_RCV_ETHERNET]++;
		local_sys_stat->length[SAPP_STAT_RCV_ETHERNET] += (unsigned long long)raw_pkt->raw_pkt_len;
		if(dir == sapp_global_val->config.packet_io.inbound_route_dir){
			local_sys_stat->count[SAPP_STAT_ETH_INBOUND]++;
			local_sys_stat->length[SAPP_STAT_ETH_INBOUND] += (unsigned long long)raw_pkt->raw_pkt_len;
		}else{
			local_sys_stat->count[SAPP_STAT_ETH_OUTBOUND]++;
			local_sys_stat->length[SAPP_STAT_ETH_OUTBOUND] += (unsigned long long)raw_pkt->raw_pkt_len;
		}
	}else{
		pstream_pr = NULL; /* 使上层承载协议的pfather为NULL */
		next_layer_offset = 0;
		if((int)CAP_LEVEL_MAC == (int)raw_pkt->low_layer_type){
			((raw_pkt_t *)raw_pkt)->raw_pkt_data = (char *)raw_pkt->__lib_raw_pkt_data + sizeof(struct mesa_ethernet_hdr);
			((raw_pkt_t *)raw_pkt)->raw_pkt_len = raw_pkt->__lib_raw_pkt_len - sizeof(struct mesa_ethernet_hdr);
		}
	}
	if(sapp_global_single.create_mpls_anyway != 0)
	{
		if(eth_type == ETHERTYPE_IP || eth_type == ETHERTYPE_IPv6)
		{
			((raw_pkt_t *)raw_pkt)->offset_to_raw_pkt_hdr = next_layer_offset;
			ret = mpls_empty_entry(pstream_pr, (const void *)next_layer_data, thread_num, dir, raw_pkt, next_layer_offset);
		}
	}
	else
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

			case ETHERTYPE_VLAN:
				((raw_pkt_t *)raw_pkt)->offset_to_raw_pkt_hdr = next_layer_offset;
				if(sapp_global_val->config.protocol_feature.treat_vlan_as_mac_in_mac_enabled){
					ret = mac_in_mac_entry(pstream_pr,next_layer_data,thread_num,dir,raw_pkt, next_layer_offset);
				}else{
					ret = vlan_8021q_entry(pstream_pr, (const void *)next_layer_data, thread_num, dir, raw_pkt, next_layer_offset);
				}
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

			/* 2018-08-19 lijia add, for PanGu项目并联回流流量格式, 复用了ETH_P_8021AD(0x88A8)字段, 实际是MAC-IN-MAC格式数据包 */
			case ETH_P_MAC_IN_MAC:
				((raw_pkt_t *)raw_pkt)->offset_to_raw_pkt_hdr = next_layer_offset;
				ret = mac_in_mac_entry(pstream_pr,next_layer_data,thread_num,dir,raw_pkt, next_layer_offset);
			break;

			default:
				/* unknown protocol */
				//g_SysInputInfo[thread_num][PKT_UNKNOWN]++;
				//g_SysInputInfo[thread_num][PKT_UNKNOWN_LEN] += raw_pkt->raw_pkt_len;
				local_sys_stat->count[SAPP_STAT_RCV_UNKNOWN]++;
				local_sys_stat->length[SAPP_STAT_RCV_UNKNOWN] += (unsigned long long)raw_pkt->raw_pkt_len;				
				if(NET_CONN_SERIAL_GDEV == g_topology_mode){
					if(sapp_identify_tunnel_inner_pkt(raw_pkt) != 0){
						ret = PASS;
					}else{
						/* GDEV模式下, 什么时候都不应该把非隧道内不认识的包再转发出去, 在线发现把SPT生成树协议再注回去, 导致网络故障 */
						//g_SysInputInfo[thread_num][SAPP_STAT_DROP]++;
						local_sys_stat->count[SAPP_STAT_DROP_ETHERNET]++;
						ret = DROP;
					}
				}
				sapp_log(20, 0, 20, "eth_entry() recv unknown pkt, protocol is:0x%04x", eth_type);
			break;
		}
	}

	return ret;
}

#if IKNOW_ENABLE
static packet_io_status_base_t g_io_eth_last_status, g_io_eth_cur_status, g_io_eth_realtime_status; 	
long ifuncb_show_eth_summary(iknow_handle ihandle, iknow_conn iconn, const void *cb_fun_arg, const char *cmd_args)
{
	iprintf(ihandle, iconn,"NOTE: unit of byte for total is 'byte', for realtime is 'bps, bit per second'!\n");
	iprintf(ihandle, iconn, "%8s %8s %12s\n", " ", "packet", "byte");
	iprintf(ihandle, iconn, "%8s %8llu %12llu\n%8s %8llu %12llu\n", 
		  "total", g_io_eth_cur_status.pkt_num, g_io_eth_cur_status.pkt_byte,
	    	  "realtime", g_io_eth_realtime_status.pkt_num, g_io_eth_realtime_status.pkt_byte*8);
	
	return 0;
}

void *packet_io_status_eth_mem_init(void)
{
	void *eth_mem;
	
	eth_mem = malloc(sizeof(packet_io_status_base_t));
	memset(eth_mem, 0, sizeof(packet_io_status_base_t));

	return eth_mem;
}

void iknow_register_eth_cb(void *ihandle)
{
	int ret;

	ret = iknow_register_cmd(ihandle, "show eth summary", "display eth flow summary", ifuncb_show_eth_summary, NULL, 0, NULL);
	assert(0 == ret);
}


static inline void packet_io_eth_status_update(int thread_seq,  int raw_pkt_len)
{
	packet_io_status_base_t *p_eth_status;

	p_eth_status = (packet_io_status_base_t *)(g_packet_io_status_pool[thread_seq]->packet_io_status[IO_STATUS_ETH]);

	p_eth_status->pkt_num++;
	p_eth_status->pkt_byte += raw_pkt_len;
}

void packet_io_status_eth_time_cb(void)
{
	/* 全局总包数, 总字节数, 平均包长, 当前实时流量 */
	int i;
	packet_io_status_base_t *p_eth_status;

 	memcpy((void *)&g_io_eth_last_status, (void *)&g_io_eth_cur_status, sizeof(packet_io_status_base_t)); /* 保存上一秒的值 */
 	memset((void *)&g_io_eth_cur_status, 0, sizeof(packet_io_status_base_t)); /* 清零 */
	
	for(i = 0; i < g_packet_io_thread_num; i++){
		p_eth_status = (packet_io_status_base_t *)(g_packet_io_status_pool[i]->packet_io_status[IO_STATUS_ETH]);
		g_io_eth_cur_status.pkt_num += p_eth_status->pkt_num;
		g_io_eth_cur_status.pkt_byte += p_eth_status->pkt_byte;
	}	

	g_io_eth_realtime_status.pkt_num = g_io_eth_cur_status.pkt_num - g_io_eth_last_status.pkt_num;
	g_io_eth_realtime_status.pkt_byte = g_io_eth_cur_status.pkt_byte - g_io_eth_last_status.pkt_byte;
}
#endif

#ifdef __cplusplus
}
#endif

