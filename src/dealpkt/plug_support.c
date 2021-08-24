/*
	此文件非平台自身需要的功能和函数,
	是提供给其他业务插件的接口, 如MESA_set_stream_opt, printaddr等,
*/
#include "sapp_api.h"
#include "sapp_private_api.h"

#ifdef __cplusplus
extern "C" {
#endif
extern int G_TCP_FLOW_STAT_PROJECT_ID ;
extern int G_UDP_FLOW_STAT_PROJECT_ID ;


extern const raw_ipfrag_list_t *get_raw_frag_list(const struct streaminfo *stream);
#if IOMODE_MARSIO
extern void * (*ptr_marsio_buff_ctrlzone)(marsio_buff_t *m, uint8_t id);
#endif

int get_opt_from_rawpkt(const void *voidpkt, int type, void *void_value)
{
	int ret = 0;
	const raw_pkt_t *rawpkt = (const raw_pkt_t *)voidpkt;

	if(NULL == voidpkt || NULL == void_value){
		return -1;
	}

	if(RAW_PKT_MAGIC_NUM != rawpkt->magic_num){ /* 可能来源于papp平台, 不支持此类功能 */
		return -1;
	}
	
	switch(type){
		case RAW_PKT_GET_DATA:
		{
			void **out_value = (void **)void_value;
			*out_value = (char *)rawpkt->raw_pkt_data + rawpkt->overlay_layer_bytes;
		}
		break;

		case RAW_PKT_GET_RAW_PKT_TYPE:
		{
			enum addr_type_t *out_value = (enum addr_type_t *)void_value;
			*out_value = rawpkt->low_layer_type;
		}
		break;		

		case RAW_PKT_GET_TOT_LEN:
		{
			int *out_value = (int *)void_value;
			*out_value = rawpkt->raw_pkt_len - rawpkt->overlay_layer_bytes;
		}
		break;

		case RAW_PKT_GET_TIMESTAMP:
		{
			struct timeval *out_value =(struct timeval *)void_value;
			memcpy(out_value, &rawpkt->raw_pkt_ts, sizeof(struct timeval));
		}
		break;
		
		case RAW_PKT_GET_THIS_LAYER_HDR:
		{
			void **out_value = (void **)void_value;
			const char *this_layer_hdr = (const char *)rawpkt->raw_pkt_data + rawpkt->offset_to_raw_pkt_hdr;
			*out_value = (void *)this_layer_hdr;
		}
		break;

		case RAW_PKT_GET_THIS_LAYER_REMAIN_LEN:
		{
			int *out_value = (int *)void_value;
			*out_value = rawpkt->raw_pkt_len - rawpkt->offset_to_raw_pkt_hdr;
		}
		break;

		case RAW_PKT_GET_VIRTUAL_LINK_ID:
		{
			/* from sapp v4.2, there is no mrtunnat module, so not support this option! */
			sapp_log(20, 0, 20, "not support option 'RAW_PKT_GET_VIRTUAL_LINK_ID' in sappv4.2 and later!");
			ret = -1;
		}
		break;
		
		case RAW_PKT_GET_REHASH_INDEX:
		{
			/* from sapp v4.2, there is no mrtunnat module, so not support this option! */
			sapp_log(20, 0, 20, "not support option 'RAW_PKT_GET_REHASH_INDEX' in sappv4.2 and later!");
			ret = -1;
		}
		break;


		/* 用于插件获取最底层真实mac地址, 无论什么模式, 有没有mrtunnat, 都用这一个接口 */
		case RAW_PKT_GET_ORIGINAL_LOWEST_ETH_SMAC:
		{
			const struct mesa_ethernet_hdr *lowest_ehdr;
			
			if(0 == sapp_global_val->config.packet_io.packet_io_tunnel.l2_l3_tunnel_support){ //with mrtunnat
				if(DEPOLYMENT_MODE_INLINE == sapp_global_val->config.packet_io.depolyment_mode_bin){
					if(CAP_MODEL_MARSIOV4 == g_packet_io_cap_mode){
						const struct mr_tunnat_ctrlzone *mr_ctrlzone = (const struct mr_tunnat_ctrlzone *)ptr_marsio_buff_ctrlzone((marsio_buff_t *)rawpkt->io_lib_pkt_reference, 0); /* index */
						if(0 == (mr_ctrlzone->action & TUNNAT_CZ_ACTION_FORWARD)){/* 非vxlan包, 肯定没有这些选项 */
							ret = -1;
						}else{
							memcpy(void_value, mr_ctrlzone->g_device_mac, ETH_ALEN);
						}
					}else{
						sapp_runtime_log(RLOG_LV_FATAL, "can't support option 'RAW_PKT_GET_ORIGINAL_LOWEST_ETH_SMAC' in no marsio inline mode!");
						ret = -1;
					}
				}else{
					lowest_ehdr = (struct mesa_ethernet_hdr *)rawpkt->raw_pkt_data;
					memcpy(void_value, lowest_ehdr->ether_shost, ETH_ALEN);
				}
			}else{ //from v4.2, without mrtunnat
				lowest_ehdr = (struct mesa_ethernet_hdr *)rawpkt->raw_pkt_data;
				memcpy(void_value, lowest_ehdr->ether_shost, ETH_ALEN);
			}
		}
		break;

		/* 用于插件获取最底层真实mac地址, 无论什么模式, 有没有mrtunnat, 都用这一个接口 */
		case RAW_PKT_GET_ORIGINAL_LOWEST_ETH_DMAC:
		{
			const struct mesa_ethernet_hdr *lowest_ehdr;
			
			if(0 == sapp_global_val->config.packet_io.packet_io_tunnel.l2_l3_tunnel_support){ //with mrtunnat
				if(DEPOLYMENT_MODE_INLINE == sapp_global_val->config.packet_io.depolyment_mode_bin){
					if(CAP_MODEL_MARSIOV4 == g_packet_io_cap_mode){
						const struct mr_tunnat_ctrlzone *mr_ctrlzone = (const struct mr_tunnat_ctrlzone *)ptr_marsio_buff_ctrlzone((marsio_buff_t *)rawpkt->io_lib_pkt_reference, 0); /* index */
						if(0 == (mr_ctrlzone->action & TUNNAT_CZ_ACTION_FORWARD)){/* 非vxlan包, 肯定没有这些选项 */
							ret = -1;
						}else{
							memcpy(void_value, mr_ctrlzone->l_device_mac, ETH_ALEN);
						}
					}else{
						sapp_runtime_log(RLOG_LV_FATAL, "can't support option 'RAW_PKT_GET_ORIGINAL_LOWEST_ETH_SMAC' in no marsio inline mode!");
						ret = -1;
					}
				}else{
					lowest_ehdr = (struct mesa_ethernet_hdr *)rawpkt->raw_pkt_data;
					memcpy(void_value, lowest_ehdr->ether_dhost, ETH_ALEN);
				}
			}else{ //from v4.2, without mrtunnat
				lowest_ehdr = (struct mesa_ethernet_hdr *)rawpkt->raw_pkt_data;
				memcpy(void_value, lowest_ehdr->ether_dhost, ETH_ALEN);
			}
		}		
		break;		

		default:
			sapp_runtime_log(RLOG_LV_FATAL, "get_opt_from_rawpkt(): not support option type: %d", type);
			ret = -1;
		break;
	}

	return ret;
}



static const struct streaminfo_private *offset_to_vxlan_layer(const struct streaminfo_private *pstream_pr)
{
	while(pstream_pr && (ADDR_TYPE_VXLAN != pstream_pr->stream_public.addr.addrtype)){
		pstream_pr = pstream_pr->pfather_pr;
	}

	return pstream_pr;
}


static int get_vxlan_info_from_streaminfo(const struct streaminfo_private *pstream_pr, int type, void *void_value)
{
	int ret = 0;
	const struct streaminfo_private *vxlan_pstream_pr;
	const raw_pkt_t *rawpkt;
	const inline_vxlan_hdr_t *p_vxlan_hdr;

	if(DEPOLYMENT_MODE_INLINE != g_topology_mode_raw){
		sapp_runtime_log(RLOG_LV_INFO, "get_rawpkt_opt_from_streaminfo() error: can't support option type: %d in no inline mode!", type);
		return -1;
	}

	vxlan_pstream_pr = offset_to_vxlan_layer(pstream_pr);
	if(NULL == vxlan_pstream_pr){
		sapp_runtime_log(RLOG_LV_FATAL, "get_rawpkt_opt_from_streaminfo() error, stream:%s not found vxlan layer!", 
						printaddr(&pstream_pr->stream_public.addr, pstream_pr->stream_public.threadnum));
		return -1;
	}

	rawpkt = pstream_pr->raw_pkt;
	p_vxlan_hdr = (inline_vxlan_hdr_t *)((char *)rawpkt->raw_pkt_data + vxlan_pstream_pr->offset_to_raw_pkt_hdr);		

	switch(type){
		case RAW_PKT_GET_GDEV_IP:
		{
			const struct mesa_ip4_hdr *pip4_hdr;
			const struct streaminfo_private *carry_vxlan_ip_layer = vxlan_pstream_pr->pfather_pr;
			if(NULL == carry_vxlan_ip_layer){
				return -1;
			}

			pip4_hdr = (struct mesa_ip4_hdr *)((char *)rawpkt->raw_pkt_data + carry_vxlan_ip_layer->offset_to_raw_pkt_hdr);
			int *out_value = (int *)void_value;
			*out_value = pip4_hdr->ip_src.s_addr;
		}
		break;

		case RAW_PKT_GET_VXLAN_LOCAL_IP:
		{
			const struct mesa_ip4_hdr *pip4_hdr;
			const struct streaminfo_private *carry_vxlan_ip_layer = vxlan_pstream_pr->pfather_pr;
			if(NULL == carry_vxlan_ip_layer){
				return -1;
			}
		
			pip4_hdr = (struct mesa_ip4_hdr *)((char *)rawpkt->raw_pkt_data + carry_vxlan_ip_layer->offset_to_raw_pkt_hdr);
			int *out_value = (int *)void_value;
			*out_value = pip4_hdr->ip_dst.s_addr;
		}
		break;

		case RAW_PKT_GET_VXLAN_ID:
		{
			int *out_value = (int *)void_value;
			*out_value = htonl((int)p_vxlan_hdr->link_id);			
		}
		break;

		case RAW_PKT_GET_VXLAN_VPNID:
		{
			int local_tmp_vpn_id;
			local_tmp_vpn_id = ((int)p_vxlan_hdr->vlan_id_half_high  << 4) | (int)p_vxlan_hdr->vlan_id_half_low; 
			int *out_value = (int *)void_value;
			*out_value = htonl(local_tmp_vpn_id);	
		}
		break;

		case RAW_PKT_GET_VXLAN_SPORT:
		{
			const struct mesa_ip4_hdr *pip4_hdr;
			const struct mesa_udp_hdr *pudp_hdr;
			const struct streaminfo_private *carry_vxlan_ip_layer = vxlan_pstream_pr->pfather_pr;
			if(NULL == carry_vxlan_ip_layer){
				return -1;
			}
		
			pip4_hdr = (struct mesa_ip4_hdr *)((char *)rawpkt->raw_pkt_data + carry_vxlan_ip_layer->offset_to_raw_pkt_hdr);
			pudp_hdr = (struct mesa_udp_hdr *)((char *)pip4_hdr + pip4_hdr->ip_hl*4);
			unsigned short *out_value = (unsigned short *)void_value;
			*out_value = pudp_hdr->uh_sport; /* 从收包的角度来看, src port是inline设备的sport */
		}
		break;

		case RAW_PKT_GET_VXLAN_ENCAP_TYPE:
		{
			char *out_value = (char *)void_value;
			*out_value = p_vxlan_hdr->link_layer_type;	
		}
		break;
		
		case RAW_PKT_GET_VXLAN_LINK_DIR:
		{
			char *out_value = (char *)void_value;
			*out_value = p_vxlan_hdr->dir;	
		}
		break;

		/* 从收包的角度来看, src host是inline设备的mac */
		case RAW_PKT_GET_VXLAN_OUTER_GDEV_MAC:
		{
			const struct mesa_ethernet_hdr *p_eth_hdr = (struct mesa_ethernet_hdr *)rawpkt->raw_pkt_data;
			memcpy(void_value, p_eth_hdr->ether_shost, ETH_ALEN);
		}
		break;

		/* 从收包的角度来看, dst host是本机的mac */
		case RAW_PKT_GET_VXLAN_OUTER_LOCAL_MAC:
		{
			const struct mesa_ethernet_hdr *p_eth_hdr = (struct mesa_ethernet_hdr *)rawpkt->raw_pkt_data;
			memcpy(void_value, p_eth_hdr->ether_dhost, ETH_ALEN);
		}
		break;	
	}

	return ret;
}


int get_rawpkt_opt_from_streaminfo(const struct streaminfo *pstream, int type, void *out_value)
{
	int ret = -1;
	const struct streaminfo_private *pstream_pr = (const struct streaminfo_private *)pstream;

	if(NULL == out_value){
		return -1;
	}
	
	if((RAW_PKT_GET_DATA == type) 
	&& ((PKT_TYPE_IPREBUILD & pstream->addr.pktipfragtype) != 0)){
		const raw_ipfrag_list_t *list_tmp = get_raw_frag_list(pstream);
		if(NULL == list_tmp){
			ret = -1;
		}else{
			const raw_ipfrag_list_t **out_list = (const raw_ipfrag_list_t **)out_value;
			*out_list = list_tmp;
			ret = 1;
		}
		return ret;
	}

	/* sappv4.2之后, 没有mrtunnat, 无法从ctrlzone获取这些vxlan相关的值, 要靠streaminfo->pfather偏移获取 */
	switch(type){
		case RAW_PKT_GET_GDEV_IP:
		case RAW_PKT_GET_VXLAN_ID:
		case RAW_PKT_GET_VXLAN_SPORT:
		case RAW_PKT_GET_VXLAN_ENCAP_TYPE:
		case RAW_PKT_GET_VXLAN_LINK_DIR:
		case RAW_PKT_GET_VXLAN_OUTER_GDEV_MAC:
		case RAW_PKT_GET_VXLAN_OUTER_LOCAL_MAC:
		case RAW_PKT_GET_VXLAN_VPNID:
		case RAW_PKT_GET_VXLAN_LOCAL_IP:
			return get_vxlan_info_from_streaminfo(pstream_pr, type, out_value);
		break;
	}
	
	return get_opt_from_rawpkt(pstream_pr->raw_pkt, type, out_value);
}

/*Convert tuple4 to string. Format: 10.0.0.1, 1234->10.0.0.2,5678*/
const char *printaddr (const struct layer_addr *paddrinfo,int threadindex)
{
	static char maxbuf[MAX_THREAD_NUM][128];
	char *buf=maxbuf[threadindex];
	char ip_str[INET6_ADDRSTRLEN];
	struct stream_tuple4_v4 *paddr;
	struct stream_tuple4_v6 *paddr6;

	if(NULL == paddrinfo){
		return NULL;
	}

	switch(paddrinfo->addrtype){
		case ADDR_TYPE_IPV4:
		{
			paddr=(struct stream_tuple4_v4 *)paddrinfo->paddr;
			memset(buf,0,64);
			//strcpy (buf, int_ntoa (paddr->saddr));
			inet_ntop(AF_INET, &paddr->saddr, ip_str, 64);
			strncpy (buf, ip_str, 64);
			sprintf (buf + strlen (buf), ".%u>", ntohs(paddr->source));
			//strcat (buf, int_ntoa (paddr->daddr));
			inet_ntop(AF_INET, &paddr->daddr, ip_str, 64);
			strcat (buf, ip_str);
			sprintf (buf + strlen (buf), ".%u", ntohs(paddr->dest));
		}	
		break;
		
		case ADDR_TYPE_IPV6:
		{
			paddr6=(struct stream_tuple4_v6 *)(paddrinfo->paddr);
			memset(buf,0,128);
			inet_ntop(AF_INET6, paddr6->saddr, ip_str, 64);
			strncpy (buf, ip_str, 64);
			sprintf (buf + strlen (buf), ".%u>", ntohs(paddr6->source));
			inet_ntop(AF_INET6, paddr6->daddr, ip_str, 64);
			strcat (buf, ip_str);
			sprintf (buf + strlen (buf), ".%u", ntohs(paddr6->dest));
		}
		break;

		case __ADDR_TYPE_IP_PAIR_V4:
		{
			paddr=(struct stream_tuple4_v4 *)paddrinfo->paddr;
			memset(buf,0,128);
			//strcpy (buf, int_ntoa (paddr->saddr));
			inet_ntop(AF_INET, &paddr->saddr, ip_str, 64);
			strncpy (buf, ip_str, 64);
			strcat (buf, ">");
			inet_ntop(AF_INET, &paddr->daddr, ip_str, 64);
			strcat (buf, ip_str);
		}
		break;

		case __ADDR_TYPE_IP_PAIR_V6:
		{
			paddr6=(struct stream_tuple4_v6 *)(paddrinfo->paddr);
			memset(buf,0,128);
			inet_ntop(AF_INET6, paddr6->saddr, ip_str, 64);
			strncpy (buf, ip_str, 64);
			strcat (buf, ">");
			inet_ntop(AF_INET6, paddr6->daddr, ip_str, 64);
			strcat (buf, ip_str);
		}
		break;
		
		default:
		{
			return (const char *)"Not support layer type";
		}
		break;
	}
	
	return buf;
}

/*
    This is a reentrant version of printaddr(), 
    Convert tuple4 to string store in out_buf. 
    Format: 10.0.0.1, 1234->10.0.0.2,5678. 
*/    
const char *printaddr_r(const struct layer_addr *paddrinfo, char *out_buf, int out_buf_len)
{
	char maxbuf[128];
	char *buf=maxbuf;
	char ip_str[INET6_ADDRSTRLEN];
	int addr_str_len;
	struct stream_tuple4_v4 *paddr;
	struct stream_tuple4_v6 *paddr6;

	if((NULL == paddrinfo) || (NULL == out_buf)){
		return "invalid args";
	}	

	if(paddrinfo->addrtype==ADDR_TYPE_IPV4)
	{
		paddr=(struct stream_tuple4_v4 *)paddrinfo->paddr;
		memset(buf,0,128);
		//strcpy (buf, int_ntoa (paddr->saddr));
		inet_ntop(AF_INET, &paddr->saddr, ip_str, 64);
		strncpy (buf, ip_str, 64);
		sprintf (buf + strlen (buf), ".%u>", ntohs(paddr->source));
		//strcat (buf, int_ntoa (paddr->daddr));
		inet_ntop(AF_INET, &paddr->daddr, ip_str, 64);
		strcat (buf, ip_str);
		sprintf (buf + strlen (buf), ".%u", ntohs(paddr->dest));
	}
	//to addjust
	else	if(paddrinfo->addrtype==ADDR_TYPE_IPV6)
	{
		paddr6=(struct stream_tuple4_v6 *)(paddrinfo->paddr);
		memset(buf,0,128);
		inet_ntop(AF_INET6, paddr6->saddr, ip_str, 64);
		strncpy (buf, ip_str,64);
		sprintf (buf + strlen (buf), ".%u>", ntohs(paddr6->source));
		inet_ntop(AF_INET6, paddr6->daddr, ip_str, 64);
		strcat (buf, ip_str);
		sprintf (buf + strlen (buf), ".%u", ntohs(paddr6->dest));
	}
	else
	{
		return (const char *)"Not support layer type";
	}

	addr_str_len = strlen(buf) + 1; /* add EOF */ 
	if(addr_str_len > out_buf_len){
		return (const char *)"buf len not enough";
	}

	memcpy(out_buf, buf, addr_str_len);
	
	return out_buf;
}


struct layer_addr * layer_addr_dup(const struct layer_addr *stack_info)
{
	void *addr_value;
	struct layer_addr *heap_addr = (struct layer_addr *)malloc(sizeof(struct layer_addr));
	addr_value = malloc(stack_info->addrlen);
	
	memcpy(heap_addr, stack_info, sizeof(struct layer_addr));
	memcpy(addr_value, stack_info->paddr, stack_info->addrlen);
	heap_addr->paddr = addr_value;

	return heap_addr;
}

void layer_addr_free(struct layer_addr *paddrinfo)
{
	free(paddrinfo->paddr);
	free(paddrinfo);
}

int get_thread_count(void)
{
	return g_packet_io_thread_num;
}

/*
	ctype:
		'c':count;
		'l':length;
*/
static inline unsigned long long __get_stream_opt_traffic_raw(int cltype, int iotype, struct streaminfo_private *pstream_pr)
{
	unsigned long long tval;
	struct streaminfo *pstream = &pstream_pr->stream_public;

	if('c' == cltype){ /* count */
		if('i' == iotype){ /* inbound */
			if(sapp_global_val->config.packet_io.inbound_route_dir == pstream_pr->stream_c2s_route_dir){
				if(STREAM_TYPE_TCP == pstream_pr->stream_public.type){
					tval = pstream->ptcpdetail->serverpktnum;
				}else{
					tval = pstream->pudpdetail->serverpktnum;
				}
			}else{
				if(STREAM_TYPE_TCP == pstream_pr->stream_public.type){
					tval = pstream->ptcpdetail->clientpktnum;
				}else{
					tval = pstream->pudpdetail->clientpktnum;
				}
			}
		}else{ /* outbound */
			if(sapp_global_val->config.packet_io.inbound_route_dir == pstream_pr->stream_c2s_route_dir){
				if(STREAM_TYPE_TCP == pstream_pr->stream_public.type){
					tval = pstream->ptcpdetail->clientpktnum;
				}else{
					tval = pstream->pudpdetail->clientpktnum;
				}
			}else{
				if(STREAM_TYPE_TCP == pstream_pr->stream_public.type){
					tval = pstream->ptcpdetail->serverpktnum;
				}else{
					tval = pstream->pudpdetail->serverpktnum;
				}
			}			
		}
	}else{/* length */
		if('i' == iotype){ /* inbound */
			if(sapp_global_val->config.packet_io.inbound_route_dir == pstream_pr->stream_c2s_route_dir){
				if(STREAM_TYPE_TCP == pstream_pr->stream_public.type){
					tval = ((struct tcpdetail_private *)pstream->ptcpdetail)->flow_stat->C2S_all_byte_raw;
				}else{
					tval = ((struct udpdetail_private *)pstream->pudpdetail)->flow_stat->C2S_all_byte_raw;
				}
			}else{
				if(STREAM_TYPE_TCP == pstream_pr->stream_public.type){
					tval = ((struct tcpdetail_private *)pstream->ptcpdetail)->flow_stat->S2C_all_byte_raw;
				}else{
					tval = ((struct udpdetail_private *)pstream->pudpdetail)->flow_stat->S2C_all_byte_raw;
				}
			}
		}else{ /* outbound */
			if(sapp_global_val->config.packet_io.inbound_route_dir == pstream_pr->stream_c2s_route_dir){
				if(STREAM_TYPE_TCP == pstream_pr->stream_public.type){
					tval = ((struct tcpdetail_private *)pstream->ptcpdetail)->flow_stat->S2C_all_byte_raw;
				}else{
					tval = ((struct udpdetail_private *)pstream->pudpdetail)->flow_stat->S2C_all_byte_raw;
				}
			}else{
				if(STREAM_TYPE_TCP == pstream_pr->stream_public.type){
					tval = ((struct tcpdetail_private *)pstream->ptcpdetail)->flow_stat->C2S_all_byte_raw;
				}else{
					tval = ((struct udpdetail_private *)pstream->pudpdetail)->flow_stat->C2S_all_byte_raw;
				}
			}			
		}		
	}

	return tval;
}



/*
	ctype:
		'c':count;
		'l':length;
*/
static inline unsigned long long __get_stream_opt_traffic(int cltype, int iotype, struct streaminfo_private *pstream_pr)
{
	unsigned long long tval;
	struct streaminfo *pstream = &pstream_pr->stream_public;

	if('c' == cltype){ /* count */
		if('i' == iotype){ /* inbound */
			if(sapp_global_val->config.packet_io.inbound_route_dir == pstream_pr->stream_c2s_route_dir){
				if(STREAM_TYPE_TCP == pstream_pr->stream_public.type){
					tval = pstream->ptcpdetail->serverpktnum;
				}else{
					tval = pstream->pudpdetail->serverpktnum;
				}
			}else{
				if(STREAM_TYPE_TCP == pstream_pr->stream_public.type){
					tval = pstream->ptcpdetail->clientpktnum;
				}else{
					tval = pstream->pudpdetail->clientpktnum;
				}
			}
		}else{ /* outbound */
			if(sapp_global_val->config.packet_io.inbound_route_dir == pstream_pr->stream_c2s_route_dir){
				if(STREAM_TYPE_TCP == pstream_pr->stream_public.type){
					tval = pstream->ptcpdetail->clientpktnum;
				}else{
					tval = pstream->pudpdetail->clientpktnum;
				}
			}else{
				if(STREAM_TYPE_TCP == pstream_pr->stream_public.type){
					tval = pstream->ptcpdetail->serverpktnum;
				}else{
					tval = pstream->pudpdetail->serverpktnum;
				}
			}			
		}
	}else{/* length */
		if('i' == iotype){ /* inbound */
			if(sapp_global_val->config.packet_io.inbound_route_dir == pstream_pr->stream_c2s_route_dir){
				if(STREAM_TYPE_TCP == pstream_pr->stream_public.type){
					tval = pstream->ptcpdetail->serverbytes;
				}else{
					tval = pstream->pudpdetail->serverbytes;
				}
			}else{
				if(STREAM_TYPE_TCP == pstream_pr->stream_public.type){
					tval = pstream->ptcpdetail->clientbytes;
				}else{
					tval = pstream->pudpdetail->clientbytes;
				}
			}
		}else{ /* outbound */
			if(sapp_global_val->config.packet_io.inbound_route_dir == pstream_pr->stream_c2s_route_dir){
				if(STREAM_TYPE_TCP == pstream_pr->stream_public.type){
					tval = pstream->ptcpdetail->clientbytes;
				}else{
					tval = pstream->pudpdetail->clientbytes;
				}
			}else{
				if(STREAM_TYPE_TCP == pstream_pr->stream_public.type){
					tval = pstream->ptcpdetail->serverbytes;
				}else{
					tval = pstream->pudpdetail->serverbytes;
				}
			}			
		}		
	}

	return tval;
}
int MESA_set_stream_opt(const struct streaminfo *pstream, enum MESA_stream_opt opt, void *opt_val, int opt_val_len)
{
	int ret = -1;

	if((NULL == opt_val) || (opt_val_len <= 0)){
		return -1;
	}
	
	switch((int)opt){
		case (int)MSO_MAX_UNORDER:
		{
			if(STREAM_TYPE_TCP != pstream->type){
				sapp_runtime_log(RLOG_LV_INFO, "%s, MESA_set_stream_opt() MSO_MAX_UNORDER error:stream type is not tcp!\n", printaddr(&pstream->addr, pstream->threadnum));
				ret = -1;
				break;
			}
			if(opt_val_len != sizeof(struct max_unorder_opt)){
				sapp_runtime_log(RLOG_LV_INFO, "%s, MESA_set_stream_opt() MSO_MAX_UNORDER error:opt_val_len invalid, must be sizeof(struct max_unorder_opt)\n", printaddr(&pstream->addr, pstream->threadnum));
				ret = -1;
				break;
			}
			struct max_unorder_opt *max_uorder = (struct max_unorder_opt *)opt_val;
			ret = tcp_set_single_stream_max_unorder(pstream, max_uorder->stream_dir, max_uorder->max_unorder_val);
		}
		break;

		case (int)MSO_NEED_ACK:
		{
			if(STREAM_TYPE_TCP != pstream->type){
				sapp_runtime_log(RLOG_LV_INFO, "%s,MESA_set_stream_opt() MSO_NEED_ACK error:stream type is not tcp!\n", printaddr(&pstream->addr, pstream->threadnum));
				ret = -1;
				break;
			}
			unsigned char nack = *((unsigned char *)opt_val);
			struct tcpdetail_private *pdetail_pr = (struct tcpdetail_private*)(pstream->pdetail);
			pdetail_pr->needackflag = nack;
			ret = 0;
		}
		break;

		case (int)MSO_TAKEOVER:
		{
			if(STREAM_TYPE_TCP != pstream->type){
				sapp_runtime_log(RLOG_LV_INFO, "%s,MESA_set_stream_opt() STREAM_TYPE_TCP error:stream type is not tcp!\n", printaddr(&pstream->addr, pstream->threadnum));
				ret = -1;
				break;
			}
			int takeover = *((int *)opt_val);
			struct tcpdetail_private *pdetail_pr=(struct tcpdetail_private*)(pstream->pdetail);
			pdetail_pr->takeoverflag = takeover;
			ret = 0;
		}
		break;

		case (int)MSO_TIMEOUT:
		{
			if(sizeof(short) != opt_val_len){
				sapp_runtime_log(RLOG_LV_INFO, "%s, MESA_set_stream_opt() MSO_TIMEOUT error:opt_val_len invalid, must be sizeof(short)\n",printaddr(&pstream->addr, pstream->threadnum));
				ret = -1;
				break;
			}
			unsigned short tmout = *((unsigned short *)opt_val);
			ret = stream_set_single_stream_timeout(pstream, tmout);
		}
		break;

		case (int)MSO_IGNORE_RST_FIN:
		{
			if(STREAM_TYPE_TCP != pstream->type){
				sapp_runtime_log(RLOG_LV_INFO, "%s,MESA_set_stream_opt() MSO_IGNORE_RST_FIN error: stream type is not tcp!\n",printaddr(&pstream->addr, pstream->threadnum));
				ret = -1;
				break;
			}
			unsigned char igrstfin = *((unsigned char *)opt_val);
			struct tcpdetail_private *pdetail_pr = (struct tcpdetail_private*)(pstream->pdetail);
			pdetail_pr->ignore_rst_fin = igrstfin;	
			ret = 0;
		}	
		break;

		case MSO_TCPALL_VALID_AFTER_KILL:
		{
#if 0		
			if(STREAM_TYPE_TCP != pstream->type){
				printf("MESA_set_stream_opt() error: stream type is not tcp!\n");
				ret = -1;
				break;
			}
			unsigned char tcpall_valid = *((unsigned char *)opt_val);
			struct tcpdetail_private *pdetail_pr = (struct tcpdetail_private*)(pstream->pdetail);
			pdetail_pr->tcpall_valid_after_kill = (tcpall_valid == 1 ? 1 : 0);	
			ret = 0;
#else
			ret = -1;
			sapp_runtime_log(RLOG_LV_INFO, "%s,MESA_set_stream_opt() MSO_TCPALL_VALID_AFTER_KILL error: this option is obsoleted!\n", printaddr(&pstream->addr, pstream->threadnum));
#endif
		}
		break;

		case MSO_DROP_STREAM:
		{
			int drop_flag = *((int *)opt_val);
			if(STREAM_TYPE_TCP == pstream->type){
				struct tcpdetail_private *tcp_pdetail_pr=(struct tcpdetail_private*)(pstream->pdetail);
				tcp_pdetail_pr->drop_stream_flag = (drop_flag != 0 ? 1:0);
				ret = 0;
			}else if(STREAM_TYPE_UDP == pstream->type){
				struct udpdetail_private *udp_pdetail_pr=(struct udpdetail_private*)(pstream->pdetail);
				udp_pdetail_pr->drop_stream_flag = (drop_flag != 0 ? 1:0);
				ret = 0;
			}else{
				sapp_runtime_log(RLOG_LV_FATAL, "%s,MESA_set_stream_opt() MSO_DROP_STREAM error: stream type is not tcp or udp!\n", printaddr(&pstream->addr, pstream->threadnum));
				ret = -1;
			}
		}
		break;

		case MSO_TCP_RST_REMEDY:
		{
			if(STREAM_TYPE_TCP != pstream->type){
				sapp_runtime_log(RLOG_LV_INFO, "%s,MESA_set_stream_opt() MSO_TCP_RST_REMEDY error: stream type is not tcp!\n", printaddr(&pstream->addr, pstream->threadnum));
				ret = -1;
				break;
			}
			int remedy_flag = *((int *)opt_val);
			struct tcpdetail_private *pdetail_pr=(struct tcpdetail_private*)(pstream->pdetail);
			pdetail_pr->auto_remedy_flag = (remedy_flag != 0 ? 1:0);
			ret = 0;
		}
		break;

		case MSO_DROP_CURRENT_PKT:
		{
			struct streaminfo_private *pstream_pr = (struct streaminfo_private *)pstream;
			raw_pkt_t *raw_pkt = (raw_pkt_t *)pstream_pr->raw_pkt;
			int drop_value = *((int *)opt_val);
			if(raw_pkt){
				raw_pkt->drop_current_pkt_flag = drop_value;
			}else{
				sapp_runtime_log(RLOG_LV_INFO, "%s,MESA_set_stream_opt() MSO_DROP_CURRENT_PKT error: current pkt is NULL!\n", printaddr(&pstream->addr, pstream->threadnum));
				ret = -1;
			}
		}
		break;
		
		default:
			sapp_runtime_log(RLOG_LV_INFO, "%s, MESA_set_stream_opt() error: unsupport MESA_stream_opt type:%d!\n", printaddr(&pstream->addr, pstream->threadnum), (int)opt);
			ret = -1;
			break;
	}

	return ret;
}


static inline int tcp_get_single_stream_max_unorder(const struct streaminfo *pstream, void *opt_val, int *opt_val_len)
{
	struct max_unorder_opt out_val;
	struct tcpdetail_private *pdetail_pr=(struct tcpdetail_private *)pstream->pdetail;
	UINT16 out_uorder_C2S = 0, out_uorder_S2C = 0;

	memset(&out_val, 0, sizeof(struct max_unorder_opt));
	if((pdetail_pr->pserver != NULL) && (tcp_default_unorder != pdetail_pr->pserver->maxunorder)){
		out_uorder_C2S = pdetail_pr->pserver->maxunorder;
		out_val.stream_dir |= DIR_C2S;
	}
	
	if((pdetail_pr->pclient != NULL) && (tcp_default_unorder != pdetail_pr->pclient->maxunorder)){
		out_uorder_S2C = pdetail_pr->pclient->maxunorder;
		out_val.stream_dir |= DIR_S2C;
	}

	out_val.max_unorder_val = (out_uorder_C2S > out_uorder_S2C)?out_uorder_C2S: out_uorder_S2C;

	memcpy(opt_val, &out_val, sizeof(struct max_unorder_opt));

	*opt_val_len = sizeof(struct max_unorder_opt);
	
	return 0;
}


static void sapp_mac_addr_to_long(const unsigned char *mac_addr, unsigned long long *smac_integer_type)
{
	int i;
	char *ptr = (char *)smac_integer_type;

	ptr += 5; /* 指向long long 的第6个字节 */

	for(i = 0; i < 6; i++){
		*ptr-- = *mac_addr++; /* 网络数据包中mac的最低位, copy至long long整数的最高位(除去最高2个字节后) */
	}
}

static int sapp_get_vxlan_info_from_streaminfo(const struct streaminfo *pstream, struct vxlan_info *vxinfo)
{
#define GDEV_SMAC_MASK_ENCAP_TYPE  	(0x00000000000F0000)
#define GDEV_SMAC_MASK_ENTRANCE_ID  	(0x0000000000007C00)
#define GDEV_SMAC_MASK_DEV_ID  			(0x00000000000003F0)
#define GDEV_SMAC_MASK_LINK_ID  		(0x000000000000000E)
#define GDEV_SMAC_MASK_LINK_DIR  		(0x0000000000000001)

	int i;
	const struct streaminfo *mim_stream = pstream->pfather;
	const struct layer_addr_mac_in_mac *mim_addr;
	const struct layer_addr_mac *mac_addr;
	unsigned char *ptr;
	unsigned long long smac_integer_type; /* 48bit mac转换为64bit的长整型数字存储, 便于操作 */

	while(mim_stream){//对于多层mac地址的情况，只从最外层MAC地址取vxlan_info
		if((ADDR_TYPE_MAC_IN_MAC == mim_stream->addr.addrtype || ADDR_TYPE_MAC == mim_stream->addr.addrtype) &&
				(mim_stream->pfather == NULL)){
			break;
		}else{
			mim_stream = mim_stream->pfather;
		}
	}

	if(NULL == mim_stream){
		return -1;
	}

	memset(vxinfo, 0, sizeof(struct vxlan_info));

	if(ADDR_TYPE_MAC_IN_MAC == mim_stream->addr.addrtype)
    {
        mim_addr = mim_stream->addr.mimac;
        sapp_mac_addr_to_long(mim_addr->outer_src_mac, &smac_integer_type);
    }
    else
    {
        mac_addr = mim_stream->addr.mac;
        sapp_mac_addr_to_long(mac_addr->src_addr.h_source, &smac_integer_type);
    }
	vxinfo->encap_type = (smac_integer_type & GDEV_SMAC_MASK_ENCAP_TYPE) >> 16;
	vxinfo->entrance_id = (smac_integer_type & GDEV_SMAC_MASK_ENTRANCE_ID) >> 10;
	vxinfo->dev_id = (smac_integer_type & GDEV_SMAC_MASK_DEV_ID) >> 4;
	vxinfo->link_id = (smac_integer_type & GDEV_SMAC_MASK_LINK_ID ) >> 1;
	vxinfo->link_dir = (smac_integer_type & GDEV_SMAC_MASK_LINK_DIR);

    if(ADDR_TYPE_MAC_IN_MAC == mim_stream->addr.addrtype)
    {
        ptr = vxinfo->inner_smac;
        for(i = 0; i < 6; i++, ptr += 3){
            sprintf((char *)ptr, "%02x:", mim_addr->inner_src_mac[i]);
        }
        vxinfo->inner_smac[17] = '\0'; /* 最后一位清零 */
        memcpy(vxinfo->inner_smac_hex, mim_addr->inner_src_mac, 6);

        ptr = vxinfo->inner_dmac;
        for(i = 0; i < 6; i++, ptr += 3){
            sprintf((char *)ptr, "%02x:", mim_addr->inner_dst_mac[i]);
        }
        vxinfo->inner_dmac[17] = '\0'; /* 最后一位清零 */
        memcpy(vxinfo->inner_dmac_hex, mim_addr->inner_dst_mac, 6);
    }
    else
    {
		ptr = vxinfo->inner_smac;
		for(i = 0; i < 6; i++, ptr += 3){
			sprintf((char *)ptr, "%02x:", mac_addr->src_addr.h_source[i]);
		}
		vxinfo->inner_smac[17] = '\0'; /* 最后一位清零 */
		memcpy(vxinfo->inner_smac_hex, mac_addr->src_addr.h_source, 6);

        ptr = vxinfo->inner_dmac;
        for(i = 0; i < 6; i++, ptr += 3){
            sprintf((char *)ptr, "%02x:", mac_addr->src_addr.h_dest[i]);
        }
        vxinfo->inner_dmac[17] = '\0'; /* 最后一位清零 */
        memcpy(vxinfo->inner_dmac_hex, mac_addr->src_addr.h_dest, 6);
    }
	return 0;
}


static void *MESA_get_stream_plug_pme_from_platform_entry(const StreamFunInfo *plug_pme_head, const void *this_plug_entry)
{
	void *this_plug_pme = NULL;
	
	while(plug_pme_head){
		if(plug_pme_head->pfun == this_plug_entry){
			this_plug_pme = plug_pme_head->pAppInfo;
			break;
		}
		plug_pme_head = plug_pme_head->next;
	}	

	return this_plug_pme;
}

/*
	根据插件入口函数和类型, 获取插件的私有存储空间指针pme.
*/
static int MESA_get_stream_plug_pme(const struct streaminfo *pstream, void *opt_val, int *opt_val_len)
{
	int ret = 0;
	struct mso_plug_pme *in_arg;
	const struct streaminfo_private *stream_pr;
	struct tcpdetail_private *ptcp_detail_pr;
	struct udpdetail_private *pudp_detail_pr;
	
	const void *this_plug_entry;
	void *plug_pme;
	
	if((NULL == opt_val) || (NULL == opt_val_len)){
		return -1;
	}

	if(*opt_val_len != sizeof(struct mso_plug_pme)){
		return -1;
	}

	in_arg = (struct mso_plug_pme *)opt_val;
	stream_pr = (struct streaminfo_private *)pstream;
	in_arg->plug_pme = NULL;

	this_plug_entry = plugin_get_plug_entry(in_arg->plug_name, in_arg->plug_entry_type);
	if(NULL == this_plug_entry){
		sapp_runtime_log(RLOG_LV_FATAL, "%s,MESA_get_stream_opt() MSO_STREAM_PLUG_PME error, can't get plug:%s entry:%s address", 
						printaddr(&pstream->addr, pstream->threadnum), in_arg->plug_name, in_arg->plug_entry_type); 
		return -1;
	}

	if(STREAM_TYPE_TCP == pstream->type){
		ptcp_detail_pr=(struct tcpdetail_private *)(pstream->pdetail);
		plug_pme = MESA_get_stream_plug_pme_from_platform_entry(ptcp_detail_pr->apme, this_plug_entry);
		if(plug_pme != NULL){
			in_arg->plug_pme = plug_pme;
			goto bingo;
		}
		plug_pme = MESA_get_stream_plug_pme_from_platform_entry(ptcp_detail_pr->pAllpktpme, this_plug_entry);
		if(plug_pme != NULL){
			in_arg->plug_pme = plug_pme;
			goto bingo;
		}		
	}else if(STREAM_TYPE_UDP == pstream->type){
		pudp_detail_pr = (struct udpdetail_private *)(pstream->pdetail);
		plug_pme = MESA_get_stream_plug_pme_from_platform_entry(pudp_detail_pr->apme, this_plug_entry);
		if(plug_pme != NULL){
			in_arg->plug_pme = plug_pme;
			goto bingo;
		}		
	}else{
		sapp_runtime_log(RLOG_LV_FATAL, "%s, MESA_get_stream_opt() MSO_STREAM_PLUG_PME error, not support stream type:%d", printaddr(&pstream->addr, pstream->threadnum),pstream->type); 
		return -1;
	}

	if(NULL == in_arg->plug_pme){
		ret = -1;
	}

bingo:
	
	return ret;
}


static int MESA_get_stream_dup_pkt_stat(const struct streaminfo *pstream, void *opt_val, int *opt_val_len)
{
	const struct streaminfo_private *pstream_pr = (struct streaminfo_private *)pstream;
	int *res_val = (int *)opt_val;
	int ret = 0;

	if((0 == sapp_global_val->config.packet_io.dup_pkt_para.dup_pkt_distinguish_all_inject)
		  && (0 == sapp_global_val->config.packet_io.dup_pkt_para.dup_pkt_distinguish_ipv4_tcp)
		  && (0 == sapp_global_val->config.packet_io.dup_pkt_para.dup_pkt_distinguish_ipv4_udp)){
		sapp_runtime_log(RLOG_LV_INFO, "%s, MESA_get_stream_opt() MSO_HAVE_DUP_PKT error, config DUPLICATE_PKT is not enable", 
						 printaddr(&pstream->addr, pstream->threadnum)); 
		*res_val = -2;
		return 0;
	}

	if(pstream_pr->has_duplicate_pkt != 0){
		*res_val = 1;
		return 0;
	}

	/* 开启了重复包检测功能,但还没发现有重复包   */
	if(STREAM_TYPE_TCP == pstream->type){
		if(pstream->ptcpdetail->clientpktnum + pstream->ptcpdetail->serverpktnum < SAPP_DUP_FIRST_PKT_NUM){ /* 包太少, 不足以判断有没有重复包 */
			*res_val = -2;
			sapp_runtime_log(RLOG_LV_DEBUG, "%s, MESA_get_stream_opt() MSO_HAVE_DUP_PKT, duplicate pkt state is pending, because has only recv %d pkt", 
						 printaddr(&pstream->addr, pstream->threadnum), pstream->ptcpdetail->clientpktnum + pstream->ptcpdetail->serverpktnum); 			
		}else{
			*res_val = 0;
		}
	}else if(STREAM_TYPE_UDP == pstream->type){
		if(pstream->pudpdetail->clientpktnum  + pstream->pudpdetail->serverpktnum < SAPP_DUP_FIRST_PKT_NUM){ /* 包太少, 不足以判断有没有重复包 */
			sapp_runtime_log(RLOG_LV_DEBUG, "%s, MESA_get_stream_opt() MSO_HAVE_DUP_PKT, duplicate pkt state is pending, because has only recv %d pkt", 
						 printaddr(&pstream->addr, pstream->threadnum), pstream->ptcpdetail->clientpktnum + pstream->ptcpdetail->serverpktnum); 		
			*res_val = -2;
		}else{
			*res_val = 0;
		}
	}else{
		sapp_runtime_log(RLOG_LV_INFO, "%s, MESA_get_stream_opt() MSO_HAVE_DUP_PKT error,  not support stream type:%d", 
						 printaddr(&pstream->addr, pstream->threadnum), pstream->type); 	
		*res_val = -2;				 
		ret = -1;
	}

	return ret;
}

int MESA_get_stream_opt(const struct streaminfo *pstream, enum MESA_stream_opt opt, void *opt_val, int *opt_val_len)
{
	int ret = 0;
	
	if((NULL == opt_val) || (NULL == opt_val_len) || (*opt_val_len <= 0)){
		return -1;
	}

	switch((int)opt){
		case (int)MSO_MAX_UNORDER:
		{
			if(STREAM_TYPE_TCP != pstream->type){
				sapp_runtime_log(RLOG_LV_INFO, "%s, MESA_get_stream_opt() MSO_MAX_UNORDER error:stream type is not tcp!\n", printaddr(&pstream->addr, pstream->threadnum));
				ret = -1;
				break;
			}		
			if(*opt_val_len < (int)sizeof(struct max_unorder_opt)){
				sapp_runtime_log(RLOG_LV_INFO,"%s, MESA_get_stream_opt() MSO_MAX_UNORDER error:opt_val_len invalid, must be sizeof(struct max_unorder_opt)\n", printaddr(&pstream->addr, pstream->threadnum));
				ret = -1;
				break;
			}
			*opt_val_len = sizeof(struct max_unorder_opt);			
			ret = tcp_get_single_stream_max_unorder(pstream, opt_val, opt_val_len);
		}
		break;

		case (int)MSO_NEED_ACK:
		{
			if(STREAM_TYPE_TCP != pstream->type){
				sapp_runtime_log(RLOG_LV_INFO,"%s, MESA_get_stream_opt() MSO_NEED_ACK error:stream type is not tcp!\n", printaddr(&pstream->addr, pstream->threadnum));
				ret = -1;
				break;
			}
			unsigned char *nack = (unsigned char *)opt_val;
			struct tcpdetail_private *pdetail_pr = (struct tcpdetail_private*)(pstream->pdetail);
			*nack = pdetail_pr->needackflag;
			*opt_val_len = sizeof(char);
		}
		break;

		case (int)MSO_TAKEOVER:
		{
			if(*opt_val_len < (int)sizeof(int)){
				ret = -1;
				break;
			}
			if(STREAM_TYPE_TCP != pstream->type){
				sapp_runtime_log(RLOG_LV_INFO,"%s, MESA_get_stream_opt() MSO_TAKEOVER error:stream type is not tcp!\n", printaddr(&pstream->addr, pstream->threadnum));
				ret = -1;
				break;
			}
			int *takeover = (int *)opt_val;
			struct tcpdetail_private *pdetail_pr=(struct tcpdetail_private*)(pstream->pdetail);
			*takeover = pdetail_pr->takeoverflag;
			*opt_val_len = sizeof(int);
		}
		break;

		case (int)MSO_TIMEOUT:
		{
			if(sizeof(short) != *opt_val_len){
				sapp_runtime_log(RLOG_LV_INFO,"%s, MESA_get_stream_opt() MSO_TIMEOUT error:opt_val_len invalid, must be sizeof(short)\n",printaddr(&pstream->addr, pstream->threadnum));
				ret = -1;
				break;
			}
			unsigned short *tmout = (unsigned short *)opt_val;
			struct streaminfo_private *pstream_pr=(struct streaminfo_private *)pstream;
			*tmout = pstream_pr->timeout;
			*opt_val_len = sizeof(short);
		}
		break;

		case (int)MSO_IGNORE_RST_FIN:
		{
			if(STREAM_TYPE_TCP != pstream->type){
				sapp_runtime_log(RLOG_LV_INFO,"%s, MESA_get_stream_opt() MSO_IGNORE_RST_FIN error:stream type is not tcp!\n",printaddr(&pstream->addr, pstream->threadnum));
				ret = -1;
				break;
			}
			unsigned char *igrstfin = (unsigned char *)opt_val;
			struct tcpdetail_private *pdetail_pr = (struct tcpdetail_private*)(pstream->pdetail);
			*igrstfin = pdetail_pr->ignore_rst_fin;	
		}	
		break;
		
		case MSO_TCP_CREATE_LINK_MODE:
		{
			struct tcpdetail_private *pdetail_pr;
			UCHAR *out_val = (UCHAR *)opt_val;
			if(STREAM_TYPE_TCP != pstream->type){
				ret = -1;
				sapp_runtime_log(RLOG_LV_INFO,"%s, MESA_get_stream_opt() MSO_TCP_CREATE_LINK_MODE error:stream type is not tcp!\n", printaddr(&pstream->addr, pstream->threadnum));
				break;
			}
			
			pdetail_pr = (struct tcpdetail_private*)(pstream->pdetail);
			*out_val = pdetail_pr->creat_mod;
			*opt_val_len = sizeof(char);
		}
		break;

		case MSO_TCP_ISN_C2S:
		{
			struct tcpdetail_private *pdetail_pr;
			UINT32 *out_val = (UINT32 *)opt_val;
			if(STREAM_TYPE_TCP != pstream->type){
				ret = -1;
				sapp_runtime_log(RLOG_LV_INFO, "%s, MESA_get_stream_opt() MSO_TCP_ISN_C2S error:stream type is not tcp!\n", printaddr(&pstream->addr, pstream->threadnum));
				break;
			}
 
			pdetail_pr = (struct tcpdetail_private*)(pstream->pdetail);
			if(pdetail_pr->creat_mod != TCP_CTEAT_LINK_BYSYN){
				ret = -1;
				sapp_runtime_log(RLOG_LV_INFO, "%s, MESA_get_stream_opt() MSO_TCP_ISN_C2S error: stream create mode is not by SYN!\n", printaddr(&pstream->addr, pstream->threadnum));
				break;
			}
			if(0 == pdetail_pr->iserverseq){
				ret = -1;
				sapp_runtime_log(RLOG_LV_INFO, "%s, MESA_get_stream_opt() MSO_TCP_ISN_C2S error: can't get SYN seq!\n", printaddr(&pstream->addr, pstream->threadnum));
				break;
			}
			
			*out_val = pdetail_pr->iserverseq - 1;
			*opt_val_len = sizeof(int);
		}
		break;

		case MSO_TCP_ISN_S2C:
		{
			/* TODO 1: 代码与上面重复, 待合并 */
			struct tcpdetail_private *pdetail_pr;
			UINT32 *out_val = (UINT32 *)opt_val;
			if(STREAM_TYPE_TCP != pstream->type){
				ret = -1;
				sapp_runtime_log(RLOG_LV_INFO, "%s,MESA_get_stream_opt() MSO_TCP_ISN_S2C error:stream type is not tcp!\n", printaddr(&pstream->addr, pstream->threadnum));
				break;
			}
			pdetail_pr = (struct tcpdetail_private*)(pstream->pdetail);
			if(pdetail_pr->creat_mod != TCP_CTEAT_LINK_BYSYN){
				ret = -1;
				sapp_runtime_log(RLOG_LV_INFO, "%s,MESA_get_stream_opt() MSO_TCP_ISN_S2C error: stream create mode is not by SYN!\n",printaddr(&pstream->addr, pstream->threadnum));
				break;
			}

			if(0 == pdetail_pr->iclientseq){
				ret = -1;
				sapp_runtime_log(RLOG_LV_INFO, "%s,MESA_get_stream_opt() MSO_TCP_ISN_S2C error: can't get SYN/ACK seq!\n",printaddr(&pstream->addr, pstream->threadnum));
				break;
			}

			*out_val = pdetail_pr->iclientseq - 1;
			*opt_val_len = sizeof(int);
		}
		break;

		case MSO_TCP_SYN_OPT:
		{
			const struct streaminfo_private *pstream_pr = (const struct streaminfo_private *)pstream;
			struct tcp_option **out_val = (struct tcp_option **)opt_val;
			if((pstream_pr->syn_opt_array != NULL) && (pstream_pr->syn_opt_num > 0)){
				*out_val = pstream_pr->syn_opt_array;
				*opt_val_len = pstream_pr->syn_opt_num; /* 此处不是长度, 表示opt_array的个数 */
				ret = 0;
			}else{
				ret = -1;
			}
		}
		break;

		case MSO_TCP_SYNACK_OPT:
		{
			const struct streaminfo_private *pstream_pr = (const struct streaminfo_private *)pstream;
			struct tcp_option **out_val = (struct tcp_option **)opt_val;
			if((pstream_pr->synack_opt_array != NULL) && (pstream_pr->synack_opt_num > 0)){
				*out_val = pstream_pr->synack_opt_array;
				*opt_val_len = pstream_pr->synack_opt_num;  /* 此处不是长度, 表示opt_array的个数 */
				ret = 0;
			}else{
				ret = -1;
			}
		}
		break;

		case MSO_STREAM_TUNNEL_TYPE:
		{
			const struct streaminfo_private *pstream_pr = (const struct streaminfo_private *)pstream;
			unsigned short *out_val = (unsigned short *)opt_val;
			*out_val = pstream_pr->stream_low_layer_tunnel_type;
			ret = 0;
		}
		break;

		case MSO_STREAM_UP_LAYER_TUNNEL_TYPE:
		{
			const struct streaminfo_private *pstream_pr = (const struct streaminfo_private *)pstream;
			unsigned short *out_val = (unsigned short *)opt_val;
			*out_val = pstream_pr->stream_carry_up_layer_tunnel_type;
			ret = 0;
		}
		break;

		case MSO_STREAM_CLOSE_REASON:
		{
			UCHAR *close_reason = (UCHAR *)opt_val;
			
			if(pstream->opstate != OP_STATE_CLOSE){
				ret = -1;
				sapp_runtime_log(RLOG_LV_DEBUG, "%s,MESA_get_stream_opt() MSO_STREAM_CLOSE_REASON error:has not closed!\n",printaddr(&pstream->addr, pstream->threadnum));
				break;				
			}
			if(STREAM_TYPE_TCP == pstream->type){
				const struct tcpdetail_private *pdetail_pr = (struct tcpdetail_private*)(pstream->pdetail);
				*close_reason = pdetail_pr->link_state;
			}else if(STREAM_TYPE_UDP == pstream->type){
				const struct streaminfo_private *pstream_pr = (const struct streaminfo_private *)pstream;
				*close_reason = pstream_pr->stream_close_reason;
			}else{
				ret = -1;
				sapp_runtime_log(RLOG_LV_INFO, "%s,MESA_get_stream_opt() MSO_STREAM_CLOSE_REASON error:unsupport stream type:%d!\n",printaddr(&pstream->addr, pstream->threadnum), pstream->type);
			}
		}
		break;

		case MSO_STREAM_VXLAN_INFO:
			if(DEPOLYMENT_MODE_MIRROR != g_topology_mode_raw){
				sapp_runtime_log(RLOG_LV_INFO, "MESA_get_stream_opt() error: can't support option MSO_STREAM_VXLAN_INFO in no mirror mode!");
				return -1;
			}		
			if(*opt_val_len != sizeof(struct vxlan_info)){
				return -1;
			}
			ret = sapp_get_vxlan_info_from_streaminfo(pstream, (struct vxlan_info *)opt_val);
		break;

		case MSO_GLOBAL_STREAM_ID:
		{
			const struct streaminfo_private *pstream_pr;
			if(*opt_val_len != sizeof(long long)){
				return -1;
			}
			pstream_pr = (const struct streaminfo_private *)pstream;
			unsigned long long *out_args = (unsigned long long *)opt_val;
			unsigned long long dev_id = *out_args;
			if(dev_id < 0 || dev_id > 4095){
				sapp_runtime_log(RLOG_LV_INFO, "%s,MESA_get_stream_opt() MSO_GLOBAL_STREAM_ID error:invalid dev_id:%llu!\n", printaddr(&pstream->addr, pstream->threadnum), dev_id);
				return -1;
			}
			unsigned long long local_global_id = pstream_pr->global_stream_id;

			*out_args = local_global_id | (dev_id << 51);
			ret = 0;
		}
		break;

		case MSO_TOTAL_INBOUND_PKT:
		{
			if((STREAM_TYPE_TCP != pstream->type) && (STREAM_TYPE_UDP != pstream->type)){
				sapp_runtime_log(RLOG_LV_INFO, "%s,MESA_get_stream_opt() MSO_TOTAL_INBOUND_PKT error: stream type is not tcp or udp!\n",printaddr(&pstream->addr, pstream->threadnum));
				ret = -1;
				break;
			}
			unsigned long long *inbound_pkt = (unsigned long long *)opt_val;
			*inbound_pkt = __get_stream_opt_traffic('c', 'i', (struct streaminfo_private *)pstream);
		}	
		break;

		case MSO_TOTAL_OUTBOUND_PKT:
		{
			if((STREAM_TYPE_TCP != pstream->type) && (STREAM_TYPE_UDP != pstream->type)){
				sapp_runtime_log(RLOG_LV_INFO, "%s,MESA_get_stream_opt() MSO_TOTAL_OUTBOUND_PKT error: stream type is not tcp or udp!\n",printaddr(&pstream->addr, pstream->threadnum));
				ret = -1;
				break;
			}
			unsigned long long *outbound_pkt = (unsigned long long *)opt_val;
			*outbound_pkt = __get_stream_opt_traffic('c', 'o', (struct streaminfo_private *)pstream);
		}	
		break;

		case MSO_TOTAL_INBOUND_BYTE:
		{
			if((STREAM_TYPE_TCP != pstream->type) && (STREAM_TYPE_UDP != pstream->type)){
				sapp_runtime_log(RLOG_LV_INFO, "%s,MESA_get_stream_opt() MSO_TOTAL_INBOUND_BYTE error: stream type is not tcp or udp!\n",printaddr(&pstream->addr, pstream->threadnum));
				ret = -1;
				break;
			}
			unsigned long long *inbound_byte = (unsigned long long *)opt_val;
			*inbound_byte = __get_stream_opt_traffic('l', 'i', (struct streaminfo_private *)pstream);
		}	
		break;

		case MSO_TOTAL_INBOUND_BYTE_RAW:
		{
			if(STREAM_TYPE_TCP == pstream->type){
				if(G_TCP_FLOW_STAT_PROJECT_ID == -1){
					ret = -1;
					sapp_runtime_log(RLOG_LV_INFO, "%s,MESA_get_stream_opt() MSO_TOTAL_INBOUND_BYTE_RAW error: project tcp_flow_stat is not enable!\n",printaddr(&pstream->addr, pstream->threadnum));
					break;
				}
			}else if(STREAM_TYPE_UDP == pstream->type){
				if(G_UDP_FLOW_STAT_PROJECT_ID == -1){
					ret = -1;
					sapp_runtime_log(RLOG_LV_INFO, "%s,MESA_get_stream_opt() MSO_TOTAL_INBOUND_BYTE_RAW error: project udp_flow_stat is not enable!\n",printaddr(&pstream->addr, pstream->threadnum));
					break;
				}
			}else{
				sapp_runtime_log(RLOG_LV_INFO, "%s,MESA_get_stream_opt() MSO_TOTAL_INBOUND_BYTE error: stream type is not tcp or udp!\n",printaddr(&pstream->addr, pstream->threadnum));
				ret = -1;
				break;
			}

			unsigned long long *inbound_byte = (unsigned long long *)opt_val;
			*inbound_byte = __get_stream_opt_traffic_raw('l', 'i', (struct streaminfo_private *)pstream);
		}
		break;

		
		case MSO_TOTAL_OUTBOUND_BYTE:
		{
			if((STREAM_TYPE_TCP != pstream->type) && (STREAM_TYPE_UDP != pstream->type)){
				sapp_runtime_log(RLOG_LV_INFO, "%s,MESA_get_stream_opt() MSO_TOTAL_OUTBOUND_BYTE error: stream type is not tcp or udp!\n",printaddr(&pstream->addr, pstream->threadnum));
				ret = -1;
				break;
			}
			unsigned long long *outbound_byte = (unsigned long long *)opt_val;
			*outbound_byte = __get_stream_opt_traffic('l', 'o', (struct streaminfo_private *)pstream);
		}	
		break;

		case MSO_TOTAL_OUTBOUND_BYTE_RAW:
		{
			if(STREAM_TYPE_TCP == pstream->type){
				if(G_TCP_FLOW_STAT_PROJECT_ID == -1){
					ret = -1;
					sapp_runtime_log(RLOG_LV_INFO, "%s,MESA_get_stream_opt() MSO_TOTAL_INBOUND_BYTE_RAW error: project tcp_flow_stat is not enable!\n",printaddr(&pstream->addr, pstream->threadnum));
					break;
				}
			}else if(STREAM_TYPE_UDP == pstream->type){
				if(G_UDP_FLOW_STAT_PROJECT_ID == -1){
					ret = -1;
					sapp_runtime_log(RLOG_LV_INFO, "%s,MESA_get_stream_opt() MSO_TOTAL_INBOUND_BYTE_RAW error: project udp_flow_stat is not enable!\n",printaddr(&pstream->addr, pstream->threadnum));
					break;
				}
			}else{
				sapp_runtime_log(RLOG_LV_INFO, "%s,MESA_get_stream_opt() MSO_TOTAL_INBOUND_BYTE error: stream type is not tcp or udp!\n",printaddr(&pstream->addr, pstream->threadnum));
				ret = -1;
				break;
			}

			unsigned long long *outbound_byte = (unsigned long long *)opt_val;
			*outbound_byte = __get_stream_opt_traffic_raw('l', 'o', (struct streaminfo_private *)pstream);
		}
		break;
		
		case MSO_STREAM_CREATE_TIMESTAMP_MS:
		{
			if ((STREAM_TYPE_TCP != pstream->type) && (STREAM_TYPE_UDP != pstream->type))
			{
				sapp_runtime_log(RLOG_LV_INFO, "%s,MESA_get_stream_opt() MSO_STREAM_CREATE_TIMESTAMP_MS error: stream type is not tcp or udp!\n",printaddr(&pstream->addr, pstream->threadnum));
				ret = -1;
				break;
			}
			unsigned long long *timestamp_ms = (unsigned long long *)opt_val;
			*timestamp_ms = ((struct streaminfo_private *)pstream)->stream_create_timestamp_ms;
		}
		break;

		case MSO_STREAM_PLUG_PME:
			ret = MESA_get_stream_plug_pme(pstream, opt_val, opt_val_len);
		break;

		case MSO_HAVE_DUP_PKT:
			ret = MESA_get_stream_dup_pkt_stat(pstream, opt_val, opt_val_len);
		break;
		
		default:
			sapp_runtime_log(RLOG_LV_INFO, "%s,MESA_get_stream_opt() error:unsupport MESA_stream_opt type:%d!\n",printaddr(&pstream->addr, pstream->threadnum), (int)opt);
			ret = -1;
			break;		
	}

	return ret;
}

int is_proxy_stream(const struct streaminfo *pstream)
{
	int ret = 0;
	
	switch(pstream->type){
		case STREAM_TYPE_SOCKS4:
		case STREAM_TYPE_SOCKS5:
		case STREAM_TYPE_HTTP_PROXY:
		case STREAM_TYPE_OPENVPN:
			ret = 1;
		break;

		default:
			ret = 0;
			break;
	}

	return ret;
}


void bind_thread_to_cpuid(int thread_id)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 18)
#if(__GNUC__ * 100 + __GNUC_MINOR__ * 10 + __GNUC_PATCHLEVEL__ >= 440)
	cpu_set_t cpuset;
	u_long core_id;
	int res;
	int tot_cpu_num = sysconf(_SC_NPROCESSORS_ONLN);

	/* Bind this thread to a specific core */
	if(tot_cpu_num > 1) {
		core_id = (thread_id + 1) % tot_cpu_num; 

		CPU_ZERO(&cpuset);
		CPU_SET(core_id, &cpuset);
		res = pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);
		if (res != 0){
			fprintf(stderr, "Error while binding thread %d to core %ld: errno=%i\n", 
	     			thread_id, core_id, res);
	      }else{
			printf("[Info]Binding thread %d to core %ld success!\n", thread_id, core_id);
	      }
	}
#endif	
#endif
	return;
}


extern int project_req_terminal_tag_id;
/* For863, 用于应用层插件获取本TCP流中对应的用户标签 */
const unsigned char *get_terminal_tag(struct streaminfo *stream)
{
	unsigned char *terminal_tag;
	
	if(project_req_terminal_tag_id < 0){
		return NULL;
	}
	
	terminal_tag = (unsigned char *)project_req_get_struct(stream, project_req_terminal_tag_id);
	
	return (const unsigned char *)terminal_tag;
}

int number_is_2powerN(uint n)
{
	if(n & (n-1)){
		return 0;
	}    

	return 1;
}



void *dictator_malloc(int thread_seq,size_t size)
{	
	/*
	if(malloccount%100000==0)
	{
		printf("malloc=%d,free=%d\n",malloccount,freecount);
	}
	*/

	if(G_DICTATOR_SW){
#if USE_MEMPOOL
		return __dictator_malloc(thread_seq, size);
#endif		
	}

	return malloc(size);
}	
void dictator_free(int thread_seq,void *pbuf)
{
#if USE_MEMPOOL	
	if(G_DICTATOR_SW){
		__dictator_free(thread_seq, pbuf);
	}
	else
#endif
	{
#if SAPP_INSECTICIDE	
		*((char *)pbuf) = 0xFE;
#endif
		free(pbuf);
	}
}

void *dictator_realloc(int thread_seq, void *ptr, size_t size)
{
#if USE_MEMPOOL	
	if(G_DICTATOR_SW){
		return __dictator_realloc(thread_seq, ptr, size);
	}
#endif

	return realloc(ptr, size);
}

/* 将业务插件返回的值转换成平台定义的值, 即将PROT_STATE_xxx转换为APP_STATE_xxx */
char biz_retval_to_platform(char biz_ret)
{
	char plat_ret = 0;

	if(biz_ret & PROT_STATE_GIVEME){
		plat_ret |= APP_STATE_GIVEME;
	}

	if(biz_ret & PROT_STATE_DROPME){
		plat_ret |= APP_STATE_DROPME;
	}

	if(biz_ret & PROT_STATE_DROPPKT){
		plat_ret |= APP_STATE_DROPPKT;
	}
	
	return plat_ret;
}

/* 将平台的state值转换成业务插件的值, 即将OP_STATE_PENDING转为SESSION_STATE_PENDING */
char plat_state_to_biz(char plat_state)
{
	char biz_ret = SESSION_STATE_CLOSE;

	switch(plat_state){
		case OP_STATE_PENDING:
			biz_ret = SESSION_STATE_PENDING;
		break;

		case OP_STATE_DATA:
			biz_ret = SESSION_STATE_DATA;
		break;

		case OP_STATE_CLOSE:
			biz_ret = SESSION_STATE_CLOSE;
		break;

		default:
		break;
	}

	return biz_ret;
}


long long sapp_get_cpu_cycle(void)
{
#ifdef __x86_64
#define X86_64_ENV 1
#endif
#ifdef  __x86_64__
#define X86_64_ENV 1
#endif

#ifdef X86_64_ENV
	 long long l;
	 long long h;

	__asm__ volatile("rdtsc" : "=a"(l), "=d"(h));
	return (long long )l | ((long long )h<<32);
#else
	return 0;
#endif
}

void sapp_set_current_state(enum sapp_state_t state)
{
	sapp_global_val->individual_volatile->current_state = (int)state;
}

enum sapp_state_t sapp_get_current_state(void)
{
	return (enum sapp_state_t)sapp_global_val->individual_volatile->current_state;
}

int sapp_size_of_sapp_global(void)
{
	return sizeof(sapp_global_t);
}


int sapp_size_of_streaminfo_private(void)
{
	return sizeof(struct streaminfo_private);
}

int sapp_size_of_tcpdetail_private(void)
{
	return sizeof(struct tcpdetail_private);
}

int sapp_size_of_udpdetail_private(void)
{
	return sizeof(struct udpdetail_private);
}

int sapp_size_of_raw_pkt_t(void)
{
	return sizeof(raw_pkt_t);
}


char *sapp_strdup(const char *raw_s)
{
	int buflen = strlen(raw_s) + 1; //add EOF
	char *new_s = (char *)calloc(1, buflen);
	memcpy(new_s, raw_s, buflen);

	return new_s;
}

int sapp_is_absolute_path(const char *filename)
{
	if('/' == filename[0]){
		return 1;
	}

	return 0;
}


void *sapp_mem_alloc(int size)
{
	char *ptr = (char *)calloc(1, size + sizeof(sapp_private_mem_t));
	sapp_private_mem_t *mhdr = (sapp_private_mem_t *)ptr;

	mhdr->magic = 0x4D4D4D4D; 
	mhdr->user_buf_size = size;
	
	return ptr + sizeof(sapp_private_mem_t);
}


void sapp_mem_free(void *data)
{	
	char *ptr = (char *)data;

	sapp_private_mem_t *mhdr = (sapp_private_mem_t *)(ptr - sizeof(sapp_private_mem_t));

	assert(0x4D4D4D4D == mhdr->magic);

	mhdr->magic = 0xFEFEFEFE;
	
	free(mhdr);
}

void *sapp_mem_realloc(void *old_ptr, int size)
{
	void *new_ptr;
	sapp_private_mem_t *mhdr;
	
	if(NULL == old_ptr){ /* first time,  NULL pointer, same to sapp_mem_alloc() */
		return sapp_mem_alloc(size);
	}

	mhdr = (sapp_private_mem_t *)((char *)old_ptr - sizeof(sapp_private_mem_t));
	new_ptr = sapp_mem_alloc(size);
	memmove(new_ptr, old_ptr, mhdr->user_buf_size); 

	sapp_mem_free(old_ptr);

	return new_ptr;
}


long long sapp_random(void)
{
	struct timespec curtime;

	clock_gettime(CLOCK_MONOTONIC, &curtime);

	return (curtime.tv_nsec * 131) ^ curtime.tv_sec;
}

int sapp_usleep(int usec)
{
	struct timespec sleep_time_val;

	sleep_time_val.tv_sec = 0;
	sleep_time_val.tv_nsec = usec * 1000;

	nanosleep(&sleep_time_val, NULL);

	return 0;
}



#ifdef __cplusplus
}
#endif

