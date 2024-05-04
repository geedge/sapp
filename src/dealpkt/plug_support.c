/*
	���ļ���ƽ̨������Ҫ�Ĺ��ܺͺ���,
	���ṩ������ҵ�����Ľӿ�, ��MESA_set_stream_opt, printaddr��,
*/
#include "sapp_api.h"
#include "sapp_private_api.h"
#include "sapp_declaration.h"
#include "stream_inc/stream_base.h"
#include "stream_inc/stream_control.h"
#include "stream_inc/stream_rawpkt.h"

#ifdef __cplusplus
extern "C" {
#endif
extern int G_TCP_FLOW_STAT_PROJECT_ID ;
extern int G_UDP_FLOW_STAT_PROJECT_ID ;


extern const raw_ipfrag_list_t *get_raw_frag_list(const struct streaminfo *stream);
#if IOMODE_MARSIO
extern void * (*ptr_marsio_buff_ctrlzone)(marsio_buff_t *m, uint8_t id);
#endif


static struct segment_id_list *segment_id_list_dup(sapp_mem_type_t type, int tid, const struct segment_id_list *slist)
{
	if(slist == NULL || slist->sz_sidlist == 0) return NULL;
	struct segment_id_list *dlist = (struct segment_id_list *)sapp_mem_calloc(type, tid, sizeof(struct segment_id_list));
	memcpy(dlist->sid_list, slist->sid_list, sizeof(short) * slist->sz_sidlist);
	dlist->sz_sidlist = slist->sz_sidlist;
	return dlist;
}

struct detain_pkt* MESA_rawpkt_detain(const struct streaminfo *pstream, const void *rawpkt)
{
	if(pstream == NULL || rawpkt == NULL)return NULL;

	raw_pkt_t *p_rawpkt = (raw_pkt_t *)rawpkt;
	assert(p_rawpkt->magic_num == RAW_PKT_MAGIC_NUM);
	if(p_rawpkt->magic_num != RAW_PKT_MAGIC_NUM )return NULL;
	
	if(p_rawpkt->d_pkt)return NULL; // rawpkt can be retained only once
	if(p_rawpkt->drop_current_pkt_flag == 1)return NULL; // rawpkt need to be drop, can not be retained

	if(sapp_global_val->config.packet_io.deployment_mode_bin != DEPLOYMENT_MODE_INLINE)return NULL;

	struct detain_pkt *d_pkt = (struct detain_pkt*)sapp_mem_calloc(SAPP_MEM_DYN_DETAIN_PKT, pstream->threadnum,  sizeof(struct detain_pkt));
	d_pkt->original = (const raw_pkt_t *)rawpkt;
	memcpy(&d_pkt->replica, p_rawpkt, sizeof(raw_pkt_t));
	d_pkt->replica.append_list=NULL;
	d_pkt->replica.prepend_list=NULL;
	if(p_rawpkt->append_list!= NULL && p_rawpkt->append_list->sz_sidlist > 0)
	{
		d_pkt->replica.append_list = segment_id_list_dup(SAPP_MEM_DYN_DETAIN_PKT, pstream->threadnum, p_rawpkt->append_list);
	}
	if(p_rawpkt->prepend_list!= NULL && p_rawpkt->prepend_list->sz_sidlist > 0)
	{
		d_pkt->replica.prepend_list = segment_id_list_dup(SAPP_MEM_DYN_DETAIN_PKT, pstream->threadnum, p_rawpkt->prepend_list);
	}
	p_rawpkt->d_pkt = d_pkt;
	d_pkt->tid = pstream->threadnum;

	return d_pkt;
}

static void detain_pkt_mem_free(struct detain_pkt *pkt)
{
	if(pkt == NULL)return;
	if(pkt->replica.append_list)
	{
		sapp_mem_free(SAPP_MEM_DYN_DETAIN_PKT, pkt->tid, pkt->replica.append_list);
	}
	if(pkt->replica.prepend_list)
	{
		sapp_mem_free(SAPP_MEM_DYN_DETAIN_PKT, pkt->tid, pkt->replica.prepend_list);
	}
	sapp_mem_free(SAPP_MEM_DYN_DETAIN_PKT, pkt->tid, pkt);
}

int MESA_detain_pkt_forward(struct detain_pkt *pkt)
{
	if(pkt->original == NULL) //original packet stack finished, being processed by all plugin;
	{
		if(pkt->replica.__lib_raw_pkt_len > 0 && pkt->replica.__lib_raw_pkt_data && pkt->replica.io_lib_pkt_reference)
		{
			dl_io_fun_list.dl_io_forward_rawpkt(&pkt->replica, pkt->tid);
		}
		detain_pkt_mem_free(pkt);
		pkt = NULL;
	}
	else //still in original packet stack, need be processed by follow-up plugin, mark operation to replica;
	{
		if(pkt->mark != RETAIN_RAWPKT)
		{
			return -1; // redundant operation, return abnormal
		}
		pkt->mark = FORWARD_RAWPKT;
	}
	return 0;
}

/* overwrite prepend and append list of current detain pakcet with the data from stream context raw packet  */
int MESA_detain_pkt_forward_based_on_stream(const struct streaminfo *pstream, struct detain_pkt *dpkt)
{
	if (pstream == NULL || dpkt == NULL) return -1;

	const struct streaminfo_private *pstream_pr = (const struct streaminfo_private *)pstream;

	if(pstream_pr->sid_append_list != NULL)
	{
		if (dpkt->replica.append_list != NULL)
		{
			memset(dpkt->replica.append_list, 0, sizeof(struct segment_id_list));
			memcpy(dpkt->replica.append_list->sid_list, pstream_pr->sid_append_list->sid_list, sizeof(unsigned short) * pstream_pr->sid_append_list->sz_sidlist);
			dpkt->replica.append_list->sz_sidlist = pstream_pr->sid_append_list->sz_sidlist;
		}
		else
		{
			dpkt->replica.append_list = segment_id_list_dup(SAPP_MEM_DYN_DETAIN_PKT, pstream->threadnum, pstream_pr->sid_append_list);
		}
	}

	if(pstream_pr->sid_prepend_list)
	{
		if (dpkt->replica.prepend_list != NULL)
		{
			memset(dpkt->replica.prepend_list, 0, sizeof(struct segment_id_list));
			memcpy(dpkt->replica.prepend_list->sid_list, pstream_pr->sid_prepend_list->sid_list, sizeof(unsigned short) * pstream_pr->sid_prepend_list->sz_sidlist);
			dpkt->replica.prepend_list->sz_sidlist = pstream_pr->sid_prepend_list->sz_sidlist;
		}
		else
		{
			dpkt->replica.prepend_list = segment_id_list_dup(SAPP_MEM_DYN_DETAIN_PKT, pstream->threadnum, pstream_pr->sid_prepend_list);
		}
	}
	dpkt->replica.stream_trace_id = ((struct streaminfo_private *)pstream)->stream_trace_id;

	return MESA_detain_pkt_forward(dpkt);
}

void MESA_detain_pkt_free(struct detain_pkt *pkt)
{
	if(pkt->original == NULL) //original packet stack finished, being processed by all plugin;
	{
		if(pkt->replica.__lib_raw_pkt_len > 0 && pkt->replica.__lib_raw_pkt_data && pkt->replica.io_lib_pkt_reference)
		{
			dl_io_fun_list.dl_io_free_rawpkt(&pkt->replica, pkt->tid);
		}
		detain_pkt_mem_free(pkt);
		pkt = NULL;

	}
	else //still in original packet stack, need be processed by follow-up plugin, mark operation to replica;
	{
		if(pkt->mark == RETAIN_RAWPKT)
		{
			pkt->mark = FREE_RAWPKT;
		}
	}
}

int MESA_retain_pkt_update(const raw_pkt_t *p_raw_pkt, int pkt_ret)
{
	int update_ret = pkt_ret;

	assert(p_raw_pkt->magic_num == RAW_PKT_MAGIC_NUM);
	if(p_raw_pkt->magic_num != RAW_PKT_MAGIC_NUM )return pkt_ret;

    if (p_raw_pkt->d_pkt != NULL)// have retain operation
    {
        if (p_raw_pkt->d_pkt->mark == RETAIN_RAWPKT) //retain pkt in use
        {
            if (pkt_ret == PASS)
            {
                update_ret = RETAIN;
            }
            if (pkt_ret == DROP)
            {
                p_raw_pkt->d_pkt->replica.io_lib_pkt_reference = NULL;
                p_raw_pkt->d_pkt->replica.__lib_raw_pkt_data = NULL;
                p_raw_pkt->d_pkt->replica.__lib_raw_pkt_len = 0;
            }
            p_raw_pkt->d_pkt->original = NULL;
        }
        else //During the processing of the original package, the retained pkt being called forward or free, so it is directly released
        {
            if (p_raw_pkt->d_pkt->mark == FREE_RAWPKT)
            {
                update_ret = DROP;
            }
			detain_pkt_mem_free(p_raw_pkt->d_pkt);
        }
    }
	return update_ret;
}


extern int marsio_get_route_dir_from_mbuff(void *pkt_reference);
extern int marsio_get_link_id_from_mbuff(void *pkt_reference);




int get_opt_from_rawpkt(const void *voidpkt, int type, void *void_value)
{
	int ret = 0;
	const raw_pkt_t *rawpkt = (const raw_pkt_t *)voidpkt;

	if(NULL == voidpkt || NULL == void_value){
		return -1;
	}

	if(RAW_PKT_MAGIC_NUM != rawpkt->magic_num){ /* ������Դ��pappƽ̨, ��֧�ִ��๦�� */
		return -1;
	}
	
	switch(type){
		case RAW_PKT_GET_DATA:
		{
			void **out_value = (void **)void_value;
			*out_value = (char *)rawpkt->raw_pkt_data + rawpkt->overlay_layer_bytes;
		}
		ret = rawpkt->raw_pkt_len-rawpkt->overlay_layer_bytes;
		break;

		case RAW_PKT_GET_RAW_PKT_TYPE:
		{
			enum addr_type_t *out_value = (enum addr_type_t *)void_value;
			*out_value = rawpkt->low_layer_type;
		}
		ret = sizeof(rawpkt->low_layer_type);
		break;		

		case RAW_PKT_GET_TOT_LEN:
		{
			int *out_value = (int *)void_value;
			*out_value = rawpkt->raw_pkt_len - rawpkt->overlay_layer_bytes;
		}
		ret = sizeof(int);
		break;

		case RAW_PKT_GET_TIMESTAMP:
		{
			struct timeval *out_value =(struct timeval *)void_value;
			memcpy(out_value, &rawpkt->raw_pkt_ts, sizeof(struct timeval));
		}
		ret = sizeof(struct timeval);
		break;
		
		case RAW_PKT_GET_THIS_LAYER_HDR:
		{
			void **out_value = (void **)void_value;
			const char *this_layer_hdr = (const char *)rawpkt->raw_pkt_data + rawpkt->offset_to_raw_pkt_hdr;
			*out_value = (void *)this_layer_hdr;
		}
		ret = rawpkt->raw_pkt_len - rawpkt->offset_to_raw_pkt_hdr;
		break;

		case RAW_PKT_GET_THIS_LAYER_REMAIN_LEN:
		{
			int *out_value = (int *)void_value;
			*out_value = rawpkt->raw_pkt_len - rawpkt->offset_to_raw_pkt_hdr;
		}
		ret = sizeof(int);
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


		/* ���ڲ����ȡ��ײ���ʵmac��ַ, ����ʲôģʽ, ��û��mrtunnat, ������һ���ӿ� */
        case RAW_PKT_GET_ORIGINAL_LOWEST_ETH_SMAC: {
            const struct mesa_ethernet_hdr *lowest_ehdr;
            lowest_ehdr = (struct mesa_ethernet_hdr *)rawpkt->raw_pkt_data;
            memcpy(void_value, lowest_ehdr->ether_shost, ETH_ALEN);
            ret = ETH_ALEN;
        }
        break;

        /* ���ڲ����ȡ��ײ���ʵmac��ַ, ����ʲôģʽ, ��û��mrtunnat, ������һ���ӿ� */
        case RAW_PKT_GET_ORIGINAL_LOWEST_ETH_DMAC: {
            const struct mesa_ethernet_hdr *lowest_ehdr;
            lowest_ehdr = (struct mesa_ethernet_hdr *)rawpkt->raw_pkt_data;
            memcpy(void_value, lowest_ehdr->ether_dhost, ETH_ALEN);
			ret = ETH_ALEN;
        }
        break;

		case RAW_PKT_GET_IS_CTRL_PKT:
		{
			int *out_value = (int *)void_value;
			*out_value = rawpkt->is_ctrl_pkt;
		}
		ret = sizeof(int);
		break;

		case RAW_PKT_GET_ROUTE_DIR:
		{
            int *out_value = (int *)void_value;
            *out_value = marsio_get_route_dir_from_mbuff((void *)rawpkt->io_lib_pkt_reference);
            ret = *out_value;
        }
		break;
		case RAW_PKT_GET_LINK_ID:
		{
            int *out_value = (int *)void_value;
            *out_value = marsio_get_link_id_from_mbuff((void *)rawpkt->io_lib_pkt_reference);
            ret = *out_value;
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

	if(DEPLOYMENT_MODE_INLINE != g_topology_mode_raw){
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
			*out_value = pudp_hdr->uh_sport; /* ���հ��ĽǶ�����, src port��inline�豸��sport */
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

		/* ���հ��ĽǶ�����, src host��inline�豸��mac */
		case RAW_PKT_GET_VXLAN_OUTER_GDEV_MAC:
		{
			const struct mesa_ethernet_hdr *p_eth_hdr = (struct mesa_ethernet_hdr *)rawpkt->raw_pkt_data;
			memcpy(void_value, p_eth_hdr->ether_shost, ETH_ALEN);
		}
		break;

		/* ���հ��ĽǶ�����, dst host�Ǳ�����mac */
		case RAW_PKT_GET_VXLAN_OUTER_LOCAL_MAC:
		{
			const struct mesa_ethernet_hdr *p_eth_hdr = (struct mesa_ethernet_hdr *)rawpkt->raw_pkt_data;
			memcpy(void_value, p_eth_hdr->ether_dhost, ETH_ALEN);
		}
		break;	
	}

	return ret;
}

inline const void *get_current_rawpkt_from_streaminfo(const struct streaminfo *pstream)
{
	const struct streaminfo_private *pstream_pr = (const struct streaminfo_private *)pstream;
	if(likely(pstream_pr->plugin_process_context != 0))
	{
		return pstream_pr->raw_pkt;
	}
	return NULL;
}


const void *get_rawpkt_from_streaminfo(const struct streaminfo *pstream, int route_direction)
{
	const struct streaminfo_private *pstream_pr = (const struct streaminfo_private *)pstream;
	if(pstream_pr->polling_inject_context == NULL)return NULL;
	int c2s_route_dir=MESA_dir_link_to_human(pstream_pr->stream_c2s_route_dir);
    if (c2s_route_dir==(int)'E')
    {
		if(route_direction == DIR_ROUTE_UP)
        	return pstream_pr->polling_inject_context->raw_pkt_stream_dir[DIR_C2S - 1];
		else
			return pstream_pr->polling_inject_context->raw_pkt_stream_dir[DIR_S2C - 1];
    }
    if (c2s_route_dir==(int)'I')
    {
		if(route_direction == DIR_ROUTE_UP)
			return pstream_pr->polling_inject_context->raw_pkt_stream_dir[DIR_S2C - 1];
		else
        	return pstream_pr->polling_inject_context->raw_pkt_stream_dir[DIR_C2S - 1];
    }
    return NULL;
}

const void *get_rawpkt_by_stream_dir(const struct streaminfo *pstream, int stream_direction)
{
	const struct streaminfo_private *pstream_pr = (const struct streaminfo_private *)pstream;
	if(pstream_pr->polling_inject_context == NULL)return NULL;
    if (stream_direction==DIR_C2S)
    {
		return pstream_pr->polling_inject_context->raw_pkt_stream_dir[DIR_C2S - 1];
    }
    if (stream_direction==DIR_S2C)
    {
        return pstream_pr->polling_inject_context->raw_pkt_stream_dir[DIR_S2C - 1];
    }
    return NULL;
}

const struct streaminfo *get_streaminfo_from_rawpkt(const void *rawpkt)
{
	if(NULL == rawpkt)return NULL;
	const raw_pkt_t *p_rawpkt = (const raw_pkt_t *)rawpkt;
	if(p_rawpkt->magic_num != RAW_PKT_MAGIC_NUM || p_rawpkt->io_lib_pkt_reference == NULL)
	{
		return NULL;
	}
	const struct streaminfo_private *pstream_pr = container_of(rawpkt, struct streaminfo_private, raw_pkt);
	if(pstream_pr)
	{
		return &pstream_pr->stream_public;
	}
	return NULL;
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

	/* sappv4.2֮��, û��mrtunnat, �޷���ctrlzone��ȡ��Щvxlan��ص��?, Ҫ��streaminfo->pfatherƫ�ƻ�ȡ */
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

	switch(type)
	{
		case RAW_PKT_GET_ROUTE_CTX:
		{
			void **value = (void **)out_value;
			if(pstream_pr->polling_inject_context!= NULL && pstream_pr->polling_inject_context->meta_stream_dir[pstream->curdir - 1] != NULL)
			{
				*value = (void *)(pstream_pr->polling_inject_context->meta_stream_dir[pstream->curdir - 1]->data);
				ret = pstream_pr->polling_inject_context->meta_stream_dir[pstream->curdir - 1]->sz_data;
			}
			return ret;
		}
		break;
        case RAW_PKT_GET_SID_LIST:
		{
			void **value = (void **)out_value;
			if(pstream_pr->polling_inject_context!= NULL && pstream_pr->polling_inject_context->meta_stream_dir[pstream->curdir - 1] != NULL)
			{
				*value = (void *)(&pstream_pr->polling_inject_context->meta_stream_dir[pstream->curdir - 1]->raw_sid_list);
				ret = sizeof(struct segment_id_list);
			}
			return ret;
		}
		break;
	}
	
	return get_opt_from_rawpkt(pstream_pr->raw_pkt, type, out_value);
}

/*Convert tuple4 to string. Format: 10.0.0.1, 1234->10.0.0.2,5678*/
const char *printaddr (const struct layer_addr *paddrinfo,int threadindex)
{

	if(MESA_handle_runtime_log_level_enabled(ABBR_SAPP_LOG_HANDLE, RLOG_LV_INFO) == 0)
	{
		return NULL;
	}
	
	static char maxbuf[MAX_THREAD_NUM][128];
	char *buf=(char*)maxbuf[threadindex];
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

	if(MESA_handle_runtime_log_level_enabled(ABBR_SAPP_LOG_HANDLE, RLOG_LV_INFO) == 0)
	{
		return NULL;
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


time_t get_timestamp_s(void)
{
	return g_CurrentTime;
}

long long get_timestamp_ms(void)
{
	return g_CurrentTime_ms;
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

extern void marsio4_emit_datapath_telemetry(const raw_pkt_t *raw_pkt,  const char * module, const char *str);

inline void sapp_emit_datapath_telemetry(const void *raw_pkt,  const char * module, const char *str)
{
	return marsio4_emit_datapath_telemetry((const raw_pkt_t *)raw_pkt, module, str);
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
		case MSO_STREAM_TIMED:
		{
			if(sizeof(int) != opt_val_len){
				sapp_runtime_log(RLOG_LV_INFO, "%s, MESA_set_stream_opt() MSO_TIMEOUT error:opt_val_len invalid, must be sizeof(short)\n",printaddr(&pstream->addr, pstream->threadnum));
				ret = -1;
				break;
			}
			unsigned int set_timer_s = *((unsigned short *)opt_val);
			struct streaminfo_private *pstream_pr=(struct streaminfo_private *)pstream;
			StreamFunInfo *funinfo = (StreamFunInfo *)pstream_pr->cur_plugin_cb_func;
			funinfo->pstream = pstream;
			funinfo->set_timer_s = set_timer_s;
			if(false == timeout_pending(&funinfo->timeout))
			{
				timeout_init(&funinfo->timeout, TIMEOUT_ABS);
				G_MESA_GLOBAL_STREAM[pstream->threadnum]->user_define_timer_cnt+=1;
			}
			timeouts_add(G_MESA_GLOBAL_STREAM[pstream->threadnum]->user_define_timer, &funinfo->timeout, set_timer_s*1000+g_CurrentTime_ms);
			ret = 0;
		}
		break;		
		case MSO_STREAM_APPLEND_SEGMENT_ID_LIST:
		{
			if(sizeof(struct segment_id_list) != opt_val_len){
				sapp_runtime_log(RLOG_LV_INFO, "%s, MESA_set_stream_opt() MSO_STREAM_APPLEND_SEGMENT_ID_LIST error:opt_val_len invalid, must be sizeof(struct segment_id_list)\n",printaddr(&pstream->addr, pstream->threadnum));
				ret = -1;
				break;
			}
			struct segment_id_list *set_sid_list = (struct segment_id_list *)opt_val;
			struct streaminfo_private *pstream_pr=(struct streaminfo_private *)pstream;
			if(pstream_pr->sid_append_list == NULL)
			{
				if(set_sid_list->sz_sidlist > 0)
				{
					pstream_pr->sid_append_list = (struct segment_id_list *)sapp_mem_calloc(SAPP_MEM_DYN_SID_LIST, pstream->threadnum, sizeof(struct segment_id_list));
					memcpy(pstream_pr->sid_append_list->sid_list, set_sid_list->sid_list, set_sid_list->sz_sidlist*sizeof(unsigned short));
					pstream_pr->sid_append_list->sz_sidlist = set_sid_list->sz_sidlist;
				}
			}
			else
			{
				if(set_sid_list->sz_sidlist > 0)
				{
					memcpy(pstream_pr->sid_append_list->sid_list, set_sid_list->sid_list, set_sid_list->sz_sidlist*sizeof(unsigned short));
					pstream_pr->sid_append_list->sz_sidlist = set_sid_list->sz_sidlist;
				}
				else
				{
					memset(pstream_pr->sid_append_list, 0, sizeof(struct segment_id_list));
				}
			}
            char tmp_buff[256];
            snprintf(tmp_buff, sizeof(tmp_buff), "update sid_append_list_sz=%u", set_sid_list->sz_sidlist);
            marsio4_emit_datapath_telemetry(pstream_pr->raw_pkt, "sapp", tmp_buff);			
			ret = 0;
		}
		break;	
		case MSO_STREAM_PREPLEND_SEGMENT_ID_LIST:
		{
			if(sizeof(struct segment_id_list) != opt_val_len){
				sapp_runtime_log(RLOG_LV_INFO, "%s, MESA_set_stream_opt() MSO_STREAM_APPLEND_SEGMENT_ID_LIST error:opt_val_len invalid, must be sizeof(struct segment_id_list)\n",printaddr(&pstream->addr, pstream->threadnum));
				ret = -1;
				break;
			}
			struct segment_id_list *set_sid_list = (struct segment_id_list *)opt_val;
			struct streaminfo_private *pstream_pr=(struct streaminfo_private *)pstream;
			if(pstream_pr->sid_prepend_list == NULL)
			{
				if(set_sid_list->sz_sidlist > 0)
				{
					pstream_pr->sid_prepend_list = (struct segment_id_list *)sapp_mem_calloc(SAPP_MEM_DYN_SID_LIST, pstream->threadnum, sizeof(struct segment_id_list));
					memcpy(pstream_pr->sid_prepend_list->sid_list, set_sid_list->sid_list, set_sid_list->sz_sidlist*sizeof(unsigned short));
					pstream_pr->sid_prepend_list->sz_sidlist = set_sid_list->sz_sidlist;
				}
			}
			else
			{
				if(set_sid_list->sz_sidlist > 0)
				{
					memcpy(pstream_pr->sid_prepend_list->sid_list, set_sid_list->sid_list, set_sid_list->sz_sidlist*sizeof(unsigned short));
					pstream_pr->sid_prepend_list->sz_sidlist = set_sid_list->sz_sidlist;
				}
				else
				{
					memset(pstream_pr->sid_prepend_list, 0, sizeof(struct segment_id_list));
				}
			}
            char tmp_buff[256];
            snprintf(tmp_buff, sizeof(tmp_buff), "update sid_prepend_list_sz=%u", set_sid_list->sz_sidlist);
            marsio4_emit_datapath_telemetry(pstream_pr->raw_pkt, "sapp", tmp_buff);
            ret = 0;
		}
		break;
		case MSO_STREAM_SET_DATAMETA_TRACE_ID:
		{
			struct streaminfo_private *pstream_pr=(struct streaminfo_private *)pstream;
			if(pstream_pr->stream_trace_id>0)
			{
				ret = -1;
				break;
			}
			pstream_pr->stream_trace_id=*((unsigned long long *)opt_val);
            char tmp_buff[256];
            snprintf(tmp_buff, sizeof(tmp_buff), "update trace_id=%llu", pstream_pr->stream_trace_id);
            marsio4_emit_datapath_telemetry(pstream_pr->raw_pkt, "sapp", tmp_buff);
            ret=0;
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

	ptr += 5; /* ָ��long long �ĵ�6���ֽ� */

	for(i = 0; i < 6; i++){
		*ptr-- = *mac_addr++; /* �������ݰ���mac������?, copy��long long����������?(��ȥ���??2���ֽں�) */
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
	unsigned long long smac_integer_type; /* 48bit macת��Ϊ64bit�ĳ��������ִ洢, ���ڲ��� */

	while(mim_stream){//���ڶ��mac��ַ�������ֻ�������MAC��ַȡvxlan_info
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

    if (ADDR_TYPE_MAC_IN_MAC == mim_stream->addr.addrtype)
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
        vxinfo->inner_smac[17] = '\0'; /* ���һλ����?? */
        memcpy(vxinfo->inner_smac_hex, mim_addr->inner_src_mac, 6);

        ptr = vxinfo->inner_dmac;
        for(i = 0; i < 6; i++, ptr += 3){
            sprintf((char *)ptr, "%02x:", mim_addr->inner_dst_mac[i]);
        }
        vxinfo->inner_dmac[17] = '\0'; /* ���һλ����?? */
        memcpy(vxinfo->inner_dmac_hex, mim_addr->inner_dst_mac, 6);
    }
    else
    {
		ptr = vxinfo->inner_smac;
		for(i = 0; i < 6; i++, ptr += 3){
			sprintf((char *)ptr, "%02x:", mac_addr->src_addr.h_source[i]);
		}
		vxinfo->inner_smac[17] = '\0'; /* ���һλ����?? */
		memcpy(vxinfo->inner_smac_hex, mac_addr->src_addr.h_source, 6);

        ptr = vxinfo->inner_dmac;
        for(i = 0; i < 6; i++, ptr += 3){
            sprintf((char *)ptr, "%02x:", mac_addr->src_addr.h_dest[i]);
        }
        vxinfo->inner_dmac[17] = '\0'; /* ���һλ����?? */
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
	���ݲ����ں���������, ��ȡ�����˽�д洢�ռ�ָ��pme.
*/
static int MESA_get_stream_plug_pme(const struct streaminfo *pstream, void *opt_val, const int *opt_val_len)
{
	int ret = 0;
	struct mso_plug_pme *in_arg;
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
	in_arg->plug_pme = NULL;

	this_plug_entry = plugin_get_plug_entry(in_arg->plug_name, in_arg->plug_entry_type);
	if(NULL == this_plug_entry){
		sapp_runtime_log(RLOG_LV_FATAL, "%s,MESA_get_stream_opt() MSO_STREAM_PLUG_PME error, can't get plug:%s entry:%s address", 
						printaddr(&pstream->addr, pstream->threadnum), in_arg->plug_name, in_arg->plug_entry_type); 
		return -1;
	}

	if(STREAM_TYPE_TCP == pstream->type){
		ptcp_detail_pr=(struct tcpdetail_private *)(pstream->pdetail);
		plug_pme = MESA_get_stream_plug_pme_from_platform_entry((const StreamFunInfo *)(ptcp_detail_pr->apme), this_plug_entry);
		if(plug_pme != NULL){
			in_arg->plug_pme = plug_pme;
			goto bingo;
		}
		plug_pme = MESA_get_stream_plug_pme_from_platform_entry((const StreamFunInfo *)(ptcp_detail_pr->pAllpktpme), this_plug_entry);
		if(plug_pme != NULL){
			in_arg->plug_pme = plug_pme;
			goto bingo;
		}		
	}else if(STREAM_TYPE_UDP == pstream->type){
		pudp_detail_pr = (struct udpdetail_private *)(pstream->pdetail);
		plug_pme = MESA_get_stream_plug_pme_from_platform_entry((const StreamFunInfo *)(pudp_detail_pr->apme), this_plug_entry);
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

	const sapp_dup_pkt_t *dup_pkt_para = &sapp_global_val->config.packet_io.dup_pkt_para;

	if((0 == dup_pkt_para->dup_pkt_distinguish_all_inject)
		  && (0 == dup_pkt_para->dup_pkt_distinguish_ipv4_tcp)
		  && (0 == dup_pkt_para->dup_pkt_distinguish_ipv4_udp)){
		sapp_runtime_log(RLOG_LV_INFO, "%s, MESA_get_stream_opt() MSO_HAVE_DUP_PKT error, config DUPLICATE_PKT is not enable", 
						 printaddr(&pstream->addr, pstream->threadnum)); 
		*res_val = -2;
		return 0;
	}

	if(pstream_pr->has_duplicate_pkt != 0){
		*res_val = 1;
		return 0;
	}

	/* �������ظ�����⹦��??,����û�������ظ���   */
	if(STREAM_TYPE_TCP == pstream->type){
		if(pstream->ptcpdetail->clientpktnum + pstream->ptcpdetail->serverpktnum < dup_pkt_para->first_packets){ /* ��̫��, �������ж���û���ظ��� */
			*res_val = -2;
			sapp_runtime_log(RLOG_LV_DEBUG, "%s, MESA_get_stream_opt() MSO_HAVE_DUP_PKT, duplicate pkt state is pending, because has only recv %d pkt", 
						printaddr(&pstream->addr, pstream->threadnum), pstream->ptcpdetail->clientpktnum + pstream->ptcpdetail->serverpktnum); 			
		}else{
			*res_val = 0;
		}
	}else if(STREAM_TYPE_UDP == pstream->type){
		if(pstream->pudpdetail->clientpktnum  + pstream->pudpdetail->serverpktnum < dup_pkt_para->first_packets){ /* ��̫��, �������ж���û���ظ��� */
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
	struct streaminfo_private *pstream_pr=(struct streaminfo_private *)pstream;
	struct tcpdetail_private *pdetail_pr = (struct tcpdetail_private*)(pstream->pdetail);

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
			*igrstfin = pdetail_pr->ignore_rst_fin;	
		}	
		break;
		
		case MSO_TCP_CREATE_LINK_MODE:
		{
			UCHAR *out_val = (UCHAR *)opt_val;
			if(STREAM_TYPE_TCP != pstream->type){
				ret = -1;
				sapp_runtime_log(RLOG_LV_INFO,"%s, MESA_get_stream_opt() MSO_TCP_CREATE_LINK_MODE error:stream type is not tcp!\n", printaddr(&pstream->addr, pstream->threadnum));
				break;
			}
			
			*out_val = pdetail_pr->creat_mod;
			*opt_val_len = sizeof(char);
		}
		break;

		case MSO_TCP_ISN_C2S:
		case MSO_TCP_ISN_S2C:
		{
			UINT32 *out_val = (UINT32 *)opt_val;
			if (STREAM_TYPE_TCP != pstream->type)
			{
				ret = -1;
				sapp_runtime_log(RLOG_LV_INFO, "%s, MESA_get_stream_opt() %s error:stream type is not tcp!\n",
								printaddr(&pstream->addr, pstream->threadnum),
								opt == MSO_TCP_ISN_C2S ? "MSO_TCP_ISN_C2S" : "MSO_TCP_ISN_S2C");
				break;
			}

			if (pdetail_pr->creat_mod != TCP_CTEAT_LINK_BYSYN)
			{
				ret = -1;
				sapp_runtime_log(RLOG_LV_INFO, "%s, MESA_get_stream_opt() %s error: stream create mode is not by SYN!\n",
								printaddr(&pstream->addr, pstream->threadnum),
								opt == MSO_TCP_ISN_C2S ? "MSO_TCP_ISN_C2S" : "MSO_TCP_ISN_S2C");
				break;
			}

			if ((opt == MSO_TCP_ISN_C2S && 0 == pdetail_pr->iserverseq) || (opt == MSO_TCP_ISN_S2C && 0 == pdetail_pr->iclientseq))
			{
				ret = -1;
				sapp_runtime_log(RLOG_LV_INFO, "%s, MESA_get_stream_opt() %s error: can't get SYN seq!\n",
								printaddr(&pstream->addr, pstream->threadnum),
								opt == MSO_TCP_ISN_C2S ? "MSO_TCP_ISN_C2S" : "MSO_TCP_ISN_S2C");
				break;
			}

			*out_val = (opt == MSO_TCP_ISN_C2S ? pdetail_pr->iserverseq : pdetail_pr->iclientseq) - 1;
			*opt_val_len = sizeof(int);
		}
		break;

		case MSO_TCP_SYN_OPT:
		{
			struct tcp_option **out_val = (struct tcp_option **)opt_val;
			if((pstream_pr->syn_opt_array != NULL) && (pstream_pr->syn_opt_num > 0)){
				*out_val = pstream_pr->syn_opt_array;
				*opt_val_len = pstream_pr->syn_opt_num; /* �˴����ǳ���, ��ʾopt_array�ĸ��� */
				ret = 0;
			}else{
				ret = -1;
			}
		}
		break;

		case MSO_TCP_SYNACK_OPT:
		{
			struct tcp_option **out_val = (struct tcp_option **)opt_val;
			if((pstream_pr->synack_opt_array != NULL) && (pstream_pr->synack_opt_num > 0)){
				*out_val = pstream_pr->synack_opt_array;
				*opt_val_len = pstream_pr->synack_opt_num;  /* �˴����ǳ���, ��ʾopt_array�ĸ��� */
				ret = 0;
			}else{
				ret = -1;
			}
		}
		break;

		case MSO_STREAM_TUNNEL_TYPE:
		{
			unsigned short *out_val = (unsigned short *)opt_val;
			*out_val = pstream_pr->stream_low_layer_tunnel_type;
			ret = 0;
		}
		break;

		case MSO_STREAM_UP_LAYER_TUNNEL_TYPE:
		{
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
				*close_reason = pdetail_pr->link_state;
			}else if(STREAM_TYPE_UDP == pstream->type){
				*close_reason = pstream_pr->stream_close_reason;
			}else{
				ret = -1;
				sapp_runtime_log(RLOG_LV_INFO, "%s,MESA_get_stream_opt() MSO_STREAM_CLOSE_REASON error:unsupport stream type:%d!\n",printaddr(&pstream->addr, pstream->threadnum), pstream->type);
			}
		}
		break;

		case MSO_STREAM_VXLAN_INFO:
			if(DEPLOYMENT_MODE_MIRROR != g_topology_mode_raw){
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
			if(*opt_val_len != sizeof(long long)){
				return -1;
			}
			unsigned long long *out_args = (unsigned long long *)opt_val;
			unsigned long long dev_id = *out_args;
			if(dev_id > 4095){
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
		case MSO_STREAM_LASTUPDATE_TIMESTAMP_MS:
		{
			if ((STREAM_TYPE_TCP != pstream->type) && (STREAM_TYPE_UDP != pstream->type))
			{
				sapp_runtime_log(RLOG_LV_INFO, "%s,MESA_get_stream_opt() MSO_STREAM_LASTUPDATE_TIMESTAMP_MS error: stream type is not tcp or udp!\n",printaddr(&pstream->addr, pstream->threadnum));
				ret = -1;
				break;
			}
			unsigned long long *timestamp_ms = (unsigned long long *)opt_val;
			*timestamp_ms = ((struct streaminfo_private *)pstream)->stream_lastupdate_timestamp_ms;
		}
		break;

		case MSO_STREAM_PLUG_PME:
			ret = MESA_get_stream_plug_pme(pstream, opt_val, opt_val_len);
		break;

		case MSO_HAVE_DUP_PKT:
			ret = MESA_get_stream_dup_pkt_stat(pstream, opt_val, opt_val_len);
		break;
		case MSO_STREAM_C2S_RAWPKT_HDR:
        case MSO_STREAM_S2C_RAWPKT_HDR: 
		{
			const raw_pkt_t *rawpkt = NULL;
			if (opt == MSO_STREAM_C2S_RAWPKT_HDR)
			{
					rawpkt = pstream_pr->polling_inject_context->raw_pkt_stream_dir[DIR_C2S - 1];
			}
			else
			{
					rawpkt = pstream_pr->polling_inject_context->raw_pkt_stream_dir[DIR_S2C - 1];
			}
			if (rawpkt != NULL)
			{
					*((void **)opt_val) = (void *)((const char *)rawpkt->raw_pkt_data + rawpkt->overlay_layer_bytes);
					*opt_val_len = rawpkt->offset_to_raw_pkt_hdr - rawpkt->overlay_layer_bytes;
			}
        }
        break;

        case MSO_STREAM_C2S_SYN_NUM:
        case MSO_STREAM_S2C_SYN_NUM:
        if ((STREAM_TYPE_TCP != pstream->type) || pdetail_pr->flow_stat == NULL || *opt_val_len != sizeof(unsigned int))
        {
                sapp_runtime_log(RLOG_LV_INFO,
                                "%s,MESA_get_stream_opt() MSO_STREAM_C2S_SYN_NUM error: stream type is not tcp or "
                                "empyt flow_stat!\n",
                                printaddr(&pstream->addr, pstream->threadnum));
                ret = -1;
        }
        else
        {

                unsigned int *syn_cnt = (unsigned int *)opt_val;
                if (opt == MSO_STREAM_C2S_SYN_NUM)
                {
                    *syn_cnt = pdetail_pr->flow_stat->C2S_syn_pkt;
                    *opt_val_len = sizeof(*syn_cnt);
                    ret = 0;
                }
                else if (opt == MSO_STREAM_S2C_SYN_NUM)
                {
                    *syn_cnt = pdetail_pr->flow_stat->S2C_syn_pkt;
                    *opt_val_len = sizeof(*syn_cnt);
                    ret = 0;
                }
                else
                {
                    ret = -1;
                }
        }
        break;

        case MSO_STREAM_INBOND_LINK_ID:
        case MSO_STREAM_OUTBOND_LINK_ID: 
		{
			ret = -1;
			struct rawpkt_metadata *meta = NULL;
			int c2s_route_dir=MESA_dir_link_to_human(pstream_pr->stream_c2s_route_dir);
			if (c2s_route_dir==(int)'E')
			{
					if (opt == MSO_STREAM_OUTBOND_LINK_ID)
					{
						meta = pstream_pr->polling_inject_context->meta_stream_dir[DIR_C2S - 1];
					}
					else
					{
						meta = pstream_pr->polling_inject_context->meta_stream_dir[DIR_S2C - 1];
					}
			}
			else
			{
					if (opt == MSO_STREAM_OUTBOND_LINK_ID)
					{
						meta = pstream_pr->polling_inject_context->meta_stream_dir[DIR_S2C - 1];
					}
					else
					{
						meta = pstream_pr->polling_inject_context->meta_stream_dir[DIR_C2S - 1];
					}
			}
			if (meta)
			{
					*(unsigned int *)(opt_val) = meta->link_id;
					*opt_val_len = sizeof(meta->link_id);
					ret = 0;
			}
        }
        break;
        case MSO_STREAM_C2S_ROUTE_DIRECTION:
		{
			 UCHAR *c2s_route_dir = (UCHAR *)opt_val;
			 *c2s_route_dir=pstream_pr->stream_c2s_route_dir;
			ret=0;
		}
		
		break;
		case MSO_STREAM_APPLEND_SEGMENT_ID_LIST:
		{
			if(sizeof(struct segment_id_list) != *opt_val_len){
				sapp_runtime_log(RLOG_LV_INFO, "%s, MESA_get_stream_opt() MSO_STREAM_APPLEND_SEGMENT_ID_LIST error:opt_val_len invalid, must be sizeof(struct segment_id_list)\n",printaddr(&pstream->addr, pstream->threadnum));
				ret = -1;
				break;
			}

			if(pstream_pr->sid_append_list!=NULL)
			{
				memcpy(opt_val, pstream_pr->sid_append_list, sizeof(struct segment_id_list));
				ret=0;
			}
			break;
		}
		case MSO_STREAM_PREPLEND_SEGMENT_ID_LIST:
		{
			if(sizeof(struct segment_id_list) != *opt_val_len){
				sapp_runtime_log(RLOG_LV_INFO, "%s, MESA_get_stream_opt() MSO_STREAM_PREPLEND_SEGMENT_ID_LIST error:opt_val_len invalid, must be sizeof(struct segment_id_list)\n",printaddr(&pstream->addr, pstream->threadnum));
				ret = -1;
				break;
			}

			if(pstream_pr->sid_prepend_list!=NULL)
			{
				memcpy(opt_val, pstream_pr->sid_prepend_list, sizeof(struct segment_id_list));
				ret=0;
			}
			break;
		}
        case MSO_STREAM_INBOND_ROUTE_CTX:
		{
            ret = -1;
            *opt_val_len = 0;
            void **value = (void **)opt_val;
            struct rawpkt_metadata *meta = NULL;
			int dir=MESA_dir_link_to_human(pstream_pr->stream_c2s_route_dir);
            if (dir==(int)'I')
            {
                meta = pstream_pr->polling_inject_context->meta_stream_dir[DIR_C2S - 1];
            }
            else
            {
 				meta = pstream_pr->polling_inject_context->meta_stream_dir[DIR_S2C - 1];
            }

            if (meta)
            {
                *value = (void *)meta->data;
                *opt_val_len = meta->sz_data;
                ret = meta->sz_data;
            }
        }		
		break;
        case MSO_STREAM_OUTBOND_ROUTE_CTX: 
		{
            ret = -1;
            *opt_val_len = 0;
            void **value = (void **)opt_val;
            struct rawpkt_metadata *meta = NULL;
			int dir=MESA_dir_link_to_human(pstream_pr->stream_c2s_route_dir);
            if (dir==(int)'E')
            {
                meta = pstream_pr->polling_inject_context->meta_stream_dir[DIR_C2S - 1];
            }
            else
            {
 				meta = pstream_pr->polling_inject_context->meta_stream_dir[DIR_S2C - 1];
            }

            if (meta)
            {
                *value = (void *)meta->data;
                *opt_val_len = meta->sz_data;
                ret = meta->sz_data;
            }
        }
        break;
		case MSO_STREAM_C2S_LINK_ID:
		case MSO_STREAM_S2C_LINK_ID:
		{
			ret = -1;
			struct rawpkt_metadata *meta = NULL;
			if (opt == MSO_STREAM_C2S_LINK_ID)
			{
				meta = pstream_pr->polling_inject_context->meta_stream_dir[DIR_C2S - 1];
			}			
			else
			{
				meta = pstream_pr->polling_inject_context->meta_stream_dir[DIR_S2C - 1];
			}
			if (meta)
			{
					*(unsigned int *)(opt_val) = meta->link_id;
					*opt_val_len = sizeof(meta->link_id);
					ret = 0;
			}			
		}
		break;
		case MSO_STREAM_C2S_ROUTE_CTX:
		case MSO_STREAM_S2C_ROUTE_CTX:
		{
			ret = -1;
			*opt_val_len = 0;
            void **value = (void **)opt_val;
			struct rawpkt_metadata *meta = NULL;
			if (opt == MSO_STREAM_C2S_ROUTE_CTX)
			{
				meta = pstream_pr->polling_inject_context->meta_stream_dir[DIR_C2S - 1];
			}			
			else
			{
				meta = pstream_pr->polling_inject_context->meta_stream_dir[DIR_S2C - 1];
			}
			if (meta)
			{
                *value = (void *)meta->data;
                *opt_val_len = meta->sz_data;
                ret = meta->sz_data;
			}	
		}
		break;		

		case MSO_IP_TTL_C2S:
			if(0 == pstream_pr->ip_ttl_c2s){
				ret = -1;
			}else{
				*((unsigned char *)opt_val) = pstream_pr->ip_ttl_c2s;
				*opt_val_len = sizeof(char);
			}
		break;
		case MSO_IP_TTL_S2C:
			if(0 == pstream_pr->ip_ttl_s2c){
				ret = -1;
			}else{
				*((unsigned char *)opt_val) = pstream_pr->ip_ttl_s2c;
				*opt_val_len = sizeof(char);
			}
		break;

		case MSO_TCP_RTT_CSC:
		{
			if(STREAM_TYPE_TCP != pstream->type){
				sapp_runtime_log(RLOG_LV_INFO, "%s,MESA_get_stream_opt() MSO_TCP_RTT_CSC error:stream type is not tcp!\n", printaddr(&pstream->addr, pstream->threadnum));
				ret = -1;
				break;
			}
			if(0xFFFF == pdetail_pr->rtt_csc){
				ret = -1;
				break;
			}
			*((unsigned short *)opt_val) = pdetail_pr->rtt_csc;
			*opt_val_len = sizeof(short);
		}
		break;

		case MSO_TCP_RTT_SCS:
		{
			if(STREAM_TYPE_TCP != pstream->type){
				sapp_runtime_log(RLOG_LV_INFO, "%s,MESA_get_stream_opt() MSO_TCP_RTT_CSC error:stream type is not tcp!\n", printaddr(&pstream->addr, pstream->threadnum));
				ret = -1;
				break;
			}
			if(0xFFFF == pdetail_pr->rtt_scs){
				ret = -1;
				break;
			}
			*((unsigned short *)opt_val) = pdetail_pr->rtt_scs;
			*opt_val_len = sizeof(short);
		}
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


void set_current_thread_cpu_affinity(int thread_index)
{
	if(sapp_global_val->config.cpu.bind_mask_array_num != 0){
		cpu_set_t cpuset;
		CPU_ZERO(&cpuset);
		CPU_SET(sapp_global_val->config.cpu.bind_mask_array[thread_index], &cpuset);
		pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);
	}

	return;
}

int get_current_thread_cpu_affinity_id(void)
{
	int i;
    cpu_set_t current_cpu_mask;
	
	CPU_ZERO(&current_cpu_mask);
	
	if(pthread_getaffinity_np(pthread_self(), sizeof(cpu_set_t), &current_cpu_mask) < 0){
		return -1;
	}
	
	int tot_cpu_core = get_nprocs();
	int tot_cpu_set_count = CPU_COUNT(&current_cpu_mask);
	if((tot_cpu_set_count == tot_cpu_core) || (tot_cpu_set_count > 1)){
		/* ȫ����������, ��ʵ����û�а�, 
		   �����������isolcpus, ���㲻���??, CPU_COUNT���ܺ������������??, 
		   ��������1���϶���û�о�ȷ�󶨵�ĳ������ */
		return -1;
	}
	
	for(i = 0; i <= tot_cpu_core; i++){
		if(CPU_ISSET(i, &current_cpu_mask)){
			break;
		}
	}
	
	return i;
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
	return malloc(size);
}	
void dictator_free(int thread_seq,void *pbuf)
{
#if SAPP_INSECTICIDE	
		*((char *)pbuf) = 0xFE;
#endif
		free(pbuf);
}

void *dictator_realloc(int thread_seq, void *ptr, size_t size)
{
	return realloc(ptr, size);
}

/* ��ҵ�������ص�ֵת����ƽ̨������?, ����PROT_STATE_xxxת��ΪAPP_STATE_xxx */
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

/* ��ƽ̨��stateֵת����ҵ������ֵ, ����OP_STATE_PENDINGתΪSESSION_STATE_PENDING */
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
	char *new_s = (char *)sapp_mem_calloc(SAPP_MEM_FIX_GLOBAL_VAL, MEM_STAT_GLOBAL_THREAD_ID, buflen);
	memcpy(new_s, raw_s, buflen);

	return new_s;
}

int sapp_is_absolute_path(const char *filename)
{
	if(filename == NULL)
	{
		return 0;
	}
	if('/' == filename[0]){
		return 1;
	}

	return 0;
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
	if(unlikely (usec <= 0))
	{
		return 0;
	}
	sleep_time_val.tv_sec = 0;
	sleep_time_val.tv_nsec = usec * 1000;

	nanosleep(&sleep_time_val, NULL);

	return 0;
}



#ifdef __cplusplus
}
#endif

