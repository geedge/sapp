#ifdef __cplusplus
extern "C" {
#endif

#include "sapp_api.h"
#include "sapp_private_api.h"

int set_vxlan_addr(const void *this_layer_hdr, struct layer_addr_vxlan_private *addr_pr)
{
	unsigned short vlan_id_high, vlan_id_low;
	
	const inline_vxlan_hdr_t *vxlan_hdr = (inline_vxlan_hdr_t *)this_layer_hdr;

	addr_pr->addr_public.dir = vxlan_hdr->dir;
	addr_pr->addr_public.link_id = vxlan_hdr->link_id;
	addr_pr->addr_public.link_type = vxlan_hdr->link_layer_type;
	vlan_id_high = vxlan_hdr->vlan_id_half_high;
	vlan_id_low = vxlan_hdr->vlan_id_half_low;
	addr_pr->addr_public.vlan_id = htons((vlan_id_high<<4) | vlan_id_low);

	addr_pr->actual_total_len = sizeof(inline_vxlan_hdr_t);

	switch(addr_pr->addr_public.link_type){
		case VXLAN_ENCAP_HDLC:
		{
			const struct hdlc_net_hdr *net_hdlc_hdr = (struct hdlc_net_hdr *)((char *)this_layer_hdr + sizeof(inline_vxlan_hdr_t));
			addr_pr->inner_hdlc.address = net_hdlc_hdr->address;
			addr_pr->inner_hdlc.control = net_hdlc_hdr->control;
			addr_pr->inner_hdlc.protocol = net_hdlc_hdr->protocol;
			addr_pr->actual_total_len += sizeof(struct hdlc_net_hdr);
		}
		break;

		case VXLAN_ENCAP_PPP:
		{
			const struct layer_ppp_hdr *net_ppp_hdr = (struct layer_ppp_hdr *)((char *)this_layer_hdr + sizeof(inline_vxlan_hdr_t));
			addr_pr->inner_ppp.address = net_ppp_hdr->address;
			addr_pr->inner_ppp.control = net_ppp_hdr->control;
			addr_pr->inner_ppp.protocol = net_ppp_hdr->protocol;
			addr_pr->actual_total_len += sizeof(struct layer_ppp_hdr);
		}
		break;
	}

	return 0;
}

int vxlan_entry(struct streaminfo_private *pfstream_pr,const void *this_layer_hdr,int thread_num, 
						unsigned char routedir, const raw_pkt_t *raw_pkt, int offset_to_raw_pkt_hdr)
{
	int ret;
	int next_layer_offset;
	const unsigned char *next_layer_data;
	struct streamindex tmp_index;
	struct streamindex *ptmp=&tmp_index;
	struct streaminfo_private *pstream_pr = &ptmp->stream;
	struct streaminfo *pstream = &pstream_pr->stream_public;	
	struct layer_addr_vxlan_private addr_pr;
	sapp_gval_mthread_sys_stat_t *local_sys_stat = &sapp_global_val->mthread_volatile[thread_num]->sys_stat;

	local_sys_stat->count_per_layer[ADDR_TYPE_VXLAN][pfstream_pr->layer_index+1]++; 
	local_sys_stat->length_per_layer[ADDR_TYPE_VXLAN][pfstream_pr->layer_index+1] += raw_pkt->raw_pkt_len - offset_to_raw_pkt_hdr;

	memset(ptmp,0,sizeof(struct streamindex));
	
	set_vxlan_addr(this_layer_hdr, &addr_pr);

	next_layer_data = (const unsigned char *)this_layer_hdr + addr_pr.actual_total_len;
	next_layer_offset = offset_to_raw_pkt_hdr + addr_pr.actual_total_len;

	pstream->addr.paddr=&addr_pr;
	pstream->addr.addrtype = ADDR_TYPE_VXLAN;
	pstream->addr.addrlen = sizeof(struct layer_addr_vxlan_private);
	pstream_pr->addr_use_as_hash = 0;//vxlan地址不参与hash比对
	pstream_pr->layer_index = pfstream_pr->layer_index+1;

	pstream_pr->offset_to_raw_pkt_hdr = offset_to_raw_pkt_hdr;
	pstream_pr->raw_pkt = raw_pkt;
	
	pstream->pfather=&pfstream_pr->stream_public;
	pstream_pr->pfather_pr = pfstream_pr;
	pstream->type=STREAM_TYPE_NON;
	pstream->routedir=routedir;
	pstream->threadnum=thread_num;

	/*
		vxlan ppp和hdlc字段基本不变, 不像ethernet, 涉及到反向发包, 要将mac地址颠倒方向.
		所以不再创建一个新的streaminfo结构, 浪费内存也耗费CPU, 意义不大,
		将hdlc, ppp的字段和vxlan合并, 类似ip层和tcp/udp的关系一样.
	*/

	switch(addr_pr.addr_public.link_type){
		case VXLAN_ENCAP_ETH:
			ret = eth_entry(pstream_pr,next_layer_data,thread_num,routedir,raw_pkt, next_layer_offset);
		break;

		case VXLAN_ENCAP_HDLC:
		{
			if(ETH_P_IP == ntohs(addr_pr.inner_hdlc.protocol)){
				ret = ipv4_entry(pstream_pr,next_layer_data,thread_num,routedir,raw_pkt, next_layer_offset);
			}else{
				sapp_runtime_log(RLOG_LV_FATAL, "vxlan etnry: unsupport HDLC protocol:0x%x\n", addr_pr.inner_hdlc.protocol);
				ret = PASS;
			}
		}
		break;

		case VXLAN_ENCAP_PPP:
		{
			if(PPP_PROTOCOL_IPv4 == ntohs(addr_pr.inner_ppp.protocol)){
				ret = ipv4_entry(pstream_pr,next_layer_data,thread_num,routedir,raw_pkt, next_layer_offset);
			}else if(PPP_PROTOCOL_IPv6 == ntohs(addr_pr.inner_ppp.protocol)){
				ret = ipv6_entry(pstream_pr,next_layer_data,thread_num,routedir,raw_pkt, next_layer_offset);
			}else{
				sapp_runtime_log(RLOG_LV_FATAL, "vxlan etnry: unsupport PPP protocol:0x%x\n", addr_pr.inner_ppp.protocol);
				ret = PASS;
			}
		}
		break;

		default:
			sapp_runtime_log(RLOG_LV_FATAL, "vxlan etnry: unsupport link type:%d\n", addr_pr.addr_public.link_type);
			ret = PASS;
		break;
	}

	return ret;
}

#ifdef __cplusplus
}
#endif


