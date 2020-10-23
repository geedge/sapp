#ifdef __cplusplus
extern "C" {
#endif

#include "sapp_api.h"
#include "sapp_private_api.h"


static inline void set_pppoe_addr(struct layer_addr_pppoe_session *tuple_pppoe, 
							struct mesa_pppoe_session_hdr *pppoe_hdr)
{
	tuple_pppoe->ver = pppoe_hdr->ver;
	tuple_pppoe->type = pppoe_hdr->type;
	tuple_pppoe->code = pppoe_hdr->code;
	tuple_pppoe->session_id= pppoe_hdr->session_id;

	
	return;
}

int pppoe_session_entry(struct streaminfo_private *pfstream_pr,const void *this_layer_hdr,
			int thread_num,unsigned char routedir, const raw_pkt_t *raw_pkt,int offset_to_raw_pkt_hdr)
{
#if COMPAT_PAPP_FOR_BENCHMARK
	return PASS;
#endif
	int ret = PASS;
	sapp_gval_mthread_sys_stat_t *local_sys_stat;

	struct streamindex tmp_index;
	struct streamindex *ptmp=&tmp_index;
	struct streaminfo_private *pstream_pr = &ptmp->stream;
	struct streaminfo *pstream = &pstream_pr->stream_public;	
	struct mesa_pppoe_session_hdr *pppoe_ses_hdr = (struct mesa_pppoe_session_hdr *)this_layer_hdr;
	struct layer_addr_pppoe_session addr;
	char *up_layer_data = (char *)this_layer_hdr+PPPOE_HDR_LEN;
	int next_layer_offset = offset_to_raw_pkt_hdr + PPPOE_HDR_LEN;

	if(0 == G_SKIP_NOT_IP_LAYER){ 
		memset(ptmp,0,sizeof(struct streamindex));
		set_pppoe_addr(&addr, (struct mesa_pppoe_session_hdr *)this_layer_hdr);
		pstream->addr.pppoe_ses=&addr;
		pstream->addr.addrtype = ADDR_TYPE_PPPOE_SES;
		pstream->addr.addrlen = sizeof(struct layer_addr_pppoe_session);
		pstream_pr->addr_use_as_hash = 1;	
		//ptmp->stream.p_layer_header = this_layer_hdr;
		//ptmp->stream.offset_to_raw_pkt_hdr = (char *)this_layer_hdr - (char *)raw_pkt->raw_pkt_data;
		pstream_pr->offset_to_raw_pkt_hdr = offset_to_raw_pkt_hdr;
		pstream_pr->raw_pkt = raw_pkt;
		
		pstream->pfather=&pfstream_pr->stream_public;
		pstream->type=STREAM_TYPE_PPPOE;
		pstream->routedir=routedir;
		pstream->threadnum=thread_num;

		pstream_pr->layer_index = pfstream_pr->layer_index + 1;
	}else{
		pstream_pr = pfstream_pr;
	}
	
	if(PPP_PROTOCOL_IPv4 == ntohs(pppoe_ses_hdr->ppp_protocol)){
		ret = ipv4_entry(pstream_pr, up_layer_data, thread_num, routedir, raw_pkt, next_layer_offset);
	}else if(PPP_PROTOCOL_IPv6 == ntohs(pppoe_ses_hdr->ppp_protocol)){
		ret = ipv6_entry(pstream_pr, up_layer_data, thread_num, routedir, raw_pkt, next_layer_offset);
	}else{
		local_sys_stat = &sapp_global_val->mthread_volatile[thread_num]->sys_stat;
		local_sys_stat->count[SAPP_STAT_RCV_UNKNOWN]++;
		local_sys_stat->length[SAPP_STAT_RCV_UNKNOWN] += (unsigned long long)raw_pkt->raw_pkt_len;		
		((raw_pkt_t *)raw_pkt)->diagnose_to_dump = 1;
	}

	return ret;
}


#ifdef __cplusplus
}
#endif

