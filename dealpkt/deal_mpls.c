
#ifdef __cplusplus
extern "C" {
#endif

#include "stream_internal.h" 
#include "sendpacket.h"
#include "stream_manage.h"
#include "mesa_net.h"

extern int ipv4_entry(struct streaminfo_private *pfstream, const void *this_layer_data, int thread_num, 
			unsigned char routedir, const raw_pkt_t *raw_pkt, int);


static inline void set_mpls_addr(struct layer_addr_mpls *addr, struct mesa_mpls_hdr *this_mpls_hdr)
{
	memcpy(&addr->mpls_pkt, this_mpls_hdr, sizeof(struct mesa_mpls_hdr));
	return;
}

int mpls_uc_entry(struct streaminfo_private *pfstream_pr,const void *this_layer_data,int thread_num, 
						unsigned char routedir, const raw_pkt_t *raw_pkt,int offset_to_raw_pkt_hdr)
{
#if COMPAT_PAPP_FOR_BENCHMARK
	return PASS;
#endif
	int ret = PASS;
	struct streamindex tmp_index;
	struct layer_addr_mpls addr;
	struct mesa_mpls_hdr this_mpls_hdr;
	struct streamindex *ptmp=&tmp_index;
	struct streaminfo_private *pstream_pr = &ptmp->stream;
	struct streaminfo *pstream = &pstream_pr->stream_public;	
	unsigned int *mpls_pkt_data = (unsigned int *)this_layer_data;
	char *next_layer_hdr = (char *)this_layer_data+ sizeof(struct mesa_mpls_hdr);
	int next_layer_offset = offset_to_raw_pkt_hdr + sizeof(struct mesa_mpls_hdr);

	//this_mpls_hdr.mpls_label = (ntohl(*mpls_pkt_data) & MPLS_LABEL_MASK) >> 12;
	this_mpls_hdr.mpls_exp = (ntohl(*mpls_pkt_data) & MPLS_EXP_MASK) >> 9;
	this_mpls_hdr.mpls_bls = (ntohl(*mpls_pkt_data) & MPLS_BLS_MASK) >> 8;
	this_mpls_hdr.mpls_ttl = (ntohl(*mpls_pkt_data) & MPLS_TTL_MASK);
		
	if(0 == G_SKIP_NOT_IP_LAYER){ 
		memset(ptmp,0,sizeof(struct streamindex));
		set_mpls_addr(&addr, &this_mpls_hdr);
		pstream->addr.paddr=&addr;
		pstream->addr.addrtype = ADDR_TYPE_MPLS;
		pstream->addr.addrlen = sizeof(struct layer_addr_mpls);
		pstream_pr->addr_use_as_hash = 0;	/* MPLS地址不参与HASH比较, 因为双向可能不一致 */
		//ptmp->stream.p_layer_header = this_layer_data;
		//ptmp->stream.offset_to_raw_pkt_hdr = (char *)this_layer_data - (char *)raw_pkt->raw_pkt_data;
		pstream_pr->offset_to_raw_pkt_hdr = offset_to_raw_pkt_hdr;
		pstream_pr->raw_pkt = raw_pkt;
		
		pstream->pfather=&pfstream_pr->stream_public;
		pstream->type=STREAM_TYPE_NON;
		pstream->routedir=routedir;
		pstream->threadnum=thread_num;
	}else{
		pstream_pr = pfstream_pr;
	}
	
	if(1 == this_mpls_hdr.mpls_bls){ /* 已到栈底, MPLS已结束 */
		/* TODO, 如果MPLS承载的是IPv6呢? 或其他协议呢? 如何区别? */
		((raw_pkt_t *)raw_pkt)->offset_to_raw_pkt_hdr = next_layer_offset;
		ret = ipv4_entry(pstream_pr,next_layer_hdr,thread_num,routedir,raw_pkt, next_layer_offset);
	}else{
		/* MPLS嵌套, 递归调用自身 */
		ret = mpls_uc_entry(pstream_pr,next_layer_hdr,thread_num,routedir,raw_pkt, next_layer_offset);
	}

	return ret;
}

#ifdef __cplusplus
}
#endif


