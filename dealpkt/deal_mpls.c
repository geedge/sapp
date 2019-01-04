
#ifdef __cplusplus
extern "C" {
#endif

#include "stream_internal.h" 
#include "sendpacket.h"
#include "stream_manage.h"
#include "mesa_net.h"

#include <MESA/MESA_htable.h>

extern int ipv4_entry(struct streaminfo_private *pfstream, const void *this_layer_data, int thread_num, 
			unsigned char routedir, const raw_pkt_t *raw_pkt, int);

extern int ipv6_entry(struct streaminfo_private *pfstream, const void *this_layer_data, int thread_num,
                      unsigned char routedir, const raw_pkt_t *raw_pkt, int);

extern int eth_entry(struct streaminfo_private *fstream_pr, const void *this_layer_hdr,int thread_num,
					 unsigned char dir, const raw_pkt_t *raw_pkt, int offset_to_raw_pkt_hdr);

static inline void set_mpls_addr(struct layer_addr_mpls *addr, struct mesa_mpls_hdr *this_mpls_hdr)
{
	memcpy(&addr->src_mpls_pkt, this_mpls_hdr, sizeof(struct mesa_mpls_hdr));
	return;
}

MESA_htable_handle g_mpls_info_hash[MAX_THREAD_NUM];

int mpls_uc_entry(struct streaminfo_private *pfstream_pr,const void *this_layer_data,int thread_num, 
						unsigned char routedir, const raw_pkt_t *raw_pkt,int offset_to_raw_pkt_hdr)
{
#if COMPAT_PAPP_FOR_BENCHMARK
	return PASS;
#endif
	int ret = PASS;
	struct streamindex tmp_index;
	struct layer_addr_mpls addr;
	const struct mesa_mpls_hdr *this_mpls_hdr;
	struct streamindex *ptmp=&tmp_index;
	struct streaminfo_private *pstream_pr = &ptmp->stream;
	struct streaminfo *pstream = &pstream_pr->stream_public;	
	unsigned char *mpls_pkt_data = (unsigned char *)this_layer_data;
	char *next_layer_hdr = NULL;
	int next_layer_offset = 0, i = 0;

    memset(&addr, 0, sizeof(addr));

	for(i = 0; i < MAX_MPLS_ADDR_LAYER; i++)
	{
		this_mpls_hdr = (const struct mesa_mpls_hdr *)mpls_pkt_data;
		memcpy(&addr.src_mpls_pkt[i], mpls_pkt_data,  sizeof(struct mesa_mpls_hdr));
		addr.src_mpls_layer_num += 1;
		if(1 == this_mpls_hdr->mpls_bls)break;
		mpls_pkt_data += sizeof(struct mesa_mpls_hdr);
	}

	if(1 != this_mpls_hdr->mpls_bls)
	{
		sapp_runtime_log(20, "MPLS layer over %d !\n", MAX_MPLS_ADDR_LAYER);
		return PASS;
	}

    next_layer_offset = offset_to_raw_pkt_hdr + sizeof(struct mesa_mpls_hdr)*addr.src_mpls_layer_num;
    next_layer_hdr = (char *)this_layer_data+ sizeof(struct mesa_mpls_hdr)*addr.src_mpls_layer_num;

#if 0	
	this_mpls_hdr.mpls_label = (ntohl(*mpls_pkt_data) & MPLS_LABEL_MASK) >> 12;
	this_mpls_hdr.mpls_exp = (ntohl(*mpls_pkt_data) & MPLS_EXP_MASK) >> 9;
	this_mpls_hdr.mpls_bls = (ntohl(*mpls_pkt_data) & MPLS_BLS_MASK) >> 8;
	this_mpls_hdr.mpls_ttl = (ntohl(*mpls_pkt_data) & MPLS_TTL_MASK);
#endif
		
	if(0 == G_SKIP_NOT_IP_LAYER){ 
		memset(ptmp,0,sizeof(struct streamindex));
		pstream->addr.paddr=&addr;
		pstream->addr.addrtype = ADDR_TYPE_MPLS;
		pstream->addr.addrlen = sizeof(struct layer_addr_mpls);
		pstream_pr->addr_use_as_hash = 0;//地址不参与hash比对，仅算层数
		pstream_pr->addr_skip_for_layer_cmp = 1;//MPLS存在一侧有标签，一侧没有的情况，该标志位设成1
		pstream_pr->need_update_opposite_addr = 1;//两侧地址不一样，需要更新对侧信息
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
	
	if(1 == this_mpls_hdr->mpls_bls)
	{ /* 已到栈底, MPLS已结束 */
		/* MPLS没有字段表示承载的协议类型, 如果MPLS承载的是IPv6协议，靠猜 */
		((raw_pkt_t *)raw_pkt)->offset_to_raw_pkt_hdr = next_layer_offset;
		struct iphdr  *ip4_hdr = (struct iphdr *)next_layer_hdr;
		if((*next_layer_hdr & 0xF0) == 0x40)
        {
            int left_pkt_len = raw_pkt->raw_pkt_len - next_layer_offset;
			if(left_pkt_len < 20 || ntohs(ip4_hdr->tot_len) > left_pkt_len)
            //if(left_pkt_len < 20)
			{
                g_SysInputInfo[thread_num][PKT_UNKNOWN]++;
                g_SysInputInfo[thread_num][PKT_UNKNOWN_LEN] += raw_pkt->raw_pkt_len;
                sapp_runtime_log(20, "illegal left Ipv4 len %d, total len %d!\n", left_pkt_len, ntohs(ip4_hdr->tot_len));
				return -1;
			}
            ret = ipv4_entry(pstream_pr,next_layer_hdr,thread_num,routedir,raw_pkt, next_layer_offset);
        }
        else if((*next_layer_hdr & 0xF0) == 0x60)
        {
            ret = ipv6_entry(pstream_pr,next_layer_hdr,thread_num,routedir,raw_pkt, next_layer_offset);
        }
        else if(ip4_hdr->version == 0)//pw ether control word, jump 4 byte
		{
			ret = eth_entry(pstream_pr,next_layer_hdr+4,thread_num,routedir,raw_pkt, next_layer_offset+4);
		}
        else
        {
            sapp_runtime_log(20, "MPLS next layer not IPv4 or IPv6, try to parse next layer as eth !\n");
			ret = eth_entry(pstream_pr,next_layer_hdr,thread_num,routedir,raw_pkt, next_layer_offset);
        }

	}else{
		/* MPLS嵌套, 递归调用自身 */
		ret = mpls_uc_entry(pstream_pr,next_layer_hdr,thread_num,routedir,raw_pkt, next_layer_offset);
	}

	return ret;
}

int mpls_empty_entry(struct streaminfo_private *pfstream_pr,const void *this_layer_data,int thread_num,
				  unsigned char routedir, const raw_pkt_t *raw_pkt,int offset_to_raw_pkt_hdr)
{
	int ret = PASS;
	struct streamindex tmp_index;
	struct layer_addr_mpls addr;
	struct streamindex *ptmp=&tmp_index;
	struct streaminfo_private *pstream_pr = &ptmp->stream;
	struct streaminfo *pstream = &pstream_pr->stream_public;

	char *next_layer_hdr = NULL;
	int next_layer_offset = 0;

	memset(&addr, 0, sizeof(addr));



	next_layer_offset = offset_to_raw_pkt_hdr;
	next_layer_hdr = (char *)this_layer_data;


	if(0 == G_SKIP_NOT_IP_LAYER){
		memset(ptmp,0,sizeof(struct streamindex));
		pstream->addr.paddr=&addr;
		pstream->addr.addrtype = ADDR_TYPE_MPLS;
		pstream->addr.addrlen = sizeof(struct layer_addr_mpls);
		pstream_pr->addr_use_as_hash = 0;//地址不参与hash比对，仅算层数
		pstream_pr->addr_skip_for_layer_cmp = 1;//MPLS存在一侧有标签，一侧没有的情况，该标志位设成1
		pstream_pr->need_update_opposite_addr = 1;//两侧地址不一样，需要更新对侧信息
		pstream_pr->offset_to_raw_pkt_hdr = offset_to_raw_pkt_hdr;
		pstream_pr->raw_pkt = raw_pkt;
		pstream->pfather=&pfstream_pr->stream_public;
		pstream->type=STREAM_TYPE_NON;
		pstream->routedir=routedir;
		pstream->threadnum=thread_num;
	}else{
		pstream_pr = pfstream_pr;
	}

	/* MPLS没有字段表示承载的协议类型, 如果MPLS承载的是IPv6协议，靠猜 */
	((raw_pkt_t *)raw_pkt)->offset_to_raw_pkt_hdr = next_layer_offset;
	if((*next_layer_hdr & 0xF0) == 0x40)
	{
		ret = ipv4_entry(pstream_pr,next_layer_hdr,thread_num,routedir,raw_pkt, next_layer_offset);
	}
	else if((*next_layer_hdr & 0xF0) == 0x60)
	{
		ret = ipv6_entry(pstream_pr,next_layer_hdr,thread_num,routedir,raw_pkt, next_layer_offset);
	}
	else
	{
		sapp_runtime_log(20, "mpls_empty_entry MPLS next layer not IPv4 or IPv6, drop pkt !\n");
		return PASS;
	}

	return ret;
}

#ifdef __cplusplus
}
#endif


