#include "stream_internal.h"
#include <MESA_handle_logger.h>
#include <sysinfo.h>
#include <sys/types.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#ifndef __USE_BSD
#define __USE_BSD 1
#endif

#include "sapp_api.h"
#include "sapp_private_api.h"
#include "sapp_declaration.h"

#ifdef __cplusplus
extern "C" {
#endif

struct frag_manage *g_ipv4_frag_manage;
static unsigned int FRAG_IP4_RANDOM;
extern int g_overlay_layer_set[__ADDR_TYPE_MAX][SAPP_SUPPORT_LAYER_NUM_MAX];   
extern int dealipv4udppkt(struct streamindex *pindex, const struct mesa_ip4_hdr * this_iphdr,
		int thread_num,unsigned char routedir, const raw_pkt_t *raw_pkt, int offset_to_raw_pkt_hdr);
extern void timestamp_record(enum timestamp_level level, const raw_pkt_t *raw_pkt, int thread_seq);
int update_global_ip_frag_list(raw_ipfrag_list_t *list_head, int thread_num, int type);
extern void raw_frags_list_free_one(int thread_seq, void *project_req_value);
int process_ipv4_pkt(struct streamindex *pfindex,const struct mesa_ip4_hdr *a_packet,int thread_num,unsigned char routedir, const raw_pkt_t *raw_pkt,int);
static int checkipv4pkt(const struct mesa_ip4_hdr * iph, const raw_pkt_t *raw_pkt);
#if USE_MESA_STREAM_HASH
static unsigned int ipv4_frag_hash_index(const MESA_htable_handle table, const uchar * key, unsigned int size);
static void build_ipv4_frag_key(struct streaminfo_private *pfstream_pr, const struct mesa_ip4_hdr *a_packet,
					/*@out@*/ struct ipv4_frag_key *ip4_frag_key);
static struct frag_ipq *ipv4_frag_queue_find(struct streaminfo *pstream, 
				struct frag_manage *handle, struct ipv4_frag_key *ip4_frag_key);		
static void *frag_reassemble_v4(struct frag_manage *handle, struct frag_ipq *ipq, 
								struct ipv4_frag_key *ip4_frag_key);	
static int ipv4_frag_key_cmp_cb(const uchar * key1, uint size1, const uchar * key2, uint size2);		
static void ipv4_frag_ipq_free_all(void *data);
static uchar * ipv4_frag_key_dup(const uchar *key, uint key_size);
static void ipv4_frag_key_free(uchar *key, uint key_size);
#endif


static inline int ipv4_buff_size(int tot_len) 
{
	//return  tot_len >= 2048 ? (tot_len >= 10240 ? 65536 : 10240) : 2048;
	return  tot_len > 2048 ? (tot_len > 10240 ? 65536 : 10240) : 2048;
}


static unsigned int ipv4_frag_hash_algo(unsigned short id, unsigned char pro,
		unsigned int sip, unsigned int dip, unsigned int frand)
{
	unsigned int comb = (unsigned int)id;
	
	return frag_common_hash((comb << 16) | pro, sip, dip, frand);
}


static int ipv4_attack_detect(struct frag_ipq *ipv4_qp)
{
	if(ipv4_qp->attack_flag != 0)
	{
		return ipv4_qp->attack_flag;
	}
	
	if(ipv4_qp->frags_num > IPV4_FRAG_NUM_PER_IPQ)
	{
		ipv4_qp->attack_flag |= IP_FRAG_IGNORE;
		return IP_FRAG_IGNORE;
	}
	
	return IP_FRAG_OK;
}

static /*@null@*/ struct mesa_ip4_hdr *process_ipv4_frag(struct streaminfo_private *pfstream_pr, 
		const struct mesa_ip4_hdr *a_packet, int thread_num,const raw_pkt_t *raw_pkt)
{
	struct mesa_ip4_hdr *new_ip4h = NULL;
	int new_buf_size;
	struct frag_ipq *ipv4_qp;
	struct ip_frags *prev, *next, *tfp, *tmp, *tmp2;
	int offset, end, flags;
	struct ipv4_frag_private *private_info;
	struct frag_manage *ip4_frag_handle = &g_ipv4_frag_manage[thread_num];
	int attack_flag;	
	int i, j;
	int ip_hl;
	char *ptr;
	unsigned short raw_ip_len;
	struct streaminfo *pfstream = &pfstream_pr->stream_public;

	struct ipv4_frag_key ip4_frag_key;
	build_ipv4_frag_key(pfstream_pr, a_packet, &ip4_frag_key);
	ipv4_qp = ipv4_frag_queue_find(pfstream, ip4_frag_handle, &ip4_frag_key);


	if(unlikely(NULL == ipv4_qp))
	{
		IPV4_PRINT("##### ipv4_qp is NULL!\n");
		return NULL;
	}

	IPV4_PRINT("##### ipv4_qp: %p\n", ipv4_qp);
	
	attack_flag = ipv4_attack_detect(ipv4_qp);
	switch(attack_flag)
	{
		case IP_FRAG_OK:
		break;

		case IP_FRAG_DISCARD:
            MESA_htable_del(ip4_frag_handle->frag_hash_table, (const uchar *)&ip4_frag_key,
                            sizeof(struct ipv4_frag_key), NULL);
            return NULL;
		break;

		case IP_FRAG_INVALID_PACKET:
		case IP_FRAG_IGNORE:
		// no break here!
		default: 
			return NULL;
	}

#if (0 == HIGH_PERF)	
	frags_list_append(ipv4_qp, raw_pkt, __ADDR_TYPE_IP_PAIR_V4, thread_num);
#endif

	ipv4_qp->frags_num++;
	ipv4_qp->frags_len+=raw_pkt->raw_pkt_len;

	offset = ntohs(a_packet->ip_off);
	flags = offset & ~IPv4_FRAG_OFFSET;
	offset &= IPv4_FRAG_OFFSET;
	offset <<= 3;        /* offset is in 8-byte chunks */
	/* Determine the position of this fragment. */
	ip_hl = a_packet->ip_hl * 4;
	end = offset + ntohs(a_packet->ip_len) - ip_hl;

	if(NULL == ipv4_qp->private_info) 
	{
		IPV4_PRINT("##### ipv4 frag first pkt!\n");
		ipv4_qp->private_info = frag_malloc(ip4_frag_handle, sizeof(struct ipv4_frag_private));
		ipv4_qp->private_len = sizeof(struct ipv4_frag_private);
		memset(ipv4_qp->private_info, 0, sizeof(struct ipv4_frag_private));
		private_info = (struct ipv4_frag_private *)ipv4_qp->private_info;
		private_info->raw_ip_hdr_len = IPV4_FRAG_RESERVED_HDR_LEN;
	}
	private_info = (struct ipv4_frag_private *)ipv4_qp->private_info;

	/* 2013-06-06 lijia add,  frag attack check */
	if(end + private_info->raw_ip_hdr_len > 65535)
	{
		MESA_htable_del(ip4_frag_handle->frag_hash_table, 
						(const uchar *)&ip4_frag_key,
						sizeof(struct ipv4_frag_key),
						NULL);
	
		return NULL;
	}
	
	if((flags & IPv4_FRAG_MF) == 0) 
	{
		/* If we already have some bits beyond end
		 * or have different end, the segment is corrrupted.
		 */
		if(end < ipv4_qp->tot_len
		  ||((ipv4_qp->last_in & IP_FRAG_LAST_IN) && ipv4_qp->tot_len))
		{    
			goto err;
		}	
		ipv4_qp->last_in |= IP_FRAG_LAST_IN;
		IPV4_PRINT("### ipv4 frag last flag!\n");
		ipv4_qp->tot_len = end;
	} 
	else 
	{
		if(end & 7) 
		{
			goto err;
		}
		if(end > ipv4_qp->tot_len) 
		{
			/* Some bits beyond end -> corruption. */
			if (ipv4_qp->last_in & IP_FRAG_LAST_IN)
			{
				goto err;
			}	
			ipv4_qp->tot_len = end;
		}
		if(0 == offset)
		{
			ipv4_qp->last_in |= IP_FRAG_FIRST_IN;
			IPV4_PRINT("### ipv4 frag first flag!\n");
			if(ip_hl > private_info->raw_ip_hdr_len){ 
				if (end + ip_hl > ipv4_qp->buf_size){  
					new_buf_size = ipv4_buff_size(end + ip_hl);
					new_ip4h = (struct mesa_ip4_hdr *)frag_malloc(ip4_frag_handle, new_buf_size);
					if(ipv4_qp->meat > 0){ /* meat>0, ֮ǰ�Ѿ��洢������, ͨ�������Ƿ�Ƭ����, �����յ������ķ�Ƭ�� */
						memcpy((char *)new_ip4h + ip_hl, (char *)ipv4_qp->new_iph + private_info->raw_ip_hdr_len,  ipv4_qp->buf_size);
					}
					frag_free(ip4_frag_handle, ipv4_qp->new_iph, ipv4_qp->buf_size);
					ipv4_qp->new_iph = new_ip4h;
					ipv4_qp->buf_size = new_buf_size;
				}
			}
			private_info->raw_ip_hdr_len = ip_hl; 
			memcpy(ipv4_qp->new_iph, a_packet, ip_hl); 
		}
	}
	if(end <= offset)
	{
		goto err;
	}

	/* Point into the IP datagram 'data' part. */
	ptr = (char *)a_packet + a_packet->ip_hl * 4;
  
	/* Find out which fragments are in front and at the back of us
	 * in the chain of fragments so far.  We must know where to put
	 * this fragment.
	 */
	prev = ipv4_qp->fragments_tail;
	if(!prev || prev->offset < offset) 
	{
		next = NULL;
		goto found;
	}

	/* search backward */
	next = NULL;
	for(prev = ipv4_qp->fragments_tail; prev != NULL; prev = prev->prev)
	{
		if(prev->offset < offset)
		{
			break;	/* bingo! */
		}	
		next = prev;
	}
	
found:
	/*We found where to put this one.  Check for overlap with preceding
    fragment, and, if needed, align things so that any overlaps are
    eliminated.*/
	i = -1; 
	if(prev != NULL && offset <= prev->end) 
	{ 
	    i = prev->end - offset;
	    offset += i;        /* ptr into datagram */
	    ptr += i;           /* ptr into fragment data */
	}

	/*Look for overlap with succeeding segments.
	If we can merge fragments, do it.*/
	j = -1; 
	if(next != NULL && end >= next->offset) 
	{
    	j = end - next->offset;
    	//end -= j;        /* ptr into datagram */
	}

	/*Is this a continuous piece?*/
    if (0 > i && 0 > j)
    {
        /*creat a new fragment piece*/
        tfp = frags_create(ip4_frag_handle, offset, end);
        tfp->prev = prev;
        tfp->next = next;
        if (prev)
            prev->next = tfp;
        else
            ipv4_qp->fragments = tfp;

        if (next)
            next->prev = tfp;
        else
            ipv4_qp->fragments_tail = tfp; /* 2013-06-06 lijia add */
    }
    else if (i >= 0 && j >= 0)
    {
        for (tmp2 = next, tmp = next; NULL != tmp; tmp = tmp->next)
        {
            if (end < tmp->offset)
            {
                break;
                // tmp2 = tmp;
            }
        }
        prev->end = end;
        for (; NULL != next && next != tmp; next = next->next)
        {
            if (end <= next->end)
            {
                prev->end = next->end;
                end -= (end - next->offset);
                frags_kill(ip4_frag_handle, ipv4_qp, next);
                break;
            }
            ipv4_qp->meat -= (next->end - next->offset);
            frags_kill(ip4_frag_handle, ipv4_qp, next);
        }
    }
    else if (i >= 0)
    {
        if (end > prev->end)
        {
            prev->end = end;
        }
        else
        {
            end = offset;
        }
    }
    else if (j >= 0)
    {
        for (prev = next, tmp = next; NULL != tmp; tmp = tmp->next)
        {
            if (end < tmp->offset)
            {
                break;
                // prev = tmp;
            }
        }

        if (next != tmp)
        {
            next->offset = offset;
            next->end = end;
            for (tmp2 = next->next; NULL != tmp2 && tmp2 != tmp; tmp2 = tmp2->next)
            {
                if (end <= tmp2->end)
                {
                    next->end = tmp2->end;
                    end -= (end - tmp2->offset);
                    frags_kill(ip4_frag_handle, ipv4_qp, tmp2);
                    break;
                }
                ipv4_qp->meat -= (tmp2->end - tmp2->offset);
                frags_kill(ip4_frag_handle, ipv4_qp, tmp2);
            }
        }
        else
        {
            end -= j;
            next->offset = offset;
        }
    }

    ipv4_qp->meat += (end - offset);
	/*If ipq buff is not enough to store current fragment piece, get a bigger one*/
	if (end + private_info->raw_ip_hdr_len > ipv4_qp->buf_size) 
	{
		new_buf_size = ipv4_buff_size(end + private_info->raw_ip_hdr_len);
		new_ip4h = (struct mesa_ip4_hdr *)frag_malloc(ip4_frag_handle, new_buf_size);
		
		memcpy(new_ip4h, ipv4_qp->new_iph, ipv4_qp->buf_size);
		frag_free(ip4_frag_handle, ipv4_qp->new_iph, ipv4_qp->buf_size);
		ipv4_qp->new_iph = new_ip4h;
		ipv4_qp->buf_size = new_buf_size;
	}

	/*Copy the usefull data to the buffer*/
	memcpy((char *)(ipv4_qp->new_iph)+private_info->raw_ip_hdr_len+offset, ptr, end-offset);

	/*OK, so we inserted this new fragment into the chain.  Check if we
	now have a full IP datagram which we can bump up to the IP
	layer...*/
	if(((ipv4_qp->last_in & 0x03) == (IP_FRAG_FIRST_IN | IP_FRAG_LAST_IN)) 
      && (ipv4_qp->meat == ipv4_qp->tot_len)) 
    {
    		IPV4_PRINT("### ipv4 frag %p reassemb OK!\n", ipv4_qp);
#if (0 == HIGH_PERF)    		
		update_global_ip_frag_list(ipv4_qp->ipfrag_list, thread_num, __ADDR_TYPE_IP_PAIR_V4);
		ipv4_qp->ipfrag_list = NULL;
#endif

		raw_ip_len = ntohs(ipv4_qp->meat + private_info->raw_ip_hdr_len);
		//set scratch before frag_reassemble, cause frag_reassemble will free ipq
		ip4_frag_handle->scratch_frag_cnt=ipv4_qp->frags_num;
		ip4_frag_handle->scratch_frag_len=ipv4_qp->frags_len;		
#if USE_MESA_STREAM_HASH
		new_ip4h = (struct mesa_ip4_hdr*)frag_reassemble_v4(ip4_frag_handle, ipv4_qp, &ip4_frag_key);
#else
		new_ip4h = (struct mesa_ip4_hdr*)frag_reassemble(ip4_frag_handle, ipv4_qp);
#endif
		/*Adjust the ip total lenth*/
		//((struct ip *)ipv4_qp->new_iph)->ip_len = raw_ip_len;
		new_ip4h->ip_len = raw_ip_len;
		/*Adjust the ip flags*/
		//((struct ip *)ipv4_qp->new_iph)->ip_off = 0x0040;
		new_ip4h->ip_off = 0x0040;

		sendpacket_do_checksum((unsigned char *)new_ip4h, IPPROTO_IP, sizeof(struct ip));
		
		return new_ip4h;
	}	

#if (USE_MESA_STREAM_HASH==0)
	frag_lru_update(ip4_frag_handle, ipv4_qp);	
#endif

err:
	return NULL;
}

static inline void set_ipv4_addr(struct stream_tuple4_v4 *addr, struct mesa_ip4_hdr *iphdr)
{
	addr->saddr = iphdr->ip_src.s_addr;
	addr->daddr = iphdr->ip_dst.s_addr;
	addr->source = 0; 
	addr->dest = 0;
}

extern int sapp_is_overlay_layer(const struct streaminfo_private *stream_pr, const raw_pkt_t *rawpkt);
extern int stream_process_overlay_ipv4(struct streaminfo *pfstream, const struct ip* this_layer_hdr,
				int thread_num,unsigned char routedir, const raw_pkt_t *raw_pkt);

int ipv4_entry(struct streaminfo_private *pfstream_pr, const void *this_layer_data, int thread_num, 
			unsigned char routedir, const raw_pkt_t *raw_pkt, int offset_to_raw_pkt_hdr)
{
	const struct mesa_ip4_hdr *a_packet = (const struct mesa_ip4_hdr *)this_layer_data;
	struct mesa_ip4_hdr *new_iph = NULL; 
	unsigned short offset, flags;
	int ret = PASS;
	char need_free = 0;
	struct streamindex tmp_index;
	struct streamindex *ptmp;
	struct stream_tuple4_v4 addr;
	struct streaminfo *pfstream = (struct streaminfo *)pfstream_pr;
	struct streaminfo_private *pstream_pr;
	struct streaminfo *pstream;
	sapp_gval_mthread_sys_stat_t *local_sys_stat = &sapp_global_val->mthread_volatile[thread_num]->sys_stat;
	int this_layer_len = ntohs(a_packet->ip_len);
	int this_layer_is_overlay = 0;


	if(likely(pfstream_pr != NULL && pfstream_pr->layer_index < SAPP_SUPPORT_LAYER_NUM_MAX - 1 ))
	{
		local_sys_stat->count_per_layer[__ADDR_TYPE_IP_PAIR_V4][pfstream_pr->layer_index + 1]++;
		local_sys_stat->length_per_layer[__ADDR_TYPE_IP_PAIR_V4][pfstream_pr->layer_index + 1] += this_layer_len;
	}

	if(unlikely(checkipv4pkt(a_packet, raw_pkt) < 0)){
		local_sys_stat->count[SAPP_STAT_DROP_IPV4]++;
		local_sys_stat->length[SAPP_STAT_DROP_IPV4]+=this_layer_len;
		((raw_pkt_t *)raw_pkt)->diagnose_error_to_dump = 1;
		return PASS;
	}


	ptmp=&tmp_index;
	memset(ptmp, 0x0, sizeof(struct streamindex));
	pstream_pr = &ptmp->stream;
	pstream = &pstream_pr->stream_public;

	if(unlikely(pfstream_pr->layer_index >= SAPP_SUPPORT_LAYER_NUM_MAX)){
		local_sys_stat->count[SAPP_STAT_DROP_IPV4]++;
		sapp_runtime_log(RLOG_LV_INFO, "ipv4_entry: layer index more than:%d", pfstream_pr->layer_index);
		((raw_pkt_t *)raw_pkt)->diagnose_error_to_dump = 1;
		return PASS;
	}else{
		pstream_pr->layer_index = pfstream_pr->layer_index + 1;
	}
	set_ipv4_addr(&addr, (struct mesa_ip4_hdr *)a_packet);
	pstream->addr.paddr = &addr;
	pstream->addr.addrtype = __ADDR_TYPE_IP_PAIR_V4;
	pstream->addr.addrlen = sizeof(struct stream_tuple4_v4); 
	pstream->addr.pkttype = PKT_TYPE_NORMAL;
	pstream->addr.pktipfragtype = PKT_TYPE_NORMAL; /* 2014-12-25 lijia add */
	this_layer_is_overlay = sapp_is_overlay_layer(pstream_pr, raw_pkt);
	
	if(this_layer_is_overlay != 0){
		pstream_pr->addr_use_as_hash = 0;	
	}else{
		pstream_pr->addr_use_as_hash = 1;	
	}

	if((g_topology_mode & __NET_CONN_GDEV) && (this_layer_is_overlay != 0)){
		if(is_multicast_addr_v4(ntohl(a_packet->ip_dst.s_addr))){
			local_sys_stat->count[SAPP_STAT_DROP_IPV4]++;
			local_sys_stat->length[SAPP_STAT_DROP_IPV4]+=this_layer_len;
			return DROP;
		}	
	}
	
	//ptmp->stream.p_layer_header = a_packet;
	//ptmp->stream.offset_to_raw_pkt_hdr = (char *)a_packet - (char *)raw_pkt->raw_pkt_data;
	pstream_pr->offset_to_raw_pkt_hdr = offset_to_raw_pkt_hdr;
	pstream_pr->raw_pkt = raw_pkt; /* 2014-12-30 lijia add */

	if(a_packet->ip_src.s_addr >= a_packet->ip_dst.s_addr){
		pstream_pr->layer_dir = 1;
		pstream->curdir = DIR_C2S;
	}else{
		pstream_pr->layer_dir = 0;
		pstream->curdir = DIR_S2C;
	}

	if((pfstream_pr != NULL)
	  && (g_overlay_layer_set[pfstream_pr->stream_public.addr.addrtype][pfstream_pr->layer_index] != 0)){ /* 2021-01-11 lijia add, overlay���pfather��ΪNULL, ������ɼ� */
		pstream->pfather = NULL;
	}else{
		pstream->pfather=pfstream;
	}
	pstream_pr->pfather_pr = pfstream_pr;
	pstream->type=STREAM_TYPE_NON;
	pstream->routedir=routedir;
	pstream->threadnum=thread_num;

	if(this_layer_is_overlay != 0){
		ret = stream_process_overlay_ipv4(pstream, (const struct ip *)this_layer_data, thread_num, routedir, raw_pkt);
		if(DROP == ret){
			return DROP;
		}
		int next_layer_offest = offset_to_raw_pkt_hdr + (a_packet->ip_hl << 2);
		ret=dealipv4udppkt(ptmp,a_packet,thread_num,routedir,raw_pkt, next_layer_offest);
		return ret;
	}
	
	/*See, is this a fragment*/
	offset = ntohs(a_packet->ip_off);
	flags = offset & ~IPv4_FRAG_OFFSET;
	offset &= IPv4_FRAG_OFFSET;

    if (unlikely(((flags & IPv4_FRAG_MF) != 0) || (offset != 0)))
    {
        if (unlikely(sapp_global_val->config.protocol_feature.ipv4_reassembly_enabled == 0))
        {
            local_sys_stat->count[SAPP_STAT_RCV_IPV4_FRAG]++;
            local_sys_stat->length[SAPP_STAT_RCV_IPV4_FRAG]++;
            return PASS;
        }
        pstream->addr.pktipfragtype = PKT_TYPE_IP_FRAG;
        new_iph = (struct mesa_ip4_hdr *)process_ipv4_frag(&ptmp->stream, a_packet, thread_num, raw_pkt);

        if (NULL == new_iph)
        {
            local_sys_stat->count[SAPP_STAT_RCV_IPV4_FRAG]++;
            local_sys_stat->length[SAPP_STAT_RCV_IPV4_FRAG]++;
            stream_process_ipv4_frag(pstream, (const struct ip *)a_packet, thread_num, routedir, raw_pkt);
            return PASS;
        }
        a_packet = new_iph;
        need_free = 1;
        pstream->addr.pktipfragtype = PKT_TYPE_IPREBUILD | PKT_TYPE_IP_FRAG_LAST;
    }

    if(need_free){
		local_sys_stat->count[SAPP_STAT_RCV_IPV4_FRAG]++;
		local_sys_stat->length[SAPP_STAT_RCV_IPV4_FRAG] += this_layer_len;
	}else{
		//if(0 == this_layer_is_overlay)
		{
			local_sys_stat->count[SAPP_STAT_RCV_IPV4]++;
			local_sys_stat->length[SAPP_STAT_RCV_IPV4] += this_layer_len;
			if (routedir == sapp_global_val->config.packet_io.inbound_route_dir)
			{
				local_sys_stat->count[SAPP_STAT_IPV4_INBOUND]++;
				local_sys_stat->length[SAPP_STAT_IPV4_INBOUND] += (unsigned long long)this_layer_len;
			}
			else
			{
				local_sys_stat->count[SAPP_STAT_IPV4_OUTBOUND]++;
				local_sys_stat->length[SAPP_STAT_IPV4_OUTBOUND] += (unsigned long long)this_layer_len;
			}
		}
	}

  	if(unlikely(sapp_global_single.ipentry_priority_over_ipfrag != 0)){
		ret = process_ipv4_pkt(ptmp, a_packet, thread_num, routedir, raw_pkt, offset_to_raw_pkt_hdr);
		if((PASS == ret) && (pstream->addr.pktipfragtype & (PKT_TYPE_IP_FRAG | PKT_TYPE_IP_FRAG_LAST))){
			ret = stream_process_ipv4_frag(pstream, (const struct ip *)this_layer_data, thread_num, routedir, raw_pkt);
		}
  	}else{
  		if(pstream->addr.pktipfragtype & (PKT_TYPE_IP_FRAG | PKT_TYPE_IP_FRAG_LAST)){
			ret = stream_process_ipv4_frag(pstream, (const struct ip *)this_layer_data, thread_num, routedir, raw_pkt);	
		}
		
		if(PASS == ret){
			ret = process_ipv4_pkt(ptmp, a_packet, thread_num, routedir, raw_pkt, offset_to_raw_pkt_hdr);
		}
  	}


	if(unlikely(need_free)){
#if (0 == HIGH_PERF)	
		raw_frags_list_free_global(thread_num, __ADDR_TYPE_IP_PAIR_V4);
#endif		
		sapp_mem_free(SAPP_MEM_DYN_IP_FRAG_PKT,thread_num, new_iph);
	}
	
	return ret;
}

MESA_htable_handle ipv4_frag_htable_create(void)
{
	MESA_htable_handle htable;
	int ret, opt_int;
	
	htable = MESA_htable_born();
	assert(htable != NULL);

	opt_int = 0;
	MESA_htable_set_opt(htable, MHO_THREAD_SAFE, &opt_int, sizeof(int));

	opt_int = 1048576;
	MESA_htable_set_opt(htable, MHO_HASH_SLOT_SIZE, &opt_int, sizeof(int));

	opt_int = 50000;
	MESA_htable_set_opt(htable, MHO_HASH_MAX_ELEMENT_NUM, &opt_int, sizeof(int));

	opt_int = IPV4_FRAG_TIMEOUT;
	MESA_htable_set_opt(htable, MHO_EXPIRE_TIME, &opt_int, sizeof(int));

	opt_int = 0;
	MESA_htable_set_opt(htable, MHO_AUTO_UPDATE_TIME, &opt_int, sizeof(int));

	opt_int = 0;
	MESA_htable_set_opt(htable, MHO_SCREEN_PRINT_CTRL, &opt_int, sizeof(int));

	opt_int = HASH_ELIMINATE_ALGO_LRU;
	MESA_htable_set_opt(htable, MHO_ELIMIMINATE_TYPE, &opt_int, sizeof(int));	

	MESA_htable_set_opt(htable, MHO_CBFUN_KEY_COMPARE, (void *)&ipv4_frag_key_cmp_cb, sizeof(void *));	

	MESA_htable_set_opt(htable, MHO_CBFUN_KEY_TO_INDEX,  (void *)&ipv4_frag_hash_index, sizeof(void *));	

	MESA_htable_set_opt(htable, MHO_CBFUN_DATA_FREE,  (void *)&ipv4_frag_ipq_free_all, sizeof(void *));	

	MESA_htable_set_opt(htable, MHO_CBFUN_COMPLEX_KEY_DUP,  (void *)&ipv4_frag_key_dup, sizeof(void *));	

	MESA_htable_set_opt(htable, MHO_CBFUN_COMPLEX_KEY_FREE,  (void *)&ipv4_frag_key_free, sizeof(void *));	
	
	opt_int = 100;
	MESA_htable_set_opt(htable, MHO_HASH_LIST_COLLIDE_THRESHOLD, &opt_int, sizeof(int));	

	char *err_log = (char *)"./log/ipv4_frag_hash_collide.log";
	MESA_htable_set_opt(htable, MHO_HASH_LOG_FILE, (void *)err_log, strlen(err_log));	
	
	ret = MESA_htable_mature(htable);
	if(ret < 0){
		return NULL;
	}

	return htable;
}

int ipv4_frag_init(int thread_count, uint32 hash_size)
{
	int i;
	
	g_ipv4_frag_manage = (struct frag_manage *)SAPP_GLOBAL_ALLOC(sizeof(struct frag_manage) * thread_count);
	if(NULL == g_ipv4_frag_manage)
	{
		//to do!
		return -1;
	}
	memset(g_ipv4_frag_manage, 0, sizeof(struct frag_manage) * thread_count);

	for(i = 0; i < thread_count; i++)
	{
		g_ipv4_frag_manage[i].thread_num = i;
		
		g_ipv4_frag_manage[i].frag_hash_table = ipv4_frag_htable_create();
		if(NULL == g_ipv4_frag_manage[i].frag_hash_table){
			printf("ipv4_frag_init(): MESA_htable_create fail!\n");
			sapp_runtime_log(RLOG_LV_FATAL, "ipv4_frag_init(): MESA_htable_create fail!");
			goto err;
		}

	}

	FRAG_IP4_RANDOM = 0xABCD9876;
	
	return 0;

err:
	SAPP_GLOBAL_FREE(g_ipv4_frag_manage);
	return -1;
}


void ipv4_frag_per_thread_exit(int thread_seq)
{
	MESA_htable_destroy(g_ipv4_frag_manage[thread_seq].frag_hash_table, NULL);
}


void ipv4_frag_exit(void)
{
	SAPP_GLOBAL_FREE(g_ipv4_frag_manage);
}

static inline int checkipv4pkt(const struct mesa_ip4_hdr * iph, const raw_pkt_t *raw_pkt)
{
	int pkt_declare_len = ntohs(iph->ip_len);
	int pkt_actual_len;
	unsigned char ip_proto;

	if (raw_pkt->offset_to_raw_pkt_hdr != 0)
	{
		pkt_actual_len = raw_pkt->raw_pkt_len - raw_pkt->offset_to_raw_pkt_hdr;
	}
	else
	{
		if (ADDR_TYPE_MAC == raw_pkt->low_layer_type)
		{
			pkt_actual_len = raw_pkt->raw_pkt_len - sizeof(struct mesa_ethernet_hdr);
		}
		else
		{
			pkt_actual_len = raw_pkt->raw_pkt_len;
		}
	}
	if ((pkt_declare_len < (int)sizeof(struct mesa_ip4_hdr)) 
		|| (pkt_declare_len > pkt_actual_len)
		|| (iph->ip_hl < 5) 
		|| (iph->ip_v != 4)
		|| (pkt_declare_len < iph->ip_hl << 2)){

		if(raw_pkt->is_ctrl_pkt==0)
		{
			sapp_runtime_log(RLOG_LV_DEBUG, "ipv4 packet check error: pkt length, hdr len, or version error, pkt_declare_len:%d, pkt_actual_len:%d", pkt_declare_len, pkt_actual_len);
			return -1;
		}
	}

	ip_proto = iph->ip_p;
	if(ip_proto >= 0x8F){ 
		sapp_runtime_log(RLOG_LV_DEBUG, "ipv4 packet check error: unknow proto: %u", ip_proto);
		return -1;
	}

	return 0;
}

#if USE_MESA_STREAM_HASH
static unsigned int ipv4_frag_hash_index(const MESA_htable_handle table, const uchar * key, unsigned int size)
{
	struct ipv4_frag_key *ipv4_key = (struct ipv4_frag_key *)key;

	return ipv4_frag_hash_algo(ipv4_key->identification,
							   ipv4_key->protocol,
						  	   ipv4_key->ip_src,
						  	   ipv4_key->ip_dst,
						  	   FRAG_IP4_RANDOM);					  	   
}

static void ipv4_frag_key_free(uchar *key, uint key_size)
{
	struct ipv4_frag_key *frag_key;
	int tid;
	
	if(NULL == key){
		return;
	}

	frag_key = (struct ipv4_frag_key *)key;
	tid = frag_key->pstream_pr->stream_public.threadnum;

	MESA_stream_list_free(SAPP_MEM_DYN_IP_FRAG_PKT, frag_key->pstream_pr);
	
	sapp_mem_free(SAPP_MEM_DYN_IP_FRAG_PKT, tid, frag_key);
}

static uchar * ipv4_frag_key_dup(const uchar *key, uint key_size)
{
	struct ipv4_frag_key *new_frag_key, *raw_frag_key;
	int tid;

	raw_frag_key = (struct ipv4_frag_key *)key;
	tid = raw_frag_key->pstream_pr->stream_public.threadnum;

	new_frag_key = (struct ipv4_frag_key *)sapp_mem_calloc(SAPP_MEM_DYN_IP_FRAG_PKT, tid, sizeof(struct ipv4_frag_key));

	new_frag_key->ip_src = raw_frag_key->ip_src;
	new_frag_key->ip_dst = raw_frag_key->ip_dst;
	new_frag_key->identification = raw_frag_key->identification;
	new_frag_key->protocol = raw_frag_key->protocol;
	memset(new_frag_key->__pad__, 0, sizeof(new_frag_key->__pad__));

	new_frag_key->pstream_pr = MESA_stream_list_dup(SAPP_MEM_DYN_IP_FRAG_PKT, raw_frag_key->pstream_pr, 0);

	return (uchar *)new_frag_key;
}

static int ipv4_frag_key_cmp_cb(const uchar * key1, uint size1, const uchar * key2, uint size2)
{
	int ret;
	const struct ipv4_frag_key *ipv4_fkey1 = (const struct ipv4_frag_key *)key1;
	const struct ipv4_frag_key *ipv4_fkey2 = (const struct ipv4_frag_key *)key2;

	if(!
	 ((ipv4_fkey1->identification == ipv4_fkey2->identification)
	 &&(ipv4_fkey1->ip_src == ipv4_fkey2->ip_src)
	 &&(ipv4_fkey1->ip_dst == ipv4_fkey2->ip_dst)
	 &&(ipv4_fkey1->protocol== ipv4_fkey2->protocol))){
		return -1;
	}

	ret = MESA_stream_list_cmp(ipv4_fkey1->pstream_pr, ipv4_fkey2->pstream_pr);

	return ret;
}

static void ipv4_frag_ipq_free_no_iph(void *data)
{
	struct frag_ipq *ipq = (struct frag_ipq *)data;
	struct ip_frags *frag, *next;
	int thread_num = ipq->thread_num;

	/* Release all fragment data. */
	frag = ipq->fragments;
	while(frag != NULL) 
	{
    		next = frag->next;
		sapp_mem_free(SAPP_MEM_DYN_IP_FRAG_PKT, thread_num, frag);
		frag = next;
	}

	if(ipq->private_info && ipq->private_len)
	{
		sapp_mem_free(SAPP_MEM_DYN_IP_FRAG_PKT, thread_num, ipq->private_info);
	}

#if (0 == HIGH_PERF)
	raw_frags_list_free_one(thread_num, ipq->ipfrag_list);
#endif

	ipq->ipfrag_list = NULL;

	sapp_mem_free(SAPP_MEM_DYN_IP_FRAG_PKT, thread_num, ipq);

	return;
}

static void ipv4_frag_ipq_free_all(void *data)
{
	struct frag_ipq *ipq = (struct frag_ipq *)data;

	if(ipq->new_iph){
		sapp_mem_free(SAPP_MEM_DYN_IP_FRAG_PKT,ipq->thread_num, ipq->new_iph);
	}
	ipv4_frag_ipq_free_no_iph(data);

	return;
}	

static void build_ipv4_frag_key(struct streaminfo_private *pfstream_pr, const struct mesa_ip4_hdr *a_packet,
						 /*@out@*/ struct ipv4_frag_key *ip4_frag_key)
{
	ip4_frag_key->ip_src = a_packet->ip_src.s_addr;
	ip4_frag_key->ip_dst = a_packet->ip_dst.s_addr;
	ip4_frag_key->identification = a_packet->ip_id; 
	ip4_frag_key->protocol = a_packet->ip_p;
	memset(ip4_frag_key->__pad__ , 0, sizeof(ip4_frag_key->__pad__));
	ip4_frag_key->pstream_pr = pfstream_pr;
}

static struct frag_ipq *ipv4_frag_queue_find(struct streaminfo *pstream, 
				struct frag_manage *handle, struct ipv4_frag_key *ip4_frag_key)
{
	struct frag_ipq *frag_ipq;
	int ret;
	
	frag_ipq = (struct frag_ipq *)MESA_htable_search(handle->frag_hash_table,
											   (const uchar *)ip4_frag_key,
											   sizeof(struct ipv4_frag_key));
	if(NULL == frag_ipq){
		frag_ipq = frag_ipq_create(pstream->threadnum);
		ret = MESA_htable_add(handle->frag_hash_table,
							 (const uchar *)ip4_frag_key,
							sizeof(struct ipv4_frag_key),
							frag_ipq);
		if(ret < 0){
			ipv4_frag_ipq_free_all(frag_ipq); /* 2015-12-01 lijia add, for memory leak */
			return NULL;
		}
	}

	return frag_ipq;
}

static void *frag_reassemble_v4(struct frag_manage *handle, struct frag_ipq *ipq, 
								struct ipv4_frag_key *ip4_frag_key)
{
	void *new_iph;

	new_iph = frag_reassemble(handle, ipq);
	
	MESA_htable_del(handle->frag_hash_table, 
					(const uchar *)ip4_frag_key,
					sizeof(struct ipv4_frag_key),
					ipv4_frag_ipq_free_no_iph);	
	return new_iph;				
}

#endif


#ifdef __cplusplus
}
#endif

