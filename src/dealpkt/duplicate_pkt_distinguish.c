#ifdef __cplusplus
extern "C" {
#endif
#include "sapp_api.h"
#include "sapp_private_api.h"
#include "sapp_declaration.h"

#include "ap_bloom.h"
#include "dablooms.h"




/*
	识别因路由策略导致的重复流量, 首次收到数据包加入bloom filter,
	每个流的前N个包扫描bloom filter, 重复的数据包直接转发即可.

	ip层的ttl, hop不能算为key, 因为经过了几跳路由器又回绕了, ttl肯定会变�??, 而上层的数据包确实是重复�??.
*/

/* 
    2021-05-18 lijia close ipv6 protocol:

    重复流量识别bloom filter句柄, 根据流量方向和协议的不同, 功能分为三类,  
    IPv6因为没有Ipid字段, 无法区别真正的应用层重传和重复流�??, 开启了会导致断网或者CT, 所以不支持!!!

	对于IPv6的两种情�??:
       1)如果开启了代理策略, 重传包被识别成了重复包的�??, sapp就直接PASS�??, 实际那个包是真实通信双方发的, 没有经过tfe处理, 可能就断网了.
       2)如果开启了firewall的drop策略, 第一次drop成功�??, 但应用层会重�??, 重传包被识别成了重复包的�??, sapp就直接PASS�??, 导致CT.
*/

void *bloom_new(const sapp_dup_pkt_t *dup_conf, struct timeval now, long now_ms)
{
	switch(dup_conf->bloom_library)
	{
		case BLOOM_LIBRARY_APBLOOM:
			return AP_bloom_new(now, dup_conf->bloom_error_rate, dup_conf->bloom_capacity, dup_conf->bloom_timeout_ms, dup_conf->bloom_slice_num);
		case BLOOM_LIBRARY_DABLOOM:
			return expiry_dablooms_init(dup_conf->bloom_partition_num, dup_conf->bloom_capacity, dup_conf->bloom_error_rate, now_ms, dup_conf->bloom_timeout_ms, dup_conf->transition_time_ms);
		default:
			return NULL;
	}
}

void bloom_free(void *bloom_filter, const sapp_dup_pkt_t *dup_conf)
{
	switch(dup_conf->bloom_library)
	{
		case BLOOM_LIBRARY_APBLOOM:
			 return AP_bloom_free(bloom_filter);
		case BLOOM_LIBRARY_DABLOOM:
			return expiry_dablooms_destroy(bloom_filter);
		default:
			break;
	}
	return;
}


int bloom_check(void *bloom_filter, const char *key, int key_len, const sapp_dup_pkt_t *dup_conf, struct timeval now, long now_ms)
{
	switch(dup_conf->bloom_library)
	{
		case BLOOM_LIBRARY_APBLOOM:
			return AP_bloom_check((const struct AP_bloom *)bloom_filter, 
										now, (const char *)key, key_len);		
		case BLOOM_LIBRARY_DABLOOM:
			return expiry_dablooms_search((struct expiry_dablooms_handle *)bloom_filter, 
										(const char *)key, key_len, now_ms);
		default:
			return 0;
	}
}

void bloom_add(void *bloom_filter, const char *key, int key_len, const sapp_dup_pkt_t *dup_conf, struct timeval now, long now_ms)
{
	switch(dup_conf->bloom_library)
	{
		case BLOOM_LIBRARY_APBLOOM:
			return AP_bloom_add((struct AP_bloom *)bloom_filter, 
										now, (const char *)key, key_len);		
		case BLOOM_LIBRARY_DABLOOM:
			expiry_dablooms_add((struct expiry_dablooms_handle *)bloom_filter, 
										(const char *)key, key_len, now_ms);
			break;
		default:
			break;
	}
	return;
}

int AP_bloomfilter_get_stat(const struct AP_bloom *bloom, sapp_sys_stat_type_t type, long long *count)
{
	switch(type){
		case SAPP_STAT_BM_HASH_NUM:
			*count = (long long)AP_bloom_stat_get_hash_num(bloom);
		break;
		case SAPP_STAT_BM_SLICE_NUM_NEW:
			*count = (long long)AP_bloom_stat_get_new_num(bloom);
		break;
		case SAPP_STAT_BM_SLICE_NUM_FREE:
			*count = (long long)AP_bloom_stat_get_free_num(bloom);
		break;
		case SAPP_STAT_BM_EXPAND_NUM:
			*count = (long long)AP_bloom_stat_get_expand_num(bloom);
		break;
		case SAPP_STAT_BM_CUR_SLICE_NUM:
			*count = (long long)AP_bloom_stat_get_cur_slice_num(bloom);
		break;
		case SAPP_STAT_APBM_EXPAND_MAX_MULTIPLE:
			*count = (long long)AP_bloom_stat_get_expand_max_multiple(bloom);
		break;

		default:
			*count = 0;
		break;
	}
	return 0;
}

int DA_bloomfilter_get_stat(const struct expiry_dablooms_handle *bloom, sapp_sys_stat_type_t type, long long *count)
{
	switch(type){
		case SAPP_STAT_BM_HASH_NUM:
			*count = (long long)DA_bloom_stat_get_hash_num(bloom);
		break;
		case SAPP_STAT_BM_SLICE_NUM_NEW:
			*count = (long long)DA_bloom_stat_get_slice_new_num(bloom);
		break;
		case SAPP_STAT_BM_SLICE_NUM_FREE:
			*count = (long long)DA_bloom_stat_get_slice_free_num(bloom);
		break;		
		case SAPP_STAT_BM_EXPAND_NUM:
			*count = (long long)DA_bloom_stat_get_expand_num(bloom);
		break;
		case SAPP_STAT_BM_CUR_SLICE_NUM:
			*count = (long long)DA_bloom_stat_get_cur_slice_num(bloom);
		break;
		case SAPP_STAT_DABM_RESIZE_MAX_RATIO:
			*count = (long long)DA_bloom_stat_get_resize_ratio(bloom);
		break;

		default:
			*count = 0;
		break;
	}
	return 0;
}

int bloomfilter_get_stat_by_type(void *bm_handle, sapp_sys_stat_type_t type, long long *count)
{
	
	switch (sapp_global_val->config.packet_io.dup_pkt_para.bloom_library)
	{
	case BLOOM_LIBRARY_APBLOOM:
		AP_bloomfilter_get_stat((const struct AP_bloom *)bm_handle, type, count);
		break;

	case BLOOM_LIBRARY_DABLOOM:
		DA_bloomfilter_get_stat((struct expiry_dablooms_handle *)bm_handle, type, count);
		break;

	default:
		break;
	}

	return 0;
}

static int bloomfilter_get_stat(int tseq, void *bm_handle)
{
	sapp_gval_mthread_t **mstat = sapp_global_val->mthread_volatile;
	long long count = 0;
	bloomfilter_get_stat_by_type(bm_handle, SAPP_STAT_BM_HASH_NUM, &count);
	mstat[tseq]->sys_stat.count[SAPP_STAT_BM_HASH_NUM] = count;
	count = 0;
	bloomfilter_get_stat_by_type(bm_handle, SAPP_STAT_BM_EXPAND_NUM, &count);
	mstat[tseq]->sys_stat.count[SAPP_STAT_BM_EXPAND_NUM] = count;
	count = 0;
	bloomfilter_get_stat_by_type(bm_handle, SAPP_STAT_BM_SLICE_NUM_NEW, &count);
	mstat[tseq]->sys_stat.count[SAPP_STAT_BM_SLICE_NUM_NEW] = count;
	count = 0;
	bloomfilter_get_stat_by_type(bm_handle, SAPP_STAT_BM_SLICE_NUM_FREE, &count);
	mstat[tseq]->sys_stat.count[SAPP_STAT_BM_SLICE_NUM_FREE] = count;
	count = 0;
	bloomfilter_get_stat_by_type(bm_handle, SAPP_STAT_BM_CUR_SLICE_NUM, &count);
	mstat[tseq]->sys_stat.count[SAPP_STAT_BM_CUR_SLICE_NUM] = count;
	count = 0;
	bloomfilter_get_stat_by_type(bm_handle, SAPP_STAT_APBM_EXPAND_MAX_MULTIPLE, &count);
	mstat[tseq]->sys_stat.count[SAPP_STAT_APBM_EXPAND_MAX_MULTIPLE] = count;
	count = 0;
	bloomfilter_get_stat_by_type(bm_handle, SAPP_STAT_DABM_RESIZE_MAX_RATIO, &count);
	mstat[tseq]->sys_stat.count[SAPP_STAT_DABM_RESIZE_MAX_RATIO] = count;
	return 0;
}

int bloomfilter_get_mem_stat(int tseq, long long *mem_blocks, long long *mem_bytes)
{
	void *bm_handle = (struct bloom_partition *)sapp_global_val->mthread_volatile[tseq]->dup_pkt_distinguish_handle;

	if(NULL == bm_handle){
		*mem_blocks = 0;
		*mem_bytes = 0;		
		return 0;
	}

	switch (sapp_global_val->config.packet_io.dup_pkt_para.bloom_library)
	{
	case BLOOM_LIBRARY_APBLOOM:
		*mem_blocks = (long long)AP_bloom_mem_blocks((const struct AP_bloom *)bm_handle);
		*mem_bytes = (long long)AP_bloom_mem_size((const struct AP_bloom *)bm_handle);
		break;

	case BLOOM_LIBRARY_DABLOOM:
		expiry_dablooms_get_mem_stat((struct expiry_dablooms_handle *)bm_handle, mem_blocks, mem_bytes);
	break;

	default:
		break;
	}

	bloomfilter_get_stat(tseq, bm_handle);

	return 0;
}

__thread time_t t_last_get_time = 0;
void bloom_mem_stat_update(int thread_seq, time_t now)
{
	if(now <= t_last_get_time)
	{
		return;
	} 

	long long blocks = 0, bytes = 0;
	bloomfilter_get_mem_stat(thread_seq, &blocks, &bytes);

	sapp_global_val->mthread_volatile[thread_seq]->mem_used_stat.mem_used_block[SAPP_MEM_DYN_BLOOM_FILTER] = blocks;
	sapp_global_val->mthread_volatile[thread_seq]->mem_used_stat.mem_used_bytes[SAPP_MEM_DYN_BLOOM_FILTER] = bytes;
	
	t_last_get_time = now;
	return;
}

int sapp_dup_stream_search(struct streaminfo *a_stream)
{
	void *key=NULL;
	int key_len=0;
	if(a_stream->addr.addrtype == ADDR_TYPE_IPV4)
	{
		key = (void *)a_stream->addr.tuple4_v4;
		key_len=sizeof(struct stream_tuple4_v4);
	}
	if(a_stream->addr.addrtype == ADDR_TYPE_IPV6)
	{
		key = (void *)a_stream->addr.tuple4_v6;
		key_len=sizeof(struct stream_tuple4_v6);
	}

	struct timeval now={g_CurrentTime, 0};
	bloom_mem_stat_update(a_stream->threadnum, g_CurrentTime);
	return bloom_check(sapp_global_val->mthread_volatile[a_stream->threadnum]->dup_pkt_distinguish_handle, key, key_len, &sapp_global_val->config.packet_io.dup_pkt_para, now, g_current_time_ms);
}


void sapp_dup_stream_add(struct streaminfo *a_stream)
{
	void *key=NULL;
	int key_len=0;
	if(a_stream->addr.addrtype == ADDR_TYPE_IPV4)
	{
		key = (void *)a_stream->addr.tuple4_v4;
		key_len=sizeof(struct stream_tuple4_v4);
	}
	if(a_stream->addr.addrtype == ADDR_TYPE_IPV6)
	{
		key = (void *)a_stream->addr.tuple4_v6;
		key_len=sizeof(struct stream_tuple4_v6);
	}
	struct timeval now={g_CurrentTime, 0};
	bloom_mem_stat_update(a_stream->threadnum, g_CurrentTime);
	bloom_add(sapp_global_val->mthread_volatile[a_stream->threadnum]->dup_pkt_distinguish_handle, key, key_len, &sapp_global_val->config.packet_io.dup_pkt_para, now, g_current_time_ms);
}

static inline int sapp_set_dup_pkt_key(enum addr_type_t addr_type, enum stream_type_t stream_type, const void *iphdr,
                                              const void *l4_hdr, void *key)
{
    struct __sapp_dup_pkt_key_l4 *l4 = (struct __sapp_dup_pkt_key_l4 *)key;
	size_t key_len = 0;
    if (stream_type == STREAM_TYPE_TCP)
    {
		const struct mesa_tcp_hdr *thdr = (const struct mesa_tcp_hdr *)l4_hdr;
        l4->tcp_seq = thdr->th_seq;
        l4->tcp_ack = thdr->th_ack;
        l4->sport = thdr->th_sport;
        l4->dport = thdr->th_dport;
        l4->checksum = thdr->th_sum;
    }
	if (stream_type == STREAM_TYPE_UDP)
    {
		const struct mesa_udp_hdr *uhdr = (const struct mesa_udp_hdr *)l4_hdr;
        l4->tcp_seq = 0x5A5A5A5A; /* udp没有, 但设�??0可能对某些hash函数不友�??, 此处设个固定�?? */
        l4->tcp_ack = 0xA5A5A5A5; /* udp没有, 但设�??0可能对某些hash函数不友�??, 此处设个固定�?? */
        l4->sport = uhdr->uh_sport;
        l4->dport = uhdr->uh_dport;
        l4->checksum = uhdr->uh_sum;
    }
    if (addr_type == ADDR_TYPE_IPV4)
    {
        sapp_dup_pkt_key_v4_t *key_v4 = (sapp_dup_pkt_key_v4_t *)key;
        const struct mesa_ip4_hdr *ip4hdr = (const struct mesa_ip4_hdr *)iphdr;
        key_v4->ip_addr.sip = ip4hdr->ip_src.s_addr;
        key_v4->ip_addr.dip = ip4hdr->ip_dst.s_addr;
        key_v4->ip_id = ip4hdr->ip_id;
		key_len = sizeof(sapp_dup_pkt_key_v4_t);
    }
    if (addr_type == ADDR_TYPE_IPV6)
    {
        sapp_dup_pkt_key_v6_t *key_v6 = (sapp_dup_pkt_key_v6_t *)key;
        const struct mesa_ip6_hdr *ip6hdr = (const struct mesa_ip6_hdr *)iphdr;
        memcpy(&key_v6->ip_addr.sip, &ip6hdr->ip6_src, sizeof(struct in6_addr));
        memcpy(&key_v6->ip_addr.dip, &ip6hdr->ip6_dst, sizeof(struct in6_addr));
		key_len = sizeof(sapp_dup_pkt_key_v6_t);
    }
    return key_len;
}


union sapp_dup_pkt_key
{
	sapp_dup_pkt_key_v4_t v4;
	sapp_dup_pkt_key_v6_t v6;
};

int sapp_dup_pkt_identify(int tid, struct streaminfo_private *pstream_pr, 
		const void *ip_hdr, const void *l4_hdr, int need_add_bloom_filter)
{
	int is_dup_pkt = 0;
	union sapp_dup_pkt_key dup_bloom_key;
	struct timeval now={g_CurrentTime, 0};	
	bloom_mem_stat_update(tid, g_CurrentTime);
	size_t key_len = sapp_set_dup_pkt_key((enum addr_type_t)pstream_pr->stream_public.addr.addrtype, (enum stream_type_t)pstream_pr->stream_public.type, ip_hdr, (void *)l4_hdr, &dup_bloom_key);			
	is_dup_pkt= bloom_check(sapp_global_val->mthread_volatile[tid]->dup_pkt_distinguish_handle, (const char*)&dup_bloom_key, key_len, &sapp_global_val->config.packet_io.dup_pkt_para, now, g_current_time_ms);
	if(is_dup_pkt != 0){
		pstream_pr->has_duplicate_pkt = 1;
	}else{
		if(need_add_bloom_filter){
			bloom_add(sapp_global_val->mthread_volatile[tid]->dup_pkt_distinguish_handle, (const char*)&dup_bloom_key, key_len, &sapp_global_val->config.packet_io.dup_pkt_para, now, g_current_time_ms);
		}
	}
	return is_dup_pkt;
}
void sapp_dup_pkt_mark_l4(struct streaminfo *a_stream, const void *ip_hdr, const void *l4_hdr)
{
	int tid = a_stream->threadnum;
    union sapp_dup_pkt_key dup_bloom_key;
    size_t key_len = 0;
    int ret = 0;
	bloom_mem_stat_update(tid, g_CurrentTime);
	struct timeval now={g_CurrentTime, 0};		
    key_len = sapp_set_dup_pkt_key((enum addr_type_t)a_stream->addr.addrtype, (enum stream_type_t)a_stream->type, ip_hdr, l4_hdr, &dup_bloom_key);
	bloom_add(sapp_global_val->mthread_volatile[tid]->dup_pkt_distinguish_handle, (const char*)&dup_bloom_key, key_len, &sapp_global_val->config.packet_io.dup_pkt_para, now, g_current_time_ms);
    return;
}

int sapp_dup_pkt_init(void)
{
	int i;
	const sapp_dup_pkt_t *p_dup_conf = &sapp_global_val->config.packet_io.dup_pkt_para;
	
	if( (0 == sapp_global_val->config.packet_io.dup_pkt_para.kickout_udp_stream_enabled)
	  && (0 == sapp_global_val->config.packet_io.dup_pkt_para.dup_pkt_distinguish_all_inject)
	  && (0 == sapp_global_val->config.packet_io.dup_pkt_para.dup_pkt_distinguish_ipv4_tcp)
	  && (0 == sapp_global_val->config.packet_io.dup_pkt_para.dup_pkt_distinguish_ipv4_udp)){
		return 0;
	}

	/* 流量入口有三个开�??, 识别句柄只有一�??, 
	   拆分句柄多耗费内存, 且判断时每个包需要扫描多个句�??, 
	   可能好处只是准确率高了一点点而已 */
	struct timeval now={time(NULL), 0};	
	for(i = 0; i < sapp_global_val->config.cpu.worker_threads; i++){
		sapp_global_val->mthread_volatile[i]->dup_pkt_distinguish_handle = bloom_new(p_dup_conf, now, g_current_time_ms);
		if(NULL == sapp_global_val->mthread_volatile[i]->dup_pkt_distinguish_handle){
			sapp_log(RLOG_LV_FATAL, 1, 1, "dup_pkt_distinguish init error!");
			return -1;
		}
	}
	sapp_log(RLOG_LV_DEBUG, 1, 1, "dup_pkt_distinguish init success");

	return 0;
}

void sapp_dup_pkt_destroy(void)
{
	int i;
	const sapp_dup_pkt_t *p_dup_conf = &sapp_global_val->config.packet_io.dup_pkt_para;
	for(i = 0; i < sapp_global_val->config.cpu.worker_threads; i++){
		if(sapp_global_val->mthread_volatile[i]->dup_pkt_distinguish_handle){
			bloom_free(sapp_global_val->mthread_volatile[i]->dup_pkt_distinguish_handle,p_dup_conf);
		}
	}

}

#ifdef __cplusplus
}
#endif


