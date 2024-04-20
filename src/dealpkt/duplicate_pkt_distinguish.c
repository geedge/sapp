#ifdef __cplusplus
extern "C" {
#endif
#include "sapp_api.h"
#include "sapp_private_api.h"
#include "sapp_declaration.h"

#include "ap_bloom.h"

/*
	识别因路由策略导致的重复流量, 首次收到数据包加入bloom filter,
	每个流的前N个包扫描bloom filter, 重复的数据包直接转发即可.

	ip层的ttl, hop不能算为key, 因为经过了几跳路由器又回绕了, ttl肯定会变化, 而上层的数据包确实是重复的.
*/

/* 
    2021-05-18 lijia close ipv6 protocol:

    重复流量识别bloom filter句柄, 根据流量方向和协议的不同, 功能分为三类,  
    IPv6因为没有Ipid字段, 无法区别真正的应用层重传和重复流量, 开启了会导致断网或者CT, 所以不支持!!!

	对于IPv6的两种情况:
       1)如果开启了代理策略, 重传包被识别成了重复包的话, sapp就直接PASS了, 实际那个包是真实通信双方发的, 没有经过tfe处理, 可能就断网了.
       2)如果开启了firewall的drop策略, 第一次drop成功了, 但应用层会重传, 重传包被识别成了重复包的话, sapp就直接PASS了, 导致CT.
*/



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

	struct timeval now;
	now.tv_sec = g_CurrentTime;
	now.tv_usec=0;
	return AP_bloom_check((const struct AP_bloom *)sapp_global_val->mthread_volatile[a_stream->threadnum]->dup_pkt_distinguish_handle, 
										now, (const char *)key, key_len);		
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
	struct timeval now;
	now.tv_sec = g_CurrentTime;
	now.tv_usec=0;	
    AP_bloom_add(
        (struct AP_bloom *)sapp_global_val->mthread_volatile[a_stream->threadnum]->dup_pkt_distinguish_handle,
		now,
        (const char *)key, key_len);
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
        l4->tcp_seq = 0x5A5A5A5A; /* udp没有, 但设成0可能对某些hash函数不友好, 此处设个固定值 */
        l4->tcp_ack = 0xA5A5A5A5; /* udp没有, 但设成0可能对某些hash函数不友好, 此处设个固定值 */
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
	struct timeval now;
	now.tv_sec = g_CurrentTime;
	now.tv_usec=0;		

	size_t key_len = sapp_set_dup_pkt_key((enum addr_type_t)pstream_pr->stream_public.addr.addrtype, (enum stream_type_t)pstream_pr->stream_public.type, ip_hdr, (void *)l4_hdr, &dup_bloom_key);			
	is_dup_pkt= AP_bloom_check((const struct AP_bloom *)sapp_global_val->mthread_volatile[tid]->dup_pkt_distinguish_handle, 
										now, (const char *)&dup_bloom_key, key_len);
	if(is_dup_pkt != 0){
		pstream_pr->has_duplicate_pkt = 1;
	}else{
		if(need_add_bloom_filter){
			AP_bloom_add((struct AP_bloom *)sapp_global_val->mthread_volatile[tid]->dup_pkt_distinguish_handle,
										now,  (const char *)&dup_bloom_key, key_len);
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
	struct timeval now;
	now.tv_sec = g_CurrentTime;
	now.tv_usec=0;		
    key_len = sapp_set_dup_pkt_key((enum addr_type_t)a_stream->addr.addrtype, (enum stream_type_t)a_stream->type, ip_hdr, l4_hdr, &dup_bloom_key);
    AP_bloom_add(
        (struct AP_bloom *)sapp_global_val->mthread_volatile[tid]->dup_pkt_distinguish_handle,
        now, (const char *)&dup_bloom_key, key_len);

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

	/* 流量入口有三个开关, 识别句柄只有一个, 
	   拆分句柄多耗费内存, 且判断时每个包需要扫描多个句柄, 
	   可能好处只是准确率高了一点点而已 */
	struct timeval now;
	now.tv_sec = time(NULL);
	now.tv_usec=0;	
	for(i = 0; i < sapp_global_val->config.cpu.worker_threads; i++){
		sapp_global_val->mthread_volatile[i]->dup_pkt_distinguish_handle = (void *)AP_bloom_new(now, p_dup_conf->bloom_error_rate, p_dup_conf->bloom_capacity, p_dup_conf->bloom_timeout*1000, p_dup_conf->bloom_slice_num);
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
	
	for(i = 0; i < sapp_global_val->config.cpu.worker_threads; i++){
		if(sapp_global_val->mthread_volatile[i]->dup_pkt_distinguish_handle){
			AP_bloom_free(sapp_global_val->mthread_volatile[i]->dup_pkt_distinguish_handle);
		}
	}

}

#ifdef __cplusplus
}
#endif


