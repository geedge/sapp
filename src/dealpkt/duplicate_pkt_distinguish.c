#ifdef __cplusplus
extern "C" {
#endif
#include "sapp_api.h"
#include "sapp_private_api.h"
#include "dablooms.h"


/*
	识别因路由策略导致的重复流量, 首次收到数据包加入bloom filter,
	每个流的前N个包扫描bloom filter, 重复的数据包直接转发即可.

	ip层的ttl, hop不能算为key, 因为经过了几跳路由器又回绕了, ttl肯定会变化, 而上层的数据包确实是重复的.
*/

static const unsigned int sapp_dabloom_capacity = 1000000;
static const double sapp_dabloom_err_rate = 0.00001;
static const int sapp_dabloom_timeout = 10;

#if 0
void sapp_get_dup_pkt_key_tcp_v4(const struct mesa_ip4_hdr *ip4hdr, const struct mesa_tcp_hdr *thdr, sapp_dup_pkt_key_v4_t *key)
{
	key->ip_addr.sip = ip4hdr->ip_src.s_addr;
	key->ip_addr.dip = ip4hdr->ip_dst.s_addr;
	key->tcp_seq = thdr->th_seq;
	key->tcp_ack = thdr->th_ack;
	key->sport = thdr->th_sport;
	key->dport = thdr->th_dport;
	key->ip_id = ip4hdr->ip_id;
	key->checksum = thdr->th_sum;
	
	return;
}

void sapp_get_dup_pkt_key_udp_v4(const struct mesa_ip4_hdr *ip4hdr, const struct mesa_udp_hdr *uhdr, sapp_dup_pkt_key_v4_t *key)
{
	key->ip_addr.sip = ip4hdr->ip_src.s_addr;
	key->ip_addr.dip = ip4hdr->ip_dst.s_addr;
	key->tcp_seq = 0x5A5A5A5A; /* udp没有, 但设成0可能对某些hash函数不友好, 此处设个固定值 */
	key->tcp_ack = 0xA5A5A5A5; /* udp没有, 但设成0可能对某些hash函数不友好, 此处设个固定值 */
	key->sport = uhdr->uh_sport;
	key->dport = uhdr->uh_dport;
	key->ip_id = ip4hdr->ip_id;
	key->checksum = uhdr->uh_sum;
	
	return;
}

void sapp_get_dup_pkt_key_tcp_v6(const struct mesa_ip6_hdr *ip6hdr, const struct mesa_tcp_hdr *thdr, sapp_dup_pkt_key_v6_t *key)
{
	memcpy(&key->ip_addr.sip, &ip6hdr->ip6_src, sizeof(struct in6_addr));
	memcpy(&key->ip_addr.dip, &ip6hdr->ip6_dst, sizeof(struct in6_addr));
	key->tcp_seq = thdr->th_seq;
	key->tcp_ack = thdr->th_ack;
	key->sport = thdr->th_sport;
	key->dport = thdr->th_dport;
	key->checksum = thdr->th_sum;
	
	return;
}


void sapp_get_dup_pkt_key_udp_v6(const struct mesa_ip6_hdr *ip6hdr, const struct mesa_udp_hdr *uhdr, sapp_dup_pkt_key_v6_t *key)
{
	memcpy(&key->ip_addr.sip, &ip6hdr->ip6_src, sizeof(struct in6_addr));
	memcpy(&key->ip_addr.dip, &ip6hdr->ip6_dst, sizeof(struct in6_addr));
	key->tcp_seq = 0x5A5A5A5A; /* udp没有, 但设成0可能对某些hash函数不友好, 此处设个固定值 */
	key->tcp_ack = 0xA5A5A5A5; /* udp没有, 但设成0可能对某些hash函数不友好, 此处设个固定值 */
	key->sport = uhdr->uh_sport;
	key->dport = uhdr->uh_dport;
	key->checksum = uhdr->uh_sum;
	
	return;
}
#endif

int sapp_dup_pkt_mark_v4(int tid, const sapp_dup_pkt_key_v4_t *key)
{
	int ret;

	ret = expiry_dablooms_add(sapp_global_val->mthread_volatile[tid]->dup_pkt_distinguish_handle, (char *)key, sizeof(sapp_dup_pkt_key_v4_t));
	if(ret < 0){
		sapp_runtime_log(RLOG_LV_FATAL, "sapp duplicate ipv4 pkt add bloom key error");
	}

	return ret;
}

int sapp_dup_pkt_mark_v6(int tid, const sapp_dup_pkt_key_v6_t *key)
{
	int ret;

	ret = expiry_dablooms_add(sapp_global_val->mthread_volatile[tid]->dup_pkt_distinguish_handle, (char *)key, sizeof(sapp_dup_pkt_key_v6_t));
	if(ret < 0){
		sapp_runtime_log(RLOG_LV_FATAL, "sapp duplicate ipv6 pkt add bloom key error");
	}

	return ret;
}

int sapp_dup_pkt_identify_v4(int tid, const sapp_dup_pkt_key_v4_t *key)
{
	int ret;

	ret = expiry_dablooms_search(sapp_global_val->mthread_volatile[tid]->dup_pkt_distinguish_handle, (char *)key, sizeof(sapp_dup_pkt_key_v4_t));

	return ret;
}

int sapp_dup_pkt_identify_v6(int tid, const sapp_dup_pkt_key_v6_t *key)
{
	int ret;

	ret = expiry_dablooms_search(sapp_global_val->mthread_volatile[tid]->dup_pkt_distinguish_handle, (char *)key, sizeof(sapp_dup_pkt_key_v6_t));

	return ret;

}


int sapp_dup_pkt_init(void)
{
	int i;
	
	if(0 == sapp_global_val->config.packet_io.dup_pkt_para.dup_pkt_distinguish_enable){
		return 0;
	}

	for(i = 0; i < sapp_global_val->config.cpu.worker_threads; i++){
		/* TODO: 这些参数是否需要通过配置文件? */
		sapp_global_val->mthread_volatile[i]->dup_pkt_distinguish_handle = (void *)expiry_dablooms_init(sapp_dabloom_capacity, sapp_dabloom_err_rate, sapp_dabloom_timeout);
		if(NULL == sapp_global_val->mthread_volatile[i]->dup_pkt_distinguish_handle){
			sapp_log(RLOG_LV_FATAL, 1, 1, "dup_pkt_distinguish init error!");
			return -1;
		}
	}

	sapp_log(RLOG_LV_DEBUG, 1, 1, "dup_pkt_distinguish init success");
	
	return 0;
}

#ifdef __cplusplus
}
#endif


