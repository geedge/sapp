#ifdef __cplusplus
extern "C" {
#endif
#include "sapp_api.h"
#include "sapp_private_api.h"
#include "sapp_declaration.h"
#include "dablooms.h"


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

static const char *dup_pkt_key_ntop_v4(const sapp_dup_pkt_key_v4_t *key, char *strbuf, int buflen)
{
	char sip_str[INET_ADDRSTRLEN], dip_str[INET_ADDRSTRLEN];
	
	inet_ntop(AF_INET, &key->ip_addr.sip, sip_str, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, &key->ip_addr.dip, dip_str, INET_ADDRSTRLEN);

	snprintf(strbuf, buflen, "%s:%u-->%s:%u, ipv4_id:%u, checksum:%u, seq:%u, ack:%u", 
			sip_str, ntohs(key->sport), dip_str, ntohs(key->dport), ntohs(key->ip_id), ntohs(key->checksum), ntohl(key->tcp_seq), ntohl(key->tcp_ack) );

	return strbuf;
}


static const char *dup_pkt_key_ntop_v6(const sapp_dup_pkt_key_v6_t *key, char *strbuf, int buflen)
{
	char sip_str[INET6_ADDRSTRLEN], dip_str[INET6_ADDRSTRLEN];
	
	inet_ntop(AF_INET6, &key->ip_addr.sip, sip_str, INET6_ADDRSTRLEN);
	inet_ntop(AF_INET6, &key->ip_addr.dip, dip_str, INET6_ADDRSTRLEN);

	snprintf(strbuf, buflen, "%s:%u-->%s:%u, checksum:%u, seq:%u, ack:%u", 
			sip_str, ntohs(key->sport), dip_str, ntohs(key->dport), ntohs(key->checksum), ntohl(key->tcp_seq), ntohl(key->tcp_ack) );

	return strbuf;
}


int sapp_dup_pkt_mark_v4(int tid, const sapp_dup_pkt_key_v4_t *key)
{
	int ret;
	char ntop_buf[1024];

	ret = expiry_dablooms_add(sapp_global_val->mthread_volatile[tid]->dup_pkt_distinguish_handle, (char *)key, sizeof(sapp_dup_pkt_key_v4_t), time(NULL));
	if(ret < 0){
		sapp_global_val->mthread_volatile[tid]->sys_stat.count[SAPP_STAT_DUP_IDENTIFY_ERR]++;
		sapp_runtime_log(RLOG_LV_INFO, "sapp dup distinguish ipv4 pkt add bloom key error, %s", dup_pkt_key_ntop_v4(key,ntop_buf,sizeof(ntop_buf)));
	}else{
		sapp_runtime_log(RLOG_LV_DEBUG, "sapp dup distinguish ipv4 pkt add bloom key succ, %s", dup_pkt_key_ntop_v4(key,ntop_buf,sizeof(ntop_buf)));
	}

	return ret;
}

int sapp_dup_pkt_mark_v6(int tid, const sapp_dup_pkt_key_v6_t *key)
{
	int ret;
	char ntop_buf[1024];

	ret = expiry_dablooms_add(sapp_global_val->mthread_volatile[tid]->dup_pkt_distinguish_handle, (char *)key, sizeof(sapp_dup_pkt_key_v6_t),time(NULL));
	if(ret < 0){
		sapp_global_val->mthread_volatile[tid]->sys_stat.count[SAPP_STAT_DUP_IDENTIFY_ERR]++;
		sapp_runtime_log(RLOG_LV_INFO, "sapp dup distinguish ipv6 pkt add bloom key error, %s", dup_pkt_key_ntop_v6(key,ntop_buf,sizeof(ntop_buf)));
	}else{
		sapp_runtime_log(RLOG_LV_DEBUG, "sapp dup distinguish ipv6 pkt add bloom key succ, %s", dup_pkt_key_ntop_v6(key,ntop_buf,sizeof(ntop_buf)));
	}

	return ret;
}

int sapp_dup_pkt_identify_v4(int tid, const sapp_dup_pkt_key_v4_t *key)
{
	int ret;

	ret = expiry_dablooms_search(sapp_global_val->mthread_volatile[tid]->dup_pkt_distinguish_handle, (char *)key, sizeof(sapp_dup_pkt_key_v4_t), time(NULL));

	return ret;
}

int sapp_dup_pkt_identify_v6(int tid, const sapp_dup_pkt_key_v6_t *key)
{
	int ret;

	ret = expiry_dablooms_search(sapp_global_val->mthread_volatile[tid]->dup_pkt_distinguish_handle, (char *)key, sizeof(sapp_dup_pkt_key_v6_t), time(NULL));

	return ret;

}


int sapp_dup_pkt_init(void)
{
	int i;
	const sapp_dup_pkt_t *p_dup_conf = &sapp_global_val->config.packet_io.dup_pkt_para;
	
	if((0 == sapp_global_val->config.packet_io.dup_pkt_para.dup_pkt_distinguish_all_inject)
	  && (0 == sapp_global_val->config.packet_io.dup_pkt_para.dup_pkt_distinguish_ipv4_tcp)
	  && (0 == sapp_global_val->config.packet_io.dup_pkt_para.dup_pkt_distinguish_ipv4_udp)){
		return 0;
	}

	/* 流量入口有三个开关, 识别句柄只有一个, 
	   拆分句柄多耗费内存, 且判断时每个包需要扫描多个句柄, 
	   可能好处只是准确率高了一点点而已 */
	for(i = 0; i < sapp_global_val->config.cpu.worker_threads; i++){
		sapp_global_val->mthread_volatile[i]->dup_pkt_distinguish_handle = (void *)expiry_dablooms_init(p_dup_conf->bloom_capacity, p_dup_conf->bloom_error_rate, time(NULL), p_dup_conf->bloom_timeout);
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
			expiry_dablooms_destroy(sapp_global_val->mthread_volatile[i]->dup_pkt_distinguish_handle);
		}
	}

}

#ifdef __cplusplus
}
#endif


