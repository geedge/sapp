#ifdef __cplusplus
extern "C" {
#endif

#include "sapp_api.h"
#include "sapp_private_api.h"

 int arp_entry(struct streaminfo_private *pfstream_pr, const void *this_layer_hdr, 
 		int thread_num, unsigned char dir, const raw_pkt_t *raw_pkt, int offset_to_raw_pkt_hdr)
{
	const struct mesa_arp_hdr *aph = (struct mesa_arp_hdr *)this_layer_hdr;

	if((ntohs(aph->ar_op) == ARPOP_REPLY) && (ETH_P_IP == ntohs(aph->ar_pro))){
		stream_process_arp(NULL, (struct mesa_arp_hdr *)this_layer_hdr, thread_num, dir, raw_pkt);
	}

	/* 双网卡串联模式无条件转发ARP, 否则网络通讯无法正常获取对方MAC */
	if(NET_CONN_SERIAL_2CARD == g_topology_mode){
		return PASS;
	}
	
#if (0 == IOMODE_MARSIO) /* marsio模式下, 驱动负责回复ARP包, sapp不处理 */
	if(gdev_keepalive(raw_pkt, thread_num, GDEV_KEEPALIVE_TYPE_ARP, dir) > 0){
		return DROP;
	}
#endif

	/* 如果是隧道内部的ARP, 应该是链路上正常的CS双方ARP包, 要回注 */
	if(sapp_identify_tunnel_inner_pkt(raw_pkt) != 0){
		return PASS;
	}else{
		sapp_runtime_log(RLOG_LV_DEBUG, "is not raw inline arp pkt, drop it."); 
	}

	/* NOTE: 其他模式什么时候都不应该把原始ARP包再转发出去, 即便是inline模式下 */
	if((ABBR_SAPP_LOG_LEVEL <= RLOG_LV_INFO ) && (NET_CONN_SERIAL_GDEV == g_topology_mode)){
		const struct mesa_arp_hdr *arph = (struct mesa_arp_hdr *)this_layer_hdr;
		char sendip_str[INET6_ADDRSTRLEN];
		char targetip_str[INET6_ADDRSTRLEN];
		inet_ntop(AF_INET, arph->ar_spa, sendip_str, sizeof(sendip_str));
		inet_ntop(AF_INET, arph->ar_tpa, targetip_str, sizeof(targetip_str));
		sapp_runtime_log(RLOG_LV_INFO, "inline mode drop not overlay arp pkt: sender_ip:%s, sender_mac:%02x-%02x-%02x-%02x-%02x-%02x,target_ip:%s",
						sendip_str,
						arph->ar_sha[0], arph->ar_sha[1], arph->ar_sha[2], arph->ar_sha[3], arph->ar_sha[4], arph->ar_sha[5], 
						targetip_str);
	}
	
	return DROP;
}

#ifdef __cplusplus
}
#endif

