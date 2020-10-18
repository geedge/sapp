#include "sapp_api.h"
#include "sapp_private_api.h"
#include "stream_inc/sapp_inject.h"


#ifdef __cplusplus
extern "C" {
#endif

/*
	MESA_kill_tcp实际是先构造好当前层的IP, TCP头部, 
	如果需要增加指纹信息, 也是写一个assistant模块, 怎么构造ipttl, ipid, tcpwin等值.
	然后调用__sapp_inject_pkt(), sio = SIO_EXCLUDE_THIS_LAYER_HDR.

	sapp不再直接负责某个头部字段怎么赋值, 靠assistant模块负责, sapp就是收包、发包而已.

	kill_remedy也是靠assistant根据当前seq, 决定rst包的seq, 如果频繁fd不成功, 需要向后追加多少.
	都是assistant决定.
*/


extern int __sapp_inject_pkt(struct streaminfo *raw_stream, enum sapp_inject_opt sio, 
        const void *payload, int payload_len, unsigned char snd_routedir, void *user_arg);


int sapp_inject_pkt(struct streaminfo *stream, enum sapp_inject_opt sio, const void *payload, int payload_len, unsigned char snd_routedir)
{
	char debug_log_buf[256];
	UCHAR send_stream_dir;
	const struct streaminfo_private *stream_pr = (struct streaminfo_private *)stream;
	
	if((ABBR_SAPP_LOG_LEVEL <= RLOG_LV_DEBUG) && (SIO_EXCLUDE_THIS_LAYER_HDR & sio)){
		/* inject使用的是routedir, 此处转换成stream dir, 
		   注意: 插件发包的动作可能不是由当前包触发的,  比如kni, 是从其他网卡收到数据包, 再注入链路的,
		         不能从raw_pkt或raw_stream->routedir判断方向,
		         要从流创建的历史记录中判断route_dir和stream_dir的关系!!!!
		*/	
		if(stream_pr->stream_c2s_route_dir == snd_routedir){
			send_stream_dir = DIR_C2S;
		}else{
			send_stream_dir = DIR_S2C; 
		}
	
		if(ADDR_TYPE_IPV4 == stream->addr.addrtype){
			const struct mesa_ip4_hdr *ip4hdr = (struct mesa_ip4_hdr *)payload;
			//inet_ntop(AF_INET, &ip4hdr->ip_src.s_addr, ipsrc_str, sizeof(ipsrc_str));
			//inet_ntop(AF_INET, &ip4hdr->ip_dst.s_addr, ipdst_str, sizeof(ipdst_str));
			sapp_runtime_log(RLOG_LV_DEBUG, "sapp_inject_pkt()->IPV4, stream:%s, send_ip_pkt_hdr:%s, stream_C2S_routedir:%d, send_routedir:%d, send_stream_dir:%d, ttl:%d, ipid:%u, ip_checksum:0x%x", 
							printaddr(&stream->addr, stream->threadnum),
							sapp_raw_ipv4_ntop(ip4hdr, debug_log_buf, sizeof(debug_log_buf)),  
							stream_pr->stream_c2s_route_dir, snd_routedir, send_stream_dir,
							ip4hdr->ip_ttl, ntohs(ip4hdr->ip_id), ntohs(ip4hdr->ip_sum));			
		}else{
			//todo;
		}
	}

	return __sapp_inject_pkt(stream, sio, payload, payload_len, snd_routedir, NULL);
}


#ifdef __cplusplus
}
#endif

