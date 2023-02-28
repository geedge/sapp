#include "sapp_api.h"
#include "sapp_private_api.h"
#include "sapp_declaration.h"
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
	int ret;
	char debug_log_buf[256];
	UCHAR send_stream_dir;
	const struct streaminfo_private *stream_pr = (struct streaminfo_private *)stream;

	ret = __sapp_inject_pkt(stream, sio, payload, payload_len, snd_routedir, NULL);
	
	if(ABBR_SAPP_LOG_LEVEL <= RLOG_LV_DEBUG){
		int log_level;
		const char *string_res;
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

		if(ret < 0){
			log_level = RLOG_LV_FATAL;
			string_res = "error";
		}else{
			log_level = RLOG_LV_DEBUG;
			string_res = "succ";
		}
		
		if(SIO_EXCLUDE_THIS_LAYER_HDR & sio){
			/* ip原始包由业务插件自行构造 */
			if(ADDR_TYPE_IPV4 == stream->addr.addrtype){
				const struct mesa_ip4_hdr *ip4hdr = (struct mesa_ip4_hdr *)payload;
				sapp_runtime_log(log_level, "sapp_inject_pkt()->IPV4 %s, exclude ip header, stream:%s, stream_curdir:%d, stream_cur_routedir:%d, stream_C2S_routedir:%d, send_ipv4_pkt_hdr:%s, send_routedir:%d, send_stream_dir:%d, send_payload_len:%d, ttl:%d, ipid:%u, ip_checksum:0x%x", 
								string_res, printaddr(&stream->addr, stream->threadnum),
								stream->curdir, stream->routedir, stream_pr->stream_c2s_route_dir,
								sapp_raw_ipv4_ntop(ip4hdr, debug_log_buf, sizeof(debug_log_buf)),  
								snd_routedir, send_stream_dir, payload_len,
								ip4hdr->ip_ttl, ntohs(ip4hdr->ip_id), ntohs(ip4hdr->ip_sum));			
			}else{
				const struct mesa_ip6_hdr *ip6hdr = (struct mesa_ip6_hdr *)payload;
				sapp_runtime_log(log_level, "sapp_inject_pkt()->IPV6 %s, exclude ip header, stream:%s, stream_curdir:%d, stream_cur_routedir:%d,stream_C2S_routedir:%d, send_ipv6_pkt_hdr:%s, send_routedir:%d, send_stream_dir:%d, send_payload_len:%d,ttl:%d", 
								string_res, printaddr(&stream->addr, stream->threadnum),
								stream->curdir, stream->routedir, stream_pr->stream_c2s_route_dir,
								sapp_raw_ipv6_ntop(ip6hdr, debug_log_buf, sizeof(debug_log_buf)),  
								snd_routedir, send_stream_dir, payload_len, ip6hdr->ip6_hop);		
			}
		}else{
			/* 插件只构建应用层负载及指定发包方向, ip包头由sapp构建 */
			sapp_runtime_log(log_level, "sapp_inject_pkt() with SIO_DEFAULT %s, stream:%s, stream_curdir:%d, stream_cur_routedir:%d, stream_C2S_routedir:%d, send_routedir:%d, send_stream_dir:%d, send_payload_len:%d", 
								string_res, printaddr(&stream->addr, stream->threadnum),
								stream->curdir, stream->routedir, stream_pr->stream_c2s_route_dir,
								snd_routedir, send_stream_dir, payload_len);					
		}
	}


	return ret;
}

int sapp_inject_ctrl_pkt(struct streaminfo *stream, enum sapp_inject_opt sio, const void *payload, int payload_len, unsigned char snd_routedir)
{
	struct streaminfo_private *stream_pr = (struct streaminfo_private *)stream;
	stream_pr->is_send_ctrl_pkt=1;
	int ret=sapp_inject_pkt(stream, SIO_DEFAULT, payload, payload_len, snd_routedir);
	stream_pr->is_send_ctrl_pkt=0;

	return ret;
}


#ifdef __cplusplus
}
#endif

