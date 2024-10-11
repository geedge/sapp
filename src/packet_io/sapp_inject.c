#include "sapp_api.h"
#include "sapp_private_api.h"
#include "sapp_declaration.h"
#include "stream_inc/sapp_inject.h"


#ifdef __cplusplus
extern "C" {
#endif

/*
	MESA_kill_tcpʵ�����ȹ���õ�ǰ���IP, TCPͷ��, 
	�����Ҫ����ָ����Ϣ, Ҳ��дһ��assistantģ��, ��ô����ipttl, ipid, tcpwin��ֵ.
	Ȼ�����__sapp_inject_pkt(), sio = SIO_EXCLUDE_THIS_LAYER_HDR.

	sapp����ֱ�Ӹ���ĳ��ͷ���ֶ���ô��ֵ, ��assistantģ�鸺��, sapp�����հ�����������.

	kill_remedyҲ�ǿ�assistant���ݵ�ǰseq, ����rst����seq, ���Ƶ��fd���ɹ�, ��Ҫ���׷�Ӷ���.
	����assistant����.
*/


int sapp_inject_pkt(struct streaminfo *stream, enum sapp_inject_opt sio, const void *payload, int payload_len, unsigned char snd_routedir)
{
	int ret;
	char debug_log_buf[256];
	UCHAR send_stream_dir;
	const struct streaminfo_private *stream_pr = (struct streaminfo_private *)stream;

	ret = __sapp_inject_pkt(stream, sio, payload, payload_len, snd_routedir, NULL);
	
	if(MESA_handle_runtime_log_level_enabled(ABBR_SAPP_LOG_HANDLE, RLOG_LV_DEBUG)){
		int log_level;
		const char *string_res;
		/* injectʹ�õ���routedir, �˴�ת����stream dir, 
		ע��: ��������Ķ������ܲ����ɵ�ǰ��������,  ����kni, �Ǵ����������յ����ݰ�, ��ע����·��,
		���ܴ�raw_pkt��raw_stream->routedir�жϷ���,
		Ҫ������������ʷ��¼���ж�route_dir��stream_dir�Ĺ�ϵ!!!!
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
			/* ipԭʼ����ҵ�������й��� */
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
			/* ���ֻ����Ӧ�ò㸺�ؼ�ָ����������, ip��ͷ��sapp���� */
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

	return __sapp_inject_ctrl_pkt(stream, sio, payload, payload_len, snd_routedir);
}

extern int marsio_send_ctrl_data(unsigned char *data,int datalen, struct segment_id_list *sids, int thread_seq);
int sapp_inject_ctrl_data(unsigned char *data,int datalen, struct segment_id_list *sids, int thread_seq)
{
	return marsio_send_ctrl_data(data, datalen, sids, thread_seq);
}

#ifdef __cplusplus
}
#endif

