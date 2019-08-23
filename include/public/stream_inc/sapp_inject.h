#ifndef _SAPP_INJECT_H_
#define _SAPP_INJECT_H_ 1

#ifdef __cplusplus
extern "C" {
#endif

#include "stream_base.h"

enum sapp_inject_opt{
	SIO_DEFAULT = (1<<0), /* 调用者只传入纯负载, 由平台根据协议规范构造当前层的传输层和IP头部, 如果是隧道, 还包括所有嵌套层的头部 */
	SIO_EXCLUDE_THIS_LAYER_HDR = (1<<1),  /* 除负载外, 当前层的传输层和IP头部也由调用者构造, 平台仅构造除当前层的承载层头部, 如果是隧道, 还包括所有嵌套层的头部 */
};

/*
	ARGS:
		stream: 当前流结构体指针;
		payload: 要发送的负载指针;
		payload_len: 要发送的负载长度;
		snd_routedir: 要发送数据的route方向, 
			 如果发送的包与当前包同向, snd_routedir = stream->routedir, 
			 如果发送的包与当前包反向, snd_routedir = MESA_dir_reverse(stream->routedir).
			
	return value:
		<=0 : error.
		> 0 : 发送的数据包实际总长度(payload_len + 底层包头长度);
*/
int sapp_inject_pkt(struct streaminfo *stream, enum sapp_inject_opt sio, const void *payload, int payload_len, unsigned char snd_routedir);



#ifdef __cplusplus
}
#endif

#endif

