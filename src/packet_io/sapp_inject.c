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

#if 0
int __sapp_inject_pkt(struct streaminfo *stream, enum sapp_inject_opt sio, const void *payload, int payload_len, unsigned char snd_routedir, void *user_arg)
{
	int ret = -1;

	switch((int)sio){
		case SIO_DEFAULT:
			ret = __do_inject_pkt(stream, (const char *)payload, payload_len, NULL, snd_routedir, (char *)KILL_TCP_PHONY_POINTER, (int *)KILL_TCP_PHONY_POINTER);
		break;

		case SIO_EXCLUDE_THIS_LAYER_HDR:
			ret = __do_inject_pkt(stream->pfather, (const char *)payload, payload_len, NULL, snd_routedir, (char *)KILL_TCP_PHONY_POINTER, (int *)KILL_TCP_PHONY_POINTER);
		break;


		default:
		break;
	}

	return ret;
}
#endif



int sapp_inject_pkt(struct streaminfo *stream, enum sapp_inject_opt sio, const void *payload, int payload_len, unsigned char snd_routedir)
{
	return __sapp_inject_pkt(stream, sio, payload, payload_len, snd_routedir, NULL);
}


#ifdef __cplusplus
}
#endif

