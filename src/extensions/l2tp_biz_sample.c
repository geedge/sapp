#ifdef __cplusplus
extern "C" {
#endif

#include "sapp_api.h"
#include "sapp_private_api.h"


/* 仅用于保证插件管理加载能成功, 实际不会被调用 */
char l2tp_sample_entry(stSessionInfo* session_info,  void **pme, int thread_seq,struct streaminfo *a_stream,const void *a_packet)
{
	assert(a_stream);
	switch(session_info->prot_flag){
		case L2TP_OPT_LINK_TYPE:
			printf("stream:%s, l2tp biz plug: link type is %s\n",  layer_addr_ntop(a_stream), (*((int *)session_info->buf) == TUNNEL_CHANNEL_TYPE_CONTROL)?"control":"data");
		break;

		case L2TP_OPT_ENCRYPT_PRO:
			printf("stream:%s, l2tp biz plug: encrypt mode is %d\n",  layer_addr_ntop(a_stream), *((int *)session_info->buf) );
		break;
		
		case L2TP_CONTENT_TYPE:
		{
			int cont_type = *((int *)session_info->buf);
			if(TUNNEL_CONTENT_TYPE_CLEAR == cont_type){
				printf("stream:%s, l2tp biz plug: content type is %s\n", layer_addr_ntop(a_stream),"clear");
			}else if(TUNNEL_CONTENT_TYPE_COMPRESS == cont_type){
				printf("stream:%s, l2tp biz plug: content type is %s\n", layer_addr_ntop(a_stream),"compress");
			}else{
				printf("stream:%s, l2tp biz plug: content type is %s\n", layer_addr_ntop(a_stream),"encrypt");
			}
		}
		break;

		case L2TP_OPT_CHAP_USER_NAME:
			printf("stream:%s, l2tp biz plug: chap uname is %s\n",  layer_addr_ntop(a_stream), (char *)session_info->buf );
		break;
	}	

	if(OP_STATE_CLOSE == a_stream->opstate){
		printf("l2tp stream:%s close!\n\n",  layer_addr_ntop(a_stream));
	}
	
	return PROT_STATE_GIVEME;
}

int l2tp_sample_init(void)
{
	return 1;
}

void l2tp_sample_destroy(void)
{
	;
}

#ifdef __cplusplus
}
#endif



