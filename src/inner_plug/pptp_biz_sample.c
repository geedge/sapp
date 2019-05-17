#ifdef __cplusplus
extern "C" {
#endif

#include "sapp_api.h"
#include "sapp_private_api.h"

struct pptp_biz_t{
	int tunnel_type; /* data or control */
	int encrypt_mode;
	int auth_mode;
	
};


char pptp_sample_entry(stSessionInfo* session_info,  void **pme, int thread_seq,struct streaminfo *a_stream,const void *a_packet)
{
	assert(a_stream);

	char tmp_list_addr[1024];
	
	if(SESSION_STATE_CLOSE == session_info->session_state){
		stream_addr_list_ntop(a_stream, tmp_list_addr, 1024);
		printf("pptp stream %p,  addr list:%s\n", a_stream, tmp_list_addr);
	}
	
	switch(session_info->prot_flag){
		case PPTP_OPT_LINK_TYPE:
			printf("stream:%p, pptp biz plug: link type is %s\n",  a_stream, (*((int *)session_info->buf) == TUNNEL_CHANNEL_TYPE_CONTROL)?"control":"data");
		break;

		case PPTP_OPT_ENCRYPT_PRO:
			printf("stream:%p, pptp biz plug: encrypt mode is %d\n",  a_stream, *((int *)session_info->buf));
		break;

		case PPTP_CONTENT_TYPE:
		{
			int cont_type = *((int *)session_info->buf);
			if(TUNNEL_CONTENT_TYPE_CLEAR == cont_type){
				printf("stream:%p, pptp biz plug: content type is %s\n", a_stream,"clear");
			}else if(TUNNEL_CONTENT_TYPE_COMPRESS == cont_type){
				printf("stream:%p, pptp biz plug: content type is %s\n", a_stream,"compress");
			}else{
				printf("stream:%p, pptp biz plug: content type is %s\n", a_stream,"encrypt");
			}
		}
		break;
		
		case TUNNEL_PHONY_PROT_FLAG:
		break;

		default:
			printf("stream:%p, pptp biz plug: unknown prot_flag:0x%llx, value:%d\n", a_stream,session_info->prot_flag, *((int *)session_info->buf));
		break;
	}
		

	return PROT_STATE_GIVEME;
}

int pptp_sample_init(void)
{
	return 1;
}

void pptp_sample_destroy(void)
{
	;
}

#ifdef __cplusplus
}
#endif



