#ifdef __cplusplus
extern "C" {
#endif

#include <assert.h>
#include "stream.h"
#include "stream_internal.h" 
#include "stream_manage.h"
#include "mesa_net.h"
#include "sysinfo.h"
#include "stream_tunnel.h"


char ipsec_sample_entry(stSessionInfo* session_info,  void **pme, int thread_seq,struct streaminfo *a_stream,const void *a_packet)
{
	assert(a_stream);
	
	if(session_info->buf != NULL){
		switch(session_info->prot_flag){
			case IPSEC_OPT_IS_NAT:
			case IPSEC_OPT_EXCHG_MODE:
				printf("isakmp biz plug: prot_flag:0x%llx, value:%u\n", session_info->prot_flag, *((unsigned char *)session_info->buf));
			break;

			default:
				printf("isakmp biz plug: prot_flag:0x%llx, value:%d\n", session_info->prot_flag, *((int *)session_info->buf));
			break;
		}
		
	}
	return PROT_STATE_GIVEME;
}

int ipsec_sample_init(void)
{
	return 1;
}

void ipsec_sample_destroy(void)
{
	;
}

#ifdef __cplusplus
}
#endif


