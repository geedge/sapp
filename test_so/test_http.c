/*
	20161103 lijia add,
	for test soq-t1, soq-t2.
	
*/

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>
#include <dlfcn.h>
#include "stream.h"
#include <linux/limits.h>
#include "http.h"
#include "MESA_handle_logger.h"
#include "MESA_prof_load.h"

const int test_http_version_VERSION_20161103;

static void test_http_data_dump(long long prot_flag, struct streaminfo *a_tcp, char *data, int datalen)
{
	FILE *fp;
	char tmp_file_name[512];

	snprintf(tmp_file_name, 512, "%s/stream_%p", "/tmp/test_http_dump", a_tcp);

	fp = fopen(tmp_file_name, "a");

	//fprintf(fp, "%llx ", prot_flag);
	fwrite(data, datalen, 1 ,fp);

	fclose(fp);
}


unsigned char TEST_HTTP_ENTRY(stSessionInfo * session_info, void ** param, int thread_seq, struct streaminfo * a_tcp, void * a_packet)
{	
	if(session_info == NULL || session_info->app_info == NULL)
	{
		return PROT_STATE_GIVEME;
	}
	int ret;
	unsigned int http_ISN;
	int *len = sizeof(int);
	http_infor *hinfo = (http_infor *)session_info->app_info;

	if(SESSION_STATE_PENDING == session_info->session_state){
		ret = MESA_get_stream_opt(a_tcp, MSO_TCP_ISN_C2S, &http_ISN, &len);
		if(ret < 0){
			printf("can't get ISN!\n");
		}else{
			printf("stream:%p, tuple4:%s, ISN is: %u\n", a_tcp,printaddr(&a_tcp->addr, thread_seq), http_ISN);
		}

		printf("stream:%p, tuple4:%s, HTTP_SEQ : %u\n", a_tcp,printaddr(&a_tcp->addr, thread_seq), hinfo->http_session_seq);
	}
	
	switch(session_info->prot_flag)
	{
		/* 2016-10-26, 特殊选项, 及工大暂不支持的选项不记录日志 */
		case HTTP_INTEREST_KEY:
		case HTTP_ALL:
		case HTTP_STATE:
		//case HTTP_X_FLASH_VERSION:
		case HTTP_TRANSFER_LENGTH:
		case HTTP_CHARSET:
		case HTTP_UNGZIP_CONTENT:
		case HTTP_MESSAGE_URL:
		break;

		default:
			if(session_info->buf != NULL){
				test_http_data_dump(session_info->prot_flag, a_tcp, session_info->buf, session_info->buflen);
			}
			break;
	}
	
	return PROT_STATE_GIVEME;
}

int TEST_HTTP_INIT(void)
{
	printf("TEST HTTP PLUG INIT OK!\n");
	system("mkdir -p /tmp/test_http_dump");
	return 1;
}

void TEST_HTTP_DESTROY(void)
{
	return;
}


