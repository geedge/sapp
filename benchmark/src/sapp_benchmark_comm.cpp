#include "sapp_benchmark.h"
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <assert.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/types.h>			/* See NOTES */
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
#include "stream.h"
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "wrap_cJSON.h"
#include "sapp_bchmk_inner.h"

#ifdef __cplusplus
extern "C" {
#endif

unsigned long sapp_bchmk_get_file_len(const char *file_name)
{
	struct stat file_stat;
	
	if(stat(file_name, &file_stat) == 0)
	{
		return file_stat.st_size;
	}
	return 0;
}


/*
	把json文件从硬盘读取到内存, 注意:使用完要free.
*/
char *sapp_benchmark_load_json_from_file(const char *json_file_name)
{
	char *json_mem;
	FILE *fp;
	
	unsigned long filelen = sapp_bchmk_get_file_len(json_file_name);
	if(0 == filelen){
		return NULL;
	}

	fp = fopen(json_file_name, "r");
	if(NULL == fp){
		return NULL;
	}

	json_mem = (char *)calloc(1, filelen+1);//add string EOF

	fread(json_mem, 1, filelen, fp);

	fclose(fp);

	return json_mem;
}

char *sapp_bchmk_strdup(const char *raw_s)
{
	int buflen = strlen(raw_s) + 1; //add EOF
	char *new_s = (char *)calloc(1, buflen);
	memcpy(new_s, raw_s, buflen);

	return new_s;
}


#ifdef __cplusplus
}
#endif

