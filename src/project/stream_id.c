#ifdef __cplusplus
extern "C" {
#endif
#include "sapp_api.h"
#include "sapp_private_api.h"

#define STREAMNUM_FILE_NAME	"./conf/streamid.txt"

static unsigned int g_stream_num = 0;
static unsigned int g_old_stream_num = 0;
static unsigned short g_papp_machineid = 0;
static pthread_mutex_t g_stream_num_mutex;

static int g_stream_id_switch = PROJECT_MODULE_DISABLE;

static int set_stream_id(unsigned long *p_stream_id)
{
	unsigned long stream_id;
	int stream_num;

	if(PROJECT_MODULE_DISABLE == g_stream_id_switch){
		return -1;
	}
	
	pthread_mutex_lock(&g_stream_num_mutex);

	g_stream_num ++;
	stream_num = g_stream_num;

	pthread_mutex_unlock(&g_stream_num_mutex);

	stream_id = (unsigned long)g_papp_machineid+(unsigned long)(0xffffffff)+stream_num;

	*p_stream_id = stream_id;

	//	printf("papp:stream_id:%lu\n",stream_id);

	return 0;
}


unsigned long get_stream_id(struct streaminfo *stream)
{
	void **p_private;
	unsigned long *p_stream_id;
	
	if(PROJECT_MODULE_DISABLE == g_stream_id_switch){
		printf("stream_id moudle is disabled!\n");
		assert(0);
		return -1;
	}	

	p_private = project_get_private_info(stream->pproject, PROGECT_REQUIREMENT_STREAM_ID);
	if(NULL == p_private){
		printf("stream_id moudle error, no mem space!\n");
		assert(0);
		return -1;	
	}

	p_stream_id = (unsigned long *)(*p_private);

	return *p_stream_id;
}

static void *update_streamnum_thread(void *art)
{
	FILE* fp;

	while(1)
	{
		fp = fopen(STREAMNUM_FILE_NAME,"w+");
		if(fp == NULL)
		{
			continue;
		}

		if((g_stream_num-g_old_stream_num) > 1000)
		{
			fprintf(fp,"%d\n",g_stream_num);
		}
		else
		{
			fprintf(fp,"%d\n",g_old_stream_num);
		}

		if(g_stream_num>0xffffffff)
		{
			g_old_stream_num = g_stream_num = 0;
		}

		fclose(fp);

		sleep(10);
	}

	return NULL;
}

static unsigned int read_streamnum(void)
{
	char buf[56] = {0};
	int stream_num;
	
	FILE* fp = fopen(STREAMNUM_FILE_NAME,"a+");
	if(fp == NULL)
	{
		printf("fopen %s error!\n",STREAMNUM_FILE_NAME);
		return -1;
	}

	if((fgets(buf,56,fp)) == NULL)		//文本文档保存
	{
		printf("fgets stream id error!\n");
		return -1;
	}

	stream_num = atoi(buf);	
	if(stream_num < 0)
	{
		return -1;
	}

	fclose(fp);

	return stream_num;
}


int stream_id_init(int thread_cnt)
{
	unsigned int conf_num;

	(void)thread_cnt;
	
	if(PROJECT_MODULE_DISABLE == g_stream_id_switch){
		return -1;
	}

	MESA_load_profile_uint_def((char *)"./conf/main.conf", (char *)"Module", (char *)"machineid", &conf_num , 0);
	g_papp_machineid = (unsigned short)conf_num;

	pthread_mutex_init(&g_stream_num_mutex, NULL);
		
	g_stream_num = read_streamnum() + 1000;
	g_old_stream_num = g_stream_num;

	pthread_t update_streamnumThread;
	pthread_create(&update_streamnumThread, NULL, update_streamnum_thread ,NULL);

	return 0;
}

void *stream_id_create_struct(int thread_num)
{
	void *info = dictator_malloc(thread_num, sizeof(long));
	memset(info, 0, sizeof(long));

	set_stream_id((unsigned long *)info);

	return info;
}

void stream_id_destroy(int thread_num, void *info)
{
	dictator_free(thread_num, info);
}


int set_stream_id_switch(int op_switch)
{
	g_stream_id_switch = op_switch;
	return 0;
}


#ifdef __cplusplus
}
#endif

