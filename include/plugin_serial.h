#ifndef _PLUGIN_SERICAL_H
#define _PLUGIN_SERICAL_H

#include <sys/time.h>

#ifndef MAX_THREAD_NUM
#define MAX_THREAD_NUM 	128
#endif

#define WY_MAX_PLUG_NUM			64


#define PLUGTYPE_JC				0
#define PLUGTYPE_GK			1



//插件基本信息
typedef struct plug_base_info
{
	int proc_version;			 //每个插件信息的操作版本
	int type;					//插件类型，0：JC；1：GK
	int pri;					//优先级，数字越小优先级越高
	int keepalive_flag;		 //0：与G保活无关；1：与G保活同步
	int keepalive_state; 		//插件实际保活状态；0：保活失败；1：保活成功,保活程序写该字段
	int valid;					//0：无效插件；1：有效插件
	char plugname[64];		//插件名称
}stPlugBaseInfo;


//插件函数调用次数、超时次数统计
typedef struct _plugctrl_runtime_info
{
	unsigned int max_runtime;
	unsigned int max_interval_num;
	int runtime_switch;
	int callentry_num[MAX_THREAD_NUM];			//for thread deadlock;
	int interval_num[MAX_THREAD_NUM];
	time_t last_time[MAX_THREAD_NUM];
	struct timeval plug_starttime[MAX_THREAD_NUM];
	struct timeval plug_endtime[MAX_THREAD_NUM];
}stPlugRuntimeInfo;



extern void plug_record_start_time(int plug_id, int thread_seq);
extern void plug_record_end_time(int plug_id, int thread_seq);


#endif

