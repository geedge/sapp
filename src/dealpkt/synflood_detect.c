#include "sapp_api.h"
#include "sapp_private_api.h"

#ifndef COUNTER_NUM
	#define COUNTER_NUM 4096
#endif
	
#ifndef PKT_TCP
	#define PKT_TCP 3
#endif

#ifndef LOG_ALL
	#define LOG_ALL 1
#endif

extern time_t g_CurrentTime; 
extern volatile unsigned long long g_SysInputInfo[MAX_THREAD_NUM][COUNTER_NUM];

typedef struct _syn_count_elem
{
int attack_flag;
unsigned int count;//计数值
unsigned long long start_tcppkt_count; //计数开始时间
}SYN_COUNT_ELEM;

typedef struct _data_count_elem
{
int attack_flag;
unsigned int count;//计数值
time_t timestamp; //计数开始时间
}DATA_COUNT_ELEM;

typedef struct _profile_data
{
	unsigned int syn_counter_threshold;
	unsigned int tcp_total_threshold;
	unsigned int data_count_threshold;
}PROFILE_DATA;

PROFILE_DATA g_profile_data;
DATA_COUNT_ELEM *g_data_counter = NULL;
SYN_COUNT_ELEM *g_syn_counter = NULL;

int synflood_detect_init(int thread_num, int syn_threshold, int tcp_threshold, int data_threshold)
{
	int i;
	if(thread_num <= 0)
		return -1;
    
//	Profile my_profile("./conf/ddos_detect.conf");	
       
       g_profile_data.syn_counter_threshold = syn_threshold; 
       g_profile_data.tcp_total_threshold =tcp_threshold; 
       g_profile_data.data_count_threshold = data_threshold; 
       
	g_syn_counter = (SYN_COUNT_ELEM *)malloc((sizeof(SYN_COUNT_ELEM))*thread_num);
	if(g_syn_counter == NULL)
		return -1;

	g_data_counter = (DATA_COUNT_ELEM *)malloc((sizeof(DATA_COUNT_ELEM))*thread_num);
	if(g_data_counter == NULL)
		return -1;
	
	for(i = 0; i < thread_num; i++)
	{
		g_syn_counter[i].count = 0;
		g_syn_counter[i].start_tcppkt_count = 0;
		g_syn_counter[i].attack_flag = NORMAL;
		g_data_counter[i].count = 0;
		g_data_counter[i].timestamp = 0;
		g_data_counter[i].attack_flag = NORMAL;
	}
//	runtime_log(RLOG_LV_INFO, (char *)"synflood_detect", (char *)"synflood_detect init succ!");
	return 0;
}

int synflood_detect_destroy()
{
	free(g_syn_counter);
	g_syn_counter = NULL;
	return 0;
}

int dataflood_detector(int thread_num)
{
	if(thread_num < 0)
		return -1;
	time_t t = 0;
	if(g_data_counter[thread_num].timestamp == 0)
	{
		g_data_counter[thread_num].timestamp = g_CurrentTime;
		g_data_counter[thread_num].count = 1;
	}
	else
	{
		g_data_counter[thread_num].count += 1;
		if(g_data_counter[thread_num].count >= g_profile_data.data_count_threshold)
		{
			t = g_CurrentTime - g_data_counter[thread_num].timestamp;
			if(t < 0)
				return -1;
			else if(t <= 1)
			{
				if(g_data_counter[thread_num].attack_flag == NORMAL)
					;
					//runtime_log(RLOG_LV_FATAL, (char *)"synflood_detect", (char *)"dataflood  detected! %u times in %ld seconds  in thread_num = %d", g_syn_counter[thread_num].count, t, thread_num);
#ifdef LOG_ALL
				else
					;
					//runtime_log(RLOG_LV_FATAL, (char *)"synflood_detect", (char *)"dataflood  lasting! %u times in %ld seconds  in thread_num = %d", g_syn_counter[thread_num].count, t, thread_num);					
#endif
				g_data_counter[thread_num].attack_flag = ATTACKING;
				g_syn_counter[thread_num].attack_flag = NORMAL; //if dataflood attack detected, switch to syn stream mode
				g_syn_counter[thread_num].start_tcppkt_count = 0;
			}
			else
			{
				if(g_data_counter[thread_num].attack_flag == ATTACKING)
					;
					//runtime_log(RLOG_LV_FATAL, (char *)"synflood_detect", (char *)"dataflood  stoped! %u times in %ld seconds  in thread_num = %d", g_syn_counter[thread_num].count, t, thread_num);					
#ifdef LOG_ALL
				else
					;
					//runtime_log(RLOG_LV_FATAL,(char *) "synflood_detect", (char *)"dataflood  normal %u times in %ld seconds  in thread_num = %d", g_syn_counter[thread_num].count, t, thread_num);					
#endif
				g_data_counter[thread_num].attack_flag = NORMAL;
			}
			g_data_counter[thread_num].count = 0;
			g_data_counter[thread_num].timestamp = 0;
		}
	}
	return g_data_counter[thread_num].attack_flag;
		
}

int synflood_detector(int thread_num)
{
	if(thread_num < 0)
		return -1;
	unsigned long long t;
	if(g_syn_counter[thread_num].start_tcppkt_count == 0)
	{
		g_syn_counter[thread_num].start_tcppkt_count = g_SysInputInfo[thread_num][PKT_TCP];
		g_syn_counter[thread_num].count = 1;
	}
	else
	{
		g_syn_counter[thread_num].count += 1;
		if(g_syn_counter[thread_num].count >= g_profile_data.syn_counter_threshold)
		{
			t =  g_SysInputInfo[thread_num][PKT_TCP] - g_syn_counter[thread_num].start_tcppkt_count;
			if(t < 0)
				return -1;
			else if(t <= g_profile_data.tcp_total_threshold)
			{
				if(g_syn_counter[thread_num].attack_flag == NORMAL)
					;
					//runtime_log(RLOG_LV_FATAL, (char *)"synflood_detect", (char *)"synflood  detected! syn_count = %u in tcp num = %lld, thread_num = %d", g_syn_counter[thread_num].count, t, thread_num);
#ifdef LOG_ALL
				else
					;
					//runtime_log(RLOG_LV_FATAL, (char *)"synflood_detect", (char *)"synflood  lasting! syn_count = %u in tcp num = %lld, thread_num = %d", g_syn_counter[thread_num].count, t, thread_num);
#endif				
				g_syn_counter[thread_num].attack_flag = ATTACKING;
				g_data_counter[thread_num].attack_flag = NORMAL; //if synflood attack detected, switch to data stream mode
				g_data_counter[thread_num].timestamp = 0; //if synflood attack detected, switch to data stream mode
			}
			else
			{
				if(g_syn_counter[thread_num].attack_flag == ATTACKING)
					;
					//runtime_log(RLOG_LV_FATAL, (char *)"synflood_detect", (char *)"synflood  stoped! syn_count = %u in tcp num = %lld, thread_num = %d", g_syn_counter[thread_num].count, t, thread_num);
#ifdef LOG_ALL
				else
					;
					//runtime_log(RLOG_LV_FATAL, (char *)"synflood_detect", (char *)"synflood  normal! syn_count = %u in tcp num = %lld, thread_num = %d", g_syn_counter[thread_num].count, t, thread_num);
#endif
				g_syn_counter[thread_num].attack_flag = NORMAL;
				
			}
			g_syn_counter[thread_num].start_tcppkt_count = 0;
			g_syn_counter[thread_num].count = 0;
		}
	}
	return g_syn_counter[thread_num].attack_flag;	
}

