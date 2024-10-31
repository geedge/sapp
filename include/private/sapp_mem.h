#ifndef __SAPP_MEM_H_
#define __SAPP_MEM_H_ 1

#ifdef __cplusplus
extern "C" {
#endif

#define MEM_STAT_GLOBAL_THREAD_ID  -1  /* ȫ�ֱ����ڴ��thread_id, ��ʵû����, ���ֽӿ�һ��, ���ڷ�IO�߳� */

typedef enum{
	__SAPP_MEM_TYPE_INIT = 0,

	SAPP_MEM_STACK_LOCAL, /* ����ջ����ʱ������ڴ�, �������ؾͻᱻ�ͷ� */
	
	SAPP_MEM_FIX_GLOBAL_VAL, 
	SAPP_MEM_FIX_GLOBAL_STREAM, 
	SAPP_MEM_FIX_PLUG_CTRL, 	/* ���������ʼ�������������ݽṹ, ��ÿ������̬���صĲ���޹� */
	
/*******************************************	
	������ȫ�ֱ���, ���ʼ���󲻱���ڴ�
*******************************************/
	__SAPP_FIX_DYN_SEPARATOR,
/*******************************************	
	�����Ƕ��̶߳�̬�ڴ�
*******************************************/

	SAPP_MEM_DYN_MEM_HDR, 		/* Ϊ���������ͳ��, ���ӵ��ڴ�ͷ������ */
	SAPP_MEM_DYN_IP_FRAG_PKT, /* ��̫��������ipv4��ipv6, �˴�ͳһ���� */
	SAPP_MEM_DYN_TCP_STREAM,
	SAPP_MEM_DYN_UDP_STREAM,
	SAPP_MEM_DYN_TCP_HALF_STREAM, /* c2s, s2c�����ṹ */
	SAPP_MEM_DYN_UDP_HALF_STREAM,
	SAPP_MEM_DYN_PLUG_CTRL, 	/* ÿ����������������������ݽṹ, ��������ҵ����ʹ�õ��ڴ� */
	SAPP_MEM_DYN_TCP_UNORDER,
	SAPP_MEM_DYN_TCP_SYN_OPT,	
	SAPP_MEM_DYN_TCP_POLLING_RAW_PKT,
	SAPP_MEM_DYN_UDP_POLLING_RAW_PKT,
	SAPP_MEM_DYN_TCP_DETAIL,
	SAPP_MEM_DYN_UDP_DETAIL,	
	SAPP_MEM_DYN_TCP_FLOW_STAT,
	SAPP_MEM_DYN_UDP_FLOW_STAT,
	SAPP_MEM_DYN_TCP_PROJECT, /* ������project����Ĺ����ṹ, �������������project_addʱ������ڴ� */
	SAPP_MEM_DYN_UDP_PROJECT,
	SAPP_MEM_DYN_TCP_BRIDGE,
	SAPP_MEM_DYN_UDP_BRIDGE,	
	SAPP_MEM_DYN_PADDR, 		/* ÿ���ַ��ռ���ڴ�, �Ͳ��־���Э����, ̫�鷳��!! */
	SAPP_MEM_DYN_DETAIN_PKT,	
	SAPP_MEM_DYN_SID_LIST,	
	SAPP_MEM_DYN_BLOOM_FILTER, 
	__SAPP_MEM_TYPE_MAX,
}sapp_mem_type_t;

void *sapp_mem_malloc(sapp_mem_type_t type, int thread_seq, unsigned int size);
void *sapp_mem_calloc(sapp_mem_type_t type, int thread_seq, unsigned int size);
void sapp_mem_free(sapp_mem_type_t type, int thread_seq, void *data);
void *sapp_mem_realloc(sapp_mem_type_t type, int thread_seq, void *old_ptr, unsigned int size);
void sapp_mem_stat_output(void);

#ifndef SAPP_FREE
#define SAPP_FREE(type,tid, mem) do{if(mem){sapp_mem_free(type, tid, (void *)mem); mem = NULL;}}while(0)
#endif


#ifndef SAPP_GLOBAL_ALLOC
#define SAPP_GLOBAL_ALLOC(size) sapp_mem_calloc(SAPP_MEM_FIX_GLOBAL_VAL, MEM_STAT_GLOBAL_THREAD_ID, size)
#endif

#ifndef SAPP_GLOBAL_FREE
#define SAPP_GLOBAL_FREE(mem) do{if(mem){sapp_mem_free(SAPP_MEM_FIX_GLOBAL_VAL, MEM_STAT_GLOBAL_THREAD_ID, (void *)mem); mem = NULL;}}while(0)
#endif


#ifdef __cplusplus
}
#endif

#endif