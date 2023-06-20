#ifndef __SAPP_MEM_H_
#define __SAPP_MEM_H_ 1

#ifdef __cplusplus
extern "C" {
#endif

#define MEM_STAT_GLOBAL_THREAD_ID  -1  /* 全局变量内存的thread_id, 其实没有用, 保持接口一致, 用于非IO线程 */

typedef enum{
	__SAPP_MEM_TYPE_INIT = 0,

	SAPP_MEM_STACK_LOCAL, /* 函数栈里临时申请的内存, 函数返回就会被释放 */
	
	SAPP_MEM_FIX_GLOBAL_VAL, 
	SAPP_MEM_FIX_GLOBAL_STREAM, 
	SAPP_MEM_FIX_PLUG_CTRL, 	/* 插件管理初始化必需的相关数据结构, 跟每个流动态挂载的插件无关 */
	
/*******************************************	
	以上是全局变量, 或初始化后不变的内存
*******************************************/
	__SAPP_FIX_DYN_SEPARATOR,
/*******************************************	
	以下是多线程动态内存
*******************************************/

	SAPP_MEM_DYN_MEM_HDR, 		/* 为了增加这个统计, 增加的内存头部消耗 */
	SAPP_MEM_DYN_IP_FRAG_PKT, /* 不太容易区别ipv4和ipv6, 此处统一计数 */
	SAPP_MEM_DYN_TCP_STREAM,
	SAPP_MEM_DYN_UDP_STREAM,
	SAPP_MEM_DYN_TCP_HALF_STREAM, /* c2s, s2c半流结构 */
	SAPP_MEM_DYN_UDP_HALF_STREAM,
	SAPP_MEM_DYN_PLUG_CTRL, 	/* 每个流插件管理必需的相关数据结构, 但不包括业务插件使用的内存 */
	SAPP_MEM_DYN_TCP_UNORDER,
	SAPP_MEM_DYN_TCP_SYN_OPT,	
	SAPP_MEM_DYN_TCP_POLLING_RAW_PKT,
	SAPP_MEM_DYN_UDP_POLLING_RAW_PKT,
	SAPP_MEM_DYN_TCP_DETAIL,
	SAPP_MEM_DYN_UDP_DETAIL,	
	SAPP_MEM_DYN_TCP_FLOW_STAT,
	SAPP_MEM_DYN_UDP_FLOW_STAT,
	SAPP_MEM_DYN_TCP_PROJECT, /* 仅包括project必需的管理结构, 但不包括插件在project_add时申请的内存 */
	SAPP_MEM_DYN_UDP_PROJECT,
	SAPP_MEM_DYN_TCP_BRIDGE,
	SAPP_MEM_DYN_UDP_BRIDGE,	
	SAPP_MEM_DYN_PADDR, 		/* 每层地址所占的内存, 就不分具体协议了, 太麻烦了!! */
	SAPP_MEM_DYN_DETAIN_PKT,	
	SAPP_MEM_DYN_SID_LIST,	

	__SAPP_MEM_TYPE_MAX,
}sapp_mem_type_t;

void *sapp_mem_malloc(sapp_mem_type_t type, int thread_seq, int size);
void *sapp_mem_calloc(sapp_mem_type_t type, int thread_seq, int size);
void sapp_mem_free(sapp_mem_type_t type, int thread_seq, void *data);
void *sapp_mem_realloc(sapp_mem_type_t type, int thread_seq, void *old_ptr, int size);
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