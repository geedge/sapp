#ifndef _SAPP_LIMITS_H_
#define _SAPP_LIMITS_H_ 1

#ifndef MAX_THREAD_NUM
#define MAX_THREAD_NUM 			256
#endif

#define SAPP_MAX_THREADS		MAX_THREAD_NUM

#define SAPP_SUPPORT_LAYER_NUM_MAX	(15) 
#define SAPP_PRUNE_LAYER_NUM_MAX    (10) 

#ifndef MTU_MAX
#define MTU_MAX 					2000
#endif

#define SAPP_MAX_PLUG_NUM		(128) 
#define SAPP_MAX_PLUG_ENTRY_NUM	(256) 

#define STATS_STR_LEN	(32)

#define PROJECT_REQ_MAX_PLUG_NUM			(128)
#define STREAM_BRIDGE_MAX_NUM  				(128)


#endif

