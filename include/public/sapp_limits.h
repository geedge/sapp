#ifndef _SAPP_LIMITS_H_
#define _SAPP_LIMITS_H_ 1

#ifndef MAX_THREAD_NUM
#define MAX_THREAD_NUM 			256
#endif

#define SAPP_MAX_THREADS		MAX_THREAD_NUM

#define SAPP_SUPPORT_LAYER_NUM_MAX	(15) /* sapp平台支持的最大嵌套层数, 与struct streaminfo_private->layer_index相关 */
#define SAPP_PRUNE_LAYER_NUM_MAX    (10) /* sapp平台支持的最大修剪配置条数 */

#ifndef MTU_MAX
#define MTU_MAX 					2000
#endif

#define SAPP_MAX_PLUG_NUM		(128) /* 所有插件数量最大值 */
#define SAPP_MAX_PLUG_ENTRY_NUM	(256) /* 所有插件的entry数量最大值 */

#define STATS_STR_LEN	(32)

#define PROJECT_REQ_MAX_PLUG_NUM			(128)
#define STREAM_BRIDGE_MAX_NUM  				(128)


#endif

