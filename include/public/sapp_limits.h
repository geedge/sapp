#ifndef _SAPP_LIMITS_H_
#define _SAPP_LIMITS_H_ 1

#ifndef MAX_THREAD_NUM
#define MAX_THREAD_NUM 			128
#endif

#define SAPP_MAX_THREADS		MAX_THREAD_NUM

#define SAPP_SUPPORT_LAYER_NUM_MAX	(15) /* sapp平台支持的最大嵌套层数, 与struct streaminfo_private->layer_index相关 */

#endif

