#ifdef __cplusplus
extern "C" {
#endif
#include "sapp_api.h"
#include "sapp_private_api.h"

/*
	后台实时监测某些全局变量, 防止被意外修改!
	比如配置文件, 命令行参数, 启动后保留一份副本, 跟当前的  sapp_global_val 比较,
	这些变量就应该是只读的, 严禁修改!
*/
static void *sapp_global_val_sanitizier(void *arg)
{
	
	while(1){

	}

	return NULL;
}


static void sapp_set_global_default(sapp_global_t *g_val)
{

}


int sapp_global_val_init(void)
{
	sapp_global_val = (sapp_global_t *)calloc(1, sizeof(sapp_global_t));

	sapp_set_global_default(sapp_global_val);

	return 0;
}


#ifdef __cplusplus
}
#endif



