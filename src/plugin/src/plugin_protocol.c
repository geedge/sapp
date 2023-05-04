#include <stdio.h>
#include <string.h>
#include <dlfcn.h>
#include "MESA_prof_load.h"
#include "MESA_handle_logger.h"
#include "stream.h"
#include "plugin_proc.h"
#include "plugin_platform.h"
#include "plugin_protocol.h"
#include "plugin_business.h"
#include "plugin.h"

stProtocolPlugInfo* g_protocol_plug_info;
stProtocolPlugInfo **g_protocol_plug_info_array;
extern int g_plugin_plugid;
extern int process_confelem_sofilename(char* filename,int plugtype,stProtocolPlugInfo* pluginfo_pro,stBusinessPlugInfo* pluginfo_bus);
extern int process_confelem_platentry(char* filename,void* fp_dlopen,char* plugname);


/* 2016-05-30 lijia add, 为了改善调用插件性能, 避免每次都遍历链表, 将指针存储于数组, 直接取下标 */
static void plugin_protocol_info_convert(void)
{
	int i;
	stProtocolPlugInfo *tmp_plug_info = g_protocol_plug_info;

	if(NULL == g_protocol_plug_info){
		return;
	}
	
	g_protocol_plug_info_array = SAPP_GLOBAL_ALLOC(sizeof(void *) * (g_plugin_plugid + 1));
	memset(g_protocol_plug_info_array, 0, sizeof(void *) * (g_plugin_plugid + 1));

	while(tmp_plug_info->next){
		tmp_plug_info = tmp_plug_info->next;
	}

	for(i = 1; i <= g_plugin_plugid; i++){
		g_protocol_plug_info_array[i] = tmp_plug_info;
		if(NULL == tmp_plug_info){
			break;
		}
		tmp_plug_info = tmp_plug_info->pre;
	}
}

/****************************************************************************
函数名:plugin_load_protocol()
功能：处理解析层插件配置文件列表
输入：解析层插件配置文件列表全路径名
输出：0:sucess
		   -1:error
*****************************************************************************/
int plugin_load_protocol(void)
{
	int rec;

	rec = process_conflist(PLUGTYPE_PROTOCOL);
#if 0	/* 此处错误继续执行plugin_protocol_info_convert(), 不能因某个protocol层插件挂载失败直接返回 */
	if(rec < 0)
	{
		return -1;
	}
#endif
	plugin_protocol_info_convert();

	return 0;
}



/****************************************************************************
函数名:init_pluginfo_elem_pro()
功能：创建解析层插件信息
输入：
输出：
*****************************************************************************/
void init_pluginfo_elem_pro(stProtocolPlugInfo** protocol_plug_info)
{
	stProtocolPlugInfo* plug_info = (stProtocolPlugInfo*)SAPP_GLOBAL_ALLOC(sizeof(stProtocolPlugInfo));
	memset(plug_info,0,sizeof(stProtocolPlugInfo));

	*protocol_plug_info = plug_info;

	return;
}

/****************************************************************************
函数名:destroy_pluginfo_elem_pro()
功能：释放解析层插件信息
输入：
输出：
*****************************************************************************/
void destroy_pluginfo_elem_pro(stProtocolPlugInfo* plug_info)
{
	if(plug_info->plugname != NULL)
	{
		SAPP_GLOBAL_FREE(plug_info->plugname);
		plug_info->plugname = NULL;
	}

	SAPP_GLOBAL_FREE(plug_info);
	plug_info = NULL;

	return;
	
}

/****************************************************************************
函数名:process_confelem_protocol()
功能：处理解析层插件加载配置文件，即静态加载插件过程
输入：解析层插件配置文件全路径名
输出：0:sucess
		   -1:error
*****************************************************************************/
int process_confelem_protocol(char* confelem_filename)
{
	int rec;	
	stProtocolPlugInfo* plug_info; 


	init_pluginfo_elem_pro(&plug_info);


	//PLUGNAME
	rec = process_confelem_plugname(confelem_filename,PLUGTYPE_PROTOCOL,&(plug_info->plugname));
	if(rec < 0)
	{
		destroy_pluginfo_elem_pro(plug_info);
		return -1;
	}

	//FILENAME
	rec = process_confelem_sofilename(confelem_filename,PLUGTYPE_PROTOCOL,plug_info,NULL);
	if(rec < 0)
	{
		destroy_pluginfo_elem_pro(plug_info);
		return -1;
	}
	

	//[IP],[IPV6],[TCP],[UDP]
	rec = process_confelem_platentry(confelem_filename,plug_info->filepoint,plug_info->plugname);

	if(rec < 0)
	{
		destroy_pluginfo_elem_pro(plug_info);
		return -1;
	}
	

	//add plug_info to protocol_plug_info's double dir link table
	if(g_protocol_plug_info == NULL)
	{
		g_protocol_plug_info = plug_info;
	}
	else
	{
		plug_info->next = g_protocol_plug_info;
		g_protocol_plug_info->pre = plug_info;
		g_protocol_plug_info = plug_info;
	}

	MESA_handle_runtime_log(g_plugin_runtime_handle,RLOG_LV_FATAL, PLUGIN_LOGNAME,"load \033[32m%s\033[0m success!",plug_info->plugname);

	return 0;
}
 
