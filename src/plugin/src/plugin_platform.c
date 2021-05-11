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

stBusinessPlugInfo* g_platform_plug_info;

extern int process_confelem_sofilename(char* filename,int plugtype,stProtocolPlugInfo* pluginfo_pro,stBusinessPlugInfo* pluginfo_bus);
extern int process_confelem_platentry(char* filename,void* fp_dlopen,char* plugname);


/****************************************************************************
函数名:plugin_load_platform()
功能：处理解析层插件配置文件列表
输入：解析层插件配置文件列表全路径名
输出：0:sucess
		   -1:error
*****************************************************************************/
int plugin_load_platform(void)
{
	int rec;

	rec = process_conflist(PLUGTYPE_PLATFORM);
	if(rec < 0)
	{
		return -1;
	}

	return 0;
}


/****************************************************************************
函数名:process_confelem_platform()
功能：处理业务层插件加载配置文件，即静态加载插件过程
输入：业务层插件配置文件全路径名
输出：0:sucess
		   -1:error
*****************************************************************************/
int process_confelem_platform(char* confelem_filename)
{
	int rec;	
	stBusinessPlugInfo* plug_info; 


	init_pluginfo_elem_bus(&plug_info);


	//PLUGNAME
	rec = process_confelem_plugname(confelem_filename,PLUGTYPE_PLATFORM,&(plug_info->plugname));
	if(rec < 0)
	{
		destroy_pluginfo_elem_bus(plug_info);
		return -1;
	}

	//FILENAME
	rec = process_confelem_sofilename(confelem_filename,PLUGTYPE_PLATFORM,NULL,plug_info);
	if(rec < 0)
	{
		destroy_pluginfo_elem_bus(plug_info);
		return -1;
	}
	

	//[IP],[IPV6],[TCP],[UDP]
	rec = process_confelem_platentry(confelem_filename,plug_info->filepoint,plug_info->plugname);
	if(rec < 0)
	{
		destroy_pluginfo_elem_bus(plug_info);
		return -1;
	}


	
	//add plug_info to protocol_plug_info's double dir link table
	if(g_platform_plug_info == NULL)
	{
		g_platform_plug_info = plug_info;
	}
	else
	{
		plug_info->next = g_platform_plug_info;
		g_platform_plug_info->pre = plug_info;
		g_platform_plug_info = plug_info;
	}

	//printf("\033[32m[Notice]%s, load %s success!\033[0m\n", PLUGIN_LOGNAME, plug_info->plugname);
	MESA_handle_runtime_log(g_plugin_runtime_handle,RLOG_LV_FATAL, PLUGIN_LOGNAME,"load \033[32m%s\033[0m success!",plug_info->plugname);


	return 0;

}



