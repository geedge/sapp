#include "sapp_api.h"
#include "sapp_declaration.h"
#include "sapp_private_api.h"

void* g_plugin_runtime_handle;
extern int g_business_plug_type;
extern stPlugRuntimeInfo plugctrl_runtime_info;

extern int platform_register_action_judge(char (*action_cb_fun)(int net_conn_mode, char plug_action));

/****************************************************************************
函数名:plugin_readconf()
功能：读配置文件，获得三类插件配置文件列表全路径名
输入：无 
输出：0:sucess
		   -1:error
*****************************************************************************/
int plugin_readconf(char* filename_platform,char* filename_protocol,char* filename_business,char* logger_filepath,unsigned int* logger_level)
{
	int rec;


	MESA_load_profile_string_def((char*)PLUGIN_CONFNAME,(char*)PLUGIN_CONFMODULE,(char*)"logger_filepath",logger_filepath,PLUGIN_FILENAME_MAXLEN,(char*)"./log/runtimelog_plugin");
	MESA_load_profile_uint_def((char*)PLUGIN_CONFNAME,(char*)PLUGIN_CONFMODULE,(char*)"logger_level",(unsigned int*)logger_level,RLOG_LV_DEBUG);

//20170525 liuy add for wy serial
	MESA_load_profile_uint_def((char*)PLUGIN_CONFNAME,(char*)PLUGIN_CONFMODULE,(char*)"runtime_switch",(unsigned int*)&(plugctrl_runtime_info.runtime_switch),0);
	MESA_load_profile_uint_def((char*)PLUGIN_CONFNAME,(char*)PLUGIN_CONFMODULE,(char*)"max_runtime",(unsigned int*)&(plugctrl_runtime_info.max_runtime),1000);
	MESA_load_profile_uint_def((char*)PLUGIN_CONFNAME,(char*)PLUGIN_CONFMODULE,(char*)"max_interval_num",(unsigned int*)&(plugctrl_runtime_info.max_interval_num),10);

//add end

	rec = MESA_load_profile_string_def(PLUGIN_CONFNAME,PLUGIN_CONFMODULE,"platform_config",
									filename_platform,PLUGIN_FILENAME_MAXLEN,FILENAME_PLAT_DEF);
	if(rec < 0)
	{
		printf("filename_platform get error!\n");
		return -1;

	}



	rec = MESA_load_profile_string_def(PLUGIN_CONFNAME,PLUGIN_CONFMODULE,"protocol_config",
								filename_protocol,PLUGIN_FILENAME_MAXLEN,FILENAME_PRO_DEF);
	if(rec < 0)
	{
		printf("filename_protocol get error!\n");
		return -1;

	}

	rec = MESA_load_profile_string_def(PLUGIN_CONFNAME,PLUGIN_CONFMODULE,"business_config",
									filename_business,PLUGIN_FILENAME_MAXLEN,FILENAME_BUS_DEF);
	if(rec < 0)
	{
		printf("filename_business get error!\n");
		return -1;

	}

	return 0;

}


char process_pkt_return(int net_conn_mode, char plug_action)
{
	if((net_conn_mode==3)&&(g_business_plug_type==PLUGTYPE_JC))
	{
		return 0;	//DROP
	}

	return plug_action;
}

/****************************************************************************
函数名:plugctrl_proc()
功能：1、读配置文件，获得三类插件配置文件列表全路径名
		   2、分别调用静态加载三类插件；
输入：无 
输出：0:sucess
		   -1:error
*****************************************************************************/
int plugctrl_proc()
{
	int rec;

	int logger_level;
	char logger_filepath[PLUGIN_FILENAME_MAXLEN]={0};


	char filename_platform[PLUGIN_FILENAME_MAXLEN] = {0};
	char filename_protocol[PLUGIN_FILENAME_MAXLEN] = {0};
	char filename_business[PLUGIN_FILENAME_MAXLEN] = {0};

	rec = plugin_readconf(filename_platform,filename_protocol,filename_business,logger_filepath,(unsigned int*)&logger_level);
	if(rec < 0)
	{
		printf("plugin_readconf error!\n");
		return -1;
	}

	 	//MESA_handle_logger init
	g_plugin_runtime_handle = MESA_create_runtime_log_handle(logger_filepath, logger_level);
	if(g_plugin_runtime_handle == NULL)
	{
		printf("rawdata MESA_create_runtime_log_handle() error!\n");
		return -1;
	}


	rec = process_conf_entryname();
	if(rec < 0)
	{
		MESA_handle_runtime_log(g_plugin_runtime_handle,RLOG_LV_FATAL, PLUGIN_LOGNAME,"plugin_readconf error!");
		return -1;
	}

	rec = plugin_load_platform(filename_platform);
	rec = plugin_load_protocol(filename_protocol);
	rec = plugin_load_business(filename_business);

	platform_register_action_judge(process_pkt_return);

	return 0;
}

