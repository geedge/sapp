/*********************************************************************************************
文件名:plugin.c
功能:  
作者: LiuY
当前版本:2.0
完成日期:20140411
修改说明:通过配置文件加载插件
**********************************************************************************************
time:20140413
content:1、加载业务层插件的update指针
**********************************************************************************************
时间:2014-11-9
内容:
1-整理插件管理功能成为独立模块，可以被sapp平台加载；
2-业务插件返回值，无论插件入口函数是什么，返回值都是相同的四个宏；
3-解析层close状态调用业务层插件时，如果当前数据不是业务层感兴趣的域，则buf和buflen为空；
4-解析层close状态调用业务层插件时，如果当前数据不是业务层感兴趣的域，则buf和buflen为空；
**********************************************************************************************
时间:2014-11-23
内容:
1-为了向后兼容性，业务层插件的返回值变更会原来的PROT系列；
2-删除之前的PROT_KILLME,增加PRTO_DROPPKT，为丢弃当前包含义；
**********************************************************************************************
时间:2014-11-24
内容:plugin_call_flagstate（）中去掉flag初值为1；
**********************************************************************************************
时间:2014-12-22
内容:add ipv4_raw_entry and ipv6_raw_entry
**********************************************************************************************
时间:2014-12-30
内容:add TCP_RAW,TCPALL_RAW,UDP_RAW
**********************************************************************************************
时间:20150129
内容:
1-modify runtime_log ---> MESA_handle_runtime_log
2-enum fun_type_t{
	FUN_TYPE_IPV4=0,
    FUN_TYPE_IPV6, 
    FUN_TYPE_TCP, 
    FUN_TYPE_TCPALL, 
    FUN_TYPE_UDP, 
    FUN_TYPE_IPV4_RAW, 
    FUN_TYPE_IPV6_RAW, 
    FUN_TYPE_TCP_RAW, 
    FUN_TYPE_TCPALL_RAW, 
    FUN_TYPE_UDP_RAW, 
};
int stream_register_fun(int funtype,char (*x)(void));
**********************************************************************************************
时间:2015-02-28
内容:plugin.c:150 add total_flag=0;否则如果没有任何业务层插件，解析层收到的
	flag值是随机值
**********************************************************************************************
时间:201503-16-2
内容:
	1-plugin.c:1259 add funelem->called_flag =1;
		否则如果pending状态没有调用业务层插件，每个data状态都会有pending的标示
	2-pending 增加called_flag的初始化
	3-close增加对调用的判断:如果该插件曾经被调用过或者当前字段是该插件所
	    需要的字段才在close状态调用，否则不调用
**********************************************************************************************
时间:201503-18 yangwei
内容:
	1-增加reset_cwd()切换当前路径的函数；因为第三方插件有初始化时切换当前路径
	   为插件所在路径导致后续程序执行错误的情况；所以在每个插件初始化结束
	   后都将当前路径切换为主程序所在的路径；
**********************************************************************************************
时间:201503-25 
内容:
	1-更改头文件形式，在makefile中指定路径；
**********************************************************************************************

时间:2016-03-14 LiJia 
内容:
	1-修改process_conf_entryname()函数删除末尾"\r\n"的BUG.
**********************************************************************************************

时间:2016-05-30 LiJia 
内容:
	1-修改plugin_porcess_data()函数修改了session_state但没有恢复, 造成后续插件session_state不对BUG;
	2-修改plugin_porcess_close()函数逻辑, 可能会造成业务插件内存泄漏.

**********************************************************************************************

时间:2016-05-30 LiJia 
内容:
	1-增加IP_FRAG入口.
**********************************************************************************************

*/


#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <dlfcn.h>
#include <assert.h>
//#include <readline/readline.h>
//#include <readline/history.h>
#include "MESA_prof_load.h"
#include "MESA_handle_logger.h"
#include "stream.h"
#include "plugin_proc.h"
#include "plugin_platform.h"
#include "plugin_protocol.h"
#include "plugin_business.h"
#include "plugin.h"

extern stProtocolPlugInfo* g_protocol_plug_info;
extern stBusinessPlugInfo* g_business_plug_info;
extern stProtocolPlugInfo **g_protocol_plug_info_array;
extern int g_timestamp_record_sw;
extern long long g_timedelay_threshold;

int g_plugin_plugid ;
stEntryNameInfo* g_entryname_info;

/*
	Lijia note:
	出现顺序要和enum fun_type_t类型顺序一致.
*/
char* g_plugin_entryname[PLUGIN_MAX_ENTRYNUM] = 
{
	SECTION_FUN_IP,
	SECTION_FUN_IPV6,
	SECTION_FUN_TCP,
	SECTION_FUN_TCP_ALL,
	SECTION_FUN_UDP,
	SECTION_FUN_IPV4_RAW,
	SECTION_FUN_IPV6_RAW,
	SECTION_FUN_TCP_RAW,
	SECTION_FUN_TCPALL_RAW,
	SECTION_FUN_UDP_RAW,
	SECTION_FUN_IP_FRAG,
	SECTION_FUN_IP_FRAG_RAW,
	SECTION_FUN_IPV6_FRAG,
	SECTION_FUN_IPV6_FRAG_RAW,
	SECTION_FUN_PHONY,
	SECTION_FUN_POLLING
};

int g_plugin_version_VERSION_20170511;

 /* 删除末尾的换行符"\r\n" */
static void plugin_del_tail_rn(char *data, int max_len)
{
    int i;
    for(i = 0; i < max_len; i++){
        if(('\r' == data[i]) || ('\n' == data[i])){
            data[i] = '\0';
            return;
        }
    }

    return;
}


/****************************************************************************
函数名:reset_cwd()
功能：切换当前路径
输入：
输出：
//add by yw 20150318, reset cwd to exe dir
*****************************************************************************/
int reset_cwd()
{
	char cur_path[1024];
	memset(cur_path, 0, sizeof(cur_path));
	int path_len = readlink("/proc/self/exe", cur_path, sizeof(cur_path));
	int i = 0, ret = 0;
	if(path_len < 0 || path_len > sizeof(cur_path))
	{
		perror(NULL);
		return -1;
	}
	for(i = path_len; i > 0; i--)
	{
		if(cur_path[i] == '/')
		{
			cur_path[i] = '\0';
			break;
		}
	}
	ret = chdir(cur_path);
	if(ret < 0)
	{	perror(NULL);
		return -1;
	}
	return 0;	
}

/****************************************************************************
函数名:get_propluginfo_name()
功能：检查解析层插件是否已经挂载
输入：插件名 
输出：NULL:没有找到
*****************************************************************************/
stProtocolPlugInfo* get_propluginfo_name(char* plugname)
{
	stProtocolPlugInfo* pluginfo = g_protocol_plug_info;

	while(pluginfo)
	{
		if(memcmp(pluginfo->plugname,plugname,strlen(plugname)) == 0)
		{
			return pluginfo;
		}

		pluginfo = pluginfo->next;
	}

	return NULL;
	
}


/****************************************************************************
函数名:get_propluginfo_name()
功能：检查解析层插件是否已经挂载
输入：插件名 
输出：NULL:没有找到
*****************************************************************************/

#if 0 /* 2016-05-30 lijia modify */
stProtocolPlugInfo* get_propluginfo_plugid(unsigned short plugid)
{
	stProtocolPlugInfo* pluginfo = g_protocol_plug_info;

	while(pluginfo)
	{
		if(pluginfo->plugid == plugid)
		{
			return pluginfo;
		}

		pluginfo = pluginfo->next;
	}

	return NULL;
	
}
#else
stProtocolPlugInfo* get_propluginfo_plugid(unsigned short plugid)
{
	return g_protocol_plug_info_array[plugid];
}
#endif



/****************************************************************************
函数名:stream_register_app()
功能：注册应用层函数
输入：
输出：0:sucess
		   -1:error
*****************************************************************************/

int stream_register_app(stProtocolFunInfo** fun_list,unsigned short plugid,AppEntry x,long long proflag)
{
	stProtocolFunInfo* funelem_last;
	stProtocolFunInfo* funelem = (stProtocolFunInfo*)malloc(sizeof(stProtocolFunInfo));
	memset(funelem,0,sizeof(stProtocolFunInfo));

	funelem->plugid = plugid;
	funelem->aliveflag = 1;
	funelem->appentry = x;
	funelem->protocol_flag = proflag;


	if(*fun_list == NULL)
	{
		*fun_list = funelem;
	}
	else
	{

		funelem_last = *fun_list;

		while(funelem_last->next !=NULL)
		{
			funelem_last = funelem_last->next;
		}

		funelem_last->next = funelem;
		funelem->pre = funelem_last;
	}

	return 0;
}



/****************************************************************************
函数名:plugin_call_flagstate()
功能：调用解析层FLAG_STATE函数，通知解析层上挂在所有业务
		   插件需要的flag值全集；
输入： 
输出：
*****************************************************************************/
void plugin_call_flagstate()
{
	int firstcall_flag;
	long long toatal_flag;
	stProtocolPlugInfo* pluginfo = g_protocol_plug_info;
	stProtocolFunInfo* funelem;

	while(pluginfo)
	{
 		firstcall_flag=0;
		toatal_flag = 0;	//20150228 modify for funelem==NULL 
		funelem = pluginfo->fun_list;

		while(funelem)
		{
			if(firstcall_flag==0)
			{
				toatal_flag = funelem->protocol_flag;

			}
			else
			{
				toatal_flag |= funelem->protocol_flag;
			}
			
			firstcall_flag ++;
 			funelem = funelem->next;
		}

		if(pluginfo->fun_flagstate != NULL)
		{
			pluginfo->fun_flagstate(toatal_flag);
		}
	
		pluginfo = pluginfo ->next;
		
	}

	return;
	
}


/****************************************************************************
函数名:check_name_fromentrylist()
功能：检查业务层挂载入口或者解析层函数名是否
		   在entrylist.conf配置文件中
输入：无 
输出：1:命中
		   0:没有命中
		   -1:错误
*****************************************************************************/
int check_name_fromentrylist(char* entryname)
{
	int i;

	for(i=0;i<g_entryname_info->num;i++)
	{
		if(memcmp(entryname,&(g_entryname_info->entryname[i]),strlen(g_entryname_info->entryname[i].name)) == 0)
		{
			return 1;
		}
	}

	return 0;
}


/****************************************************************************
函数名:check_entryname_fromplug()
功能：检查业务层插件入口函数是否正确；
输入：无 
输出：1:命中
		   0:没有命中
		   -1:错误
*****************************************************************************/
int check_entryname_fromplug(char* entryname)
{
	stProtocolPlugInfo* protocol_elem = g_protocol_plug_info;

	while(protocol_elem != NULL)
	{
		if(memcmp(entryname,protocol_elem->plugname,strlen(protocol_elem->plugname)) == 0)
		{
			return 1;
		}

		protocol_elem = protocol_elem->next;
	}

	return 0;
	
}

/****************************************************************************
函数名:check_name_fromentrylist()
功能：检查业务层挂载入口或者解析层函数名是否
		   在entrylist.conf配置文件中
输入：无 
输出：1:命中
		   0:没有命中
		   -1:错误
*****************************************************************************/
int check_plug_conf(char* filename,int plugtype)
{
	int ret;
	char* begin;
	char config_buf[PLUGIN_MAX_CONFLEN];

	FILE* fp = fopen(filename,"r");
	if(fp == NULL)
	{
		MESA_handle_runtime_log(g_plugin_runtime_handle,RLOG_LV_FATAL, PLUGIN_LOGNAME,"check_plug_conf(): fopen() %s error!\n",filename);
		return -1;
	}

	while(feof(fp)==0)
	{
		memset(config_buf,0,PLUGIN_MAX_CONFLEN);

		//获取文件中每行内容
		if((fgets(config_buf,PLUGIN_MAX_CONFLEN,fp)) == NULL)
		{
			break;
		}

		plugin_del_tail_rn(config_buf, strlen(config_buf));

		//第一个字符不是"[",不做处理
		if(memcmp(config_buf,KEYWORD_SPECIAL1,strlen(KEYWORD_SPECIAL1)) != 0)
		{
			continue;
		}

		begin = config_buf+1;
		
		//如果是[PLUGINFO]，不做处理
		if(memcmp(begin,SECTION_PLUGINFO,strlen(SECTION_PLUGINFO)) == 0)
		{
			continue;
		}

		if((memcmp(begin,SECTION_FUN_IP,strlen(SECTION_FUN_IP)) ==0) || 
			(memcmp(begin,SECTION_FUN_IP_FRAG,strlen(SECTION_FUN_IP_FRAG)) ==0) || 
			(memcmp(begin,SECTION_FUN_IPV6,strlen(SECTION_FUN_IPV6)) ==0) ||
			(memcmp(begin,SECTION_FUN_TCP,strlen(SECTION_FUN_TCP)) ==0) ||
			(memcmp(begin,SECTION_FUN_TCP_ALL,strlen(SECTION_FUN_TCP_ALL)) ==0) ||
			(memcmp(begin,SECTION_FUN_UDP,strlen(SECTION_FUN_UDP)) ==0) ||
			(memcmp(begin,SECTION_FUN_PHONY,strlen(SECTION_FUN_PHONY)) ==0) ||
			(memcmp(begin,SECTION_FUN_POLLING,strlen(SECTION_FUN_POLLING)) ==0))
		{
			continue;
		}


		if(plugtype==PLUGTYPE_BUSENISS)
		{
			ret = check_name_fromentrylist(begin);
			if(ret == 1)
			{
				continue;
			}
		}
		fclose(fp);
		fp=NULL;
		
		MESA_handle_runtime_log(g_plugin_runtime_handle,RLOG_LV_FATAL, PLUGIN_LOGNAME,"%s's entry name is unknow:%s\n",filename,config_buf);
		return -1;
		

	}
	//20160217 liuy add
	fclose(fp);
	fp=NULL;

	return 0;
}


/****************************************************************************
函数名:plugin_load_entryname()
功能：加载所有函数名，即挂载层的名称
输入：无 
输出：0:sucess
		   -1:error
*****************************************************************************/
int process_conf_entryname()
{
	int rec;
	int len;
	char filename[PLUGIN_FILENAME_MAXLEN] = {0};
	char buf_entryname[PLUGIN_MAX_CONFLEN] = {0};
	FILE* fp;

	//get entrylist's full name from in plugin.conf
	rec = MESA_load_profile_string_def(PLUGIN_CONFNAME,PLUGIN_CONFMODULE,
									"entrylist_config",filename,PLUGIN_FILENAME_MAXLEN,FILENAME_CONFLIST_DEF);
	if(rec < 0)
	{
		MESA_handle_runtime_log(g_plugin_runtime_handle,RLOG_LV_FATAL, PLUGIN_LOGNAME,"filename_entryname get error!\n");
		return -1;

	}

	//process entrylist conf
	fp = fopen(filename,"r");
	if(fp == NULL)
	{
		MESA_handle_runtime_log(g_plugin_runtime_handle,RLOG_LV_FATAL, PLUGIN_LOGNAME,"fopen %s error!\n",filename);
		return -1;
	}

	g_entryname_info = (stEntryNameInfo*)malloc(sizeof(stEntryNameInfo));
	memset(g_entryname_info,0,sizeof(stEntryNameInfo));

	while(feof(fp) == 0)
	{
		if((fgets(buf_entryname,PLUGIN_MAX_CONFLEN,fp)) == NULL)
		{
			fclose(fp);
			fp=NULL;
			return 0;
		}

		//注释
		if(buf_entryname[0]=='#')
		{
			continue;
		}

#if 0 /* 2016-03-14 lijia modify, 此处不能认为末尾就是\r\n, 还可能是\n */
		///r/n
		len = strlen(buf_entryname);
		buf_entryname[len-2] = '\0';
#else
		plugin_del_tail_rn(buf_entryname, strlen(buf_entryname));
#endif
		if('\0' == buf_entryname[0]){
			continue;
		}
		
		//平台入口,IP,IPV6,TCP,TCPALL,UDP
		if((memcmp(buf_entryname,SECTION_FUN_IP,strlen(SECTION_FUN_IP))==0)||
		      (memcmp(buf_entryname,SECTION_FUN_IP_FRAG ,strlen(SECTION_FUN_IP_FRAG))==0)||
			(memcmp(buf_entryname,SECTION_FUN_IPV6,strlen(SECTION_FUN_IPV6))==0)||
			(memcmp(buf_entryname,SECTION_FUN_TCP,strlen(SECTION_FUN_TCP))==0)||
			(memcmp(buf_entryname,SECTION_FUN_TCP_ALL,strlen(SECTION_FUN_TCP_ALL))==0)||
			(memcmp(buf_entryname,SECTION_FUN_UDP,strlen(SECTION_FUN_UDP))==0) ||
			(memcmp(buf_entryname,SECTION_FUN_PHONY,strlen(SECTION_FUN_PHONY)) ==0) ||
			(memcmp(buf_entryname,SECTION_FUN_PHONY,strlen(SECTION_FUN_PHONY)) ==0) ||
			(memcmp(buf_entryname,SECTION_FUN_POLLING,strlen(SECTION_FUN_POLLING)) ==0))
		{
			continue;
		}

		g_entryname_info->num ++;
		g_entryname_info->entryname = (stEntryNameElem* )realloc(g_entryname_info->entryname,(g_entryname_info->num)*sizeof(stEntryNameElem));
		memset(&(g_entryname_info->entryname[g_entryname_info->num-1]),0,sizeof(stEntryNameElem));
		memcpy(&(g_entryname_info->entryname[g_entryname_info->num-1]),buf_entryname,strlen(buf_entryname));
	}
//20160217 liuy add
	fclose(fp);
	fp=NULL;

	return 0;
	
}


/****************************************************************************
函数名:process_confelem_plugname()
功能：处理插件配置文件的插件名字段
输入：filename:插件配置文件名[IN]
		  plugtype:插件类型，解析层插件需要检查文件名，业务层不需要
		   plugname:从配置文件读取插件名，存储到此变量中[OUT]
输出：0:sucess
		   -1:error
*****************************************************************************/
int process_confelem_plugname(char* filename,int plugtype,char** plugname)
{
	int rec;
	int len;
	char buf_plugname[PLUGIN_MAX_CONFLEN]={0};
	char* plugname_tmp;
	
	rec = MESA_load_profile_string_nodef(filename,SECTION_PLUGINFO,KEYWORD_PLUGNAME,buf_plugname,PLUGIN_MAX_CONFLEN);
	if(rec < 0)
	{
		MESA_handle_runtime_log(g_plugin_runtime_handle,RLOG_LV_FATAL, PLUGIN_LOGNAME,"%s get plugname error\n",filename);
		return -1;
	}

	if(plugtype == PLUGTYPE_PROTOCOL)
	{
		rec = check_name_fromentrylist(buf_plugname);
		if(rec != 1)
		{
			MESA_handle_runtime_log(g_plugin_runtime_handle,RLOG_LV_FATAL, PLUGIN_LOGNAME,"%s's plugname is %s,not in the entrylist.conf\n",filename,buf_plugname);
			return -1;
		}
	}

	len = strlen(buf_plugname);
	plugname_tmp = (char*)malloc(len+1);
	memcpy(plugname_tmp,buf_plugname,len);
	plugname_tmp[len] = '\0';

	*plugname = plugname_tmp;

	return 0;
}


/****************************************************************************
函数名:process_confelem_sofilename()
功能：处理插件配置文件的so文件路径名字段
		1、通过dlopen打开文件
		2、加载初始化函数CHAR_INIT，并调用初始化函数
		3、加载卸载函数CHAR_DESTROY，不是必须的
		4、如果是解析层插件:加载标记位通知FLAG_STATE和标记位转换FLAG_CHANGE函数
输入：filename:插件配置文件名[IN]
		  plugtype:插件类型，解析层插件需要检查文件名，业务层不需要
		   plugname:从配置文件读取插件名，存储到此变量中[OUT]
输出：0:sucess
		   -1:error
*****************************************************************************/
int process_confelem_sofilename(char* filename,int plugtype,stProtocolPlugInfo* pluginfo_pro,stBusinessPlugInfo* pluginfo_bus)
{
	int rec;
	char buf_sofilename[PLUGIN_MAX_CONFLEN]={0};
	char buf_funname[PLUGIN_MAX_CONFLEN]= {0};

	void* filepoint;
	
	int (*fun_init)();
	void  (*fun_destroy)();	
	void (*fun_getplugid)(unsigned short plugid);


	//load FILENAME 
	MESA_load_profile_string_nodef(filename,SECTION_PLUGINFO,KEYWORD_FILENAME,buf_sofilename,PLUGIN_MAX_CONFLEN);
	if(buf_sofilename[0] == '\0')
	{
		MESA_handle_runtime_log(g_plugin_runtime_handle,RLOG_LV_FATAL, PLUGIN_LOGNAME,"%s get %s error\n",filename,KEYWORD_FILENAME);
		return -1;
	}

	if((plugtype == PLUGTYPE_PLATFORM) || (plugtype == PLUGTYPE_PROTOCOL))
	{
		//平台层和解析层插件符号表公开
		filepoint = dlopen(buf_sofilename,RTLD_LAZY|RTLD_GLOBAL|RTLD_DEEPBIND);
	}
	else
	{
		//业务层插件符号表优先调用自己符号表
		filepoint = dlopen(buf_sofilename,RTLD_LAZY|RTLD_DEEPBIND);
	}

	if( filepoint == NULL ) 
	{
		MESA_handle_runtime_log(g_plugin_runtime_handle,RLOG_LV_FATAL, PLUGIN_LOGNAME,"dlopen %s in %s error:%s\n",buf_sofilename,filename,dlerror());
		return -1;
	}

	//load FUNAME_INIT
	memset(buf_funname,0,PLUGIN_MAX_CONFLEN);
	MESA_load_profile_string_nodef(filename,SECTION_PLUGINFO,KEYWORD_FUNINIT,buf_funname,PLUGIN_MAX_CONFLEN);
	if(buf_funname[0]=='\0')
	{
		MESA_handle_runtime_log(g_plugin_runtime_handle,RLOG_LV_FATAL, PLUGIN_LOGNAME,"%s no FUNNAME_INIT!\n",buf_sofilename);
		return -1;
	}

	fun_init = (int (*)())(dlsym(filepoint,buf_funname));
	//add by yw 20150318, reset cwd after init plugin
	reset_cwd();
	if(fun_init == NULL)
	{
		MESA_handle_runtime_log(g_plugin_runtime_handle,RLOG_LV_FATAL, PLUGIN_LOGNAME,"%s no function %s error!\n",buf_sofilename,buf_funname);
		return -1;
	}
	else
	{
		MESA_handle_runtime_log(g_plugin_runtime_handle,RLOG_LV_INFO, PLUGIN_LOGNAME,"%s load %s succ\n",filename,buf_funname);

	}

	
	rec = fun_init();
	if(rec < 0)
	{
		MESA_handle_runtime_log(g_plugin_runtime_handle,RLOG_LV_FATAL, PLUGIN_LOGNAME,"%s init error,don't load it\n",buf_sofilename);
		return -1;
	}


	//load FUNNAME_DESTROY
	memset(buf_funname,0,PLUGIN_MAX_CONFLEN);
	MESA_load_profile_string_nodef(filename,SECTION_PLUGINFO,KEYWORD_FUNDESTROY,buf_funname,PLUGIN_MAX_CONFLEN);
	if(buf_funname[0] !='\0')
	{
		fun_destroy = (void(*)())(dlsym(filepoint,buf_funname));
		if(fun_destroy == NULL)
		{
			MESA_handle_runtime_log(g_plugin_runtime_handle,RLOG_LV_FATAL, PLUGIN_LOGNAME,"%s has func:%s,but there is no in %s\n",filename,buf_funname,buf_sofilename);
		}
		else
		{
			MESA_handle_runtime_log(g_plugin_runtime_handle,RLOG_LV_INFO, PLUGIN_LOGNAME,"%s load %s succ\n",filename,buf_funname);

		}
	}

	//load update		
	memset(buf_funname,0,PLUGIN_MAX_CONFLEN);
	MESA_load_profile_string_nodef(filename,SECTION_PLUGINFO,KEYWORD_FUNUPDATE,buf_funname,PLUGIN_MAX_CONFLEN);
	if(buf_funname[0] !='\0')
	{
		pluginfo_bus->fun_update = (int (*)(int,int,char*,char*))(dlsym(filepoint,buf_funname));
		if(pluginfo_bus->fun_update == NULL)
		{
			MESA_handle_runtime_log(g_plugin_runtime_handle,RLOG_LV_FATAL, PLUGIN_LOGNAME,"%s has func:%s,but there is no in %s\n",filename,buf_funname,buf_sofilename);
		}
		else
		{
			MESA_handle_runtime_log(g_plugin_runtime_handle,RLOG_LV_INFO, PLUGIN_LOGNAME,"%s load %s succ\n",filename,buf_funname);

		}

	}

	

	//protocol plug 
	if(plugtype== PLUGTYPE_PROTOCOL)
	{
		pluginfo_pro->filepoint = filepoint;
		pluginfo_pro->fun_destroy = fun_destroy;

	
		//dlsym GET_PLUGID()
		memset(buf_funname,0,PLUGIN_MAX_CONFLEN);
		MESA_load_profile_string_nodef(filename,SECTION_PLUGINFO,KEYWORD_FUNGETID,buf_funname,PLUGIN_MAX_CONFLEN);
		if(buf_funname[0]=='\0')
		{
			MESA_handle_runtime_log(g_plugin_runtime_handle,RLOG_LV_FATAL, PLUGIN_LOGNAME,"%s no %s!\n",buf_sofilename,KEYWORD_FUNGETID);
			return -1;
		}

		fun_getplugid = (void(*)(unsigned short))(dlsym(filepoint,buf_funname));
		if(fun_getplugid == NULL)
		{
			MESA_handle_runtime_log(g_plugin_runtime_handle,RLOG_LV_FATAL, PLUGIN_LOGNAME,"%s no %s!\n",buf_sofilename,buf_funname);
			return -1;
		}
		else
		{
			MESA_handle_runtime_log(g_plugin_runtime_handle,RLOG_LV_INFO, PLUGIN_LOGNAME,"%s load %s succ\n",filename,buf_funname);

		}


		g_plugin_plugid++;
		fun_getplugid(g_plugin_plugid);
		pluginfo_pro->plugid = g_plugin_plugid;

		//dlsym flag_change
		memset(buf_funname,0,PLUGIN_MAX_CONFLEN);
		MESA_load_profile_string_nodef(filename,SECTION_PLUGINFO,KEYWORD_FUNCHANGE,buf_funname,PLUGIN_MAX_CONFLEN);
		if(buf_funname[0]=='\0')
		{
			MESA_handle_runtime_log(g_plugin_runtime_handle,RLOG_LV_FATAL, PLUGIN_LOGNAME,"%s no %s!\n",buf_sofilename,KEYWORD_FUNCHANGE);
			return -1;
		}

		pluginfo_pro->fun_flagchange = (long long (*)(char*))(dlsym(filepoint,buf_funname));
		if(pluginfo_pro->fun_flagchange == NULL)
		{
			MESA_handle_runtime_log(g_plugin_runtime_handle,RLOG_LV_FATAL, PLUGIN_LOGNAME,"%s no function %s error!\n",buf_sofilename,buf_funname);
			return -1;
		}
		else
		{
			MESA_handle_runtime_log(g_plugin_runtime_handle,RLOG_LV_INFO, PLUGIN_LOGNAME,"%s load %s succ\n",filename,buf_funname);

		}


		//dlsym flag_state
		memset(buf_funname,0,PLUGIN_MAX_CONFLEN);
		MESA_load_profile_string_nodef(filename,SECTION_PLUGINFO,KEYWORD_FUNSTATE,buf_funname,PLUGIN_MAX_CONFLEN);
		if(buf_funname[0]=='\0')
		{
			MESA_handle_runtime_log(g_plugin_runtime_handle,RLOG_LV_FATAL, PLUGIN_LOGNAME,"%s no %s!\n",buf_sofilename,KEYWORD_FUNSTATE);
			return -1;
		}

		pluginfo_pro->fun_flagstate = (void (*)(long long))(dlsym(filepoint,buf_funname));
		if(pluginfo_pro->fun_flagstate == NULL)
		{
			MESA_handle_runtime_log(g_plugin_runtime_handle,RLOG_LV_FATAL, PLUGIN_LOGNAME,"%s no function %s error!\n",buf_sofilename,buf_funname);
		}
		else
		{
			MESA_handle_runtime_log(g_plugin_runtime_handle,RLOG_LV_INFO, PLUGIN_LOGNAME,"%s load %s succ\n",filename,buf_funname);
		}

	}
	//business plug
	else
	{
		pluginfo_bus->filepoint = filepoint;
		pluginfo_bus->fun_destroy = fun_destroy;
//		pluginfo_bus->fun_update = (int (*)(int,int,char*,char*))(dlsym(filepoint,FUNNAME_UPDATE));
	}

/*	if(check_plug_conf(filename,plugtype) == -1)
	{
		return -1;
	}
*/
	check_plug_conf(filename,plugtype);

	return 0;
	
}



/****************************************************************************
函数名:process_confelem_platentry()
功能：加载平台入口函数
		1、IP_ENTRY,IPV6_ENTRY,TCP_ENTRY,UDP_ENTRY
		2、平台入口函数名目前固定，不是从配置文件中读取
输入：filename:插件配置文件名[IN]
		 
输出：0:sucess
		   -1:error
备注:任何一个配置文件中填写的入口函数错误，则返回错误
*****************************************************************************/
int process_confelem_platentry(char* filename,void* fp_dlopen,char* plugname)
{
	int i;
	int ret=0;
	char buf_funflag[PLUGIN_MAX_CONFLEN]={0};
	char buf_funname[PLUGIN_MAX_CONFLEN] = {0};

	char (*fun_pointer)(void);

	for(i=0;i<PLUGIN_MAX_ENTRYNUM;i++)
	{
		if(NULL == g_plugin_entryname[i]){
			break;
		}
		memset(buf_funflag,0,PLUGIN_MAX_CONFLEN);
		memset(buf_funname,0,PLUGIN_MAX_CONFLEN);
	
		MESA_load_profile_string_nodef(filename,g_plugin_entryname[i],KEYWORD_FUNFLAG,buf_funflag,PLUGIN_MAX_CONFLEN);
		if((buf_funflag[0] != '\0') && ((memcmp(buf_funflag,FUNFLAG_ALL_B,strlen(FUNFLAG_ALL_B)) == 0) || (memcmp(buf_funflag,FUNFLAG_ALL_S,strlen(FUNFLAG_ALL_S)) == 0)))
		{
			MESA_load_profile_string_nodef(filename,g_plugin_entryname[i],KEYWORD_FUNNAME,buf_funname,PLUGIN_MAX_CONFLEN);
			if(buf_funname[0] == '\0')
			{
				printf("\033[1;31;40m[Error]%s has [%s] and %s,but no %s\033[0m\n", filename,g_plugin_entryname[i],KEYWORD_FUNFLAG,KEYWORD_FUNNAME);
				MESA_handle_runtime_log(g_plugin_runtime_handle,RLOG_LV_FATAL, PLUGIN_LOGNAME,"%s has [%s] and %s,but no %s\n",filename,g_plugin_entryname[i],KEYWORD_FUNFLAG,KEYWORD_FUNNAME);
				return -1;
			}
		
			fun_pointer = (char(*)())(dlsym(fp_dlopen,buf_funname));
			if(fun_pointer == NULL)
			{
				printf("\033[1;31;40m[Error]%s has [%s],but not load %s from %s sofile\033[0m\n", filename,g_plugin_entryname[i],buf_funname,plugname);
				MESA_handle_runtime_log(g_plugin_runtime_handle,RLOG_LV_FATAL, PLUGIN_LOGNAME,"%s has [%s],but not load %s from %s sofile\n",filename,g_plugin_entryname[i],buf_funname,plugname);
				return -1;
			}
			
			ret=stream_register_fun(i,fun_pointer); 
			if(ret==-1)
			{
				printf("\033[1;31;40m[Error]%s stream_register %s entry error\033[0m\n",filename,g_plugin_entryname[i]);
				MESA_handle_runtime_log(g_plugin_runtime_handle,RLOG_LV_INFO, PLUGIN_LOGNAME,"%s stream_register %s entry error!\n",filename,g_plugin_entryname[i]);
			}
			else
			{
				MESA_handle_runtime_log(g_plugin_runtime_handle,RLOG_LV_INFO, PLUGIN_LOGNAME,"%s stream_register %s entry succ!\n",filename,g_plugin_entryname[i]);
			}
			
		}

	}

	return 0;


/*
	IPv4_CB_FUN_T ip_entry;
	IPv6_CB_FUN_T ip_entry_v6;
	SAPP_PKT_CB_FUN_T ipv4_raw;
	SAPP_PKT_CB_FUN_T ipv6_raw;
	STREAM_CB_FUN_T tcp_entry;
	STREAM_CB_FUN_T tcp_entry_all;
	STREAM_CB_FUN_T udp_entry;
	

	//IPV_ENTRY
	MESA_load_profile_string_nodef(filename,SECTION_FUN_IP,KEYWORD_FUNFLAG,buf_funflag,PLUGIN_MAX_CONFLEN);
	if((buf_funflag[0] != '\0') && ((memcmp(buf_funflag,FUNFLAG_ALL_B,strlen(FUNFLAG_ALL_B)) == 0) || (memcmp(buf_funflag,FUNFLAG_ALL_S,strlen(FUNFLAG_ALL_S)) == 0)))
	{
		MESA_load_profile_string_nodef(filename,SECTION_FUN_IP,KEYWORD_FUNNAME,buf_funname,PLUGIN_MAX_CONFLEN);
		if(buf_funname == NULL)
		{
			runtime_log(RLOG_LV_FATAL, PLUGIN_LOGNAME,"%s has [%s] and %s,but no %s\n",filename,SECTION_FUN_IP,KEYWORD_FUNFLAG,KEYWORD_FUNNAME);
			return -1;
		}
	
		ip_entry = (char(*)(const struct streaminfo *pstream,unsigned char routedir,int thread_seq,  const void *raw_pkt))(dlsym(fp_dlopen,buf_funname));
		if(ip_entry == NULL)
		{
			runtime_log(RLOG_LV_FATAL, PLUGIN_LOGNAME,"%s has [%s],but not load %s from %s sofile\n",filename,SECTION_FUN_IP,buf_funname,plugname);
			return -1;
		}
		
		ret=stream_register_ip(ip_entry);
		if(ret==-1)
		{
			runtime_log(RLOG_LV_INFO, PLUGIN_LOGNAME,"%s stream_register_ip %s entry err!\n",filename,SECTION_FUN_IP);
		}
		else
		{
			runtime_log(RLOG_LV_INFO, PLUGIN_LOGNAME,"%s load %s entry succ!\n",filename,SECTION_FUN_IP);
		}
		
	}

	//IPV6_ENTRY
	memset(buf_funflag,0,PLUGIN_MAX_CONFLEN);
	memset(buf_funname,0,PLUGIN_MAX_CONFLEN);
	
	MESA_load_profile_string_nodef(filename,SECTION_FUN_IPV6,KEYWORD_FUNFLAG,buf_funflag,PLUGIN_MAX_CONFLEN);
	if((buf_funflag[0] != '\0') && ((memcmp(buf_funflag,FUNFLAG_ALL_B,strlen(FUNFLAG_ALL_B)) == 0) || (memcmp(buf_funflag,FUNFLAG_ALL_S,strlen(FUNFLAG_ALL_S)) == 0)))
	{
		MESA_load_profile_string_nodef(filename,SECTION_FUN_IPV6,KEYWORD_FUNNAME,buf_funname,PLUGIN_MAX_CONFLEN);
		if(buf_funname == NULL)
		{
			runtime_log(RLOG_LV_FATAL, PLUGIN_LOGNAME,"%s has [%s] and %s,but no %s\n",filename,SECTION_FUN_IPV6,KEYWORD_FUNFLAG,KEYWORD_FUNNAME);
			return -1;
		}
	
		ip_entry_v6= (char(*)(const struct streaminfo *pstream,unsigned char routedir,int thread_seq,  const void *raw_pkt))(dlsym(fp_dlopen,buf_funname));
		if(ip_entry_v6 == NULL)
		{
			runtime_log(RLOG_LV_FATAL, PLUGIN_LOGNAME,"%s has [%s],but not load %s from %s sofile\n",filename,SECTION_FUN_IPV6,buf_funname,plugname);
			return -1;
		}
		
		ret=stream_register_ipv6(ip_entry_v6);
		if(ret==-1)
		{
			runtime_log(RLOG_LV_INFO, PLUGIN_LOGNAME,"%s stream_register_ipv6 %s entry err!\n",filename,SECTION_FUN_IPV6);
		}
		else
		{
			runtime_log(RLOG_LV_INFO, PLUGIN_LOGNAME,"%s load %s entry succ!\n",filename,SECTION_FUN_IPV6);
		}
	}

	//IPV4_RAW_ENTRY
	MESA_load_profile_string_nodef(filename,SECTION_FUN_IPV4_RAW,KEYWORD_FUNFLAG,buf_funflag,PLUGIN_MAX_CONFLEN);
	if((buf_funflag[0] != '\0') && ((memcmp(buf_funflag,FUNFLAG_ALL_B,strlen(FUNFLAG_ALL_B)) == 0) || (memcmp(buf_funflag,FUNFLAG_ALL_S,strlen(FUNFLAG_ALL_S)) == 0)))
	{
		MESA_load_profile_string_nodef(filename,SECTION_FUN_IPV4_RAW,KEYWORD_FUNNAME,buf_funname,PLUGIN_MAX_CONFLEN);
		if(buf_funname == NULL)
		{
			runtime_log(RLOG_LV_FATAL, PLUGIN_LOGNAME,"%s has [%s] and %s,but no %s\n",filename,SECTION_FUN_IPV4_RAW,KEYWORD_FUNFLAG,KEYWORD_FUNNAME);
			return -1;
		}
	
		ipv4_raw = (SAPP_PKT_CB_FUN_T)(dlsym(fp_dlopen,buf_funname));
		if(ipv4_raw == NULL)
		{
			runtime_log(RLOG_LV_FATAL, PLUGIN_LOGNAME,"%s has [%s],but not load %s from %s sofile\n",filename,SECTION_FUN_IPV4_RAW,buf_funname,plugname);
			return -1;
		}
		
		ret=stream_register_ip_raw(ipv4_raw);
		if(ret==-1)
		{
			runtime_log(RLOG_LV_INFO, PLUGIN_LOGNAME,"%s stream_register_ip_raw %s entry err!\n",filename,SECTION_FUN_IPV4_RAW);
		}
		else
		{
			runtime_log(RLOG_LV_INFO, PLUGIN_LOGNAME,"%s load %s entry succ!\n",filename,SECTION_FUN_IPV4_RAW);
		}

		
		
	}

	//IPV6_RAW_ENTRY
	memset(buf_funflag,0,PLUGIN_MAX_CONFLEN);
	memset(buf_funname,0,PLUGIN_MAX_CONFLEN);
	
	MESA_load_profile_string_nodef(filename,SECTION_FUN_IPV6_RAW,KEYWORD_FUNFLAG,buf_funflag,PLUGIN_MAX_CONFLEN);
	if((buf_funflag[0] != '\0') && ((memcmp(buf_funflag,FUNFLAG_ALL_B,strlen(FUNFLAG_ALL_B)) == 0) || (memcmp(buf_funflag,FUNFLAG_ALL_S,strlen(FUNFLAG_ALL_S)) == 0)))
	{
		MESA_load_profile_string_nodef(filename,SECTION_FUN_IPV6_RAW,KEYWORD_FUNNAME,buf_funname,PLUGIN_MAX_CONFLEN);
		if(buf_funname == NULL)
		{
			runtime_log(RLOG_LV_FATAL, PLUGIN_LOGNAME,"%s has [%s] and %s,but no %s\n",filename,SECTION_FUN_IPV6_RAW,KEYWORD_FUNFLAG,KEYWORD_FUNNAME);
			return -1;
		}
	
		ipv6_raw= (SAPP_PKT_CB_FUN_T)(dlsym(fp_dlopen,buf_funname));
		if(ipv6_raw == NULL)
		{
			runtime_log(RLOG_LV_FATAL, PLUGIN_LOGNAME,"%s has [%s],but not load %s from %s sofile\n",filename,SECTION_FUN_IPV6_RAW,buf_funname,plugname);
			return -1;
		}
		
		ret=stream_register_ipv6_raw(ipv6_raw);
		if(ret==-1)
		{
			runtime_log(RLOG_LV_INFO, PLUGIN_LOGNAME,"%s stream_register_ipv6_raw %s entry err!\n",filename,SECTION_FUN_IPV6_RAW);
		}
		else
		{
			runtime_log(RLOG_LV_INFO, PLUGIN_LOGNAME,"%s load %s entry succ!\n",filename,SECTION_FUN_IPV6_RAW);
		}

		
		
	}


	//TCP_ENTRY
	memset(buf_funflag,0,PLUGIN_MAX_CONFLEN);
	memset(buf_funname,0,PLUGIN_MAX_CONFLEN);
	
	MESA_load_profile_string_nodef(filename,SECTION_FUN_TCP,KEYWORD_FUNFLAG,buf_funflag,PLUGIN_MAX_CONFLEN);
	if((buf_funflag[0] != '\0') && ((memcmp(buf_funflag,FUNFLAG_ALL_B,strlen(FUNFLAG_ALL_B)) == 0) || (memcmp(buf_funflag,FUNFLAG_ALL_S,strlen(FUNFLAG_ALL_S)) == 0)))
	{
		MESA_load_profile_string_nodef(filename,SECTION_FUN_TCP,KEYWORD_FUNNAME,buf_funname,PLUGIN_MAX_CONFLEN);
		if(buf_funname == NULL)
		{
			runtime_log(RLOG_LV_FATAL, PLUGIN_LOGNAME,"%s has [%s] and %s,but no %s\n",filename,SECTION_FUN_TCP,KEYWORD_FUNFLAG,KEYWORD_FUNNAME);
			return -1;
		}
	
		tcp_entry = (char(*)(const struct streaminfo *pstream,void **pme, int thread_seq,const void *raw_pkt))(dlsym(fp_dlopen,buf_funname));
		if(tcp_entry == NULL)
		{
			runtime_log(RLOG_LV_FATAL, PLUGIN_LOGNAME,"%s has [%s],but not load %s from %s sofile\n",filename,SECTION_FUN_TCP,buf_funname,plugname);
			return -1;
		}
		
		ret=stream_register_tcp(tcp_entry);
		if(ret==-1)
		{
			runtime_log(RLOG_LV_INFO, PLUGIN_LOGNAME,"%s stream_register_tcp %s entry err!\n",filename,SECTION_FUN_TCP);
		}
		else
		{
			runtime_log(RLOG_LV_INFO, PLUGIN_LOGNAME,"%s load %s entry succ!\n",filename,SECTION_FUN_TCP);
		}

		
		
		
	}

	//TCP_ENTRY_ALL
	memset(buf_funflag,0,PLUGIN_MAX_CONFLEN);
	memset(buf_funname,0,PLUGIN_MAX_CONFLEN);
	
	MESA_load_profile_string_nodef(filename,SECTION_FUN_TCP_ALL,KEYWORD_FUNFLAG,buf_funflag,PLUGIN_MAX_CONFLEN);
	if((buf_funflag[0] != '\0') && ((memcmp(buf_funflag,FUNFLAG_ALL_B,strlen(FUNFLAG_ALL_B)) == 0) || (memcmp(buf_funflag,FUNFLAG_ALL_S,strlen(FUNFLAG_ALL_S)) == 0)))
	{
		MESA_load_profile_string_nodef(filename,SECTION_FUN_TCP_ALL,KEYWORD_FUNNAME,buf_funname,PLUGIN_MAX_CONFLEN);
		if(buf_funname == NULL)
		{
			runtime_log(RLOG_LV_FATAL, PLUGIN_LOGNAME,"%s has [%s] and %s,but no %s\n",filename,SECTION_FUN_TCP_ALL,KEYWORD_FUNFLAG,KEYWORD_FUNNAME);
			return -1;
		}
	
		tcp_entry_all= (char(*)(const struct streaminfo *pstream,void **pme, int thread_seq,const void *raw_pkt))(dlsym(fp_dlopen,buf_funname));
		if(tcp_entry_all == NULL)
		{
			runtime_log(RLOG_LV_FATAL, PLUGIN_LOGNAME,"%s has [%s],but not load %s from %s sofile\n",filename,SECTION_FUN_TCP_ALL,buf_funname,plugname);
			return -1;
		}
		
		ret=stream_register_tcp_allpkt(tcp_entry_all);
		if(ret==-1)
		{
			runtime_log(RLOG_LV_INFO, PLUGIN_LOGNAME,"%s stream_register_tcp_allpkt %s entry err!\n",filename,SECTION_FUN_TCP_ALL);
		}
		else
		{
			runtime_log(RLOG_LV_INFO, PLUGIN_LOGNAME,"%s load %s entry succ!\n",filename,SECTION_FUN_TCP_ALL);
		}


		
	}

	//UDP_ENTRY
	memset(buf_funflag,0,PLUGIN_MAX_CONFLEN);
	memset(buf_funname,0,PLUGIN_MAX_CONFLEN);
	
	MESA_load_profile_string_nodef(filename,SECTION_FUN_UDP,KEYWORD_FUNFLAG,buf_funflag,PLUGIN_MAX_CONFLEN);
	if((buf_funflag[0] != '\0') && ((memcmp(buf_funflag,FUNFLAG_ALL_B,strlen(FUNFLAG_ALL_B)) == 0) || (memcmp(buf_funflag,FUNFLAG_ALL_S,strlen(FUNFLAG_ALL_S)) == 0)))
	{
		MESA_load_profile_string_nodef(filename,SECTION_FUN_UDP,KEYWORD_FUNNAME,buf_funname,PLUGIN_MAX_CONFLEN);
		if(buf_funname == NULL)
		{
			runtime_log(RLOG_LV_FATAL, PLUGIN_LOGNAME,"%s has [%s] and %s,but no %s\n",filename,SECTION_FUN_UDP,KEYWORD_FUNFLAG,KEYWORD_FUNNAME);
			return -1;
		}
	
	
		udp_entry = (char(*)(const struct streaminfo *pstream,void **pme, int thread_seq,const void *raw_pkt))(dlsym(fp_dlopen,buf_funname));
		if(udp_entry == NULL)
		{
			runtime_log(RLOG_LV_FATAL, PLUGIN_LOGNAME,"%s has [%s],but not load %s from %s sofile\n",filename,SECTION_FUN_UDP,buf_funname,plugname);
			return -1;
		}
		
		ret=stream_register_udp(udp_entry);
		if(ret==-1)
		{
			runtime_log(RLOG_LV_INFO, PLUGIN_LOGNAME,"%s stream_register_tcp_allpkt %s entry err!\n",filename,SECTION_FUN_UDP);
		}
		else
		{
			runtime_log(RLOG_LV_INFO, PLUGIN_LOGNAME,"%s load %s entry succ!\n",filename,SECTION_FUN_UDP);
		}

		

	}
*/
	
	
}

/****************************************************************************
函数名:process_confelem_appentry()
功能：加载业务插件的解析层入口函数
		1、轮询所有entrylist.conf中函数入口是否挂载
		2、检查该解析层插件是否存在；
		3、自动转换入口函数名
		4、调用解析层插件的FLAG_CHANG函数转换flag值
		5、挂载到对应解析层函数链上；
		 
输出：0:sucess
		   -1:error
备注:
	1、因为采用轮询entrylist.conf中函数入口是否挂载，所有
		程序只检测插件配置文件中是否拥有正确的挂载接口；
		但是配置文件中如果挂载接口错误，无法检查；
*****************************************************************************/
int process_confelem_appentry(char* filename,stBusinessPlugInfo* pluginfo_bus)
{
	int i,rec;
	long long flag;
	void* file_point = pluginfo_bus->filepoint;
	char* entryname;
	char buf_funname[PLUGIN_MAX_CONFLEN];
	char buf_funflag[PLUGIN_MAX_CONFLEN];
	stProtocolPlugInfo* pluginfo_pro;

	AppEntry appentry;

	for(i=0;i<g_entryname_info->num;i++)
	{
		memset(buf_funname,0,PLUGIN_MAX_CONFLEN);
		memset(buf_funflag,0,PLUGIN_MAX_CONFLEN);
	
		entryname = g_entryname_info->entryname[i].name;

		MESA_load_profile_string_nodef(filename,entryname,KEYWORD_FUNFLAG,buf_funflag,PLUGIN_MAX_CONFLEN);
		if(buf_funflag[0] != '\0')  
		{
			pluginfo_pro = get_propluginfo_name(entryname);
			if(pluginfo_pro == NULL)
			{
				printf("\033[1;31;40m[Error]%s has %s entry,but ther is no  protocol plug %s\033[0m\n", filename,entryname,entryname);
				MESA_handle_runtime_log(g_plugin_runtime_handle,RLOG_LV_FATAL, PLUGIN_LOGNAME,"%s has %s entry,but ther is no  protocol plug %s\n",filename,entryname,entryname);
				return -1;
			}

			flag = pluginfo_pro->fun_flagchange(buf_funflag);
			if(flag < 0)
			{
				MESA_handle_runtime_log(g_plugin_runtime_handle,RLOG_LV_FATAL, PLUGIN_LOGNAME,"%s's %s in [%s] error!\n",filename,KEYWORD_FUNFLAG,entryname);
				return -1;
			}

			MESA_load_profile_string_nodef(filename,entryname,KEYWORD_FUNNAME,buf_funname,PLUGIN_MAX_CONFLEN);
			if(buf_funname[0] =='\0')
			{
				printf("\033[1;31;40m[Error]%s has [%s] and %s,but no %s\033[0m\n", filename,entryname,KEYWORD_FUNFLAG,KEYWORD_FUNNAME);			
				MESA_handle_runtime_log(g_plugin_runtime_handle,RLOG_LV_FATAL, PLUGIN_LOGNAME,"%s has [%s] and %s,but no %s\n",filename,entryname,KEYWORD_FUNFLAG,KEYWORD_FUNNAME);
				return -1;
			}
		
			appentry = (char(*)(stSessionInfo* session_info,  void **pme, int thread_seq,struct streaminfo *a_stream,const void *a_packet))(dlsym(file_point,buf_funname));
			if(appentry == NULL)
			{
				printf("\033[1;31;40m[Error]%s has %s in [%s],not load from %s sofile\033[0m\n", filename,buf_funname,entryname,pluginfo_bus->plugname);
				MESA_handle_runtime_log(g_plugin_runtime_handle,RLOG_LV_FATAL, PLUGIN_LOGNAME,"%s has %s in [%s],not load from %s sofile\n",filename,buf_funname,entryname,pluginfo_bus->plugname);
				return -1;
			}
			
			rec = stream_register_app(&(pluginfo_pro->fun_list),pluginfo_bus->plugid,appentry,flag);
			if(rec < 0)
			{
				printf("\033[1;31;40m[Error]%s's %s stream_register_app() error\033[0m\n", pluginfo_bus->plugname,buf_funname);
				MESA_handle_runtime_log(g_plugin_runtime_handle,RLOG_LV_FATAL, PLUGIN_LOGNAME,"%s's %s stream_register_app() error!\n",pluginfo_bus->plugname,buf_funname);
				continue;
			}

			MESA_handle_runtime_log(g_plugin_runtime_handle,RLOG_LV_INFO, PLUGIN_LOGNAME,"%s load %s entry succ!\n",filename,entryname);

		}

	}

	return 0;
}



/****************************************************************************
函数名:process_conflist()
功能：处理各类插件配置文件列表内容
输入：
输出：0:sucess
		   -1:error
*****************************************************************************/
int process_conflist(char* filename,int plug_type)
{
	int rec;
	int len;
	char buf_confname[PLUGIN_FILENAME_MAXLEN] = {0};

	FILE* fp = fopen(filename,"r");
	if(fp == NULL)
	{
		MESA_handle_runtime_log(g_plugin_runtime_handle,RLOG_LV_FATAL, PLUGIN_LOGNAME,"process_conflist() fopen %s error!\n",filename);
		return -1;	
	}

	while(feof(fp) == 0)
	{
	
		if((fgets(buf_confname,PLUGIN_FILENAME_MAXLEN,fp)) == NULL)
		{
			//20160217 add fclose(fp) by liuyang
			fclose(fp);
			fp=NULL;
			return 0;
		}

		if(buf_confname[0]=='#')
		{
			continue;
		}

		len = strlen(buf_confname);
		buf_confname[len-1] = '\0';

		if(plug_type == PLUGTYPE_PROTOCOL)
		{
			rec = process_confelem_protocol(buf_confname);
			
		}
		else if(plug_type == PLUGTYPE_BUSENISS)
		{
			rec = process_confelem_business(buf_confname);
		}
		else
		{
			rec = process_confelem_platform(buf_confname);
		}

	}
	//20160217 add fclose(fp) by liuyang
	fclose(fp);
	fp=NULL;
	//add end

	return 0;
	
}


char plugin_process_pending(stProtocolFunInfo* funlist_pro,stSessionInfo* session_info,void **pme, int thread_seq,struct streaminfo *a_stream,const void *a_packet)
{
	char ret = PROT_STATE_DROPME;
	char appstate;
	long long prot_flag=session_info->prot_flag;
	stSessionFunInfo* funlist_session=NULL;
	stSessionFunInfo* funelem_session=NULL;
	stSessionFunInfo* pre=NULL;
	stProtocolFunInfo* funelem_pro = funlist_pro;
	//long long begin_cpu_cycle, end_cpu_cycle;

	*pme = NULL;

	while(funelem_pro)
	{
		if(funelem_session == NULL)
		{
			funelem_session = (stSessionFunInfo*)malloc(sizeof(stSessionFunInfo));
		}
	
		funelem_session->next=NULL;
		funelem_session->appstate = PROT_STATE_GIVEME;
		funelem_session->pme =NULL;
		funelem_session->protflag = funelem_pro->protocol_flag;
		funelem_session->pre_kill_flag = 0;
		funelem_session->appentry = funelem_pro->appentry;
//modify liuy 20150316 for init
		funelem_session->called_flag = 0;
//modify end

		if(funelem_session->protflag&prot_flag)
		{
			/* 2016-05-30 lijia add, 有关心的数据必须设置SESSION_STATE_DATA
				但此处还不能改, 因为很多插件用如下语句判断状态:

				if(session_state == SESSION_STATE_PENDING)
				{

				}
				switch(session_state)
				
				如果加上session_info->session_state |= SESSION_STATE_DATA;
				很多流就都不处理了.
			*/	
			//session_info->session_state |= SESSION_STATE_DATA; 
			funelem_session->appstate = funelem_session->appentry(session_info,&(funelem_session->pme),thread_seq,a_stream,a_packet);
			funelem_session->called_flag = 1;
		}

		appstate = funelem_session->appstate;

		if(!(appstate&PROT_STATE_DROPME))
		{
			
			if(funlist_session==NULL)
			{
				funlist_session=funelem_session;
			
			}                                                                                                                                                                                                 
			else
			{
				pre->next=funelem_session;
			}
			pre=funelem_session;
			funelem_session=NULL;

			ret = PROT_STATE_GIVEME;
		}

		if(appstate&PROT_STATE_DROPPKT)	
		{
			ret |= PROT_STATE_DROPPKT;		
			break;
		}

		funelem_pro = funelem_pro->next;

		
	}

	if(funelem_session != NULL)
	{
		free(funelem_session);
		funelem_session=NULL;
	}

	if(funlist_session != NULL)
	{
		*pme = funlist_session;
		return ret;
	}

	return ret;

	
	
}

char plugin_porcess_data(stSessionInfo* session_info,void **pme, int thread_seq,struct streaminfo *a_stream,const void *a_packet)
{
	char ret = PROT_STATE_GIVEME;
	long long prot_flag=session_info->prot_flag;
	stSessionFunInfo* funlist=(stSessionFunInfo*)(*pme);
	stSessionFunInfo* funelem=funlist;
	stSessionFunInfo* pre=NULL;
	stSessionFunInfo* next=NULL;
	stSessionFunInfo* killelem=NULL;
	//stSessionInfo session_info_tmp;
	//long long begin_cpu_cycle, end_cpu_cycle;
	char tmp_session_state;
	
	//memcpy(&session_info_tmp,session_info,sizeof(stSessionInfo));

	while(funelem)
	{
		if(!((funelem->protflag)&prot_flag))
		{
			pre = funelem;
			funelem=funelem->next;
			continue;
		}

		if(funelem->pre_kill_flag)
		{
			break;
		}
		
//modify liuy 20140616 for pending has no flag;
		if(funelem->called_flag != 1)
		{
			tmp_session_state = session_info->session_state;
			session_info->session_state |= SESSION_STATE_PENDING;
			funelem->called_flag =1;
			funelem->appstate = funelem->appentry(session_info,&(funelem->pme),thread_seq,a_stream,a_packet);
			session_info->session_state = tmp_session_state;
		}else{
			funelem->appstate = funelem->appentry(session_info,&(funelem->pme),thread_seq,a_stream,a_packet);
		}

		if(funelem->appstate&PROT_STATE_DROPPKT)
		{
			ret |= PROT_STATE_DROPPKT;
			
			if(funelem->appstate&PROT_STATE_DROPME)
			{
				killelem = funelem;
			}
			else
			{
				killelem = funelem->next;
			}

			while(killelem)
			{
				killelem->pre_kill_flag = 1;
				killelem = killelem->next;

			}
			
		}
		
		if(funelem->appstate&PROT_STATE_DROPME)
		{
			if(pre==NULL)
			{
				funlist=funelem->next;
				*pme= funlist;
			}	
			else
			{
				pre->next=funelem->next;
			}
			next=funelem->next;
			
			free(funelem);
			funelem=next;		
		}
		else
		{
			pre=funelem;
			funelem=funelem->next;
		}

		*pme=funlist;
			
	}
	

	if(funlist==NULL)
	{
		if(ret&PROT_STATE_DROPPKT)
		{
			ret = PROT_STATE_DROPME|PROT_STATE_DROPPKT;
		}
		else
		{
			ret = PROT_STATE_DROPME;
		}
	
	}

	return ret;

}

#if 0
char plugin_porcess_close(int callbake_flag,stSessionInfo* session_info,void **pme, int thread_seq,struct streaminfo *a_stream,const void *a_packet)
{
	char ret = PROT_STATE_DROPME;
	long long prot_flag=session_info->prot_flag;
	stSessionFunInfo* funlist=(stSessionFunInfo*)(*pme);
	stSessionFunInfo* funelem=funlist;
	stSessionFunInfo* next=NULL;
	stSessionInfo session_info_tmp;
	//long long begin_cpu_cycle, end_cpu_cycle;
	//
	
	while(funelem)
	{
		memcpy(&session_info_tmp,session_info,sizeof(stSessionInfo));
		
		if(callbake_flag)
		{
//modify liuy 20140616 for pending has no flag;
			if(funelem->called_flag != 1)
			{
				session_info_tmp.session_state |= SESSION_STATE_PENDING;
			}

			if(!((funelem->protflag)&prot_flag))
			{
				session_info_tmp.buf = NULL;
				session_info_tmp.buflen = 0;
			}

//modify by liuy 20150316
			if((funelem->called_flag == 1) || ((funelem->protflag)&prot_flag))
			{
//begin_cpu_cycle = rdtsc();				
				funelem->appstate = funelem->appentry(&session_info_tmp,&(funelem->pme),thread_seq,a_stream,a_packet);
//end_cpu_cycle = rdtsc();				
			}
//modify end
		
			if(funelem->appstate&PROT_STATE_DROPPKT)
			{
				ret |= PROT_STATE_DROPPKT;
			}
		}
		else
		{
			if(funelem->pre_kill_flag)
			{
	//modify liuy 20140616 for pending has no flag;
				if(funelem->called_flag != 1)
				{
					session_info_tmp.session_state |= SESSION_STATE_PENDING;
				}

				if(!((funelem->protflag)&prot_flag))
				{
					session_info_tmp.buf = NULL;
					session_info_tmp.buflen = 0;
				}
//begin_cpu_cycle = rdtsc();
				funelem->appstate = funelem->appentry(&session_info_tmp,&(funelem->pme),thread_seq,a_stream,a_packet);
//end_cpu_cycle = rdtsc();
	
/*
				else
				{
					funelem->appstate = funelem->appentry(session_info,&(funelem->pme),thread_seq,a_stream,a_packet);
				}
*/
	//modify end
//				funelem->appstate = funelem->appentry(session_info,&(funelem->pme),thread_seq,a_stream,a_packet);
				if(funelem->appstate&PROT_STATE_DROPPKT)
				{
					ret |= PROT_STATE_DROPPKT;
				}
			}
		}
		
		next=funelem->next;
		free(funelem);
		
		funelem=next;	
	}

	*pme=NULL;

	return ret;
	
}
#else
char plugin_porcess_close(int callbake_flag,stSessionInfo* session_info,void **pme, int thread_seq,struct streaminfo *a_stream,const void *a_packet)
{
	char ret = PROT_STATE_DROPME;
	long long prot_flag=session_info->prot_flag;
	stSessionFunInfo* funlist=(stSessionFunInfo*)(*pme);
	stSessionFunInfo* funelem=funlist;
	stSessionFunInfo* next=NULL;
	stSessionInfo session_info_tmp;
	
	while(funelem)
	{
		memcpy(&session_info_tmp,session_info,sizeof(stSessionInfo));
		
//modify liuy 20140616 for pending has no flag;
		if(funelem->called_flag != 1)
		{
			session_info_tmp.session_state |= SESSION_STATE_PENDING;
		}

		if(!((funelem->protflag)&prot_flag))
		{
			session_info_tmp.buf = NULL;
			session_info_tmp.buflen = 0;
			session_info_tmp.prot_flag = 0;
		}
			
		funelem->appstate = funelem->appentry(&session_info_tmp,&(funelem->pme),thread_seq,a_stream,a_packet);
	
		if(funelem->appstate&PROT_STATE_DROPPKT)
		{
			ret |= PROT_STATE_DROPPKT;
		}

		next=funelem->next;
		free(funelem);
		
		funelem=next;	
	}

	*pme=NULL;

	return ret;
	
}
#endif

char PROT_PROCESS(stSessionInfo* session_info, void **pme, int thread_seq,struct streaminfo *a_stream,const void *a_packet)
{
	char ret1=PROT_STATE_DROPME;
	char ret2=PROT_STATE_GIVEME;
	unsigned short plugid = session_info->plugid;
	int session_state = session_info->session_state;
	stProtocolPlugInfo* pluginfo;
	stProtocolFunInfo* funlist_pro;

#if 0 /* 2016-05-30 lijia modify */
	if(pme == NULL)
	{
		MESA_handle_runtime_log(g_plugin_runtime_handle,RLOG_LV_FATAL, PLUGIN_LOGNAME,"PROT_PROCESS(),plugid:%d input pme is NULL,error!\n",plugid);
		return ret1;
	}
#else
	assert(pme);
#endif

	pluginfo = get_propluginfo_plugid(plugid);
#if 0	/* 2016-05-30 lijia modify */
	if(pluginfo == NULL)
	{
		MESA_handle_runtime_log(g_plugin_runtime_handle,RLOG_LV_FATAL, PLUGIN_LOGNAME,"PROT_PROCESS():there is no plugid %d in protocol pluginfo!\n",plugid);
		return ret1;
	}
#else
	assert(pluginfo);
#endif

	funlist_pro = pluginfo->fun_list;
	if(funlist_pro == NULL)
	{
		return ret1;
	}

	if(session_state&SESSION_STATE_PENDING)
	{
		ret1=plugin_process_pending(funlist_pro,session_info,pme,thread_seq,a_stream,a_packet);

		if(session_state&SESSION_STATE_CLOSE)
		{
			ret2 = plugin_porcess_close(0,session_info,pme,thread_seq,a_stream,a_packet);
		}
		else
		{
			ret2 =ret1;
		}

		if(ret1&PROT_STATE_DROPPKT)
		{
			return ret2|PROT_STATE_DROPPKT;
		}
		else
		{
			return ret2;
		}

		
	}

	if(session_state&SESSION_STATE_DATA)
	{
		if(*pme==NULL)
		{
			return ret1;
		}
		ret1 = plugin_porcess_data(session_info,pme,thread_seq,a_stream,a_packet);

		if(session_state&SESSION_STATE_CLOSE)
		{
			ret2 = plugin_porcess_close(0,session_info,pme,thread_seq,a_stream,a_packet);
		}
		else
		{
			ret2=ret1;
		}

		if(ret1&PROT_STATE_DROPPKT)
		{
			return ret2|PROT_STATE_DROPPKT;
		}
		else
		{
			return ret2;
		}
	}

	if(session_state&SESSION_STATE_CLOSE)
	{
		ret1 = plugin_porcess_close(1,session_info,pme,thread_seq,a_stream,a_packet);
	}

	return ret1;

}

