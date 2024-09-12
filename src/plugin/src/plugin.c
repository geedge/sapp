/*********************************************************************************************
�ļ���:plugin.c
����:  
����: LiuY
��ǰ�汾:2.0
�������:20140411
�޸�˵��:ͨ�������ļ����ز��
**********************************************************************************************
time:20140413
content:1������ҵ�������updateָ��
**********************************************************************************************
ʱ��:2014-11-9
����:
1-��������������ܳ�Ϊ����ģ�飬���Ա�sappƽ̨���أ�
2-ҵ��������ֵ�����۲����ں�����ʲô������ֵ������ͬ���ĸ��ꣻ
3-������close״̬����ҵ�����ʱ�������ǰ���ݲ���ҵ������Ȥ������buf��buflenΪ�գ�
4-������close״̬����ҵ�����ʱ�������ǰ���ݲ���ҵ������Ȥ������buf��buflenΪ�գ�
**********************************************************************************************
ʱ��:2014-11-23
����:
1-Ϊ���������ԣ�ҵ������ķ���ֵ�����ԭ����PROTϵ�У�
2-ɾ��֮ǰ��PROT_KILLME,����PRTO_DROPPKT��Ϊ������ǰ�����壻
**********************************************************************************************
ʱ��:2014-11-24
����:plugin_call_flagstate������ȥ��flag��ֵΪ1��
**********************************************************************************************
ʱ��:2014-12-22
����:add ipv4_raw_entry and ipv6_raw_entry
**********************************************************************************************
ʱ��:2014-12-30
����:add TCP_RAW,TCPALL_RAW,UDP_RAW
**********************************************************************************************
ʱ��:20150129
����:
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
int stream_register_fun(int funtype,char (*x)(void), int);
**********************************************************************************************
ʱ��:2015-02-28
����:plugin.c:150 add total_flag=0;�������û���κ�ҵ��������������յ���
	flagֵ�����ֵ
**********************************************************************************************
ʱ��:201503-16-2
����:
	1-plugin.c:1259 add funelem->called_flag =1;
		�������pending״̬û�е���ҵ�������ÿ��data״̬������pending�ı�ʾ
	2-pending ����called_flag�ĳ�ʼ��
	3-close���ӶԵ��õ��ж�:����ò�����������ù����ߵ�ǰ�ֶ��Ǹò����
	    ��Ҫ���ֶβ���close״̬���ã����򲻵���
**********************************************************************************************
ʱ��:201503-18 yangwei
����:
	1-����reset_cwd()�л���ǰ·���ĺ�������Ϊ����������г�ʼ��ʱ�л���ǰ·��
	   Ϊ�������·�����º�������ִ�д���������������ÿ�������ʼ������
	   �󶼽���ǰ·���л�Ϊ���������ڵ�·����
**********************************************************************************************
ʱ��:201503-25 
����:
	1-����ͷ�ļ���ʽ����makefile��ָ��·����
**********************************************************************************************

ʱ��:2016-03-14 LiJia 
����:
	1-�޸�process_conf_entryname()����ɾ��ĩβ"\r\n"��BUG.
**********************************************************************************************

ʱ��:2016-05-30 LiJia 
����:
	1-�޸�plugin_porcess_data()�����޸���session_state��û�лָ�, ��ɺ������session_state����BUG;
	2-�޸�plugin_porcess_close()�����߼�, ���ܻ����ҵ�����ڴ�й©.

**********************************************************************************************

ʱ��:2016-05-30 LiJia 
����:
	1-����IP_FRAG���.
**********************************************************************************************

*/

#include <libgen.h>

#include "sapp_api.h"
#include "sapp_private_api.h"
#include "plugin_proc.h"
#include "plugin_platform.h"
#include "plugin_protocol.h"
#include "plugin_business.h"
#include "plugin.h"
#include "plugin_serial.h"

#include "sapp_declaration.h"

extern stProtocolPlugInfo* g_protocol_plug_info;
extern stBusinessPlugInfo* g_business_plug_info;
extern stProtocolPlugInfo **g_protocol_plug_info_array;
extern long long g_timedelay_threshold;

int g_plugin_plugid ;
stEntryNameInfo* g_entryname_info;
//20170525 liuyang add for wy serial
int g_business_plug_type=-1;
stPlugRuntimeInfo plugctrl_runtime_info;
//add end

/*
	Lijia note:
	����˳��Ҫ��enum fun_type_t����˳��һ��.
*/
const char* g_plugin_entryname[PLUGIN_MAX_ENTRYNUM] = 
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


static inline void __plug_record_time_start(struct timespec *start)
{
    clock_gettime(CLOCK_MONOTONIC, start);
}
static inline long __plug_record_time_elapse_us(struct timespec *start)
{
    struct timespec end;
    long elapsed = 0;
    clock_gettime(CLOCK_MONOTONIC, &end);
    elapsed = (end.tv_sec - start->tv_sec)*1000000 + (end.tv_nsec - start->tv_nsec)/1000;
    return elapsed;
}

 /* ɾ����ͷ�Ŀո�,tab, �Լ�ĩβ�Ļ��з�, �ո�, tab�� "\r\n " */
static void plugin_del_blank_rn(char *data, int max_len)
{
	int i;

	while((' ' == *data) || ('\t' == *data)){
		memmove(data, data+1, max_len);
		max_len--;
	}
    
    for(i = 0; i < max_len; i++){
        if(('\r' == data[i]) || ('\n' == data[i]) || ('\t' == data[i]) || (' ' == data[i])){
            data[i] = '\0';
            return;
        }
    }

    return;
}


/****************************************************************************
������:reset_cwd()
���ܣ��л���ǰ·��
���룺
�����
//add by yw 20150318, reset cwd to exe dir
*****************************************************************************/
#if 0 
static int reset_cwd()
{
	char cur_path[1024];
	memset(cur_path, 0, sizeof(cur_path));
	int path_len = readlink("/proc/self/exe", cur_path, sizeof(cur_path));
	int i = 0, ret = 0;
	if(path_len < 0 || path_len > (int)sizeof(cur_path))
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
#endif

static int reset_cwd() 
{
    char path[PATH_MAX];
    ssize_t path_len = readlink("/proc/self/exe", path, sizeof(path) - 1);
    if (path_len == -1) {
        perror("readlink");
        return -1;
    }
    path[path_len] = '\0';

    // ��ȡ��ִ���ļ����ڵ�Ŀ¼
    char *dir = dirname(path);

    if (chdir(dir) == -1) {
        perror("chdir");
        return -1;
    }

    return 0;
}


/****************************************************************************
������:get_propluginfo_name()
���ܣ������������Ƿ��Ѿ�����
���룺����� 
�����NULL:û���ҵ�
*****************************************************************************/
stProtocolPlugInfo* get_propluginfo_name(char* plugname)
{
	stProtocolPlugInfo* pluginfo = g_protocol_plug_info;

	while(pluginfo)
	{
		if(strcmp(pluginfo->plugname,plugname) == 0)
		{
			return pluginfo;
		}

		pluginfo = pluginfo->next;
	}

	return NULL;
	
}


/****************************************************************************
������:get_propluginfo_name()
���ܣ������������Ƿ��Ѿ�����
���룺����� 
�����NULL:û���ҵ�
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
������:stream_register_app()
���ܣ�ע��Ӧ�ò㺯��
���룺
�����0:sucess
		   -1:error
*****************************************************************************/

int stream_register_app(stProtocolFunInfo** fun_list,unsigned short plugid,AppEntry x,long long proflag, int plug_entry_id)
{
	stProtocolFunInfo* funelem_last;
	stProtocolFunInfo* funelem = (stProtocolFunInfo*)malloc(sizeof(stProtocolFunInfo));
	memset(funelem,0,sizeof(stProtocolFunInfo));

	funelem->plugid = plugid;
	funelem->aliveflag = 1;
	funelem->appentry = x;
	funelem->protocol_flag = proflag;
	funelem->entry_id = plug_entry_id;

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
������:plugin_call_flagstate()
���ܣ����ý�����FLAG_STATE������֪ͨ�������Ϲ�������ҵ��
		   �����Ҫ��flagֵȫ����
���룺 
�����
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
������:check_name_fromentrylist()
���ܣ����ҵ��������ڻ��߽����㺯�����Ƿ�
		   ��entrylist.conf�����ļ���
���룺�� 
�����1:����
		   0:û������
		   -1:����
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
������:check_entryname_fromplug()
���ܣ����ҵ�������ں����Ƿ���ȷ��
���룺�� 
�����1:����
		   0:û������
		   -1:����
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
������:check_name_fromentrylist()
���ܣ����ҵ��������ڻ��߽����㺯�����Ƿ�
		   ��entrylist.conf�����ļ���
���룺�� 
�����1:����
		   0:û������
		   -1:����
*****************************************************************************/
int check_plug_conf(char* filename,int plugtype)
{
	int ret;
	char* begin;
	char config_buf[PLUGIN_MAX_CONFLEN];

	FILE* fp = fopen(filename,"r");
	if(fp == NULL)
	{
		MESA_handle_runtime_log(g_plugin_runtime_handle,RLOG_LV_FATAL, PLUGIN_LOGNAME,"check_plug_conf(): fopen() %s error!",filename);
		return -1;
	}

	while(feof(fp)==0)
	{
		memset(config_buf,0,PLUGIN_MAX_CONFLEN);

		//��ȡ�ļ���ÿ������
		if((fgets(config_buf,PLUGIN_MAX_CONFLEN,fp)) == NULL)
		{
			break;
		}

		plugin_del_blank_rn(config_buf, sizeof(config_buf));

		//��һ���ַ�����"[",��������
		if(memcmp(config_buf,KEYWORD_SPECIAL1,strlen(KEYWORD_SPECIAL1)) != 0)
		{
			continue;
		}

		begin = config_buf+1;
		
		//�����[PLUGINFO]����������
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
		
		MESA_handle_runtime_log(g_plugin_runtime_handle,RLOG_LV_FATAL, PLUGIN_LOGNAME,"%s's entry name is unknow:%s",filename,config_buf);
		return -1;
		

	}
	//20160217 liuy add
	fclose(fp);
	fp=NULL;

	return 0;
}


/****************************************************************************
������:plugin_load_entryname()
���ܣ��������к������������ز������
���룺�� 
�����0:sucess
		   -1:error
*****************************************************************************/
int process_conf_entryname()
{
	//char filename[PLUGIN_FILENAME_MAXLEN] = {0};
	char buf_entryname[PLUGIN_MAX_CONFLEN] = {0};
	FILE* fp;

#if 0
	//get entrylist's full name from in plugin.conf
	rec = MESA_load_profile_string_def(PLUGIN_CONFNAME,PLUGIN_CONFMODULE,
									"entrylist_config",filename,PLUGIN_FILENAME_MAXLEN,FILENAME_CONFLIST_DEF);
	if(rec < 0)
	{
		MESA_handle_runtime_log(g_plugin_runtime_handle,RLOG_LV_FATAL, PLUGIN_LOGNAME,"filename_entryname get error!");
		return -1;

	}
#endif

	//process entrylist conf
	fp = fopen(ABBR_PLUG_ENTRY_LIST_CONF_FILE,"r");
	if(fp == NULL)
	{
		//MESA_handle_runtime_log(g_plugin_runtime_handle,RLOG_LV_FATAL, PLUGIN_LOGNAME,"fopen %s error!\n",filename);
		sapp_log(RLOG_LV_FATAL, ~0, ~0, "open entry_list cfg file: '%s' error!", ABBR_PLUG_ENTRY_LIST_CONF_FILE);
		//return -1;
		exit(1);
	}

	g_entryname_info = (stEntryNameInfo*)SAPP_GLOBAL_ALLOC(sizeof(stEntryNameInfo));
	memset(g_entryname_info,0,sizeof(stEntryNameInfo));

	while(feof(fp) == 0)
	{
		if((fgets(buf_entryname,PLUGIN_MAX_CONFLEN,fp)) == NULL)
		{
			fclose(fp);
			fp=NULL;
			return 0;
		}

		//ע��
		if(buf_entryname[0]=='#')
		{
			continue;
		}

#if 0 /* 2016-03-14 lijia modify, �˴�������Ϊĩβ����\r\n, ��������\n */
		///r/n
		len = strlen(buf_entryname);
		buf_entryname[len-2] = '\0';
#else
		plugin_del_blank_rn(buf_entryname, sizeof(buf_entryname));
#endif
		if('\0' == buf_entryname[0]){
			continue;
		}
		
		//ƽ̨���,IP,IPV6,TCP,TCPALL,UDP
		if( ((strcmp(buf_entryname,SECTION_FUN_IP)==0))||
		      (strcmp(buf_entryname,SECTION_FUN_IP_FRAG)==0)||
			(strcmp(buf_entryname,SECTION_FUN_IPV6)==0)||
			(strcmp(buf_entryname,SECTION_FUN_TCP)==0)||
			(strcmp(buf_entryname,SECTION_FUN_TCP_ALL)==0)||
			(strcmp(buf_entryname,SECTION_FUN_UDP)==0) ||
			(strcmp(buf_entryname,SECTION_FUN_PHONY) ==0) ||
			(strcmp(buf_entryname,SECTION_FUN_POLLING) ==0))
		{
			continue;
		}

		g_entryname_info->num ++;
		g_entryname_info->entryname = (stEntryNameElem* )sapp_mem_realloc(SAPP_MEM_FIX_GLOBAL_VAL, MEM_STAT_GLOBAL_THREAD_ID,g_entryname_info->entryname,(g_entryname_info->num)*sizeof(stEntryNameElem));
		memset(&(g_entryname_info->entryname[g_entryname_info->num-1]),0,sizeof(stEntryNameElem));
		memcpy(&(g_entryname_info->entryname[g_entryname_info->num-1]),buf_entryname,strlen(buf_entryname));
	}
//20160217 liuy add
	fclose(fp);
	fp=NULL;

	return 0;
	
}

extern int plugin_load_new_plug(const char *plug_name, const char *plug_path);
extern int plugin_is_necessary(const char *plug_path, int *priority);
/****************************************************************************
������:process_confelem_plugname()
���ܣ�������������ļ��Ĳ�����ֶ�
���룺filename:��������ļ���[IN], ./plug/business/example/example.inf
		  plugtype:������ͣ�����������Ҫ����ļ�����ҵ��㲻��Ҫ
		   plugname:�������ļ���ȡ��������洢���˱�����[OUT]
�����0:sucess
		   -1:error
*****************************************************************************/
int process_confelem_plugname(char* filename,int plugtype,char** plugname)
{
	int rec;
	int len;
	char buf_plugname[PLUGIN_MAX_CONFLEN]={0};
	char* plugname_tmp;
	int priority=0;
	
	rec = MESA_load_profile_string_nodef(filename,SECTION_PLUGINFO,KEYWORD_PLUGNAME,buf_plugname,PLUGIN_MAX_CONFLEN);
	if(rec < 0)
	{
		MESA_handle_runtime_log(g_plugin_runtime_handle,RLOG_LV_FATAL, PLUGIN_LOGNAME,"%s get plugname error",filename);
		goto plug_init_error;
	}

	if(plugtype == PLUGTYPE_PROTOCOL)
	{
		rec = check_name_fromentrylist(buf_plugname);
		if(rec != 1)
		{
			MESA_handle_runtime_log(g_plugin_runtime_handle,RLOG_LV_FATAL, PLUGIN_LOGNAME,"\033[1;31;40m%s's\033[0m plugname is %s,not in the entrylist.conf",filename,buf_plugname);
			goto plug_init_error;
		}
	}

	if(plugin_load_new_plug(buf_plugname, filename) < 0){
		exit(1);
	}

	len = strlen(buf_plugname);
	plugname_tmp = (char*)SAPP_GLOBAL_ALLOC(len+1);
	memcpy(plugname_tmp,buf_plugname,len);
	plugname_tmp[len] = '\0';

	*plugname = plugname_tmp;

	return 0;

plug_init_error:
	if(plugin_is_necessary(filename, &priority)){
		sapp_log(RLOG_LV_FATAL, 1, 1, "%s init error, but this plug is necessary, priority:%d, exit!", filename, priority);
		exit(1);
	}
	return -1;
}


/****************************************************************************
������:process_confelem_sofilename()
���ܣ�������������ļ���so�ļ�·�����ֶ�
		1��ͨ��dlopen���ļ�
		2�����س�ʼ������CHAR_INIT�������ó�ʼ������
		3������ж�غ���CHAR_DESTROY�����Ǳ����
		4������ǽ�������:���ر��λ֪ͨFLAG_STATE�ͱ��λת��FLAG_CHANGE����
���룺filename:��������ļ���[IN]
		  plugtype:������ͣ�����������Ҫ����ļ�����ҵ��㲻��Ҫ
		   plugname:�������ļ���ȡ��������洢���˱�����[OUT]
�����0:sucess
		   -1:error
*****************************************************************************/
int process_confelem_sofilename(char* filename,int plugtype,stProtocolPlugInfo* pluginfo_pro,stBusinessPlugInfo* pluginfo_bus)
{
	int rec;
	char buf_sofilename[PLUGIN_MAX_CONFLEN]={0};
	char buf_funname[PLUGIN_MAX_CONFLEN]= {0};
	char buf_plug_name[PLUGIN_MAX_CONFLEN]= {0};

	void* filepoint = NULL;
	int (*fun_init)() = NULL;
	void  (*fun_destroy)() = NULL;	
	void (*fun_getplugid)(unsigned short plugid) = NULL;
	int priority=0;
	struct timespec start;
	long time_cost_us = 0;
	
	//load FILENAME 
	MESA_load_profile_string_nodef(filename,SECTION_PLUGINFO,KEYWORD_FILENAME,buf_sofilename,PLUGIN_MAX_CONFLEN);
	if(buf_sofilename[0] == '\0')
	{
		MESA_handle_runtime_log(g_plugin_runtime_handle,RLOG_LV_FATAL, PLUGIN_LOGNAME,"%s get %s error",filename,KEYWORD_FILENAME);
		goto plug_init_error;
	}

	if((plugtype == PLUGTYPE_PLATFORM) || (plugtype == PLUGTYPE_PROTOCOL))
	{
		//ƽ̨��ͽ����������ű�����
		#if defined(USE_TCMALLOC) || defined(USE_MIMALLOC) || defined(ASAN_ENABLED)
			filepoint = dlopen(buf_sofilename,RTLD_NOW|RTLD_LAZY|RTLD_GLOBAL);
		#else
			filepoint = dlopen(buf_sofilename,RTLD_NOW|RTLD_LAZY|RTLD_GLOBAL|RTLD_DEEPBIND);
		#endif
	}
	else
	{
		//ҵ��������ű����ȵ����Լ����ű�
		#if defined(USE_TCMALLOC) || defined(USE_MIMALLOC) || defined(ASAN_ENABLED)
			filepoint = dlopen(buf_sofilename,RTLD_NOW|RTLD_LAZY|RTLD_LOCAL);
		#else
			filepoint = dlopen(buf_sofilename,RTLD_NOW|RTLD_LAZY|RTLD_LOCAL|RTLD_DEEPBIND);
		#endif
	}

	if( filepoint == NULL ) 
	{
		MESA_handle_runtime_log(g_plugin_runtime_handle,RLOG_LV_FATAL, PLUGIN_LOGNAME,"dlopen %s in %s error:%s",buf_sofilename,filename,dlerror());
		goto plug_init_error;
	}

	//load FUNAME_INIT
	memset(buf_funname,0,PLUGIN_MAX_CONFLEN);
	MESA_load_profile_string_nodef(filename,SECTION_PLUGINFO,KEYWORD_FUNINIT,buf_funname,PLUGIN_MAX_CONFLEN);
	if(buf_funname[0]=='\0')
	{	
		MESA_handle_runtime_log(g_plugin_runtime_handle,RLOG_LV_FATAL, PLUGIN_LOGNAME,"%s no FUNNAME_INIT!",buf_sofilename);
		goto plug_init_error;
	}

	fun_init = (int (*)())(dlsym(filepoint,buf_funname));
	//add by yw 20150318, reset cwd after init plugin

	reset_cwd();

	if(fun_init == NULL)
	{
		MESA_handle_runtime_log(g_plugin_runtime_handle,RLOG_LV_FATAL, PLUGIN_LOGNAME,"%s no function %s error!",buf_sofilename,buf_funname);
		goto plug_init_error;
	}
	else
	{
		MESA_handle_runtime_log(g_plugin_runtime_handle,RLOG_LV_INFO, PLUGIN_LOGNAME,"%s load %s succ",filename,buf_funname);

	}

	MESA_load_profile_string_def(filename,SECTION_PLUGINFO,KEYWORD_PLUGNAME,buf_plug_name,PLUGIN_MAX_CONFLEN, "");
	if(buf_plug_name[0] == '\0')
	{
		MESA_handle_runtime_log(g_plugin_runtime_handle,RLOG_LV_INFO, PLUGIN_LOGNAME, "%s not found PLUGNAME",filename);
	}
			

	__plug_record_time_start(&start);
	rec = fun_init();
	if(rec < 0)
	{
		MESA_handle_runtime_log(g_plugin_runtime_handle,RLOG_LV_FATAL, PLUGIN_LOGNAME,"\033[1;31;40m%s\033[0m init error,don't load it",buf_sofilename);
		plugin_load_state_update(-1, 0, filename, buf_plug_name);
		goto plug_init_error;
	}

	time_cost_us = __plug_record_time_elapse_us(&start);
	plugin_load_state_update(rec, time_cost_us, filename, buf_plug_name);
	MESA_handle_runtime_log(g_plugin_runtime_handle,RLOG_LV_FATAL, PLUGIN_LOGNAME,"\033[32m%s\033[0m init succ, using [\033[32m%lld\033[0m] us",buf_sofilename,time_cost_us);

	//load FUNNAME_DESTROY
	memset(buf_funname,0,PLUGIN_MAX_CONFLEN);
	MESA_load_profile_string_nodef(filename,SECTION_PLUGINFO,KEYWORD_FUNDESTROY,buf_funname,PLUGIN_MAX_CONFLEN);
	if(buf_funname[0] !='\0')
	{
		fun_destroy = (void(*)())(dlsym(filepoint,buf_funname));
		if(fun_destroy == NULL)
		{
			MESA_handle_runtime_log(g_plugin_runtime_handle,RLOG_LV_FATAL, PLUGIN_LOGNAME,"%s has func:%s,but there is no in %s",filename,buf_funname,buf_sofilename);
		}
		else
		{
			MESA_handle_runtime_log(g_plugin_runtime_handle,RLOG_LV_INFO, PLUGIN_LOGNAME,"%s load %s succ",filename,buf_funname);

		}
	}

	//load update		
	memset(buf_funname,0,PLUGIN_MAX_CONFLEN);
	MESA_load_profile_string_nodef(filename,SECTION_PLUGINFO,KEYWORD_FUNUPDATE,buf_funname,PLUGIN_MAX_CONFLEN);
	if(buf_funname[0] !='\0')
	{
		pluginfo_bus->fun_update = (int (*)(int,char*,int))(dlsym(filepoint,buf_funname));
		if(pluginfo_bus->fun_update == NULL)
		{
			MESA_handle_runtime_log(g_plugin_runtime_handle,RLOG_LV_FATAL, PLUGIN_LOGNAME,"%s has func:%s,but there is no in %s",filename,buf_funname,buf_sofilename);
		}
		else
		{
			MESA_handle_runtime_log(g_plugin_runtime_handle,RLOG_LV_INFO, PLUGIN_LOGNAME,"%s load %s succ",filename,buf_funname);

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
			MESA_handle_runtime_log(g_plugin_runtime_handle,RLOG_LV_FATAL, PLUGIN_LOGNAME,"%s no %s!",buf_sofilename,KEYWORD_FUNGETID);
			goto plug_init_error;
		}

		fun_getplugid = (void(*)(unsigned short))(dlsym(filepoint,buf_funname));
		if(fun_getplugid == NULL)
		{
			MESA_handle_runtime_log(g_plugin_runtime_handle,RLOG_LV_FATAL, PLUGIN_LOGNAME,"%s no %s!",buf_sofilename,buf_funname);
			goto plug_init_error;
		}
		else
		{
			MESA_handle_runtime_log(g_plugin_runtime_handle,RLOG_LV_INFO, PLUGIN_LOGNAME,"%s load %s succ",filename,buf_funname);

		}


		g_plugin_plugid++;
		fun_getplugid(g_plugin_plugid);
		pluginfo_pro->plugid = g_plugin_plugid;

		//dlsym flag_change
		memset(buf_funname,0,PLUGIN_MAX_CONFLEN);
		MESA_load_profile_string_nodef(filename,SECTION_PLUGINFO,KEYWORD_FUNCHANGE,buf_funname,PLUGIN_MAX_CONFLEN);
		if(buf_funname[0]=='\0')
		{
			MESA_handle_runtime_log(g_plugin_runtime_handle,RLOG_LV_FATAL, PLUGIN_LOGNAME,"%s no %s!",buf_sofilename,KEYWORD_FUNCHANGE);
			goto plug_init_error;
		}

		pluginfo_pro->fun_flagchange = (long long (*)(char*))(dlsym(filepoint,buf_funname));
		if(pluginfo_pro->fun_flagchange == NULL)
		{
			MESA_handle_runtime_log(g_plugin_runtime_handle,RLOG_LV_FATAL, PLUGIN_LOGNAME,"%s no function %s error!",buf_sofilename,buf_funname);
			goto plug_init_error;
		}
		else
		{
			MESA_handle_runtime_log(g_plugin_runtime_handle,RLOG_LV_INFO, PLUGIN_LOGNAME,"%s load %s succ",filename,buf_funname);

		}


		//dlsym flag_state
		memset(buf_funname,0,PLUGIN_MAX_CONFLEN);
		MESA_load_profile_string_nodef(filename,SECTION_PLUGINFO,KEYWORD_FUNSTATE,buf_funname,PLUGIN_MAX_CONFLEN);
		if(buf_funname[0]=='\0')
		{
			MESA_handle_runtime_log(g_plugin_runtime_handle,RLOG_LV_FATAL, PLUGIN_LOGNAME,"%s no %s!",buf_sofilename,KEYWORD_FUNSTATE);
			goto plug_init_error;
		}

		pluginfo_pro->fun_flagstate = (void (*)(long long))(dlsym(filepoint,buf_funname));
		if(pluginfo_pro->fun_flagstate == NULL)
		{
			MESA_handle_runtime_log(g_plugin_runtime_handle,RLOG_LV_FATAL, PLUGIN_LOGNAME,"%s no function %s error!",buf_sofilename,buf_funname);
		}
		else
		{
			MESA_handle_runtime_log(g_plugin_runtime_handle,RLOG_LV_INFO, PLUGIN_LOGNAME,"%s load %s succ",filename,buf_funname);
		}

	}
	//business plug
	else
	{
		pluginfo_bus->filepoint = filepoint;
		pluginfo_bus->fun_destroy = fun_destroy;
//add 20170525 liuyang for wy serial,business plugid get from inf file
		MESA_load_profile_short_nodef(filename,SECTION_PLUGINFO,KEYWORD_PLUGID,(short*)&(pluginfo_bus->plugid));
#if 0 /* delete by liuyang 20180417 */		
		MESA_load_profile_int_nodef(filename,SECTION_PLUGINFO,KEYWORD_PLUGTYPE,&g_business_plug_type);
#endif
	}

/*	if(check_plug_conf(filename,plugtype) == -1)
	{
		return -1;
	}
*/
	check_plug_conf(filename,plugtype);

	return 0;

plug_init_error:

	if(plugin_is_necessary(filename, &priority)){
		sapp_log(RLOG_LV_FATAL, 1, 1, "%s init error, but this plug is necessary, priority:%d, exit!", filename, priority);
		exit(1);
	}	
	return -1;
}

extern int plugin_load_new_plug_entry(const char *plug_name, const char *plug_entry_type, void *entry_addr);
extern int stream_register_fun(enum fun_type_t funtype,char (*x)(void), int plug_entry_id);
/****************************************************************************
������:process_confelem_platentry()
���ܣ�����ƽ̨��ں���
		1��IP_ENTRY,IPV6_ENTRY,TCP_ENTRY,UDP_ENTRY
		2��ƽ̨��ں�����Ŀǰ�̶������Ǵ������ļ��ж�ȡ
���룺filename:��������ļ���[IN]
		 
�����0:sucess
		   -1:error
��ע:�κ�һ�������ļ�����д����ں��������򷵻ش���
*****************************************************************************/
int process_confelem_platentry(char* filename,void* fp_dlopen,char* plugname)
{
	int i;
	int ret=0;
	char buf_funflag[PLUGIN_MAX_CONFLEN]={0};
	char buf_funname[PLUGIN_MAX_CONFLEN] = {0};
	int plug_entry_id;
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
				sapp_printf("\033[1;31;40m[Error]%s has [%s] and %s,but no %s\033[0m\n", filename,g_plugin_entryname[i],KEYWORD_FUNFLAG,KEYWORD_FUNNAME);
				MESA_handle_runtime_log(g_plugin_runtime_handle,RLOG_LV_FATAL, PLUGIN_LOGNAME,"%s has [%s] and %s,but no %s",filename,g_plugin_entryname[i],KEYWORD_FUNFLAG,KEYWORD_FUNNAME);
				return -1;
			}
		
			fun_pointer = (char(*)())(dlsym(fp_dlopen,buf_funname));
			if(fun_pointer == NULL)
			{
				sapp_printf("\033[1;31;40m[Error]%s has [%s],but not load %s from %s sofile\033[0m\n", filename,g_plugin_entryname[i],buf_funname,plugname);
				MESA_handle_runtime_log(g_plugin_runtime_handle,RLOG_LV_FATAL, PLUGIN_LOGNAME,"%s has [%s],but not load %s from %s sofile",filename,g_plugin_entryname[i],buf_funname,plugname);
				return -1;
			}

			plug_entry_id = plug_mange_get_entry_id(plugname, buf_funname);
			ret=stream_register_fun((enum fun_type_t)i,fun_pointer, plug_entry_id); 
			if(ret==-1)
			{
				sapp_printf("\033[1;31;40m[Error]%s stream_register %s entry error\033[0m\n",filename,g_plugin_entryname[i]);
				MESA_handle_runtime_log(g_plugin_runtime_handle,RLOG_LV_INFO, PLUGIN_LOGNAME,"%s stream_register %s entry error!",filename,g_plugin_entryname[i]);
			}
			else
			{
				plugin_load_new_plug_entry(plugname, g_plugin_entryname[i], (void *)fun_pointer);
				MESA_handle_runtime_log(g_plugin_runtime_handle,RLOG_LV_INFO, PLUGIN_LOGNAME,"%s stream_register %s entry succ!",filename,g_plugin_entryname[i]);
			}
			
		}

	}

	return 0;
}

/****************************************************************************
������:process_confelem_appentry()
���ܣ�����ҵ�����Ľ�������ں���
		1����ѯ����entrylist.conf�к�������Ƿ����
		2�����ý��������Ƿ���ڣ�
		3���Զ�ת����ں�����
		4�����ý���������FLAG_CHANG����ת��flagֵ
		5�����ص���Ӧ�����㺯�����ϣ�
		 
�����0:sucess
		   -1:error
��ע:
	1����Ϊ������ѯentrylist.conf�к�������Ƿ���أ�����
		����ֻ����������ļ����Ƿ�ӵ����ȷ�Ĺ��ؽӿڣ�
		���������ļ���������ؽӿڴ����޷���飻
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
	int plug_entry_id;
	AppEntry appentry;

	for(i=0;i<g_entryname_info->num;i++)
	{
		memset(buf_funname,0,PLUGIN_MAX_CONFLEN);
		memset(buf_funflag,0,PLUGIN_MAX_CONFLEN);
	
		entryname = g_entryname_info->entryname[i].name;

		/* �Ӳ����.inf�����ļ���, ��ȡ�Ƿ��й��ص���ǰentry���ֵ���� */
		MESA_load_profile_string_nodef(filename,entryname,KEYWORD_FUNFLAG,buf_funflag,PLUGIN_MAX_CONFLEN);
		if(buf_funflag[0] != '\0')  
		{
			pluginfo_pro = get_propluginfo_name(entryname);
			if(pluginfo_pro == NULL)
			{
				sapp_printf("\033[1;31;40m[Error]%s has %s entry,but ther is no  protocol plug %s\033[0m\n", filename,entryname,entryname);
				MESA_handle_runtime_log(g_plugin_runtime_handle,RLOG_LV_FATAL, PLUGIN_LOGNAME,"%s has %s entry,but ther is no  protocol plug %s",filename,entryname,entryname);
				return -1;
			}

			flag = pluginfo_pro->fun_flagchange(buf_funflag);
			if(flag < 0)
			{
				MESA_handle_runtime_log(g_plugin_runtime_handle,RLOG_LV_FATAL, PLUGIN_LOGNAME,"%s's %s in [%s] error!",filename,KEYWORD_FUNFLAG,entryname);
				return -1;
			}

			MESA_load_profile_string_nodef(filename,entryname,KEYWORD_FUNNAME,buf_funname,PLUGIN_MAX_CONFLEN);
			if(buf_funname[0] =='\0')
			{
				sapp_printf("\033[1;31;40m[Error]%s has [%s] and %s,but no %s\033[0m\n", filename,entryname,KEYWORD_FUNFLAG,KEYWORD_FUNNAME);			
				MESA_handle_runtime_log(g_plugin_runtime_handle,RLOG_LV_FATAL, PLUGIN_LOGNAME,"%s has [%s] and %s,but no %s",filename,entryname,KEYWORD_FUNFLAG,KEYWORD_FUNNAME);
				return -1;
			}
		
			appentry = (char(*)(stSessionInfo* session_info,  void **pme, int thread_seq,struct streaminfo *a_stream,const void *a_packet))(dlsym(file_point,buf_funname));
			if(appentry == NULL)
			{
				sapp_printf("\033[1;31;40m[Error]%s has %s in [%s],not load from %s sofile\033[0m\n", filename,buf_funname,entryname,pluginfo_bus->plugname);
				MESA_handle_runtime_log(g_plugin_runtime_handle,RLOG_LV_FATAL, PLUGIN_LOGNAME,"%s has %s in [%s],not load from %s sofile",filename,buf_funname,entryname,pluginfo_bus->plugname);
				return -1;
			}

			plug_entry_id = plug_mange_get_entry_id(pluginfo_bus->plugname, buf_funname);
			rec = stream_register_app(&(pluginfo_pro->fun_list),pluginfo_bus->plugid,appentry,flag, plug_entry_id);
			if(rec < 0)
			{
				sapp_printf("\033[1;31;40m[Error]%s's %s stream_register_app() error\033[0m\n", pluginfo_bus->plugname,buf_funname);
				MESA_handle_runtime_log(g_plugin_runtime_handle,RLOG_LV_FATAL, PLUGIN_LOGNAME,"%s's %s stream_register_app() error!",pluginfo_bus->plugname,buf_funname);
				continue;
			}
			plugin_load_new_plug_entry(pluginfo_bus->plugname, entryname, (void *)appentry);
			
			MESA_handle_runtime_log(g_plugin_runtime_handle,RLOG_LV_INFO, PLUGIN_LOGNAME,"%s load %s entry succ!",filename,entryname);

		}

	}

	return 0;
}

static int fetch_section_name(char *filename, char *section_name)
{
	char *start_ptr;
	filename++;
	while(*filename == ' '){
		memmove(filename, filename+1, strlen(filename));
		filename++;
	}
	while(*filename == '\t'){
		memmove(filename, filename+1, strlen(filename));
		filename++;
	}

	start_ptr = filename;

	while(*filename != ']'){
		filename++;
	}

	*filename = '\0';

	strncpy(section_name, start_ptr, PLUGIN_FILENAME_MAXLEN);

	return 0;
}

/*
	filename : ./plug/conflist.inf
*/
static int process_conflist_single(char* filename, int plug_type, const char *wanted_section_name)
{
	int rec = 0;
	char buf_confname[PLUGIN_FILENAME_MAXLEN] = {0};
	char section_name[PLUGIN_FILENAME_MAXLEN];
	
	FILE* fp = fopen(filename,"r");
	if(fp == NULL)
	{
		MESA_handle_runtime_log(g_plugin_runtime_handle,RLOG_LV_FATAL, PLUGIN_LOGNAME,"process_conflist() fopen %s error!",filename);
		return -1;	
	}

	while(fgets(buf_confname,PLUGIN_FILENAME_MAXLEN,fp) != NULL){
		if(('#' == buf_confname[0]) || ('\r' == buf_confname[0]) || ('\n' == buf_confname[0]))
		{
			continue;
		}
		plugin_del_blank_rn(buf_confname, sizeof(buf_confname));
		
		if('[' == buf_confname[0]){
			fetch_section_name(buf_confname, section_name);
			continue;
		}
		if(strncasecmp(wanted_section_name, section_name, PLUGIN_FILENAME_MAXLEN) != 0){
			continue;
		}

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

		if(rec < 0){
            int priority = 0;
            if (plugin_is_necessary(buf_confname, &priority))
            {
                sapp_log(RLOG_LV_FATAL, 1, 1, "%s init error, but this plug is necessary, priority:%d, exit!", filename,
                         priority);
                exit(1);
            }
			plugin_load_state_update(rec, 0, buf_confname, NULL);
		}
	}

	fclose(fp);

	return rec;
}


static void confilist_file_check(void)
{
	struct stat fstat;
	int fres;

	fres = stat(ABBR_PLUG_LIST_CONF_FILE, &fstat);
	if(fres < 0){
		if(ENOENT == errno){
			sapp_log(30, 1, 1, "Error: plug conf list file:%s is not exist!", ABBR_PLUG_LIST_CONF_FILE);
			sapp_log(30, 1, 1, "\tin sapp_v4.0, conflist_platform.inf, conflist_protocol.inf, conflist_business.inf are obsoleted, use plug/conflist.inf instead,");
			sapp_log(30, 1, 1, "\tyou can copy and run the following command in sapp working directory, to generate a new conflist.inf:");
			sapp_log(30, 1, 1, "\tcommand: \n\techo \"[platform]\" > plug/conflist.inf;cat plug/platform/conflist_platform.inf >> plug/conflist.inf;\n\techo \"[protocol]\"  >> plug/conflist.inf;cat plug/protocol/conflist_protocol.inf >> plug/conflist.inf;\n\techo \"[business]\"  >> plug/conflist.inf;cat plug/business/conflist_business.inf >> plug/conflist.inf;\n");
			sapp_log(30, 1, 1, "\tyou can also run the shell script: '%s' in sapp working directory, to generate a new conflist.inf", "generate_v4.0_conflist.sh");

			exit(1);
		}
	}
}


/****************************************************************************
������:process_conflist()
���ܣ����������������ļ��б�����
���룺
�����0:sucess
		   -1:error
*****************************************************************************/
int process_conflist(int plug_type)
{
	int rec;

	confilist_file_check();

	/* 20190605 lijia modify, ʹ�õ�һ�����ļ�, ����ԭ����������������ļ� */
	if(PLUGTYPE_PLATFORM == plug_type){
		rec = process_conflist_single((char *)ABBR_PLUG_LIST_CONF_FILE, plug_type, "platform");
	}else if(PLUGTYPE_PROTOCOL == plug_type){
		rec = process_conflist_single((char *)ABBR_PLUG_LIST_CONF_FILE, plug_type, "protocol");
	}else{
		rec = process_conflist_single((char *)ABBR_PLUG_LIST_CONF_FILE, plug_type, "business");
	}

	return rec;	
}

void plug_record_start_time(int plug_id, int thread_seq)
{
	if(plugctrl_runtime_info.runtime_switch == 1)
	{
		plugctrl_runtime_info.callentry_num[thread_seq]++;
	
		gettimeofday(&(plugctrl_runtime_info.plug_starttime[thread_seq]),NULL);

	}
}
void plug_record_end_time(int plug_id, int thread_seq)
{
	unsigned long total_usetime;

	if(plugctrl_runtime_info.runtime_switch == 1)
	{
		plugctrl_runtime_info.callentry_num[thread_seq]++;
	
		gettimeofday(&(plugctrl_runtime_info.plug_endtime[thread_seq]),NULL);

		total_usetime = (unsigned long)(1000000*plugctrl_runtime_info.plug_endtime[thread_seq].tv_sec+plugctrl_runtime_info.plug_endtime[thread_seq].tv_usec)
		         	   -(unsigned long)(1000000*plugctrl_runtime_info.plug_starttime[thread_seq].tv_sec+plugctrl_runtime_info.plug_starttime[thread_seq].tv_usec);

		if(total_usetime > plugctrl_runtime_info.max_runtime*1000)
		{
			plugctrl_runtime_info.interval_num[thread_seq]++;
			if(g_CurrentTime-plugctrl_runtime_info.last_time[thread_seq]>60)
			{
				plugctrl_runtime_info.last_time[thread_seq]=g_CurrentTime;
				plugctrl_runtime_info.interval_num[thread_seq]=0;
			}
		
			MESA_handle_runtime_log(g_plugin_runtime_handle,RLOG_LV_FATAL, "CALL_APP_ENTRY","plug_id:%d timeout, total:%luus",plug_id,total_usetime);	

		}
	}
}


char plugin_call_appentry(stSessionFunInfo* funelem_session,stSessionInfo* session_info,int thread_seq,struct streaminfo *a_stream,const void *a_packet)
{
	char rec=APP_STATE_DROPME;
	struct timespec before_ts, after_ts;
	long long time_spent_ns;
	const struct streaminfo_private *stream_pr =(struct streaminfo_private *)a_stream;

	if(g_business_plug_info==NULL)
	{
		return rec;
	}
	int latency_enabled=MESA_handle_runtime_log_level_enabled(ABBR_PROCESS_LATENCY_LOG_HANDLE, RLOG_LV_INFO);
	if(unlikely(latency_enabled))
	{
		clock_gettime(g_clock_gettime_clock_id, &before_ts);
	}

	rec=funelem_session->appentry(session_info,&(funelem_session->pme),thread_seq,a_stream,a_packet);

	if(unlikely(latency_enabled)){
		clock_gettime(g_clock_gettime_clock_id, &after_ts);
		time_spent_ns = (after_ts.tv_sec*1000000000 + after_ts.tv_nsec) - (before_ts.tv_sec*1000000000 + before_ts.tv_nsec);
		if(sapp_global_val->config.profiling.histogram_enabled && time_spent_ns > 0)
		{
			sapp_fs2_fuzzy_latency_update_per_entry(thread_seq, funelem_session->entry_id, time_spent_ns);
		}
		if(time_spent_ns >= g_timestamp_record_threshold*1000){
			if(stream_pr->raw_pkt!=NULL)
			{
				((raw_pkt_t *)(stream_pr->raw_pkt))->diagnose_error_to_dump=1;
			}
			if(NULL == a_packet || (SESSION_STATE_CLOSE & session_info->session_state)){
				sapp_process_latency_log(RLOG_LV_INFO, "plug_name:%s, entry:%s, session close process latency:%lld us, addr:%s, datalen:%u, c:%u, s:%u, thread:%d", 
								g_plug_global_entry[funelem_session->entry_id].plug_name, 
								g_plug_global_entry[funelem_session->entry_id].plug_entry_name, time_spent_ns/1000,
								printaddr(&a_stream->addr, thread_seq), 
								a_stream->pudpdetail->datalen,
								a_stream->pudpdetail->clientpktnum,
								a_stream->pudpdetail->serverpktnum,
								thread_seq);

			}else{
				sapp_process_latency_log(RLOG_LV_INFO, "plug_name:%s, entry:%s, pkt process latency:%lld us, addr:%s, raw_len:%d, c:%u, s:%u, thread:%d", 
								g_plug_global_entry[funelem_session->entry_id].plug_name, 
								g_plug_global_entry[funelem_session->entry_id].plug_entry_name, 
								time_spent_ns/1000,
								printaddr(&a_stream->addr, thread_seq), 
								stream_pr->raw_pkt->raw_pkt_len,
								a_stream->pudpdetail->clientpktnum,
								a_stream->pudpdetail->serverpktnum,
								thread_seq);
			}				
		}
	}	
	return rec;
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
			funelem_session = (stSessionFunInfo*)sapp_mem_calloc(SAPP_MEM_DYN_PLUG_CTRL, thread_seq, sizeof(stSessionFunInfo));
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
		funelem_session->entry_id = funelem_pro->entry_id;

		if(funelem_session->protflag&prot_flag)
		{
			/* 2016-05-30 lijia add, �й��ĵ����ݱ�������SESSION_STATE_DATA
				���˴������ܸ�, ��Ϊ�ܶ�������������ж�״̬:

				if(session_state == SESSION_STATE_PENDING)
				{

				}
				switch(session_state)
				
				�������session_info->session_state |= SESSION_STATE_DATA;
				�ܶ����Ͷ���������.
			*/	
			//session_info->session_state |= SESSION_STATE_DATA; 
//del by liuy 20170525 for wy serial
//			funelem_session->appstate = funelem_session->appentry(session_info,&(funelem_session->pme),thread_seq,a_stream,a_packet);
			funelem_session->appstate =plugin_call_appentry(funelem_session,session_info,thread_seq,a_stream,a_packet);
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
		sapp_mem_free(SAPP_MEM_DYN_PLUG_CTRL, thread_seq, funelem_session);
		funelem_session=NULL;
	}

	if(funlist_session != NULL)
	{
		*pme = funlist_session;
		return ret;
	}

	return ret;

	
	
}

char plugin_process_data(stSessionInfo* session_info,void **pme, int thread_seq,struct streaminfo *a_stream,const void *a_packet)
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
//			funelem->appstate = funelem->appentry(session_info,&(funelem->pme),thread_seq,a_stream,a_packet);
			funelem->appstate =plugin_call_appentry(funelem,session_info,thread_seq,a_stream,a_packet);
			session_info->session_state = tmp_session_state;
		}else{
//			funelem->appstate = funelem->appentry(session_info,&(funelem->pme),thread_seq,a_stream,a_packet);
			funelem->appstate =plugin_call_appentry(funelem,session_info,thread_seq,a_stream,a_packet);
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
			
			sapp_mem_free(SAPP_MEM_DYN_PLUG_CTRL, thread_seq, funelem);
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
char plugin_process_close(int callbake_flag,stSessionInfo* session_info,void **pme, int thread_seq,struct streaminfo *a_stream,const void *a_packet)
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
char plugin_process_close(int callbake_flag,stSessionInfo* session_info,void **pme, int thread_seq,struct streaminfo *a_stream,const void *a_packet)
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
			
//		funelem->appstate = funelem->appentry(&session_info_tmp,&(funelem->pme),thread_seq,a_stream,a_packet);
		funelem->appstate =plugin_call_appentry(funelem,&session_info_tmp,thread_seq,a_stream,a_packet);
		if(funelem->appstate&PROT_STATE_DROPPKT)
		{
			ret |= PROT_STATE_DROPPKT;
		}

		next=funelem->next;
		sapp_mem_free(SAPP_MEM_DYN_PLUG_CTRL, thread_seq, funelem);
		
		funelem=next;	
	}

	*pme=NULL;

	return ret;
	
}
#endif

/*
	���session_state״̬ͬʱ���ʱ, ����: SESSION_STATE_PENDING|SESSION_STATE_DATA|SESSION_STATE_CLOSE

	ֻfree���stSessionFunInfo�ṹ, ���ٵ���ҵ����.
*/
static char session_multi_state_context_free(stSessionInfo* session_info,int thread_seq, void **pme)
{
	stSessionFunInfo* funlist=(stSessionFunInfo*)(*pme);
	stSessionFunInfo* funelem=funlist;
	stSessionFunInfo* next=NULL;
	
	while(funelem)
	{
		next=funelem->next;
		sapp_mem_free(SAPP_MEM_DYN_PLUG_CTRL, thread_seq, funelem);
		funelem=next;	
	}

	*pme=NULL;

	return 0;
}



char PROT_PROCESS(stSessionInfo* session_info, void **pme, int thread_seq,struct streaminfo *a_stream,const void *a_packet)
{
	char ret1=PROT_STATE_DROPME;
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

        /* 2021-05-12 lijia modify, close״̬�Ѿ������һ����, �����ظ�����ҵ���� */
		if(session_state&SESSION_STATE_CLOSE)
		{
			session_multi_state_context_free(session_info, thread_seq, pme);
		}

		return ret1;
	}

	if(session_state&SESSION_STATE_DATA)
	{
		if(*pme==NULL)
		{
			return ret1;
		}
		ret1 = plugin_process_data(session_info,pme,thread_seq,a_stream,a_packet);

        /* 2021-05-12 lijia modify, close״̬�Ѿ������һ����, �����ظ�����ҵ���� */
		if(session_state&SESSION_STATE_CLOSE)
		{
			session_multi_state_context_free(session_info, thread_seq, pme);
		}

		return ret1;
	}

	if(session_state&SESSION_STATE_CLOSE)
	{
		ret1 = plugin_process_close(1,session_info,pme,thread_seq,a_stream,a_packet);
	}

	return ret1;

}

extern stBusinessPlugInfo* g_platform_plug_info;
extern stBusinessPlugInfo* g_business_plug_info;
extern stProtocolPlugInfo* g_protocol_plug_info;

void plugctrl_destroy_all_plug()
{
	stBusinessPlugInfo *plug_info, *plug_next;
	stProtocolPlugInfo *pro_plug_info, *pro_plug_next;

	sapp_runtime_log(RLOG_LV_INFO, "plugctrl_destroy_all_plug, begin destory all plugin !");
	/***** call all plugins destory callback fun *****/
	plug_info = g_platform_plug_info;
	while (plug_info)
	{
		if (plug_info->fun_destroy)
		{
			sapp_runtime_log(RLOG_LV_INFO, "plugctrl_destroy_all_plug, platform, call [%s] destroy", plug_info->plugname);
			plug_info->fun_destroy();
		}
		plug_info = plug_info->next;
	}

	pro_plug_info = g_protocol_plug_info;
	while (pro_plug_info)
	{
		if (pro_plug_info->fun_destroy)
		{
			sapp_runtime_log(RLOG_LV_INFO, "plugctrl_destroy_all_plug, protocol, call [%s] destroy", pro_plug_info->plugname);
			pro_plug_info->fun_destroy();
		}
		while(pro_plug_info->fun_list)
		{
			stProtocolFunInfo* funlist=pro_plug_info->fun_list;
			pro_plug_info->fun_list=funlist->next;
			free(funlist);
		}
		pro_plug_info = pro_plug_info->next;
	}

	plug_info = g_business_plug_info;
	while (plug_info)
	{
		if (plug_info->fun_destroy)
		{
			sapp_runtime_log(RLOG_LV_INFO, "plugctrl_destroy_all_plug, business, call [%s] destroy", plug_info->plugname);
			plug_info->fun_destroy();
		}
		plug_info = plug_info->next;
	}

	sapp_runtime_log(RLOG_LV_INFO, "plugctrl_destroy_all_plug, begin dlcose all plugin !");
	/***** dlclose all plugins library handle  *****/
	plug_info = g_business_plug_info;
	while(plug_info){
		sapp_runtime_log(RLOG_LV_INFO, "plugctrl_destroy_all_plug, business, dlcose [%s]", plug_info->plugname);
		if(sapp_global_val->config.packet_io.dlclose_all_plug_enabled == 1)
		{
			dlclose(plug_info->filepoint);
		}
		plug_next = plug_info->next;
		if(plug_info->plugname != NULL)
		{
			SAPP_GLOBAL_FREE(plug_info->plugname);
			plug_info->plugname = NULL;
		}
		SAPP_GLOBAL_FREE(plug_info);
		plug_info = plug_next;
	}	
	g_business_plug_info = NULL;
	
	pro_plug_info = g_protocol_plug_info;
	while(pro_plug_info){
		sapp_runtime_log(RLOG_LV_INFO, "plugctrl_destroy_all_plug, protocol, dlcose [%s]", pro_plug_info->plugname);
		if(sapp_global_val->config.packet_io.dlclose_all_plug_enabled == 1)
		{
			dlclose(pro_plug_info->filepoint);
		}
		pro_plug_next = pro_plug_info->next;
		if(pro_plug_info->plugname != NULL)
		{
			SAPP_GLOBAL_FREE(pro_plug_info->plugname);
			pro_plug_info->plugname = NULL;
		}
		SAPP_GLOBAL_FREE(pro_plug_info);
		pro_plug_info = pro_plug_next;
	}	
	g_protocol_plug_info = NULL;
	
	plug_info = g_platform_plug_info;
	while(plug_info){
		sapp_runtime_log(RLOG_LV_INFO, "plugctrl_destroy_all_plug, platform, dlcose [%s]", plug_info->plugname);
		if(sapp_global_val->config.packet_io.dlclose_all_plug_enabled == 1)
		{
			dlclose(plug_info->filepoint);
		}
		plug_next = plug_info->next;
		if(plug_info->plugname != NULL)
		{
			SAPP_GLOBAL_FREE(plug_info->plugname);
			plug_info->plugname = NULL;
		}
		SAPP_GLOBAL_FREE(plug_info);
		plug_info = plug_next;
	}	
	g_platform_plug_info = NULL;

 	SAPP_GLOBAL_FREE(g_entryname_info->entryname);
 	SAPP_GLOBAL_FREE(g_entryname_info);

	g_plugin_plugid = 0;
	
	MESA_destroy_runtime_log_handle(g_plugin_runtime_handle);
	g_plugin_runtime_handle = NULL;
	sapp_runtime_log(RLOG_LV_INFO, "plugctrl_destroy_all_plug, finish !");

}


