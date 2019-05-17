#ifndef _PLUGIN_H
#define _PLUGIN_H

#include <netinet/ip.h>
#include "stream.h"

#ifdef __cplusplus
extern "C" {
#endif


#ifndef MAX_THREAD_NUM
#define MAX_THREAD_NUM 	128
#endif

#define PLUGTYPE_PROTOCOL		1
#define PLUGTYPE_BUSENISS		2
#define PLUGTYPE_PLATFORM		3

#define PLUGIN_MAX_ENTRYNUM	16

#define PLUGIN_MAX_CONFLEN	1024

#define KEYWORD_SPECIAL1		"["
#define KEYWORD_SPECIAL2		"]"

#define SECTION_PLUGINFO				"PLUGINFO"
#define SECTION_FUN_IP					"IP"
#define SECTION_FUN_IPV6				"IPV6"
#define SECTION_FUN_IPV4_RAW			"IPV4_RAW"
#define SECTION_FUN_IPV6_RAW			"IPV6_RAW"

#define SECTION_FUN_TCP				"TCP"
#define SECTION_FUN_TCP_ALL			"TCP_ALL"
#define SECTION_FUN_UDP				"UDP"
#define SECTION_FUN_TCP_RAW			"TCP_RAW"
#define SECTION_FUN_TCPALL_RAW		"TCPALL_RAW"
#define SECTION_FUN_UDP_RAW			"UDP_RAW"

#define SECTION_FUN_IP_FRAG			"IP_FRAG"
#define SECTION_FUN_IP_FRAG_RAW		"IP_FRAG_RAW"

#define SECTION_FUN_IPV6_FRAG			"IPV6_FRAG"
#define SECTION_FUN_IPV6_FRAG_RAW		"IPV6_FRAG_RAW"

/* 2016-09-01 lijia add, phony plug entry, will not be called in fact. */
#define SECTION_FUN_PHONY				"PHONY"

/* 2016-09-26 lijia add, polling plug entry, will be called wherether has received packet or not. */
#define SECTION_FUN_POLLING			"POLLING"


//20170525 liuyang add for wy serial
#define KEYWORD_PLUGID		"PLUGID"
#define KEYWORD_PLUGTYPE		"PLUGTYPE"
//add end
#define KEYWORD_PLUGNAME		"PLUGNAME"
#define KEYWORD_FILENAME		"SO_PATH"
#define KEYWORD_FUNINIT		"INIT_FUNC"
#define KEYWORD_FUNDESTROY	"DESTROY_FUNC"
#define KEYWORD_FUNUPDATE	"UPDATE_FUNC"
//只有解析层插件才需要
#define KEYWORD_FUNCHANGE	"FLAGCHANGE_FUNC"
#define KEYWORD_FUNSTATE		"FLAGSTATE_FUNC"
#define KEYWORD_FUNGETID		"GETPLUGID_FUNC"
#define KEYWORD_FUNFLAG		"FUNC_FLAG"
#define KEYWORD_FUNNAME		"FUNC_NAME"


#define FUNFLAG_ALL_B			"ALL"
#define FUNFLAG_ALL_S			"all"


typedef struct _plugin_entryname_elem
{
	char name[PLUGIN_MAX_CONFLEN];
}stEntryNameElem;


typedef struct _plugin_entry_name_info
{
	int num;
	stEntryNameElem* entryname;
}stEntryNameInfo;


typedef char (*AppEntry)(stSessionInfo* session_info,  void **pme, int thread_seq,struct streaminfo *a_stream,const void *a_packet);

//每个应用层会话需要的函数情况
typedef struct _plugin_protocol_session_fun_info
{
	long long protflag;
	AppEntry appentry;
//modify liuy 20140616 for pending has no flag;
	char called_flag;
//modify end
	char appstate;
	char pre_kill_flag;
	void* pme;			//业务插件上下文信息
	struct _plugin_protocol_session_fun_info* next;
}stSessionFunInfo;

extern void* g_plugin_runtime_handle;
extern int stream_register_fun(int funtype,char (*x)(void));

void plugin_call_flagstate();
int process_conf_entryname();
int process_confelem_plugname(char* filename,int plugtype,char** plugname);
int process_conflist(char* filename,int plug_type);

#ifdef __cplusplus
}
#endif


#endif

