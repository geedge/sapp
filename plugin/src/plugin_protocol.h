#ifndef _PLUGIN_PROTOCOL_H
#define _PLUGIN_PROTOCOL_H

#include "plugin.h"


//解析层函数链情况，存储挂载在该解析层上每个业务层函数情况
//双向链表存储
typedef struct _plugin_protocol_fun_info
{
	int plugid;
	int aliveflag;										//业务层插件是否被卸载标记，被卸载的函数不再给新会话调用
	int callnum;										//入口函数被会话调用次数，只有当没有被调用时，才能卸载该插件
	long long protocol_flag;							//需要解析层解析字段flag标志
	AppEntry appentry;								//入口函数
	struct _plugin_protocol_fun_info* pre;
	struct _plugin_protocol_fun_info* next;
	
}stProtocolFunInfo;


//解析层插件信息，双向链表存储；
typedef struct _plugin_protocol_plug_info
{
	unsigned short plugid;
	char* plugname;									//解析层插件名，唯一标示
	void* filepoint;									//.so文件指针，卸载时close
	void  (*fun_destroy)();								//注销函数，卸载时调用
	void (*fun_flagstate)(long long protflag);				//业务插件需要协议flag值情况函数
	long long (*fun_flagchange)(char* flagstr);			//将业务层注册的字符串的flag转换成long long类型的函数
	stProtocolFunInfo* fun_list;
	struct _plugin_protocol_plug_info* pre;				
	struct _plugin_protocol_plug_info* next;

}stProtocolPlugInfo;


int plugin_load_protocol(char* conflist_filename);
int process_confelem_protocol(char* confelem_filename);



#endif

