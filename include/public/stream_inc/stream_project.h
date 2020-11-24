#ifndef _STREAM_PROJECT_H_
#define _STREAM_PROJECT_H_

#include "stream_base.h"

#ifdef __cplusplus
extern "C" {
#endif

#define STREAM_PROJECT_H_VERSION			(20201117)

#define PROJECT_REQ_NAME_MAX_LEN			(64)

typedef void (project_req_free_t)(int thread_seq, void *project_req_value);

#define PROJECT_VAL_TYPE_CHAR				"char"
#define PROJECT_VAL_TYPE_SHORT			"short"
#define PROJECT_VAL_TYPE_INT				"int"
#define PROJECT_VAL_TYPE_LONG				"long"
#define PROJECT_VAL_TYPE_STRUCT			"struct"

/* 
	CHN : 用于存储全部IP分片原始包 
	ENG : for store all ip frag packet in non-ip-frag entry.
*/
#define PROJECT_REQ_IPV4_FRAG_LIST			"ipv4_frag_list"
#define PROJECT_REQ_IPV6_FRAG_LIST			"ipv6_frag_list"


/* 
	CHN : 此宏定义表示TCP流量统计功能在project_list.conf中名称, 对应的project_id需要使用如下函数获取:
	ENG : this MARCO is use for tcp flow statistics, should enable this in project_list.conf. 		
	project_customer_register(PROJECT_REQ_TCP_FLOW, "struct");
*/
#define PROJECT_REQ_TCP_FLOW				"tcp_flow_stat"


#define PROJECT_REQ_TCP_DEDUCE_FLOW		"tcp_deduce_flow_stat"

/* 
	CHN : UDP流量统计功能平台固定开启, 不依赖project_list.conf控制, 对应的project_id需要使用如下函数获取:
	ENG : this MARCO is use for tcp flow statistics, it's always enable.
		project_customer_register(PROJECT_REQ_UDP_FLOW, "struct");
*/	
#define PROJECT_REQ_UDP_FLOW				"udp_flow_stat"

/* 
	CHN : 将包数,字节数统计值从pdetail中移动到project,字节数扩展为64bit. 
	ENG : before 2015-12-31, this statistics in struct streaminfo, after 2015-12-31, you must get these use project_req_get_struct().
*/
struct tcp_flow_stat
{
	UINT32 C2S_all_pkt;	/* All tcp packets, include SYN, ACK, FIN, RST, etc. */
	UINT32 C2S_data_pkt;	/* TCP reassemble packet, payload size more than zero, no retransmit packet */
	UINT32 S2C_all_pkt;
	UINT32 S2C_data_pkt;
	UINT64 C2S_all_byte;	/* All tcp packet's data size, include retransmit packet */
	UINT64 C2S_data_byte;	
	UINT64 S2C_all_byte;
	UINT64 S2C_data_byte;
	/* 以下是2020-11-17新增, 包括所有底层包头的原始包长度, 之前的内存结构不变, 向前兼容 */
	UINT64 C2S_all_byte_raw;
	UINT64 S2C_all_byte_raw;
};

struct udp_flow_stat
{
	UINT32 C2S_pkt;
	UINT32 S2C_pkt;
	UINT64 C2S_byte;
	UINT64 S2C_byte;
	/* 以下是2020-11-17新增, 包括所有底层包头的原始包长度, 之前的内存结构不变, 向前兼容 */
	UINT64 C2S_all_byte_raw;
	UINT64 S2C_all_byte_raw;	
};

/*	
	must call this function in initialization, only one times,
	the 'free_cb' should be NULL if 'project_req_val_type' is simple type,
	otherwise must implement it by youself.

	args:
		project_req_name: for example, "terminal_tag", "stream_id", "tcp_flow_stat".
		project_req_val_type: support "char","short","int","long","struct".
		free_cb: used to free resource when 'project_req_val_type' is "struct".
	
	return value: 'project_req_id' of this project_req_name, must use this id in following functions.
		>= 0 : success;
		  -1 : error.
*/
int project_producer_register(const char *project_req_name, const char *project_req_val_type, project_req_free_t *free_cb);

/* args and return value same with project_producer_register() */
int project_customer_register(const char *project_req_name, const char *project_req_val_type);

/*	
	Function project_req_add_struct(): 'project_req_value' must be a pointer to heap memory(obtain by malloc).
	
	return value:
		0 : success;
		-1: error.
*/
int project_req_add_char(struct streaminfo *stream, int project_req_id, char project_req_value);
int project_req_add_short(struct streaminfo *stream, int project_req_id, short project_req_value);
int project_req_add_int(struct streaminfo *stream, int project_req_id, int project_req_value);
int project_req_add_long(struct streaminfo *stream, int project_req_id, long project_req_value);

int project_req_add_uchar(struct streaminfo *stream, int project_req_id, unsigned char project_req_value);
int project_req_add_ushort(struct streaminfo *stream, int project_req_id, unsigned short project_req_value);
int project_req_add_uint(struct streaminfo *stream, int project_req_id, unsigned int project_req_value);
int project_req_add_ulong(struct streaminfo *stream, int project_req_id, unsigned long project_req_value);


int project_req_add_struct(struct streaminfo *stream, int project_req_id, const void *project_req_value);


/*
	return value:
		-1(or all bit is '1' in Hex mode, 0xFF, 0xFFFF, etc.): 
			maybe error, maybe the actual project_req_value is -1 indeed, 
			must check tht 'errno' in this case, 
			the 'errno' will be set to 'ERANGE' indicate an error.
		other: success, get the stored value.    

	For example:
		int value = project_req_get_int(stream, req_id);
		if((-1 == value) && (ERANGE == errno)){
			error_handle();                      
		}else{
			// this is not an error!!
			do_something();
		}
*/
char project_req_get_char(const struct streaminfo *stream, int project_req_id);
short project_req_get_short(const struct streaminfo *stream, int project_req_id);
int project_req_get_int(const struct streaminfo *stream, int project_req_id);
long project_req_get_long(const struct streaminfo *stream, int project_req_id);

unsigned char project_req_get_uchar(const struct streaminfo *stream, int project_req_id);
unsigned short project_req_get_ushort(const struct streaminfo *stream, int project_req_id);
unsigned int project_req_get_uint(const struct streaminfo *stream, int project_req_id);
unsigned long project_req_get_ulong(const struct streaminfo *stream, int project_req_id);

/*
	return value:
		NULL  : error;
		others: success.    
*/
const void *project_req_get_struct(const struct streaminfo *stream, int project_req_id);

#ifdef __cplusplus
}
#endif

#endif

