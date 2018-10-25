#ifndef _MESA_FEEDBACK_H_
#define _MESA_FEEDBACK_H_

/*	version : 2015-12-31 */

#include <endian.h>

#define MESA_FEEDBACK_DEBUG		(1)

#if MESA_FEEDBACK_DEBUG
#define MESA_FEEDBACK_HDR_MAGIC	(0x4153454D) /* "MESA" */
#endif

typedef enum{
	MESA_FEEDBACK_TRANSFLAG_CONTINUE	=	0,	
	MESA_FEEDBACK_TRANSFLAG_START		=	1,
	MESA_FEEDBACK_TRANSFLAG_END			=	2,
	MESA_FEEDBACK_TRANSFLAG_ALL_IN_ONE	=	3,	
	MESA_FEEDBACK_TRANSFLAG_VOID		=	0xFF,	/* transflag在网络接口中只占两个bit, 0xFF是一个不可能的值, 在内存里表示未初始化状态 */
}MESA_feedback_transflag_t;

typedef enum{
	MESA_FEEDBACK_DTYPE_RESERVED		= 0,
	MESA_FEEDBACK_DTYPE_IPv4			= 1,
	MESA_FEEDBACK_DTYPE_IPv6			= 2,
	MESA_FEEDBACK_DTYPE_TCP				= 3,
	MESA_FEEDBACK_DTYPE_UDP				= 4,
	MESA_FEEDBACK_DTYPE_APP				= 5, /* 已知协议类型数据 */
	MESA_FEEDBACK_DTYPE_UNKNOWN_APP		= 6, /* 未知协议数据 */
	MESA_FEEDBACK_DTYPE_FEEDBACK		= 7,
	MESA_FEEDBACK_DTYPE_MAX				= 8,
}MESA_feedback_data_type_t;


/* 
	为了封装、解析方便, 定义了多种结构体, 
	先根据MESA_feedback_property_hdr_t的值, 决定后续结构体类型:

	stream = 0: 	MESA_feedback_raw_pkt_t;

	stream = 1时:
		reliable = 0 && chunk = 0: MESA_feedback_s_t;
		reliable = 0 && chunk = 1: MESA_feedback_sc_t;
		reliable = 1 && chunk = 0: MESA_feedback_sr_t;
		reliable = 1 && chunk = 1: MESA_feedback_scr_t;
*/
typedef struct {
/*
	因二进制接口无明显起始、结束标志, 
	DEBUG版本增加magic用于快速校验传输错误.
*/
#if MESA_FEEDBACK_DEBUG
	unsigned int magic;
#endif
#if __BYTE_ORDER == __LITTLE_ENDIAN
	unsigned char stream:1;
	unsigned char reliable:1;
	unsigned char chunk:1;
	unsigned char keepalive:1;
	unsigned char data_type:3;  /* 取值详见: MESA_feedback_data_type_t */
	unsigned char reserved2:1;
#elif __BYTE_ORDER == __BIG_ENDIAN
	unsigned char reserved2:1;
	unsigned char data_type:3; /* 取值详见: MESA_feedback_data_type_t */
	unsigned char keepalive:1;
	unsigned char chunk:1;
	unsigned char reliable:1;
	unsigned char stream:1;
#else
# error "Please fix <bits/endian.h>"
#endif
}__attribute__((packed, aligned(1)))MESA_feedback_property_hdr_t;


typedef struct{
	MESA_feedback_property_hdr_t property_hdr;
	unsigned short data_len; /* 指后续负载长度, 不含此头部 */
}__attribute__((packed, aligned(1)))MESA_feedback_raw_pkt_t;


/*
	说明:
		data_len字段指除当前头部外, 所有选项头部+选项内容+数据部分总和.
*/
typedef struct{
	MESA_feedback_property_hdr_t property_hdr;
#if __BYTE_ORDER == __LITTLE_ENDIAN
	unsigned char trans_flags:2; /* 取值详见: MESA_feedback_transflag_t */
	unsigned char trans_dir:2;	/* 流传输方向, 取值参考平台streaminfo定义 */
	unsigned char opt_num:4;
#elif __BYTE_ORDER == __BIG_ENDIAN
	unsigned char opt_num:4;
	unsigned char trans_dir:2;
	unsigned char trans_flags:2;
#else
# error "Please fix <bits/endian.h>"
#endif	
	unsigned short data_len;
	unsigned int data_id;
}__attribute__((packed, aligned(1)))MESA_feedback_sr_t;

typedef struct{
	MESA_feedback_property_hdr_t property_hdr;
#if __BYTE_ORDER == __LITTLE_ENDIAN
	unsigned char trans_flags:2;
	unsigned char trans_dir:2;
	unsigned char opt_num:4;
#elif __BYTE_ORDER == __BIG_ENDIAN
	unsigned char opt_num:4;
	unsigned char trans_dir:2;
	unsigned char trans_flags:2;
#else
# error "Please fix <bits/endian.h>"
#endif	
	unsigned short data_len;
	unsigned int data_id;
	unsigned int data_offset;
}__attribute__((packed, aligned(1)))MESA_feedback_s_t;

typedef struct{
	MESA_feedback_property_hdr_t property_hdr;
#if __BYTE_ORDER == __LITTLE_ENDIAN
	unsigned char trans_flags:2;
	unsigned char trans_dir:2;
	unsigned char opt_num:4;
#elif __BYTE_ORDER == __BIG_ENDIAN
	unsigned char opt_num:4;
	unsigned char trans_dir:2;
	unsigned char trans_flags:2;
#else
# error "Please fix <bits/endian.h>"
#endif	
	unsigned int data_len;
	unsigned int data_id;
}__attribute__((packed, aligned(1)))MESA_feedback_scr_t;

typedef struct{
	MESA_feedback_property_hdr_t property_hdr;
#if __BYTE_ORDER == __LITTLE_ENDIAN
	unsigned char trans_flags:2;
	unsigned char trans_dir:2;
	unsigned char opt_num:4;
#elif __BYTE_ORDER == __BIG_ENDIAN
	unsigned char opt_num:4;
	unsigned char trans_dir:2;
	unsigned char trans_flags:2;
#else
# error "Please fix <bits/endian.h>"
#endif	
	unsigned int data_len;
	unsigned int data_id;
	unsigned int data_offset;
}__attribute__((packed, aligned(1)))MESA_feedback_sc_t;

#endif

