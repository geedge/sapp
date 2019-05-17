#ifndef _APP_STREAM_TUNNEL_H_
#define _APP_STREAM_TUNNEL_H_ 1 

#define STREAM_TUNNEL_H_VERSION		(20161201)

#ifdef __cplusplus
extern "C" {
#endif

enum tunnel_channel_type_t{
	TUNNEL_CHANNEL_TYPE_CONTROL	= 1, /* 隧道协议控制通道 */
	TUNNEL_CHANNEL_TYPE_DATA	= 2, /* 隧道协议数据通道 */
};

enum tunnel_content_type_t{
	TUNNEL_CONTENT_TYPE_CLEAR		= 1, /* 明文数据 */
	TUNNEL_CONTENT_TYPE_COMPRESS	= 2,	/* 压缩数据 */
	TUNNEL_CONTENT_TYPE_ENCRYPT		= 3, /* 加密数据 */
};

#define PPTP_ENCRYPT_MPPE				(1)
#define PPTP_ENCRYPT_IPSEC				(2)
#define PPTP_ENCRYPT_PAP				(3)
#define PPTP_ENCRYPT_CHAP				(4)
#define PPTP_ENCRYPT_MS_CHAP			(5)
#define PPTP_ENCRYPT_EAP_TLS			(6)

#define PPTP_ENCRYPT_MPPC				(100) /* 压缩算法, 但日志库表中不存在, 使用100, 预留上述值的扩展空间 */

typedef struct{
	int link_type;
	int encrypt_pro;
	int authentication_pro;
	int protocol_compress_enable;
	int addr_ctrl_compress_enable;
	int content_type; /* refer to tunnel_content_type_t */	
}pptp_info_t;


#define L2TP_ENCRYPT_OTHER	(0)	
#define L2TP_ENCRYPT_IPSEC		(1)
#define L2TP_ENCRYPT_NONE		(2)

typedef struct{
	int link_type;
	int encrypt_pro;
	int authentication_pro;
	int protocol_compress_enable;
	int addr_ctrl_compress_enable;	
	int content_type; /* tunnel_content_type_t */	
	char *chap_username; /* string end with '\0' */
}l2tp_info_t;

#define IPSEC_VERSION_ISAKMP_V1	(1)
#define IPSEC_VERSION_IKE_V2		(2)


typedef struct{
	unsigned long long init_cookie;
	unsigned long long resp_cookie;
	unsigned short encry_algo;
	unsigned short hash_algo;
	unsigned short auth_method;
	unsigned char upon_udp_nat; /* 是否基于UDP-4500端口的NAT */
	unsigned char exchange_type;
	unsigned char major_version;
	unsigned char minor_version;
}isakmp_info_t;

typedef enum{
	/* NOTE: 很多协议相关的值并不连续, 因为需求不断再增加, 已有的定义不能改动, 只能再后面追加新值 */
	TUNNEL_PHONY_PROT_FLAG	= 1<<0,		/* phony flag, meaningless */	
	IPSEC_OPT_IKE_VERSION 		= 1<<1,  		/* opt_val type is int* */
	IPSEC_OPT_ENCRYPT_ALGO 	= 1<<2,  		/* opt_val type is int* */
	IPSEC_OPT_HASH_ALGO 		= 1<<3,  		/* opt_val type is int* */
	PPTP_OPT_LINK_TYPE 		= 1<<4,		/* opt_val type is int* */
	PPTP_OPT_ENCRYPT_PRO 		= 1<<5,		/* opt_val type is int* */
	PPTP_OPT_AUTHEN_PRO 		= 1<<6,		/* opt_val type is int* */
	PPTP_OPT_COMPRESS_PRO	= 1<<7,		/* opt_val type is int* */
	L2TP_OPT_LINK_TYPE 		= 1<<8,		/* opt_val type is int* */
	L2TP_OPT_ENCRYPT_PRO 		= 1<<9,		/* opt_val type is int* */	
	IPSEC_OPT_EXCHG_MODE		= 1<<10,		/* opt_val type is uint8*, just a 8bit integer, not string */	
	IPSEC_OPT_IS_NAT			= 1<<11, 	/* opt_val type is uint8*, just a 8bit integer, not string */
	L2TP_OPT_CHAP_USER_NAME 	= 1<<12, 	/* opt_val type is string, end with '\0' */
	PPTP_CONTENT_TYPE			= 1<<13,		/* opt_val type is int*,  refer to enum tunnel_content_type_t */
	L2TP_CONTENT_TYPE			= 1<<14,		/* opt_val type is int*,  refer to enum tunnel_content_type_t */	
}tunnel_info_opt_t;


struct MESA_tunnel_info{
	int tunnel_type; /* refer to stream_base.h --> enum stream_type_t */
	union{
		pptp_info_t pptp_info;
		l2tp_info_t l2tp_info;
		isakmp_info_t isakmp_info;
	};
};


#ifdef __cplusplus
}
#endif

#endif
