#ifndef _DEAL_PPP_H_
#define _DEAL_PPP_H_ 1

#include "mesa_net.h"

/* PPP协议解析公共模块, 从原始包中解析出的LCP参数, 仅当flag被置位时, 对应ppp_lcp_field_data_t类型的值才有意义 */
enum ppp_lcp_field_flag_t{
	PPP_LCP_FIELD_FLAG_AUTH_PRO_TYPE 				= 1 << 0,
	PPP_LCP_FIELD_FLAG_PRO_FIELD_COMPRESS			= 1 << 1,
	PPP_LCP_FIELD_FLAG_ADDR_CTRL_FIELD_COMPRESS 	= 1 << 2,
};

typedef struct{
	unsigned int ppp_lcp_field_pro_type; /* 认证协议类型, PAP, CHAP等 */
	unsigned int ppp_lcp_filed_pro_compress; /* 是否协议类型压缩 */
	unsigned int ppp_lcp_filed_addr_ctrl_compress; /* 是否控制、地址字段压缩 */
}ppp_lcp_field_data_t;

/* PPP协议解析公共模块, 从原始包中解析出的CCP参数 */
enum ppp_ccp_field_flag_t{
	PPP_CCP_FIELD_FLAG_COMPRESS 			= 1 << 0,
	PPP_CCP_FIELD_FLAG_ENCRYPT_TYPE		= 1 << 1,  /* 说明ppp_ccp_field_encrypt_type字段有效, 实际取值范围:ppp_ccp_encrypt_type_t */
};

enum ppp_ccp_encrypt_type_t{
	PPP_CCP_ENCRY_L40_BIT			= 1,
	PPP_CCP_ENCRY_M56_BIT		= 2,
	PPP_CCP_ENCRY_S128_BIT		= 3,	
};

typedef struct{
	unsigned int ppp_ccp_field_compress_enable;
	unsigned int ppp_ccp_field_encrypt_type;	 /* 实际取值范围:ppp_ccp_encrypt_type_t */
}ppp_ccp_field_data_t;



int ppp_lcp_pkt_parse(const struct mesa_ppp_lcp_ack_hdr *plcp_hdr, unsigned long long *field_flag, ppp_lcp_field_data_t *res);
int ppp_ccp_pkt_parse(const struct mesa_ppp_ccp_ack_hdr *pccp_hdr, unsigned long long *field_flag, ppp_ccp_field_data_t *res);

/*
	return value:
		0 : success.
		-1: internal error;
		-2: args error.
*/
int ppp_chap_pkt_parse(const struct mesa_ppp_chap_hdr *chap_hdr, char *res, int *res_len);

#endif
