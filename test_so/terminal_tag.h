#ifndef _TERMINAL_TAG_H_
#define _TERMINAL_TAG_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "mesa_net.h"
#include <stdio.h>
#include <sys/types.h>

#define TERMINAL_MODULE_NAME		"terminal_tag"

#define TCP_SYN_TAG_TYPE	(0xF1)	
#define TCP_SYN_TAG_LEN		(12) /* 6BMAC+2B设备ID+1B类型+1B校验和+1B类型+1B长度 */
#define TCP_HDR_MAX_LEN		(60) /* TCP头部最大长度 */

#define rol(x,n)  (((x)<<(n)) | ((x)>>(8*sizeof(x)-(n))))
#define ror(x,n)  (((x)>>(n)) | ((x)<<(8*sizeof(x)-(n))))


#define IP_STRUCT_MAGIC		(0x8633)
struct local_ip_t{
	unsigned int ipaddr;				/* 终端设备内网IP, 网络序 */
	unsigned short ip_magic_num;		/* 魔数,存储IP时会空余两个字节,可用于验证 */
}BYTE_ALIGNED(1);	//sizeof(this)=6B

union local_addr_t{
 	unsigned char local_mac[6];			/* 终端设备MAC地址 */
	struct local_ip_t local_ip;			/* 终端设备内网IP结构 */
}BYTE_ALIGNED(1);   	//sizeof(this)=6B

#define TERMINAL_ADDR_TYPE_MAC			(0)
#define TERMINAL_ADDR_TYPE_IP			(1)
#define TERMINAL_ADDR_TYPE_TRACE		(2)
#define TERMINAL_ADDR_TYPE_GLOBAL_SIP	(3)
struct terminal_tag_t{
#if __BYTE_ORDER == __BIG_ENDIAN
	unsigned char type:2;  				/* 内网参数获取方式, 1:MAC; 2:IP */
	unsigned char random:6;				/* 随机数,用于加密 */
#elif __BYTE_ORDER == __LITTLE_ENDIAN
	unsigned char random:6;				/* 随机数,用于加密 */
	unsigned char type:2;  				/* 内网参数获取方式, 1:MAC; 2:IP */
#endif

	unsigned char check_sum;	  		/* 校验和，用于完整性认证、防伪造 */
	unsigned short dev_id; 				/* 设备ID (区域ID），网络序 */
	union local_addr_t local_addr;		/* 设备内网地址结构 */
}BYTE_ALIGNED(1);   	//sizeof(this)=10B

extern unsigned char terminal_tag_encrypt_hash(unsigned char rand_num, unsigned int ip_addr);
extern unsigned char terminal_tag_checksum_hash(unsigned char rand_num,	unsigned int ip_addr, unsigned short dev_id);
extern unsigned char terminal_tag_checksum(struct terminal_tag_t *terminal_tag,unsigned char checksum_key);

#ifdef __cplusplus
}
#endif

#endif


