#ifndef __MESA_JUMP_LAYER_H_
#define __MESA_JUMP_LAYER_H_ 1
#endif

#ifdef __cplusplus
extern "C" {
#endif

#include "stream.h"
#include <netinet/ip.h>
#include <netinet/ip6.h>


const char *MESA_jump_layer_get_last_error(void);


/*
	CHN : 数据包头部偏移函数.

	参数:
		raw_data: 当前层的头部指针;
		raw_layer_type: 当前层的地址类型, 详见: enum addr_type_t ;
		expect_layer_type: 期望跳转到的地址类型, 详见:  enum addr_type_t ;

	返回值:
		NULL: 无此地址;
		NON-NULL: 对应层的头部地址.

	举例:
		假设当前层为Ethernet, 起始包头地址为this_layer_hdr, 想跳转到IPv6层头部:
		struct ip6_hdr *ip6_header;
		ip6_header = MESA_net_jump_to_layer(this_layer_hdr, ADDR_TYPE_MAC, ADDR_TYPE_IPV6);
*/
const void *MESA_jump_layer(const void *raw_data,  int raw_layer_type, int expect_layer_type);

/*
	MESA_jump_layer_greedy与MESA_jump_layer的区别:
	   对于隧道嵌套协议来说,
	       MESA_jump_layer跳转到第一个expect_layer_type;
	       MESA_jump_layer_greedy跳转到最内层的expect_layer_type; 
*/
const void *MESA_jump_layer_greedy(const void *raw_data, int raw_layer_type, int expect_layer_type);



/* 向前兼容以前的接口名称, 作用同上 */
const void *MESA_net_jump_to_layer(const void *raw_data,  int raw_layer_type, int expect_layer_type);
const void *MESA_net_jump_to_layer_greedy(const void *raw_data, int raw_layer_type, int expect_layer_type);



const char *MESA_jump_layer_ipv4_ntop(const struct ip *ip4_hdr, char *out_buf, int buf_len );
const char *MESA_jump_layer_ipv6_ntop(const struct ip6_hdr *ip6_hdr, char *out_buf, int buf_len);

#ifdef __cplusplus
}
#endif
