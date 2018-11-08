#ifndef _APP_STREAM_RAWPKT_H_
#define _APP_STREAM_RAWPKT_H_ 

#define STREAM_RAWPKT_H_VERSION		(20181029)

#include "stream_base.h"

enum{
	RAW_PKT_GET_DATA	= 1,	//return value is 0: out_value should be void **; return value is 1: out_value type is raw_ipfrag_list_t **;
	RAW_PKT_GET_RAW_PKT_TYPE,	//value type: enum addr_type_t in stream_base.h, out_value should be enum addr_type_t*
	RAW_PKT_GET_TOT_LEN,		//value type: int , out_value should be int *
	RAW_PKT_GET_TIMESTAMP,		//value type: struct timeval , out_value should be struct timeval *
	RAW_PKT_GET_THIS_LAYER_HDR,	//value type: void *, out_value should be void **
	RAW_PKT_GET_THIS_LAYER_REMAIN_LEN, //value type: int , out_value should be int *

	RAW_PKT_GET_GDEV_IP, // network-order, value type is int, out_value should be int *
	RAW_PKT_GET_VXLAN_ID, // network-order, LINK_ID, not VPN_ID, value type is int, out_value should be int *
	RAW_PKT_GET_VXLAN_SPORT, // network-order, value type is short, out_value should be short *
	RAW_PKT_GET_VXLAN_ENCAP_TYPE,  //value type is char, 
	RAW_PKT_GET_VXLAN_LINK_DIR,  //value type is char, 
	RAW_PKT_GET_VXLAN_OUTER_GDEV_MAC,  //value type is char[6],  
	RAW_PKT_GET_VXLAN_OUTER_LOCAL_MAC,  //value type is char[6],  
};

#ifdef __cplusplus
extern "C" {
#endif

/*
	get option from raw packet.

for example:
	CHN : 获取原始包数据, (根据捕包类型的不同, 可能从MAC开始, 也可能从IP头部开始, 需要使用RAW_PKT_GET_RAW_PKT_TYPE获取);
	ENG : get raw packet header, header's type depend on raw pacekt type, you should use RAW_PKT_GET_RAW_PKT_TYPE first;
	
	void *raw_pkt_data;
	ret = get_opt_from_rawpkt(voidpkt, RAW_PKT_GET_DATA, &raw_pkt_data);	
	if(0 == ret){
		(struct mesa_ethernet_hdr *)raw_pkt_data;
	}else if(1 == ret){
		(raw_ipfrag_list_t *)raw_pkt_data;
	}else{
		error!
	}
	
	CHN : 获取原始包总长度;
	ENG : get raw packet size;
	int tot_len;
	get_opt_from_rawpkt(voidpkt, RAW_PKT_GET_TOT_LEN, &tot_len);
	 
	CHN : 获取本层包头起始地址:
	ENG : get this layer header;
	void *this_layer_hdr;
	get_opt_from_rawpkt(voidpkt, RAW_PKT_GET_THIS_LAYER_HDR, &this_layer_hdr); 

	CHN : 获取原始包时间戳, 如果网卡或底层捕包库不支持时间戳功能, 值为全0:
	ENG : get raw packet timestamp, maybe zero if network card or library not support.
	struct timeval pkt_stamp;
	get_opt_from_rawpkt(voidpkt, RAW_PKT_GET_TIMESTAMP, &pkt_stamp); 

	return value:
		 1:only for RAW_PKT_GET_DATA type, value is raw_ipfrag_list_t;
		 0:success;
		-1:error, or not support.
*/
int get_opt_from_rawpkt(const void *rawpkt, int type, void *out_value);

/*
	CHN: 功能同上, 传入参数不同.
	ENG: Function ibid, except args pstream.
*/
int get_rawpkt_opt_from_streaminfo(const struct streaminfo *pstream, int type, void *out_value);

/* 	
	获取本层流在原始包中对应的头部地址,
	假设本层流类型为TCP, 调用此函数后, 得到原始包中对应的TCP头部地址.
*/
const void *get_this_layer_header(const struct streaminfo *pstream);

/*
	CHN : 数据包头部偏移函数.
	ENG : 

	参数:
		raw_data: 当前层的头部指针;
		raw_layer_type: 当前层的地址类型;
		expect_layer_type: 期望跳转到的地址类型;

	返回值:
		NULL: 无此地址;
		NON-NULL: 对应层的头部地址.
	

	举例:
		假设当前层为Ethernet, 起始包头地址为this_layer_hdr, 想跳转到IPv6层头部:
		struct ip6_hdr *ip6_header;
		ip6_header = MESA_net_jump_to_layer(this_layer_hdr, ADDR_TYPE_MAC, ADDR_TYPE_IPV6);
*/
const void *MESA_net_jump_to_layer(const void *raw_data,  int raw_layer_type, int expect_layer_type);

#ifdef __cplusplus
}
#endif

#endif

