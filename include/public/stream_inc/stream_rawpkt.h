#ifndef _APP_STREAM_RAWPKT_H_
#define _APP_STREAM_RAWPKT_H_ 

#define STREAM_RAWPKT_H_VERSION		(20201104)

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
	RAW_PKT_GET_VIRTUAL_LINK_ID, //value type is uint64 *, out_value should be uint64 *
	RAW_PKT_GET_REHASH_INDEX,    // value type is uint64 *, out_value should be uint64 *
	RAW_PKT_GET_VXLAN_VPNID, // network-order, VPN_ID, value type is int, out_value should be int *
	RAW_PKT_GET_VXLAN_LOCAL_IP, // network-order, VXLAN Local IP, value type is int, out_value should be int *

	RAW_PKT_GET_ORIGINAL_LOWEST_ETH_SMAC, /* value type is char[6],真实原始包最外层的smac地址,mirror模式下, 等同于RAW_PKT_GET_DATA, 或者使用stream->pfather自行偏移; inline + vxlan + mrtunnat模式下, 等同于RAW_PKT_GET_VXLAN_OUTER_GDEV_MAC; */
	RAW_PKT_GET_ORIGINAL_LOWEST_ETH_DMAC, /* value type is char[6],真实原始包最外层的dmac地址,mirror模式下, 等同于RAW_PKT_GET_DATA, 或者使用stream->pfather自行偏移; inline + vxlan + mrtunnat模式下, 等同于RAW_PKT_GET_VXLAN_OUTER_LOCAL_MAC; */

	RAW_PKT_GET_ROUTE_CTX, /* max value size  char[64] */
	RAW_PKT_GET_SID_LIST, /* value defined in stream_control.h, struct segment_id_list */
	RAW_PKT_GET_IS_CTRL_PKT,
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
		 >=0:success,length of out_value;
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
	注意: 如果本层流类型为TCP或UDP, 调用此函数后, 得到原始包中对应的承载本层传输层的IP头部地址.
*/
const void *get_this_layer_header(const struct streaminfo *pstream);

/*
	CHN : 数据包头部偏移函数.
	ENG : 

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
		ip6_header = MESA_jump_layer(this_layer_hdr, ADDR_TYPE_MAC, ADDR_TYPE_IPV6);
*/
const void *MESA_jump_layer(const void *raw_data,  int raw_layer_type, int expect_layer_type);

const void *get_current_rawpkt_from_streaminfo(const struct streaminfo *pstream);

const void *get_rawpkt_from_streaminfo(const struct streaminfo *pstream, int route_direction);

struct detain_pkt;
struct detain_pkt* MESA_rawpkt_detain(const struct streaminfo *pstream, const void *rawpkt);
int MESA_detain_pkt_forward(struct detain_pkt *pkt);
void MESA_detain_pkt_free(struct detain_pkt *pkt);

#ifdef __cplusplus
}
#endif

#endif

