#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

enum {

    /* 报文回注 */
    TUNNAT_CZ_ACTION_FORWARD = ( 1 << 0 ),
    /* 内层隧道封装，设置该选项后，网关负责封装MAC头部 */
    TUNNAT_CZ_ACTION_ENCAP_INNER = ( 1 << 1 ),
    /* 外层隧道封装，设置该选项后，网关负责封装专用设备外层封装 */
    TUNNAT_CZ_ACTION_ENCAP_OUTER  = ( 1 << 2 ),
	/* 隧道封装方法，直接构建，不查询Session表 */
	TUNNAT_CZ_ACTION_ENCAP_NO_SESSION  = ( 1 << 3 )
	/* 使用虚拟链路号封装 */
	TUNNAT_CZ_ACTION_ENCAP_VIRTUAL_LINK_ID = ( 1 << 4),
};

enum
{
	TUNNAT_TUNNEL_TYPE_UNKNOWN,
	TUNNAT_TUNNEL_TYPE_G_VXLAN,
	TUNNAT_TUNNEL_TYPE_G_MAC_IN_MAC,
	TUNNAT_TUNNEL_TYPE_ETHER,
	TUNNAT_TUNNEL_TYPE_PPP,
	TUNNAT_TUNNEL_TYPE_HDLC,
	TUNNAT_TUNNEL_TYPE_IPV4,
	TUNNAT_TUNNEL_TYPE_IPV6
};

struct mr_tunnat_ctrlzone
{
    /* 封装格式，内部使用，应用程序不使用 */
    uint8_t __encap_type;
    /* 封装长度，内部使用，应用程序不使用 */
    uint16_t __encap_len;
    /* 伪以太网头部类型数据，内部使用，应用程序不使用 */
    uint16_t __p_ether_type;

    /* 方向，C-I或I-C方向 */
    uint8_t route_dir;
    /* 动作，见ACTION系列宏 */
    uint8_t action;

	/* 专用设备MAC地址 */
	uint8_t g_device_mac[6];
	/* 本地设备MAC地址 */
	uint8_t l_device_mac[6];
    /* 专用设备IP地址 */
    uint32_t g_device_in_addr;
	/* 本地设备IP地址 */
	uint32_t l_device_in_addr;
	/* 本地设备端口 */
	uint16_t l4_src_port;

    /* 专用设备VPN号 */
    uint32_t g_device_vpn_id;
    /* 专用设备链路ID号 */
    uint32_t g_device_linkpair;
    /* 专用设备封装格式（外层） */
    uint8_t g_device_outer_encap_type;
    /* 专用设备封装格式（内层）*/
    uint8_t g_device_inner_encap_type;

	/* 虚拟链路号 */
	uint64_t virtual_link_id;
	/* 分流重计算索引 */
	uint64_t rehash_index;
};

#ifdef __cplusplus
}
#endif