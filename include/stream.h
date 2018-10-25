#ifndef _APP_STREAM_H_
#define _APP_STREAM_H_           

#include "stream_inc/stream_base.h"
#include "stream_inc/stream_proxy.h"
#include "stream_inc/stream_project.h"
#include "stream_inc/stream_inject.h"
#include "stream_inc/stream_control.h"
#include "stream_inc/stream_entry.h"
#include "stream_inc/stream_rawpkt.h"
#include "stream_inc/stream_tunnel.h"

#define STREAM_H_VERSION		(20170911)

#endif

/***********************************************************************************
	Update log:
	2015-02-03 lijia,
		修改stream_base.h,
		增加类型定义PKT_TYPE_IP_FRAG;
		增加stream_addr_list_ntop, stream_addr_list_pton系列函数.
		
	2015-01-23 lqy
		修改stream_base.h, 将pkttyp进行了扩展，增加了多个tcppkt的定义
		把pktipfragtype 从pkttype中独立为一个变量

	2015-01-04 lijia, 
		修改stream_base.h, 将pkttype移动至struct layer_addr结构中, 
		将routedir扩展为uchar类型;
		新增MESA_dir_reverse()函数, 用于发包时反向routedir.
		stream.h增加版本号和MD5验证值.

	2014-12-30 lqy,
		将原stream.h按功能类别拆分为7个stream_xxx.h, 
		将平台内部变量隐藏, public类型对插件可见, private为内部使用对外不可见.

	2015-11-12 lijia,
		增加新函数MESA_set_stream_opt(),
		用于设置当前流的独立参数.

	2015-12-30 lijia,
		修改stream_base.h,
		将struct tcpdetail, struct udpdetail中的包数、字节数统计移动至project.
		为了向后兼容, 暂时保留这些变量保证内存排列和旧版一致, 只是不再更新, 数值也无意义.
	
	2016-01-18 lijia,
		增加英文注释, 避免某些环境下SHELL无法显示中文的问题.

	2016-01-18 lijia,
		stream_base.h增加printaddr_r可重入版本, 可用于非捕包处理线程打印地址.

	2016-03-23 lijia,
		stream_base.h增加layer_addr_dup, layer_addr_free.

	2016-04-18 lijia,
		stream_control.h增加MSO_TCP_ISN_C2S, MSO_TCP_ISN_S2C.

	2016-04-27 lijia,
		修改stream_inject.h描述.

	2016-07-08 lijia,
		修改stream_control.h, 增加选项MSO_TCP_SYN_OPT, MSO_TCP_SYNACK_OPT.
		新增接口MESA_get_tcp_pkt_opts().

	2016-07-14 李佳,
		新增get_rawpkt_opt_from_streaminfo(), 用于没有原始包指针的插件获取原始包中的信息。

	2016-07-25 lijia		
		新增enum stream_carry_tunnel_t, 用于表示当前流底层隧道类型.

	2016-09-01 lijia		
		1)新增函数接口streaminfo_dup, streaminfo_free;
		2)新增stream_tunnel.h, 用于soq项目关于隧道协议相关信息的获取;

	2016-09-06 lijia
		1)新增STREAM_TYPE_OPENVPN, STREAM_TYPE_PPTP.

	2016-09-26 lijia
		1)新增STREAM_TYPE_PPTP.

	2016-10-09 lijia
		1)修改stream_inject.h, 增加MESA_kill_tcp_feedback()等带反馈功能的函数接口.

	2016-10-11 lijia
		1)修改stream_tunnel.h, 增加IPSEC_OPT_IS_NAT, L2TP_OPT_CHAP_USER_NAME.

	2016-12-01 lijia
		1)修改stream_tunnel.h, 增加PPTP_CONTENT_TYPE, L2TP_CONTENT_TYPE.
		2)修改stream_base.h, 增加ADDR_TYPE_PPTP地址类型, 和结构struct layer_addr_pptp.

	2016-12-01 lijia
		1)修改stream_base.h, 增加layer_addr_ntop, layer_addr_ntop_r地址转换函数.

	2017-09-11 lijia
		1)stream_control.h增加sapp_get_platform_opt()接口, 供外部插件获取平台内部参数.
		
*************************************************************************************/

