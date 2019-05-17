#include "sapp_api.h"
#include "sapp_private_api.h"

#ifdef __cplusplus
extern "C" {
#endif

/**************************
packet_io.conf

[device_io]  //para env
IN=eth0, eth1 //可以多网卡收, 靠系统路由socket发包, 无需底层驱动支持
OUT=
[device_forward_flow] //para env
dir0=  //发送方向配置都是空
dir1= 

[device_io]  //2card device env
IN=eth0, eth1
OUT=eth1,eth0
through_send=eth1,eth0
reverse_send=eth0,eth1

[device_io]  //g-device master env
IN=vxlan_user
OUT=vxlan_user
through_send=vxlan_user
reverse_send=vxlan_user

[device_io]  //g-device slave env
IN=loop1
OUT=vxlan_user


[device_forward_flow] //2card device env
dir0=eth0->eth1
dir1=eth1->eth0

[device_forward_flow] //g-device master env
dir0=vxlan_user->vxlan_user
dir1=vxlan_user->vxlan_user

[device_forward_flow] //g-device slave env
dir0=loop1->vxlan_user
dir1=loop1->vxlan_user

[device_name_alias]
#target_id io_mode_custom_args
0    eth0 eth1 
1   eth1  eth2


*************************/

typedef struct{
	union{
		void *pkt_dio_buf; /* 由底层驱动定义, 如marsio的mbuff */

		/* 为了处理效率, 避免底层还要用临时变量做一次强制转换, 可以直接用不同dio的类型表示 */
#ifdef IOMODE_MARSIO
		marsio_buff_t *marsio_pkt_dio_buf;
#endif

#ifdef IOMODE_PFRING
		struct pfring_pkthdr *pfring_pkt_dio_buf;
#endif
	};
}sapp_vio_pkt_t;



typedef struct{
	/* options->type为输入参, 表示想获取什么类型, options->length, options->valud为输出参 */
	int *(vio_get_dio_param)(sapp_vio_pkt_t *pkt_dio_buf, SAPP_TLV_T *options);  /* 经过此函数转换后, 可以获取vio层面的数据, 比如获取原始包数据, 原始包长度, 原始包时间戳等 */
}sapp_vio_bridge_t;


int sapp_vio_pkt_entry(sapp_vio_pkt_t *pkt_dio_buf, int tid, unsigned char route_dir)
{
	/* 为了效率, dio直接提供raw_pkt的data和datalen, 其他不常用参数用vio_get_dio_param()函数获取 */
}

typedef struct{
	void *rcv_device_handle; /* 设备接收句柄 */
	void *fwd_device_handle; /* 设备转发句柄, 和rcv_device_handle一一对应 */
	void *snd_device_handle; /* 设备发送句柄 */
}sapp_io_device_handle;

typedef void * sapp_io_buf_t;

typedef struct{
	sapp_io_buf_t send_mbuf; /* 原始的发送缓存结构, 不一定可以直接供插件使用, 比如marsio->mbuf, 需要mtod转换 */
	void *(mbuf_mtod)(void *mbuf);  /* 经过此函数转换后, 可以供插件直接读取或写入数据 */

	

}sapp_io_handle;

/* 转发之前, 对于纯GDEV环境, 需要交换SMAC, DMAC, 由平台负载, 底层驱动不关心 */
int packet_io2_pre_forward(sapp_io_buf_t pkt_buf)
{

}


int packet_io2_forward(sapp_io_device_handle *device_handle, sapp_io_buf_t pkt_buf, int tid)
{
	int ret;
	
	packet_io2_pre_forward(pkt_buf);

	ret = dl_io2_forward(device_handle, pkt_buf);

	return ret;
}

/*
	兼容回调式(pcap, dpdk3.0)和主动获取式驱动(pag, pfring, marsio),
	最终包处理函数为回调式.
*/
int packet_io2_pkt_cb(sapp_io_device_handle *device_handle, sapp_io_buf_t pkt_buf, int tid)
{
	int ret;
	
	ret = mesa_default_pkt_cb();

	if(PASS == ret){
		packet_io2_forward(device_handle, pkt_buf, tid);
	}

	return 0;
}



int packet_io2_init()
{

}

int packet_io2_run()
{

}

#ifdef __cplusplus
}
#endif
